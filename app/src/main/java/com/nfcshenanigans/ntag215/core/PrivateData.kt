package com.nfcshenanigans.ntag215.core

import java.security.SecureRandom

/** Three-digit private identifier "000".."999", stored as 3 ASCII bytes + 0x00 in page 0x20. */
class PrivateId private constructor(val value: String) {

    fun encode(): ByteArray = byteArrayOf(value[0].code.toByte(), value[1].code.toByte(), value[2].code.toByte(), 0x00)

    /** Next identifier (e.g. 041 -> 042), or null after 999. */
    fun next(): PrivateId? = (value.toInt() + 1).takeIf { it <= 999 }?.let { PrivateId(it.toString().padStart(3, '0')) }

    override fun equals(other: Any?) = other is PrivateId && other.value == value
    override fun hashCode() = value.hashCode()
    override fun toString() = value

    sealed interface Decoded {
        data class Valid(val id: PrivateId) : Decoded
        data object Empty : Decoded
        data class Malformed(val raw: ByteArray) : Decoded
    }

    companion object {
        private val PATTERN = Regex("^[0-9]{3}$")

        /** Returns an error message or null if [input] is a valid 3-digit ID. */
        fun validate(input: String): String? = when {
            input.isEmpty() -> "Enter a three-digit ID"
            !input.all { it in '0'..'9' } -> "Digits only"
            input.length != 3 -> "Exactly 3 digits (e.g. 042)"
            else -> null
        }

        fun parse(input: String): PrivateId? = if (PATTERN.matches(input)) PrivateId(input) else null

        fun decode(page: ByteArray): Decoded {
            require(page.size >= 4)
            val p = page.copyOf(4)
            if (p.all { it.toInt() == 0 }) return Decoded.Empty
            val digits = (0..2).all { p[it].u() in 0x30..0x39 }
            return if (digits && p[3].toInt() == 0) {
                Decoded.Valid(PrivateId(String(CharArray(3) { p[it].u().toChar() })))
            } else {
                Decoded.Malformed(p)
            }
        }
    }
}

/** Exactly 32 printable ASCII characters, stored in pages 0x21..0x28. */
class Secret private constructor(val value: String) {

    fun encode(): ByteArray = Ascii.toBytes(value)

    fun pages(): List<ByteArray> = Ntag215Memory.splitIntoPages(encode())

    fun masked(): String = "•".repeat(LENGTH)

    override fun equals(other: Any?) = other is Secret && other.value == value
    override fun hashCode() = value.hashCode()

    /** Never print secrets accidentally (logs, exceptions, toString interpolation). */
    override fun toString() = "Secret(********)"

    sealed interface Decoded {
        data class Valid(val secret: Secret) : Decoded
        data object Empty : Decoded
        data class Malformed(val reason: String) : Decoded
    }

    companion object {
        const val LENGTH = Ntag215Memory.SECRET_LENGTH
        private const val ALPHANUMERIC = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

        fun validate(input: String): String? {
            val nonAscii = input.firstOrNull { !Ascii.isAscii(it) }
            val nonPrintable = input.firstOrNull { Ascii.isAscii(it) && !Ascii.isPrintable(it) }
            return when {
                nonAscii != null -> "Non-ASCII character '$nonAscii' is not allowed"
                nonPrintable != null -> "Control characters are not allowed"
                input.length < LENGTH -> "Too short: ${input.length}/$LENGTH characters"
                input.length > LENGTH -> "Too long: ${input.length}/$LENGTH characters"
                else -> null
            }
        }

        fun parse(input: String): Secret? = if (validate(input) == null) Secret(input) else null

        /** Random alphanumeric secret from a CSPRNG. SecureRandom.nextInt(bound) is unbiased. */
        fun generate(random: SecureRandom = SecureRandom()): Secret =
            Secret(String(CharArray(LENGTH) { ALPHANUMERIC[random.nextInt(ALPHANUMERIC.length)] }))

        fun decode(bytes: ByteArray): Decoded {
            require(bytes.size >= LENGTH)
            val b = bytes.copyOf(LENGTH)
            if (b.all { it.toInt() == 0 }) return Decoded.Empty
            if (!b.all { Ascii.isPrintable(it) }) return Decoded.Malformed("contains non-printable or non-ASCII bytes")
            return Decoded.Valid(Secret(Ascii.fromBytes(b)))
        }
    }
}

/**
 * 32-bit NTAG password. Bytes are kept in transmission order: the same order is written to page 0x85
 * and sent in PWD_AUTH (datasheet 8.8.1: "written LSByte first ... same byte order as PWD_AUTH").
 */
class Password private constructor(private val bytes: ByteArray) {
    fun bytes(): ByteArray = bytes.copyOf()
    fun hex(): String = bytes.toHex()

    override fun equals(other: Any?) = other is Password && other.bytes.contentEquals(bytes)
    override fun hashCode() = bytes.contentHashCode()
    override fun toString() = "Password(********)"

    companion object {
        const val HEX_LENGTH = 8

        fun validate(hex: String): String? = when {
            hex.isEmpty() -> "Enter an 8-digit hex password"
            !hex.all { Character.digit(it, 16) >= 0 } -> "Hex digits 0-9, A-F only"
            hex.length != HEX_LENGTH -> "Exactly 8 hex digits (${hex.length}/8)"
            else -> null
        }

        fun parse(hex: String): Password? = if (validate(hex) == null) Password(Hex.decode(hex)) else null

        fun of(bytes: ByteArray): Password {
            require(bytes.size == 4)
            return Password(bytes.copyOf())
        }

        /** Random password, avoiding the factory default FFFFFFFF and the trivial 00000000. */
        fun generate(random: SecureRandom = SecureRandom()): Password {
            while (true) {
                val b = ByteArray(4).also { random.nextBytes(it) }
                val all = b.map { it.u() }.toSet()
                if (all != setOf(0xFF) && all != setOf(0x00)) return Password(b)
            }
        }
    }
}

/** 16-bit password acknowledge returned by PWD_AUTH. Not a cryptographic authenticator. */
class Pack private constructor(private val bytes: ByteArray) {
    fun bytes(): ByteArray = bytes.copyOf()
    fun hex(): String = bytes.toHex()

    /** Page 0x86 content: PACK0, PACK1, RFUI (00), RFUI (00). */
    fun page(): ByteArray = byteArrayOf(bytes[0], bytes[1], 0x00, 0x00)

    fun matches(response: ByteArray) = response.contentEquals(bytes)

    override fun equals(other: Any?) = other is Pack && other.bytes.contentEquals(bytes)
    override fun hashCode() = bytes.contentHashCode()
    override fun toString() = "Pack(${hex()})"

    companion object {
        const val HEX_LENGTH = 4

        fun validate(hex: String): String? = when {
            hex.isEmpty() -> "Enter a 4-digit hex PACK"
            !hex.all { Character.digit(it, 16) >= 0 } -> "Hex digits 0-9, A-F only"
            hex.length != HEX_LENGTH -> "Exactly 4 hex digits (${hex.length}/4)"
            else -> null
        }

        fun parse(hex: String): Pack? = if (validate(hex) == null) Pack(Hex.decode(hex)) else null

        fun of(bytes: ByteArray): Pack {
            require(bytes.size == 2)
            return Pack(bytes.copyOf())
        }

        fun generate(random: SecureRandom = SecureRandom()): Pack = Pack(ByteArray(2).also { random.nextBytes(it) })
    }
}
