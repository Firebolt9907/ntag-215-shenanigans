package com.nfcshenanigans.ntag215.core

/** Unsigned value of a byte (0..255). */
fun Byte.u(): Int = toInt() and 0xFF

fun ByteArray.toHex(separator: String = ""): String = Hex.encode(this, separator)

/** Hexadecimal conversion helpers. */
object Hex {
    private val DIGITS = "0123456789ABCDEF".toCharArray()

    fun encode(bytes: ByteArray, separator: String = ""): String {
        if (bytes.isEmpty()) return ""
        val sb = StringBuilder(bytes.size * (2 + separator.length))
        bytes.forEachIndexed { i, b ->
            if (i > 0) sb.append(separator)
            sb.append(DIGITS[(b.u() shr 4) and 0x0F])
            sb.append(DIGITS[b.u() and 0x0F])
        }
        return sb.toString()
    }

    fun byte(value: Int): String = encode(byteArrayOf(value.toByte()))

    /**
     * Decodes a hex string. Whitespace, ':' and '-' separators are ignored.
     * @throws IllegalArgumentException for odd length or non-hex characters.
     */
    fun decode(hex: String): ByteArray {
        val clean = hex.filterNot { it.isWhitespace() || it == ':' || it == '-' }
        require(clean.length % 2 == 0) { "Hex string must have an even number of digits" }
        return ByteArray(clean.length / 2) { i ->
            val hi = Character.digit(clean[i * 2], 16)
            val lo = Character.digit(clean[i * 2 + 1], 16)
            require(hi >= 0 && lo >= 0) { "Invalid hex digit" }
            ((hi shl 4) or lo).toByte()
        }
    }

    fun isValid(hex: String, byteCount: Int): Boolean {
        val clean = hex.filterNot { it.isWhitespace() || it == ':' || it == '-' }
        return clean.length == byteCount * 2 && clean.all { Character.digit(it, 16) >= 0 }
    }
}

/** ASCII conversion helpers. */
object Ascii {
    fun isAscii(c: Char): Boolean = c.code in 0x00..0x7F
    fun isPrintable(c: Char): Boolean = c.code in 0x20..0x7E
    fun isPrintable(b: Byte): Boolean = b.u() in 0x20..0x7E

    /** Encodes a pure-ASCII string to bytes. @throws IllegalArgumentException on non-ASCII input. */
    fun toBytes(text: String): ByteArray {
        require(text.all { isAscii(it) }) { "Text contains non-ASCII characters" }
        return ByteArray(text.length) { text[it].code.toByte() }
    }

    /** Decodes bytes as ASCII. @throws IllegalArgumentException if any byte is >= 0x80. */
    fun fromBytes(bytes: ByteArray): String {
        require(bytes.all { it.u() < 0x80 }) { "Bytes are not ASCII" }
        return String(CharArray(bytes.size) { bytes[it].u().toChar() })
    }

    fun asciiToHex(text: String, separator: String = " "): String = Hex.encode(toBytes(text), separator)

    fun hexToAscii(hex: String): String = fromBytes(Hex.decode(hex))

    /** Character used by memory viewers: printable ASCII or '.'. */
    fun displayChar(b: Byte): Char = if (isPrintable(b)) b.u().toChar() else '.'

    fun display(bytes: ByteArray): String = String(CharArray(bytes.size) { displayChar(bytes[it]) })
}
