package com.nfcshenanigans.ntag215.core

/** GET_VERSION (0x60) response, datasheet Table 28. */
class TagVersion(bytes: ByteArray) {
    val raw: ByteArray = bytes.copyOf()

    init {
        require(raw.size == 8) { "GET_VERSION response must be 8 bytes, got ${raw.size}" }
    }

    val header get() = raw[0].u()
    val vendorId get() = raw[1].u()
    val productType get() = raw[2].u()
    val productSubtype get() = raw[3].u()
    val majorVersion get() = raw[4].u()
    val minorVersion get() = raw[5].u()
    val storageSize get() = raw[6].u()
    val protocolType get() = raw[7].u()

    val isNxp get() = vendorId == 0x04
    val isNtag get() = isNxp && productType == 0x04

    /** NTAG215: vendor 04h, product type 04h (NTAG), storage size 11h, protocol 03h. */
    val isNtag215 get() = isNtag && storageSize == 0x11 && protocolType == 0x03

    val productName: String
        get() = when {
            isNtag && storageSize == 0x0F -> "NTAG213"
            isNtag && storageSize == 0x11 -> "NTAG215"
            isNtag && storageSize == 0x13 -> "NTAG216"
            isNtag -> "NTAG (unknown variant)"
            isNxp && productType == 0x03 -> "MIFARE Ultralight family"
            isNxp -> "NXP product type 0x${Hex.byte(productType)}"
            else -> "Unknown (vendor 0x${Hex.byte(vendorId)})"
        }

    /** Storage size coding: 7 MSBs = n, total user memory is 2^n (LSB 0) or between 2^n and 2^(n+1) (LSB 1). */
    val storageDescription: String
        get() {
            val n = storageSize shr 1
            return if (storageSize and 1 == 0) "${1 shl n} bytes" else "between ${1 shl n} and ${1 shl (n + 1)} bytes"
        }
}

/** Capability container (page 0x03), NFC Forum T2T. */
class CapabilityContainer(bytes: ByteArray) {
    val raw: ByteArray = bytes.copyOf(4)

    val magic get() = raw[0].u()
    val version get() = raw[1].u()
    val sizeByte get() = raw[2].u()
    val access get() = raw[3].u()

    val hasNdefMagic get() = magic == 0xE1
    val versionMajor get() = version shr 4
    val versionMinor get() = version and 0x0F
    val dataAreaBytes get() = sizeByte * 8
    val readAccess get() = access shr 4
    val writeAccess get() = access and 0x0F

    /** Formatted as NDEF with a supported mapping version (1.x). */
    val isNdefFormatted get() = hasNdefMagic && versionMajor == 1
    val allowsRead get() = readAccess == 0x0
    val allowsWrite get() = writeAccess == 0x0

    /** NTAG215 factory value E1 10 3E 00 (datasheet Table 6). */
    val isNtag215Default get() = raw.contentEquals(byteArrayOf(0xE1.toByte(), 0x10, 0x3E, 0x00))

    override fun toString(): String = raw.toHex(" ")
}

/** Static lock bytes: page 0x02 bytes 2 and 3 (datasheet 8.5.2, Fig. 9). */
class StaticLockBits(val lock0: Int, val lock1: Int) {
    /** Pages locked read-only. lock0 bit3 = CC, bits4..7 = pages 4..7; lock1 bits0..7 = pages 8..15. */
    val lockedPages: Set<Int>
        get() = buildSet {
            if (lock0 and 0x08 != 0) add(Ntag215Memory.CC_PAGE)
            for (bit in 4..7) if (lock0 and (1 shl bit) != 0) add(bit)
            for (bit in 0..7) if (lock1 and (1 shl bit) != 0) add(8 + bit)
        }

    val blockLockBits get() = lock0 and 0x07
    val anySet get() = lock0 != 0 || lock1 != 0

    companion object {
        fun fromPage2(page2: ByteArray) = StaticLockBits(page2[2].u(), page2[3].u())
    }
}

/** NTAG215 dynamic lock bytes at page 0x82 (datasheet 8.5.3, Fig. 11). Granularity 16 pages. */
class DynamicLockBits(val lock0: Int, val lock1: Int, val lock2: Int) {
    /** Byte 0 bit i (0..6) locks pages 16+16i .. 16+16i+15; bit 7 locks pages 128-129. Byte 1 is RFUI. */
    val lockedPages: Set<Int>
        get() = buildSet {
            for (bit in 0..6) if (lock0 and (1 shl bit) != 0) addAll((16 + 16 * bit)..(16 + 16 * bit + 15))
            if (lock0 and 0x80 != 0) addAll(128..129)
        }

    /** Byte 2 bits 0..3: block-locking for page ranges 16-47, 48-79, 80-111, 112-129. */
    val blockLockBits get() = lock2 and 0x0F
    val anySet get() = lock0 != 0 || (lock2 and 0x0F) != 0

    companion object {
        fun fromPage(page: ByteArray) = DynamicLockBits(page[0].u(), page[1].u(), page[2].u())
    }
}

/**
 * Configuration pages CFG0 (0x83) and CFG1 (0x84), datasheet section 8.5.7, Tables 8-11.
 * All bits not intentionally changed (MIRROR, MIRROR_PAGE, RFUI bytes, CFGLCK, NFC_CNT_*, AUTHLIM)
 * are preserved by [withProtection] / [withoutProtection].
 */
class Ntag215Config(cfg0: ByteArray, cfg1: ByteArray) {
    val cfg0: ByteArray = cfg0.copyOf(4)
    val cfg1: ByteArray = cfg1.copyOf(4)

    val mirror get() = cfg0[0].u()
    val mirrorConf get() = (mirror shr 6) and 0x03
    val mirrorByte get() = (mirror shr 4) and 0x03
    val strongModulation get() = mirror and STRG_MOD_EN != 0
    val mirrorPage get() = cfg0[2].u()
    val auth0 get() = cfg0[3].u()

    val access get() = cfg1[0].u()
    val prot get() = access and PROT != 0
    val cfgLock get() = access and CFGLCK != 0
    val nfcCounterEnabled get() = access and NFC_CNT_EN != 0
    val nfcCounterPasswordProtected get() = access and NFC_CNT_PWD_PROT != 0
    val authLim get() = access and AUTHLIM_MASK

    /** AUTH0 within addressable memory activates password protection (8.8.3). */
    val protectionActive get() = auth0 <= Ntag215Memory.LAST_PAGE
    val readProtectedFrom: Int? get() = if (protectionActive && prot) auth0 else null
    val writeProtectedFrom: Int? get() = if (protectionActive) auth0 else null

    /** ASCII mirror enabled when MIRROR_CONF != 00b and MIRROR_PAGE > 03h. */
    val mirrorEnabled get() = mirrorConf != 0 && mirrorPage > 0x03

    /** Absolute byte addresses covered by the virtual ASCII mirror, or null when disabled. */
    val mirrorByteRange: IntRange?
        get() {
            if (!mirrorEnabled) return null
            val len = when (mirrorConf) {
                1 -> 14 // UID: 7 bytes as 14 hex chars
                2 -> 6 // NFC counter: 3 bytes as 6 hex chars
                else -> 21 // UID + 'x' + counter
            }
            val start = mirrorPage * Ntag215Memory.PAGE_SIZE + mirrorByte
            return start until start + len
        }

    fun mirrorOverlapsPages(pages: IntRange): Boolean {
        val r = mirrorByteRange ?: return false
        val first = pages.first * Ntag215Memory.PAGE_SIZE
        val last = (pages.last + 1) * Ntag215Memory.PAGE_SIZE - 1
        return r.first <= last && r.last >= first
    }

    /** Returns a copy with AUTH0 and PROT set; every other bit is preserved. */
    fun withProtection(auth0: Int, readProtect: Boolean): Ntag215Config {
        require(auth0 in 0x00..0xFF)
        val n0 = cfg0.copyOf().also { it[3] = auth0.toByte() }
        val newAccess = (access and PROT.inv()) or (if (readProtect) PROT else 0)
        val n1 = cfg1.copyOf().also { it[0] = newAccess.toByte() }
        return Ntag215Config(n0, n1)
    }

    /** Disables protection: AUTH0 = FFh, PROT = 0. Every other bit is preserved. */
    fun withoutProtection(): Ntag215Config = withProtection(Ntag215Memory.AUTH0_DISABLED, false)

    fun sameAs(other: Ntag215Config) = cfg0.contentEquals(other.cfg0) && cfg1.contentEquals(other.cfg1)

    fun describeProtection(): String = when {
        !protectionActive -> "Disabled (AUTH0 = 0x${Hex.byte(auth0)})"
        prot -> "Read + write protected from page 0x${Hex.byte(auth0)}"
        else -> "Write protected from page 0x${Hex.byte(auth0)} (reads are open)"
    }

    fun describeAuthLim(): String =
        if (authLim == 0) "0 (unlimited attempts)" else "$authLim (failed attempts are limited; reaching the limit permanently blocks protected memory)"

    companion object {
        const val PROT = 0x80
        const val CFGLCK = 0x40
        const val NFC_CNT_EN = 0x10
        const val NFC_CNT_PWD_PROT = 0x08
        const val AUTHLIM_MASK = 0x07
        const val STRG_MOD_EN = 0x04

        /** Factory defaults (Table 11): MIRROR 04h (STRG_MOD_EN=1), AUTH0 FFh, ACCESS 00h. */
        fun factoryDefault() = Ntag215Config(
            byteArrayOf(0x04, 0x00, 0x00, 0xFF.toByte()),
            byteArrayOf(0x00, 0x00, 0x00, 0x00),
        )
    }
}
