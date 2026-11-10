package com.nfcshenanigans.ntag215.core

/**
 * NTAG215 memory map (NXP NTAG213/215/216 datasheet Rev. 3.2, section 8.5, Fig. 6)
 * and the application layout used by this app.
 *
 * Datasheet map (NTAG215):
 *  0x00-0x01  UID / serial number (read-only)
 *  0x02       UID byte 3, internal, static lock bytes 0-1 (OTP)
 *  0x03       Capability container (OTP, bit-wise OR on write)
 *  0x04-0x81  User memory, 504 bytes
 *  0x82       Dynamic lock bytes 0-2 + RFUI
 *  0x83       CFG0: MIRROR, RFUI, MIRROR_PAGE, AUTH0
 *  0x84       CFG1: ACCESS, RFUI, RFUI, RFUI
 *  0x85       PWD (write-only, reads 00h)
 *  0x86       PACK (2 bytes, write-only, reads 00h) + 2 RFUI bytes
 *
 * Application layout:
 *  0x04-0x1F  Public NDEF TLV area (112 bytes)
 *  0x20       Private ID (3 ASCII digits + 0x00)
 *  0x21-0x28  Private 32-byte ASCII secret
 *  0x29-0x81  Reserved (not touched)
 *  AUTH0 = 0x20, PROT = 1 -> pages 0x20..0x86 need PWD_AUTH for read and write.
 */
object Ntag215Memory {
    const val PAGE_SIZE = 4
    const val FIRST_PAGE = 0x00
    const val LAST_PAGE = 0x86
    const val TOTAL_PAGES = LAST_PAGE + 1 // 135

    const val STATIC_LOCK_PAGE = 0x02
    const val CC_PAGE = 0x03
    const val USER_FIRST_PAGE = 0x04
    const val USER_LAST_PAGE = 0x81
    const val USER_MEMORY_BYTES = (USER_LAST_PAGE - USER_FIRST_PAGE + 1) * PAGE_SIZE // 504
    const val DYNAMIC_LOCK_PAGE = 0x82
    const val CFG0_PAGE = 0x83
    const val CFG1_PAGE = 0x84
    const val PWD_PAGE = 0x85
    const val PACK_PAGE = 0x86

    // ---- Application layout ----
    const val PUBLIC_FIRST_PAGE = 0x04
    const val PUBLIC_LAST_PAGE = 0x1F
    const val PRIVATE_ID_PAGE = 0x20
    const val SECRET_FIRST_PAGE = 0x21
    const val SECRET_LAST_PAGE = 0x28
    const val PRIVATE_FIRST_PAGE = PRIVATE_ID_PAGE
    const val PRIVATE_LAST_PAGE = SECRET_LAST_PAGE

    /** AUTH0 value used by this app: first password-protected page. */
    const val APP_AUTH0 = PRIVATE_ID_PAGE

    const val PUBLIC_CAPACITY_BYTES = (PUBLIC_LAST_PAGE - PUBLIC_FIRST_PAGE + 1) * PAGE_SIZE // 112
    const val SECRET_LENGTH = (SECRET_LAST_PAGE - SECRET_FIRST_PAGE + 1) * PAGE_SIZE // 32
    const val AUTH0_DISABLED = 0xFF

    /**
     * Pages this app will never write: UID/manufacturer (0x00-0x01), static lock bytes (0x02),
     * capability container (0x03, OTP) and dynamic lock bytes (0x82).
     * Writing any of these can be irreversible.
     */
    fun isNeverWritable(page: Int): Boolean =
        page in FIRST_PAGE..CC_PAGE || page == DYNAMIC_LOCK_PAGE

    fun isValidPage(page: Int): Boolean = page in FIRST_PAGE..LAST_PAGE

    fun byteOffset(page: Int): Int = page * PAGE_SIZE

    fun pagesFor(byteCount: Int): Int = (byteCount + PAGE_SIZE - 1) / PAGE_SIZE

    /** Inclusive page range occupied by [byteCount] bytes starting at [startPage]. Empty for 0 bytes. */
    fun pageRange(startPage: Int, byteCount: Int): IntRange =
        if (byteCount <= 0) IntRange.EMPTY else startPage until startPage + pagesFor(byteCount)

    /** True if [byteCount] bytes written from [startPage] stay at or below [lastPage]. */
    fun fitsBefore(startPage: Int, byteCount: Int, lastPage: Int): Boolean =
        byteCount <= (lastPage - startPage + 1) * PAGE_SIZE

    /** Splits data into 4-byte pages, zero padding the last page (and up to [padToPages] pages). */
    fun splitIntoPages(data: ByteArray, padToPages: Int = 0): List<ByteArray> {
        val pages = maxOf(pagesFor(data.size), padToPages)
        return List(pages) { p ->
            ByteArray(PAGE_SIZE) { i ->
                val idx = p * PAGE_SIZE + i
                if (idx < data.size) data[idx] else 0
            }
        }
    }

    fun pageName(page: Int): String = when (page) {
        0x00, 0x01 -> "UID"
        STATIC_LOCK_PAGE -> "UID / static lock"
        CC_PAGE -> "Capability container"
        in PUBLIC_FIRST_PAGE..PUBLIC_LAST_PAGE -> "Public NDEF"
        PRIVATE_ID_PAGE -> "Private ID"
        in SECRET_FIRST_PAGE..SECRET_LAST_PAGE -> "Private secret"
        in (SECRET_LAST_PAGE + 1)..USER_LAST_PAGE -> "Reserved"
        DYNAMIC_LOCK_PAGE -> "Dynamic lock"
        CFG0_PAGE -> "CFG0 (AUTH0)"
        CFG1_PAGE -> "CFG1 (ACCESS)"
        PWD_PAGE -> "PWD (reads 00)"
        PACK_PAGE -> "PACK (reads 00)"
        else -> "?"
    }

    fun pageLabel(page: Int): String = "0x" + Hex.byte(page)
}
