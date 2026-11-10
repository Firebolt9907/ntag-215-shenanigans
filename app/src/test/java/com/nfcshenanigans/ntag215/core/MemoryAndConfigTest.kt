package com.nfcshenanigans.ntag215.core

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class MemoryAndConfigTest {

    private fun bytes(vararg v: Int) = ByteArray(v.size) { v[it].toByte() }

    // ---------------------------------------------------------------- memory layout

    @Test fun layoutConstantsMatchDatasheet() {
        assertEquals(135, Ntag215Memory.TOTAL_PAGES)
        assertEquals(504, Ntag215Memory.USER_MEMORY_BYTES)
        assertEquals(112, Ntag215Memory.PUBLIC_CAPACITY_BYTES)
        assertEquals(32, Ntag215Memory.SECRET_LENGTH)
        assertEquals(0x20, Ntag215Memory.APP_AUTH0)
        assertEquals(0x82, Ntag215Memory.DYNAMIC_LOCK_PAGE)
        assertEquals(0x85, Ntag215Memory.PWD_PAGE)
        // Private data fits in the user memory and before the reserved area.
        assertEquals(0x28, Ntag215Memory.SECRET_FIRST_PAGE + Ntag215Memory.pagesFor(32) - 1)
    }

    @Test fun pageAddressCalculations() {
        assertEquals(0x80, Ntag215Memory.byteOffset(0x20))
        assertEquals(0, Ntag215Memory.pagesFor(0))
        assertEquals(1, Ntag215Memory.pagesFor(1))
        assertEquals(1, Ntag215Memory.pagesFor(4))
        assertEquals(2, Ntag215Memory.pagesFor(5))
        assertEquals(0x04..0x08, Ntag215Memory.pageRange(0x04, 19))
        assertTrue(Ntag215Memory.pageRange(0x04, 0).isEmpty())
        assertTrue(Ntag215Memory.fitsBefore(0x04, 112, 0x1F))
        assertFalse(Ntag215Memory.fitsBefore(0x04, 113, 0x1F))
    }

    @Test fun splitIntoPagesPadsWithZeros() {
        val pages = Ntag215Memory.splitIntoPages(bytes(1, 2, 3, 4, 5))
        assertEquals(2, pages.size)
        assertArrayEquals(bytes(5, 0, 0, 0), pages[1])
        assertEquals(4, Ntag215Memory.splitIntoPages(bytes(1), padToPages = 4).size)
    }

    @Test fun systemPagesAreNeverWritable() {
        (0x00..0x03).forEach { assertTrue(Ntag215Memory.isNeverWritable(it)) }
        assertTrue(Ntag215Memory.isNeverWritable(0x82))
        assertFalse(Ntag215Memory.isNeverWritable(0x04))
        assertFalse(Ntag215Memory.isNeverWritable(0x83))
        assertFalse(Ntag215Memory.isValidPage(0x87))
    }

    // ---------------------------------------------------------------- GET_VERSION / CC / locks

    @Test fun parsesGetVersion() {
        val v215 = TagVersion(bytes(0x00, 0x04, 0x04, 0x02, 0x01, 0x00, 0x11, 0x03))
        assertTrue(v215.isNtag215)
        assertEquals("NTAG215", v215.productName)
        assertEquals("between 256 and 512 bytes", v215.storageDescription)
        val v213 = TagVersion(bytes(0x00, 0x04, 0x04, 0x02, 0x01, 0x00, 0x0F, 0x03))
        assertFalse(v213.isNtag215)
        assertEquals("NTAG213", v213.productName)
        assertFalse(TagVersion(bytes(0x00, 0x04, 0x03, 0x01, 0x01, 0x00, 0x0B, 0x03)).isNtag215) // Ultralight EV1
    }

    @Test(expected = IllegalArgumentException::class) fun rejectsShortVersion() { TagVersion(bytes(0, 4, 4)) }

    @Test fun parsesCapabilityContainer() {
        val cc = CapabilityContainer(bytes(0xE1, 0x10, 0x3E, 0x00))
        assertTrue(cc.isNdefFormatted)
        assertTrue(cc.isNtag215Default)
        assertEquals(496, cc.dataAreaBytes)
        assertTrue(cc.allowsWrite)
        val ro = CapabilityContainer(bytes(0xE1, 0x10, 0x3E, 0x0F))
        assertFalse(ro.allowsWrite)
        assertFalse(CapabilityContainer(bytes(0, 0, 0, 0)).isNdefFormatted)
    }

    @Test fun staticLockBitMapping() {
        // lock0 bit3 = CC, bit4 = page 4, bit7 = page 7; lock1 bit0 = page 8, bit7 = page 15.
        assertEquals(setOf(3, 4, 7), StaticLockBits(0x98, 0x00).lockedPages)
        assertEquals(setOf(8, 15), StaticLockBits(0x00, 0x81).lockedPages)
        assertEquals(0x07, StaticLockBits(0x07, 0x00).blockLockBits)
        assertTrue(StaticLockBits(0x07, 0x00).lockedPages.isEmpty())
    }

    @Test fun dynamicLockBitMapping() {
        assertEquals((16..31).toSet(), DynamicLockBits(0x01, 0, 0).lockedPages)
        assertEquals((32..47).toSet(), DynamicLockBits(0x02, 0, 0).lockedPages)
        assertEquals(setOf(128, 129), DynamicLockBits(0x80, 0, 0).lockedPages)
        assertFalse(DynamicLockBits(0, 0xFF, 0xF0).anySet) // byte1 RFUI, byte2 high nibble RFUI
        assertTrue(DynamicLockBits(0, 0, 0x01).anySet)
    }

    // ---------------------------------------------------------------- configuration bits

    @Test fun parsesFactoryConfig() {
        val c = Ntag215Config.factoryDefault()
        assertEquals(0xFF, c.auth0)
        assertFalse(c.protectionActive)
        assertFalse(c.prot)
        assertTrue(c.strongModulation)
        assertEquals(0, c.authLim)
        assertNull(c.readProtectedFrom)
    }

    @Test fun withProtectionChangesOnlyAuth0AndProt() {
        // MIRROR=0x54 (UID mirror, byte 1, STRG_MOD_EN), RFUI byte nonzero (preserved), MIRROR_PAGE 0x50.
        // ACCESS = CFGLCK | RFUI bit5 | NFC_CNT_EN | NFC_CNT_PWD_PROT | AUTHLIM=3.
        val c = Ntag215Config(bytes(0x54, 0x00, 0x50, 0xFF), bytes(0x7B, 0x01, 0x02, 0x03))
        val p = c.withProtection(0x20, readProtect = true)
        assertArrayEquals(bytes(0x54, 0x00, 0x50, 0x20), p.cfg0)
        assertArrayEquals(bytes(0xFB, 0x01, 0x02, 0x03), p.cfg1)
        assertTrue(p.prot)
        assertTrue(p.cfgLock)
        assertTrue(p.nfcCounterEnabled)
        assertTrue(p.nfcCounterPasswordProtected)
        assertEquals(3, p.authLim)
        assertEquals(0x20, p.readProtectedFrom)
        // Original object unchanged.
        assertEquals(0xFF, c.auth0)
    }

    @Test fun withoutProtectionClearsOnlyAuth0AndProt() {
        val c = Ntag215Config(bytes(0x04, 0x00, 0x00, 0x20), bytes(0x93, 0x00, 0x00, 0x00))
        val d = c.withoutProtection()
        assertArrayEquals(bytes(0x04, 0x00, 0x00, 0xFF), d.cfg0)
        assertArrayEquals(bytes(0x13, 0x00, 0x00, 0x00), d.cfg1)
    }

    @Test fun writeOnlyProtection() {
        val c = Ntag215Config(bytes(0x04, 0, 0, 0x10), bytes(0x00, 0, 0, 0))
        assertTrue(c.protectionActive)
        assertNull(c.readProtectedFrom)
        assertEquals(0x10, c.writeProtectedFrom)
    }

    @Test fun mirrorOverlapDetection() {
        // UID mirror (MIRROR_CONF=01) at page 0x10 byte 0 covers bytes 0x40..0x4D = pages 0x10..0x13.
        val m = Ntag215Config(bytes(0x44, 0, 0x10, 0xFF), bytes(0, 0, 0, 0))
        assertTrue(m.mirrorEnabled)
        assertTrue(m.mirrorOverlapsPages(0x04..0x28))
        assertFalse(m.mirrorOverlapsPages(0x14..0x28))
        // MIRROR_PAGE <= 3 disables the mirror.
        assertFalse(Ntag215Config(bytes(0x44, 0, 0x03, 0xFF), bytes(0, 0, 0, 0)).mirrorEnabled)
        // UID + counter mirror at 0x30 is beyond the app's pages.
        assertFalse(Ntag215Config(bytes(0xC4, 0, 0x30, 0xFF), bytes(0, 0, 0, 0)).mirrorOverlapsPages(0x04..0x28))
    }
}
