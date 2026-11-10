package com.nfcshenanigans.ntag215.core

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class NdefUrlEncoderTest {

    private fun bytes(vararg v: Int) = ByteArray(v.size) { v[it].toByte() }

    @Test fun encodesExactNdefBytes() {
        val e = NdefUrlEncoder.encode("https://example.com")
        val expected = bytes(0x03, 0x10, 0xD1, 0x01, 0x0C, 0x55, 0x04) + "example.com".toByteArray() + bytes(0xFE)
        assertArrayEquals(expected, e.tlvBytes)
        assertEquals(12, e.payloadSize)
        assertEquals(16, e.messageSize)
        assertEquals(19, e.tlvSize)
        assertEquals(5, e.pagesUsed)
        assertEquals(0x08, e.lastPage)
    }

    @Test fun prefixCompressionPicksLongestMatch() {
        assertEquals(0x02, NdefUrlEncoder.encode("https://www.example.com").prefixCode)
        assertEquals(0x04, NdefUrlEncoder.encode("https://example.com").prefixCode)
        assertEquals(0x01, NdefUrlEncoder.encode("http://www.example.com").prefixCode)
        assertEquals(0x03, NdefUrlEncoder.encode("http://example.com").prefixCode)
        // Prefix expansion is literal, so an upper-case scheme is stored uncompressed.
        val upper = NdefUrlEncoder.encode("HTTPS://example.com")
        assertEquals(0x00, upper.prefixCode)
        assertEquals("HTTPS://example.com", String(upper.payload, 1, upper.payloadSize - 1))
    }

    @Test fun typical77CharacterUrlFits() {
        val url = "https://www.example-company.com/products/nfc/tags/activate?id=ABCDEFGH1234567"
        assertEquals(77, url.length)
        val e = NdefUrlEncoder.encode(url)
        // "https://www." (12 chars) -> 1 byte; remainder 65 bytes; record 4+1+65 = 70; TLV 2+70+1 = 73.
        assertEquals(73, e.tlvSize)
        assertTrue(e.fitsPublicRegion)
        assertEquals(39, e.bytesRemaining)
        assertEquals(0x04 + 19 - 1, e.lastPage)
    }

    @Test fun sizeBoundaryAtProtectedRegion() {
        // https:// prefix: TLV = 2 (TLV hdr) + 4 (record hdr) + 1 (prefix code) + n + 1 (terminator) = 8 + n.
        val fits = "https://" + "a".repeat(100) + ".com" // n = 104 -> 112 bytes
        val tooLong = "https://" + "a".repeat(101) + ".com" // n = 105 -> 113 bytes
        assertEquals(112, NdefUrlEncoder.encode(fits).tlvSize)
        assertTrue(NdefUrlEncoder.encode(fits).fitsPublicRegion)
        assertEquals(0, NdefUrlEncoder.encode(fits).bytesRemaining)
        assertEquals(113, NdefUrlEncoder.encode(tooLong).tlvSize)
        assertFalse(NdefUrlEncoder.encode(tooLong).fitsPublicRegion)
        assertEquals(Ntag215Memory.PUBLIC_CAPACITY_BYTES, NdefUrlEncoder.encode(fits).publicRegionImage().size)
    }

    @Test fun nonAsciiUrlIsMeasuredInUtf8Bytes() {
        val e = NdefUrlEncoder.encode("https://example.com/é")
        assertEquals(1 + "example.com/".length + 2, e.payloadSize)
    }

    @Test fun longMessagesUseLongRecordAndThreeByteTlvLength() {
        val payload = ByteArray(300) { 0x41 }
        val record = NdefUrlEncoder.buildRecord(NdefUrlEncoder.TNF_WELL_KNOWN, byteArrayOf(0x55), payload)
        assertEquals(0xC1, record[0].u()) // MB|ME, no SR
        assertEquals(1 + 1 + 4 + 1 + 300, record.size)
        val tlv = NdefUrlEncoder.wrapTlv(record)
        assertArrayEquals(bytes(0x03, 0xFF, 0x01, 0x33), tlv.copyOf(4))
        assertEquals(0xFE, tlv.last().u())
    }

    @Test fun validation() {
        assertTrue(NdefUrlEncoder.validate("https://example.com/a?b=c#d") is UrlValidation.Valid)
        assertTrue(NdefUrlEncoder.validate("http://example.com:8080/") is UrlValidation.Valid)
        assertTrue(NdefUrlEncoder.validate("") is UrlValidation.Invalid)
        assertTrue(NdefUrlEncoder.validate("ftp://example.com") is UrlValidation.Invalid)
        assertTrue(NdefUrlEncoder.validate("example.com") is UrlValidation.Invalid)
        assertTrue(NdefUrlEncoder.validate("https://exa mple.com") is UrlValidation.Invalid)
        assertTrue(NdefUrlEncoder.validate("https://") is UrlValidation.Invalid)
        assertTrue(NdefUrlEncoder.validate("https:example.com") is UrlValidation.Invalid)
        assertTrue(NdefUrlEncoder.validate("https://exa<mple.com") is UrlValidation.Invalid)
    }

    @Test fun parseRoundTrip() {
        val url = "https://www.example.com/path?x=1"
        val area = NdefUrlEncoder.encode(url).publicRegionImage()
        val tlv = NdefParser.parseTlvArea(area)
        assertTrue(tlv.hasNdefTlv)
        assertNull(tlv.error)
        val msg = NdefParser.parseMessage(tlv.ndefMessage!!) as NdefMessageParse.Ok
        assertEquals(1, msg.records.size)
        assertTrue(msg.records[0].isUri)
        assertEquals(url, msg.records[0].uri)
    }

    @Test fun parsesFactoryEmptyNdef() {
        val tlv = NdefParser.parseTlvArea(bytes(0x03, 0x00, 0xFE, 0x00, 0x00))
        assertTrue(tlv.hasNdefTlv)
        assertTrue(tlv.isEmptyNdef)
        assertEquals(0, (NdefParser.parseMessage(tlv.ndefMessage!!) as NdefMessageParse.Ok).records.size)
    }

    @Test fun skipsNullAndLockControlTlvs() {
        val msg = NdefUrlEncoder.encode("https://a.io").ndefMessage
        val area = bytes(0x00, 0x01, 0x03, 0xA0, 0x0C, 0x34) + NdefUrlEncoder.wrapTlv(msg)
        val tlv = NdefParser.parseTlvArea(area)
        assertEquals(listOf("NULL", "Lock Control", "NDEF"), tlv.tlvs.map { it.name })
        assertEquals("https://a.io", (NdefParser.parseMessage(tlv.ndefMessage!!) as NdefMessageParse.Ok).records[0].uri)
    }

    @Test fun detectsTruncatedNdef() {
        val tlv = NdefParser.parseTlvArea(bytes(0x03, 0x50, 0xD1, 0x01))
        assertTrue(tlv.truncated)
        assertNull(tlv.ndefMessage)
        assertEquals(2 + 0x50, tlv.ndefEndOffset)
    }

    @Test fun rejectsCorruptedRecords() {
        assertTrue(NdefParser.parseMessage(bytes(0x51, 0x01, 0x01, 0x55, 0x04)) is NdefMessageParse.Error) // no MB
        assertTrue(NdefParser.parseMessage(bytes(0xD1, 0x01, 0x10, 0x55, 0x04)) is NdefMessageParse.Error) // payload too long
        assertTrue(NdefParser.parseMessage(bytes(0x91, 0x01, 0x01, 0x55, 0x04)) is NdefMessageParse.Error) // no ME
        assertTrue(NdefParser.parseTlvArea(bytes(0xFE)).error != null)
        assertTrue(NdefParser.parseTlvArea(ByteArray(0)).error != null)
    }

    @Test fun uriPrefixTableMatchesSpec() {
        assertEquals(0x24, UriPrefixes.TABLE.size)
        assertEquals("https://", UriPrefixes.expand(0x04))
        assertEquals("urn:nfc:", UriPrefixes.expand(0x23))
        assertNull(UriPrefixes.expand(0x24))
    }
}
