package com.nfcshenanigans.ntag215.core

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.SecureRandom

class HexAndPrivateDataTest {

    private fun bytes(vararg v: Int) = ByteArray(v.size) { v[it].toByte() }

    // Low-entropy "A..Z012345" fixture, built at runtime rather than written as a literal.
    private val alphabetSecret = ('A'..'Z').joinToString("") + (0..5).joinToString("")

    // ---------------------------------------------------------------- hex / ascii

    @Test fun hexEncodeDecodeRoundTrip() {
        val b = bytes(0x00, 0x7F, 0x80, 0xFF, 0x0A)
        assertEquals("007F80FF0A", Hex.encode(b))
        assertEquals("00 7F 80 FF 0A", b.toHex(" "))
        assertArrayEquals(b, Hex.decode("00 7f:80-FF0a"))
    }

    @Test(expected = IllegalArgumentException::class) fun hexOddLengthRejected() { Hex.decode("ABC") }

    @Test(expected = IllegalArgumentException::class) fun hexInvalidDigitRejected() { Hex.decode("GG") }

    @Test fun hexValidity() {
        assertTrue(Hex.isValid("A1B2C3D4", 4))
        assertTrue(!Hex.isValid("A1B2C3", 4))
        assertTrue(!Hex.isValid("A1B2C3DZ", 4))
    }

    @Test fun asciiToHexAndBack() {
        assertEquals("30 34 32", Ascii.asciiToHex("042"))
        assertEquals("Hello", Ascii.hexToAscii("48656C6C6F"))
        assertEquals("A.b.", Ascii.display(bytes(0x41, 0x00, 0x62, 0xFF)))
    }

    @Test(expected = IllegalArgumentException::class) fun nonAsciiRejected() { Ascii.toBytes("café") }

    // ---------------------------------------------------------------- private ID

    @Test fun idEncodingPreservesLeadingZeros() {
        assertArrayEquals(bytes(0x30, 0x34, 0x32, 0x00), PrivateId.parse("042")!!.encode())
        assertArrayEquals(bytes(0x30, 0x30, 0x31, 0x00), PrivateId.parse("001")!!.encode())
        assertArrayEquals(bytes(0x39, 0x39, 0x39, 0x00), PrivateId.parse("999")!!.encode())
        assertArrayEquals(bytes(0x30, 0x30, 0x30, 0x00), PrivateId.parse("000")!!.encode())
    }

    @Test fun idValidation() {
        assertNull(PrivateId.validate("042"))
        assertNotNull(PrivateId.validate(""))
        assertNotNull(PrivateId.validate("42"))
        assertNotNull(PrivateId.validate("0420"))
        assertNotNull(PrivateId.validate("4a2"))
        assertNotNull(PrivateId.validate("-12"))
        assertNull(PrivateId.parse("12"))
        assertNull(PrivateId.parse("١٢٣")) // non-ASCII digits rejected
    }

    @Test fun idDecoding() {
        assertEquals(PrivateId.Decoded.Valid(PrivateId.parse("042")!!), PrivateId.decode(bytes(0x30, 0x34, 0x32, 0x00)))
        assertEquals(PrivateId.Decoded.Empty, PrivateId.decode(bytes(0, 0, 0, 0)))
        assertTrue(PrivateId.decode(bytes(0x30, 0x34, 0x32, 0x01)) is PrivateId.Decoded.Malformed)
        assertTrue(PrivateId.decode(bytes(0x41, 0x34, 0x32, 0x00)) is PrivateId.Decoded.Malformed)
    }

    @Test fun idIncrement() {
        assertEquals("042", PrivateId.parse("041")!!.next()!!.value)
        assertEquals("100", PrivateId.parse("099")!!.next()!!.value)
        assertNull(PrivateId.parse("999")!!.next())
    }

    // ---------------------------------------------------------------- secret

    @Test fun secretValidation() {
        assertNull(Secret.validate("A".repeat(32)))
        assertTrue(Secret.validate("A".repeat(31))!!.contains("short"))
        assertTrue(Secret.validate("A".repeat(33))!!.contains("long"))
        assertTrue(Secret.validate("é" + "A".repeat(31))!!.contains("Non-ASCII"))
        assertNotNull(Secret.validate("\u0001" + "A".repeat(31)))
        assertNull(Secret.validate((0x20 until 0x40).map { it.toChar() }.joinToString(""))) // every printable char from space to ?
    }

    @Test fun secretEncodingSplitsIntoEightPages() {
        val s = Secret.parse(alphabetSecret)!!
        val pages = s.pages()
        assertEquals(8, pages.size)
        assertArrayEquals(bytes(0x41, 0x42, 0x43, 0x44), pages[0])
        assertArrayEquals(bytes(0x32, 0x33, 0x34, 0x35), pages[7])
        assertEquals(32, s.encode().size)
    }

    @Test fun secretDecoding() {
        val raw = Secret.parse(alphabetSecret)!!.encode()
        assertEquals(alphabetSecret, (Secret.decode(raw) as Secret.Decoded.Valid).secret.value)
        assertEquals(Secret.Decoded.Empty, Secret.decode(ByteArray(32)))
        raw[5] = 0x00
        assertTrue(Secret.decode(raw) is Secret.Decoded.Malformed)
    }

    @Test fun secretGenerationIsAlphanumericAndRandom() {
        val rnd = SecureRandom()
        val a = Secret.generate(rnd).value
        val b = Secret.generate(rnd).value
        assertEquals(32, a.length)
        assertTrue(a.all { it.isLetterOrDigit() && it.code < 0x80 })
        assertNotEquals(a, b)
    }

    @Test fun secretToStringDoesNotLeak() {
        val s = Secret.parse(alphabetSecret)!!
        assertTrue(!s.toString().contains("ABCD"))
    }

    // ---------------------------------------------------------------- password / PACK

    @Test fun passwordParsingAndByteOrder() {
        val input = Hex.encode(bytes(0x01, 0x02, 0x03, 0x04))
        val p = Password.parse(input)!!
        assertArrayEquals(bytes(0x01, 0x02, 0x03, 0x04), p.bytes())
        assertEquals(input, p.hex())
        assertNull(Password.parse(input.dropLast(2)))
        assertNull(Password.parse(input.dropLast(1) + "G"))
        assertTrue(!p.toString().contains(input))
    }

    @Test fun passwordGenerationAvoidsDefaults() {
        repeat(200) {
            val h = Password.generate().hex()
            assertNotEquals("F".repeat(8), h)
            assertNotEquals("0".repeat(8), h)
        }
    }

    @Test fun packPageHasZeroRfuBytes() {
        val pack = Pack.parse(Hex.encode(bytes(0xBE, 0xEF)))!!
        assertArrayEquals(bytes(0xBE, 0xEF, 0x00, 0x00), pack.page())
        assertTrue(pack.matches(bytes(0xBE, 0xEF)))
        assertNull(Pack.parse(Hex.encode(bytes(0xBE, 0xEF)).dropLast(1)))
    }
}
