package com.nfcshenanigans.ntag215.nfc

import com.nfcshenanigans.ntag215.core.TestCredentials
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class NfcCommandExecutorTest {

    private fun bytes(vararg v: Int) = ByteArray(v.size) { v[it].toByte() }

    /** Scripted transport returning canned responses, for exact response-parsing checks. */
    private class ScriptedTransport(vararg responses: Any) : NfcTransport {
        val queue = ArrayDeque(responses.toList())
        val sent = mutableListOf<ByteArray>()
        var reconnects = 0
        var reconnectFails = false
        override val maxTransceiveLength = 253
        override fun transceive(command: ByteArray): ByteArray {
            sent += command
            return when (val r = queue.removeFirst()) {
                is ByteArray -> r
                is Exception -> throw r
                else -> error("bad script")
            }
        }
        override fun reconnect() { reconnects++; if (reconnectFails) throw TransportException.TagLost() }
        override fun close() {}
    }

    @Test fun buildsCorrectCommandFrames() {
        val t = ScriptedTransport(ByteArray(8), ByteArray(16), ByteArray(8), bytes(0x0A), bytes(0x12, 0x34))
        val e = NfcCommandExecutor(t)
        e.getVersion()
        e.read(0x20)
        e.fastRead(0x04, 0x05)
        e.write(0x21, bytes(0x41, 0x42, 0x43, 0x44))
        assertArrayEquals(bytes(0x12, 0x34), e.pwdAuth(TestCredentials.pwd(0x11)))
        assertArrayEquals(bytes(0x60), t.sent[0])
        assertArrayEquals(bytes(0x30, 0x20), t.sent[1])
        assertArrayEquals(bytes(0x3A, 0x04, 0x05), t.sent[2])
        assertArrayEquals(bytes(0xA2, 0x21, 0x41, 0x42, 0x43, 0x44), t.sent[3])
        assertArrayEquals(bytes(0x1B, 0x11, 0x11, 0x11, 0x11), t.sent[4])
        assertTrue(e.isAuthenticated)
    }

    @Test fun oneByteNakIsParsedAndTagReactivated() {
        val t = ScriptedTransport(bytes(0x00))
        val e = NfcCommandExecutor(t)
        try { e.read(0x20); fail() } catch (x: NtagException.Nak) { assertEquals(0x0, x.code) }
        assertEquals(1, t.reconnects)
    }

    @Test fun nakCodesAreDescribed() {
        assertTrue(NtagException.Nak.describe(0x4).contains("counter overflow"))
        assertTrue(NtagException.Nak.describe(0x5).contains("EEPROM"))
        assertTrue(NtagException.Nak.describe(null).contains("no response"))
    }

    @Test fun androidStyleNakBecomesNakWhenTagStillPresent() {
        val t = ScriptedTransport(TransportException.IoFailure())
        val e = NfcCommandExecutor(t)
        try { e.read(0x20); fail() } catch (x: NtagException.Nak) { assertNull(x.code) }
    }

    @Test fun ioFailureWithFailedReconnectMeansTagRemoved() {
        val t = ScriptedTransport(TransportException.IoFailure()).apply { reconnectFails = true }
        try { NfcCommandExecutor(t).read(0x04); fail() } catch (_: NtagException.TagRemoved) {}
    }

    @Test fun tagLostMapsToTagRemoved() {
        val t = ScriptedTransport(TransportException.TagLost())
        try { NfcCommandExecutor(t).write(0x04, ByteArray(4)); fail() } catch (_: NtagException.TagRemoved) {}
    }

    @Test fun writeAckParsing() {
        NfcCommandExecutor(ScriptedTransport(bytes(0x0A))).write(0x04, ByteArray(4))
        try { NfcCommandExecutor(ScriptedTransport(bytes(0x05))).write(0x04, ByteArray(4)); fail() } catch (x: NtagException.Nak) { assertEquals(5, x.code) }
    }

    @Test fun malformedResponseRejected() {
        try { NfcCommandExecutor(ScriptedTransport(ByteArray(7))).getVersion(); fail() } catch (_: NtagException.MalformedResponse) {}
    }

    @Test fun refusesToWriteSystemPages() {
        val e = NfcCommandExecutor(ScriptedTransport())
        for (p in listOf(0x00, 0x01, 0x02, 0x03, 0x82)) {
            try { e.write(p, ByteArray(4)); fail("page $p") } catch (_: NtagException.SafetyViolation) {}
        }
    }

    @Test fun failedPwdAuthClearsSessionAndReportsCounterOverflow() {
        val e = NfcCommandExecutor(ScriptedTransport(bytes(0x12, 0x34), bytes(0x04)))
        e.pwdAuth(TestCredentials.pwd(0x01))
        try { e.pwdAuth(TestCredentials.pwd(0x02)); fail() } catch (x: NtagException.AuthenticationFailed) { assertTrue(x.counterOverflow) }
        assertFalse(e.isAuthenticated)
    }

    @Test fun fastReadChunksRespectTransceiveLimit() {
        val fake = FakeNtag215(maxTransceiveLength = 64)
        val e = NfcCommandExecutor(fake)
        assertEquals(15, e.fastReadMaxPages)
        val data = e.readPages(0x00, 0x86)
        assertEquals(135 * 4, data.size)
        val fastReads = fake.commandHistory.filter { it.startsWith("3A") }
        assertEquals(9, fastReads.size) // ceil(135 / 15)
        assertTrue(e.fastReadSupported)
    }

    @Test fun fallsBackToReadWhenFastReadUnavailable() {
        val fake = FakeNtag215()
        val t = object : NfcTransport by fake {
            override fun transceive(command: ByteArray): ByteArray =
                if (command[0].toInt() == 0x3A) throw TransportException.IoFailure() else fake.transceive(command)
        }
        val e = NfcCommandExecutor(t)
        val data = e.readPages(0x03, 0x09)
        assertArrayEquals(fake.page(0x03), data.copyOfRange(0, 4))
        assertArrayEquals(fake.page(0x09), data.copyOfRange(24, 28))
        assertFalse(e.fastReadSupported)
    }

    @Test fun readRollsOverBeforeAuth0WhenProtected() {
        // Datasheet 10.2: unauthenticated READ below AUTH0 rolls over just before AUTH0.
        val fake = FakeNtag215()
        fake.pages[0x83][3] = 0x20
        fake.pages[0x84][0] = 0x80.toByte()
        fake.pages[0x1F] = bytes(1, 2, 3, 4)
        val r = NfcCommandExecutor(fake).read(0x1E)
        assertArrayEquals(fake.page(0x1F), r.copyOfRange(4, 8))
        assertArrayEquals(fake.page(0x00), r.copyOfRange(8, 12))
    }
}
