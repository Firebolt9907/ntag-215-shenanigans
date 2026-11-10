package com.nfcshenanigans.ntag215.nfc

import com.nfcshenanigans.ntag215.core.NdefMessageParse
import com.nfcshenanigans.ntag215.core.NdefParser
import com.nfcshenanigans.ntag215.core.NdefUrlEncoder
import com.nfcshenanigans.ntag215.core.Ntag215Memory
import com.nfcshenanigans.ntag215.core.Pack
import com.nfcshenanigans.ntag215.core.Password
import com.nfcshenanigans.ntag215.core.PrivateId
import com.nfcshenanigans.ntag215.core.Secret
import com.nfcshenanigans.ntag215.core.u
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.Parameterized

/**
 * The integration scenarios from the specification, run against [FakeNtag215] with both NAK
 * delivery styles (raw 4-bit NAK byte and Android's exception-after-reselect behaviour).
 */
@RunWith(Parameterized::class)
class Ntag215ManagerScenarioTest(private val nakStyle: FakeNtag215.NakStyle) {

    companion object {
        @JvmStatic
        @Parameterized.Parameters(name = "{0}")
        fun styles() = FakeNtag215.NakStyle.entries.toList()

        const val URL = "https://www.example-company.com/products/nfc/tags/activate?id=ABCDEFGH1234567"
        val SECRET: Secret = Secret.parse("Zq3vN8xLw2Rt6YpB0sKd9HmF4cJu7GaE")!!
        val PWD: Password = Password.parse("A1B2C3D4")!!
        val PACK: Pack = Pack.parse("BEEF")!!
    }

    private val tracker = AuthAttemptTracker()
    private val fake = FakeNtag215(nakStyle = nakStyle)

    private fun manager(transport: NfcTransport = fake) = Ntag215Manager(NfcCommandExecutor(transport), fake.uid, tracker)

    private val uidHex = fake.uid.joinToString("") { "%02X".format(it.u()) }

    private fun request(
        url: String = URL,
        id: String = "042",
        secret: Secret = SECRET,
        pwd: Password = PWD,
        pack: Pack = PACK,
        current: Password? = null,
        confirmed: Boolean = false,
    ) = WriteRequest(NdefUrlEncoder.encode(url), PrivateId.parse(id)!!, secret, pwd, pack, current, if (confirmed) uidHex else null)

    private val steps = mutableListOf<Pair<WriteStep, StepStatus>>()
    private val listener = WriteProgressListener { s, st, _ -> steps += s to st }

    private fun writeOk(req: WriteRequest): WriteReport {
        val o = manager().write(req, listener)
        if (o is WriteOutcome.Failure) fail("Failed at ${o.step}: ${o.error.message}")
        assertTrue("Expected success but was $o", o is WriteOutcome.Success)
        return (o as WriteOutcome.Success).report
    }

    /** Simulates how a standard NFC Forum T2T reader (e.g. AOSP rw_t2t) reads NDEF: aligned 16-byte READs, no auth. */
    private fun standardReaderUrl(): String? {
        val e = NfcCommandExecutor(fake)
        e.reconnect()
        val header = e.read(0x00)
        assertEquals(0xE1, header[12].u())
        val area = ByteArray(Ntag215Memory.PUBLIC_CAPACITY_BYTES)
        for (block in 0 until 7) e.read(0x04 + block * 4).copyInto(area, block * 16)
        val tlv = NdefParser.parseTlvArea(area)
        return (NdefParser.parseMessage(tlv.ndefMessage ?: return null) as NdefMessageParse.Ok).records.firstOrNull()?.uri
    }

    // 1. Fresh NTAG215
    @Test fun scenario01_freshTag() {
        val report = writeOk(request())
        assertEquals("042", report.id.value)
        assertEquals(0x20, fake.auth0)
        assertTrue(fake.prot)
        assertArrayEquals(PWD.bytes(), fake.password)
        assertArrayEquals(PACK.bytes(), fake.pack)
        assertArrayEquals(byteArrayOf(0x30, 0x34, 0x32, 0x00), fake.page(0x20))
        assertArrayEquals(SECRET.encode().copyOfRange(0, 4), fake.page(0x21))
        assertArrayEquals(SECRET.encode().copyOfRange(28, 32), fake.page(0x28))
        // Unrelated configuration preserved: MIRROR byte (STRG_MOD_EN), RFUI bytes, AUTHLIM.
        assertArrayEquals(byteArrayOf(0x04, 0x00, 0x00, 0x20), fake.page(0x83))
        assertArrayEquals(byteArrayOf(0x80.toByte(), 0x00, 0x00, 0x00), fake.page(0x84))
        // UID, lock bytes and CC untouched.
        assertArrayEquals(byteArrayOf(0xE1.toByte(), 0x10, 0x3E, 0x00), fake.page(0x03))
        assertArrayEquals(byteArrayOf(0x00, 0x00), fake.page(0x02).copyOfRange(2, 4))
        assertArrayEquals(byteArrayOf(0x00, 0x00, 0x00, 0xBD.toByte()), fake.page(0x82))
        // Every step after authentication completed in order.
        val done = steps.filter { it.second == StepStatus.DONE }.map { it.first }
        assertEquals(
            listOf(
                WriteStep.IDENTIFY, WriteStep.DETECT_PROTECTION, WriteStep.CHECK_WRITABLE, WriteStep.CHECK_LAYOUT,
                WriteStep.WRITE_URL, WriteStep.WRITE_ID, WriteStep.WRITE_SECRET, WriteStep.VERIFY_DATA,
                WriteStep.CONFIGURE_PROTECTION, WriteStep.VERIFY_PROTECTION, WriteStep.VERIFY_PUBLIC,
            ),
            done,
        )
        assertTrue(steps.contains(WriteStep.AUTHENTICATE to StepStatus.SKIPPED))
    }

    // 2. Tag with an existing URL
    @Test fun scenario02_existingUrlRequiresConfirmation() {
        val area = NdefUrlEncoder.encode("https://old.example.org").publicRegionImage()
        Ntag215Memory.splitIntoPages(area).forEachIndexed { i, p -> fake.pages[4 + i] = p }
        val o = manager().write(request(), listener)
        assertTrue(o is WriteOutcome.NeedsConfirmation)
        assertTrue((o as WriteOutcome.NeedsConfirmation).reasons.any { it.contains("https://old.example.org") })
        // Nothing was written.
        assertEquals(0xFF, fake.auth0)
        assertTrue(fake.commandHistory.none { it.startsWith("A2") })
        writeOk(request(confirmed = true))
        assertEquals(URL, standardReaderUrl())
    }

    // 3. Tag with existing password protection
    @Test fun scenario03_existingProtectionNeedsCurrentPassword() {
        writeOk(request())
        val attemptsBefore = fake.pwdAuthAttempts
        val o = manager().write(request(id = "043", pwd = Password.parse("11223344")!!), listener)
        assertTrue(o is WriteOutcome.NeedsPassword)
        assertEquals("No PWD_AUTH without a user-supplied password", attemptsBefore, fake.pwdAuthAttempts)
        val o2 = manager().write(request(id = "043", pwd = Password.parse("11223344")!!, current = PWD), listener)
        assertTrue(o2 is WriteOutcome.NeedsConfirmation)
        writeOk(request(id = "043", pwd = Password.parse("11223344")!!, current = PWD, confirmed = true))
        assertArrayEquals(Password.parse("11223344")!!.bytes(), fake.password)
    }

    // 4. Incorrect authentication password
    @Test fun scenario04_wrongPassword() {
        writeOk(request())
        val before = fake.pages.map { it.copyOf() }
        val wrong = Password.parse("DEADBEEF")!!
        val o = manager().write(request(id = "777", current = wrong, confirmed = true), listener)
        assertTrue(o is WriteOutcome.Failure)
        o as WriteOutcome.Failure
        assertEquals(WriteStep.AUTHENTICATE, o.step)
        assertTrue(o.error is NtagException.AuthenticationFailed)
        assertTrue(o.tagState.startsWith("No data was written"))
        assertEquals(1, tracker.failures(uidHex))
        fake.pages.forEachIndexed { i, p -> assertArrayEquals("page $i changed", before[i], p) }
        // Read screen path: one attempt, reported as AuthFailed.
        val r = manager().inspect(wrong, null, null)
        assertTrue(r.privateState is PrivateState.AuthFailed)
        assertEquals(2, tracker.failures(uidHex))
        // A correct password resets the counter.
        manager().inspect(PWD, PACK, null)
        assertEquals(0, tracker.failures(uidHex))
    }

    // 5. URL too long for the public region
    @Test fun scenario05_urlTooLong() {
        val longUrl = "https://" + "a".repeat(101) + ".com"
        val o = manager().write(request(url = longUrl), listener)
        assertTrue(o is WriteOutcome.Failure)
        o as WriteOutcome.Failure
        assertEquals(WriteStep.CHECK_LAYOUT, o.step)
        assertTrue(o.error is NtagException.InsufficientMemory)
        assertTrue(fake.commandHistory.none { it.startsWith("A2") })
    }

    // 6. Tag removed during writing
    @Test fun scenario06_tagRemovedDuringWrite() {
        // Count commands of a full successful run, then remove the tag in the middle of the secret write.
        val probe = FakeNtag215(nakStyle = nakStyle)
        val writesBeforeSecret = run {
            Ntag215Manager(NfcCommandExecutor(probe), probe.uid, AuthAttemptTracker()).write(request(), { _, _, _ -> })
            probe.commandHistory.indexOfFirst { it == "A2 21" }
        }
        fake.commandsUntilRemoval = writesBeforeSecret + 3
        val o = manager().write(request(), listener)
        assertTrue(o is WriteOutcome.Failure)
        o as WriteOutcome.Failure
        assertEquals(WriteStep.WRITE_SECRET, o.step)
        assertTrue(o.error is NtagException.TagRemoved)
        assertTrue(o.tagState.contains("partially written"))
        assertEquals("Protection must not be enabled after a partial write", 0xFF, fake.auth0)
        // Tag comes back: rewrite succeeds after confirmation of the partial content.
        fake.reinsert()
        val again = manager().write(request(), listener)
        assertTrue(again is WriteOutcome.NeedsConfirmation)
        writeOk(request(confirmed = true))
    }

    @Test fun scenario06b_tagRemovedDuringProtectionConfig() {
        val probe = FakeNtag215(nakStyle = nakStyle)
        Ntag215Manager(NfcCommandExecutor(probe), probe.uid, AuthAttemptTracker()).write(request(), { _, _, _ -> })
        fake.commandsUntilRemoval = probe.commandHistory.indexOfFirst { it == "A2 86" }
        val o = manager().write(request(), listener) as WriteOutcome.Failure
        assertEquals(WriteStep.CONFIGURE_PROTECTION, o.step)
        assertTrue(o.tagState.contains("NOT enabled"))
        assertEquals(0xFF, fake.auth0)
    }

    // 7. Public URL scanning after protection
    @Test fun scenario07_publicUrlReadableAfterProtection() {
        writeOk(request())
        assertEquals(URL, standardReaderUrl())
        val r = manager().inspect(null, null, null)
        assertEquals(URL, r.publicArea.url)
        assertTrue(r.protection.matchesAppLayout)
        assertTrue(r.publicArea.fitsPublicRegion)
    }

    // 8. Failed unauthenticated private-memory read
    @Test fun scenario08_unauthenticatedPrivateReadFails() {
        writeOk(request())
        val e = NfcCommandExecutor(fake)
        e.reconnect()
        try { e.read(0x20); fail("READ 0x20 must NAK") } catch (_: NtagException.Nak) {}
        try { e.fastRead(0x1C, 0x23); fail("FAST_READ across AUTH0 must NAK") } catch (_: NtagException.Nak) {}
        try { e.read(0x28); fail() } catch (_: NtagException.Nak) {}
        val r = manager().inspect(null, null, null)
        assertEquals(PrivateState.Locked, r.privateState)
        assertEquals(0x20, r.protection.readProtectedFrom)
        assertFalse(r.protection.configReadable)
    }

    // 9. Successful authenticated private-memory read
    @Test fun scenario09_authenticatedPrivateRead() {
        writeOk(request())
        val r = manager().inspect(PWD, PACK, null)
        val auth = r.privateState as PrivateState.Authenticated
        assertEquals(true, auth.packMatches)
        assertEquals("042", (auth.area.id as PrivateId.Decoded.Valid).id.value)
        assertEquals(SECRET, (auth.area.secret as Secret.Decoded.Valid).secret)
        assertEquals(0x20, r.config!!.auth0)
        assertTrue(r.config!!.prot)
        assertTrue(r.warnings.none { it.contains("NOT password-protected") })
    }

    // 10. Rewriting a previously configured tag
    @Test fun scenario10_rewriteConfiguredTagPreservesSettings() {
        writeOk(request())
        // Someone enabled AUTHLIM=5 and the NFC counter; those bits must survive a rewrite.
        val e = NfcCommandExecutor(fake)
        e.pwdAuth(PWD)
        e.write(0x84, byteArrayOf((0x80 or 0x10 or 0x05).toByte(), 0, 0, 0))
        val newSecret = Secret.generate()
        val newPwd = Password.parse("0BADF00D")!!
        writeOk(request(url = "https://example.com/v2", id = "043", secret = newSecret, pwd = newPwd, pack = Pack.parse("1234")!!, current = PWD, confirmed = true))
        assertEquals(0x95, fake.access)
        assertEquals("https://example.com/v2", standardReaderUrl())
        val r = manager().inspect(newPwd, Pack.parse("1234"), null)
        val auth = r.privateState as PrivateState.Authenticated
        assertEquals("043", (auth.area.id as PrivateId.Decoded.Valid).id.value)
        assertEquals(newSecret, (auth.area.secret as Secret.Decoded.Valid).secret)
        // Old password no longer works.
        assertTrue(manager().inspect(PWD, null, null).privateState is PrivateState.AuthFailed)
        // Previous longer URL bytes were cleared.
        assertTrue(fake.pages.slice(0x0A..0x1F).all { p -> p.all { it.toInt() == 0 } })
    }

    // ------------------------------------------------------------------ additional safety cases

    @Test fun refusesNonNtag215() {
        fake.version = byteArrayOf(0x00, 0x04, 0x04, 0x02, 0x01, 0x00, 0x0F, 0x03)
        val o = manager().write(request(), listener) as WriteOutcome.Failure
        assertEquals(WriteStep.IDENTIFY, o.step)
        assertTrue(o.error is NtagException.UnsupportedTag)
        assertTrue(fake.commandHistory.none { it.startsWith("A2") })
    }

    @Test fun refusesReadOnlyCapabilityContainer() {
        fake.pages[3][3] = 0x0F
        val o = manager().write(request(), listener) as WriteOutcome.Failure
        assertEquals(WriteStep.CHECK_WRITABLE, o.step)
        assertTrue(o.error is NtagException.WriteProtected)
    }

    @Test fun refusesStaticallyLockedPages() {
        fake.pages[2][2] = 0x20 // L5
        val o = manager().write(request(), listener) as WriteOutcome.Failure
        assertTrue(o.error is NtagException.WriteProtected)
        assertTrue(o.error.message!!.contains("0x05"))
    }

    @Test fun refusesDynamicallyLockedPrivatePages() {
        fake.pages[0x82][0] = 0x02 // pages 32-47
        val o = manager().write(request(), listener) as WriteOutcome.Failure
        assertTrue(o.error is NtagException.WriteProtected)
    }

    @Test fun refusesLockedConfiguration() {
        fake.pages[0x84][0] = 0x40 // CFGLCK
        fake.cfgLockActive = true
        val o = manager().write(request(), listener) as WriteOutcome.Failure
        assertEquals(WriteStep.CHECK_WRITABLE, o.step)
        assertTrue(fake.commandHistory.none { it.startsWith("A2") })
    }

    @Test fun refusesOverlappingMirror() {
        fake.pages[0x83] = byteArrayOf(0x44, 0x00, 0x10, 0xFF.toByte())
        val o = manager().write(request(), listener) as WriteOutcome.Failure
        assertTrue(o.error is NtagException.InvalidConfiguration)
    }

    @Test fun refusesUnformattedTagWithoutTouchingCc() {
        fake.pages[3] = byteArrayOf(0, 0, 0, 0)
        val o = manager().write(request(), listener) as WriteOutcome.Failure
        assertEquals(WriteStep.CHECK_LAYOUT, o.step)
        assertArrayEquals(byteArrayOf(0, 0, 0, 0), fake.page(3))
    }

    @Test fun probesForeignAuth0Boundary() {
        fake.pages[0x83][3] = 0x10
        fake.pages[0x84][0] = 0x80.toByte()
        val p = manager().probeProtection()
        assertEquals(0x10, p.readProtectedFrom)
        assertFalse(p.configReadable)
        val r = manager().inspect(null, null, null)
        assertTrue(r.warnings.any { it.contains("0x10") })
    }

    @Test fun writeOnlyProtectionIsDetected() {
        fake.pages[0x83][3] = 0x20
        val p = manager().probeProtection()
        assertTrue(p.configReadable)
        assertNull(p.readProtectedFrom)
        assertEquals(0x20, p.writeProtectedFrom)
        // Private pages are readable by anyone: the inspector must warn once they contain data.
        fake.pages[0x20] = byteArrayOf(0x30, 0x30, 0x31, 0)
        assertTrue(manager().inspect(null, null, null).privateState is PrivateState.Unprotected)
    }

    @Test fun authLimitIsReportedAsBlocked() {
        writeOk(request())
        val e = NfcCommandExecutor(fake)
        e.pwdAuth(PWD)
        e.write(0x84, byteArrayOf((0x80 or 0x01).toByte(), 0, 0, 0)) // AUTHLIM = 1
        e.reconnect()
        val first = manager().inspect(Password.parse("00000001")!!, null, null).privateState as PrivateState.AuthFailed
        assertFalse(first.blocked)
        val second = manager().inspect(PWD, null, null).privateState as PrivateState.AuthFailed
        assertEquals(nakStyle == FakeNtag215.NakStyle.RAW_BYTE, second.blocked) // code 4h only visible as a raw NAK
    }

    @Test fun removeProtectionRestoresOpenAccess() {
        writeOk(request())
        val result = manager().removeProtection(PWD)
        assertTrue(result is RemoveProtectionOutcome.Success)
        assertEquals(0xFF, fake.auth0)
        assertFalse(fake.prot)
        assertTrue(manager().inspect(null, null, null).privateState is PrivateState.Unprotected)
    }

    @Test fun dumpHidesProtectedPagesWithoutAuth() {
        writeOk(request())
        val d = manager().dump(null, null)
        assertEquals(PageStatus.READ, d.pages[0x1F].status)
        assertEquals(PageStatus.PROTECTED, d.pages[0x20].status)
        assertNull(d.pages[0x86].data)
        val full = manager().dump(PWD, PACK)
        assertTrue(full.authenticated)
        assertTrue(full.pages.all { it.status == PageStatus.READ })
        assertArrayEquals(ByteArray(4), full.pages[0x85].data) // PWD reads as 00
    }
}
