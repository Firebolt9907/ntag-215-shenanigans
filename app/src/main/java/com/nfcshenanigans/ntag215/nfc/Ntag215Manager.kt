package com.nfcshenanigans.ntag215.nfc

import com.nfcshenanigans.ntag215.core.DynamicLockBits
import com.nfcshenanigans.ntag215.core.Hex
import com.nfcshenanigans.ntag215.core.NdefParser
import com.nfcshenanigans.ntag215.core.Ntag215Config
import com.nfcshenanigans.ntag215.core.Ntag215Memory
import com.nfcshenanigans.ntag215.core.Ntag215Memory.APP_AUTH0
import com.nfcshenanigans.ntag215.core.Ntag215Memory.CFG0_PAGE
import com.nfcshenanigans.ntag215.core.Ntag215Memory.CFG1_PAGE
import com.nfcshenanigans.ntag215.core.Ntag215Memory.DYNAMIC_LOCK_PAGE
import com.nfcshenanigans.ntag215.core.Ntag215Memory.LAST_PAGE
import com.nfcshenanigans.ntag215.core.Ntag215Memory.PACK_PAGE
import com.nfcshenanigans.ntag215.core.Ntag215Memory.PRIVATE_FIRST_PAGE
import com.nfcshenanigans.ntag215.core.Ntag215Memory.PRIVATE_LAST_PAGE
import com.nfcshenanigans.ntag215.core.Ntag215Memory.PUBLIC_FIRST_PAGE
import com.nfcshenanigans.ntag215.core.Ntag215Memory.PUBLIC_LAST_PAGE
import com.nfcshenanigans.ntag215.core.Ntag215Memory.PWD_PAGE
import com.nfcshenanigans.ntag215.core.Ntag215Memory.USER_LAST_PAGE
import com.nfcshenanigans.ntag215.core.Pack
import com.nfcshenanigans.ntag215.core.Password
import com.nfcshenanigans.ntag215.core.PrivateId
import com.nfcshenanigans.ntag215.core.Secret
import com.nfcshenanigans.ntag215.core.TagVersion
import com.nfcshenanigans.ntag215.core.toHex

/**
 * High-level NTAG215 operations on one connected tag. All methods block; call from a background
 * dispatcher. One instance per tag session.
 */
class Ntag215Manager(
    private val exec: NfcCommandExecutor,
    tagId: ByteArray,
    private val tracker: AuthAttemptTracker,
) {
    private val uidHex = tagId.toHex()
    private val tagIdBytes = tagId.copyOf()
    val authenticator = Ntag215Authenticator(exec, tracker, uidHex)
    private val reauth: () -> Unit = { authenticator.ensureAuthenticated() }

    // ------------------------------------------------------------------ identification

    /** GET_VERSION check (refuses anything but NTAG215) and read of pages 0x00..0x03 when allowed. */
    fun identify(): TagIdentity {
        val versionBytes = try {
            exec.getVersion()
        } catch (e: NtagException.Nak) {
            throw NtagException.UnsupportedTag("Tag does not answer GET_VERSION; it is not an NTAG21x tag.")
        } catch (e: NtagException.MalformedResponse) {
            throw NtagException.UnsupportedTag("Unexpected GET_VERSION response; this is not an NTAG215.")
        }
        val version = TagVersion(versionBytes)
        if (!version.isNtag215) {
            throw NtagException.UnsupportedTag("Detected ${version.productName}. This app only supports NTAG215.")
        }
        val header = try { exec.read(0x00) } catch (e: NtagException.Nak) { null }
        val uid = header?.let { byteArrayOf(it[0], it[1], it[2], it[4], it[5], it[6], it[7]) } ?: tagIdBytes
        return TagIdentity(uid, version, header)
    }

    fun probeProtection(): ProtectionInfo {
        val cfg0 = tryReadPage(CFG0_PAGE)
        if (cfg0 != null) {
            val cfg1 = tryReadPage(CFG1_PAGE)
                ?: return ProtectionInfo(null, CFG1_PAGE) // AUTH0 = 0x84, PROT = 1
            return ProtectionInfo(Ntag215Config(cfg0, cfg1), null)
        }
        // Config pages are read-protected: AUTH0 <= 0x83 and PROT = 1. Locate AUTH0 by probing.
        if (!canRead(APP_AUTH0) && canRead(APP_AUTH0 - 1)) return ProtectionInfo(null, APP_AUTH0)
        var lo = 0x00
        var hi = CFG0_PAGE // invariant: page hi is not readable
        while (lo < hi) {
            val mid = (lo + hi) / 2
            if (canRead(mid)) lo = mid + 1 else hi = mid
        }
        return ProtectionInfo(null, lo)
    }

    private fun tryReadPage(page: Int): ByteArray? = try { exec.readPage(page) } catch (e: NtagException.Nak) { null }

    private fun canRead(page: Int): Boolean = try { exec.read(page); true } catch (e: NtagException.Nak) { false }

    /** Reads the NDEF TLV area using only pages readable in the current session. */
    fun readPublicArea(readableBelow: Int?): PublicArea {
        val limit = minOf((readableBelow ?: (USER_LAST_PAGE + 1)) - 1, USER_LAST_PAGE)
        val publicEnd = minOf(PUBLIC_LAST_PAGE, limit)
        if (publicEnd < PUBLIC_FIRST_PAGE) {
            return PublicArea(ByteArray(0), PUBLIC_FIRST_PAGE - 1, null, null, "The NDEF area is password-protected (AUTH0 = 0x${Hex.byte(readableBelow ?: 0)}).")
        }
        var bytes = exec.readPages(PUBLIC_FIRST_PAGE, publicEnd, if (exec.isAuthenticated) reauth else null)
        var lastPage = publicEnd
        var tlv = NdefParser.parseTlvArea(bytes)
        if (tlv.truncated && tlv.hasNdefTlv && limit > publicEnd) {
            // NDEF longer than this app's public region (foreign layout): read as far as needed and allowed.
            val neededEnd = PUBLIC_FIRST_PAGE + Ntag215Memory.pagesFor(tlv.ndefEndOffset) - 1
            val end = minOf(limit, neededEnd)
            if (end > publicEnd) {
                bytes += exec.readPages(publicEnd + 1, end, if (exec.isAuthenticated) reauth else null)
                lastPage = end
                tlv = NdefParser.parseTlvArea(bytes)
            }
        }
        val message = tlv.ndefMessage?.let { NdefParser.parseMessage(it) }
        return PublicArea(bytes, lastPage, tlv, message)
    }

    fun readPrivateArea(): PrivateArea =
        PrivateArea(exec.readPages(PRIVATE_FIRST_PAGE, PRIVATE_LAST_PAGE, if (exec.isAuthenticated) reauth else null))

    private fun readConfig(): Ntag215Config {
        val pages = exec.readPages(CFG0_PAGE, CFG1_PAGE, if (exec.isAuthenticated) reauth else null)
        return Ntag215Config(pages.copyOfRange(0, 4), pages.copyOfRange(4, 8))
    }

    private fun readDynamicLock(): DynamicLockBits = DynamicLockBits.fromPage(exec.readPage(DYNAMIC_LOCK_PAGE))

    /** Whether [page] is readable in the current session. */
    private fun readable(page: Int, protection: ProtectionInfo) =
        exec.isAuthenticated || protection.readProtectedFrom?.let { page < it } ?: true

    // ------------------------------------------------------------------ read / inspect

    fun inspect(password: Password?, expectedPack: Pack?, systemNdef: SystemNdefStatus?): TagReport {
        var identity = identify()
        val protection = probeProtection()
        val publicArea = readPublicArea(protection.readProtectedFrom)
        var config = protection.config

        val privateState: PrivateState = when {
            !protection.privateReadProtected -> PrivateState.Unprotected(readPrivateArea())
            password == null -> PrivateState.Locked
            else -> try {
                val auth = authenticator.authenticate(password, expectedPack)
                val area = readPrivateArea()
                PrivateState.Authenticated(area, auth.pack.toHex(), auth.packMatches)
            } catch (e: NtagException.AuthenticationFailed) {
                PrivateState.AuthFailed(e.message ?: "Authentication failed", tracker.failures(uidHex), e.counterOverflow)
            }
        }

        if (exec.isAuthenticated) {
            config = readConfig()
            if (identity.header == null) identity = identity.withHeader(exec.read(0x00))
        }
        val dynamicLock = if (readable(DYNAMIC_LOCK_PAGE, protection)) readDynamicLock() else null

        val warnings = buildWarnings(identity, protection, config, dynamicLock, publicArea, privateState, systemNdef)
        return TagReport(identity, protection, config, dynamicLock, publicArea, privateState, systemNdef, warnings)
    }

    private fun buildWarnings(
        identity: TagIdentity,
        protection: ProtectionInfo,
        config: Ntag215Config?,
        dynamicLock: DynamicLockBits?,
        publicArea: PublicArea,
        privateState: PrivateState,
        systemNdef: SystemNdefStatus?,
    ): List<String> = buildList {
        val cc = identity.cc
        if (cc == null) add("Pages 0x00-0x03 are read-protected (AUTH0 ≤ 0x03). Phones cannot read NDEF from this tag.")
        else if (!cc.isNdefFormatted) add("Capability container ($cc) is not NDEF formatted.")
        else if (!cc.allowsWrite) add("Capability container marks the tag read-only (CC3 = 0x${Hex.byte(cc.access)}).")
        if (protection.publicReadProtected) add("The public NDEF area is read-protected. Ordinary phones cannot open the URL.")
        if (protection.anyProtection && !protection.matchesAppLayout) {
            add("Protection starts at page 0x${Hex.byte(protection.readProtectedFrom ?: protection.writeProtectedFrom ?: 0)}; this app's layout uses 0x20 with read protection.")
        }
        if (publicArea.hasContent && !publicArea.fitsPublicRegion) add("The NDEF message extends past page 0x1F into the private region (incompatible layout).")
        publicArea.error?.let { if (publicArea.unreadableReason == null) add("NDEF: $it") }
        if (privateState is PrivateState.Unprotected && !privateState.area.isBlank) {
            add("Private data is NOT password-protected on this tag. Any NFC app can read it.")
        }
        config?.let {
            if (it.authLim != 0) add("AUTHLIM = ${it.authLim}: failed password attempts are counted and can permanently block protected memory.")
            if (it.cfgLock) add("CFGLCK is set: configuration pages are permanently locked.")
            if (it.mirrorOverlapsPages(PUBLIC_FIRST_PAGE..PRIVATE_LAST_PAGE)) add("ASCII mirror overlaps this app's data pages; reads will show mirrored data.")
        }
        if (config == null && protection.anyProtection) add("AUTHLIM is unknown until authenticated. If it is set, each wrong password counts toward permanent lockout.")
        if (dynamicLock?.anySet == true) add("Dynamic lock bits are set (some pages are permanently read-only).")
        if (identity.staticLock?.anySet == true) add("Static lock bits are set (some pages are permanently read-only).")
        if (systemNdef != null && !systemNdef.detected && publicArea.hasContent) {
            add("Android's NDEF detection did not report a message on this tap, although the app parsed one.")
        }
    }

    // ------------------------------------------------------------------ advanced dump

    fun dump(password: Password?, expectedPack: Pack?): MemoryDump {
        var identity = identify()
        val protection = probeProtection()
        var authenticated = false
        var authError: String? = null
        var packHex: String? = null
        if (password != null && protection.anyProtection) {
            try {
                val r = authenticator.authenticate(password, expectedPack)
                authenticated = true
                packHex = r.pack.toHex() + when (r.packMatches) { true -> " (matches)"; false -> " (MISMATCH)"; null -> "" }
            } catch (e: NtagException.AuthenticationFailed) {
                authError = e.message
            }
        }
        val readableEnd = if (authenticated) LAST_PAGE else (protection.readProtectedFrom ?: (LAST_PAGE + 1)) - 1
        val data = if (readableEnd >= 0) exec.readPages(0x00, readableEnd, if (authenticated) reauth else null) else ByteArray(0)
        val pages = (0..LAST_PAGE).map { p ->
            if (p <= readableEnd) PageEntry(p, data.copyOfRange(p * 4, p * 4 + 4), PageStatus.READ)
            else PageEntry(p, null, PageStatus.PROTECTED)
        }
        if (identity.header == null && readableEnd >= 3) identity = identity.withHeader(data.copyOfRange(0, 16))
        val config = if (readableEnd >= CFG1_PAGE) Ntag215Config(pages[CFG0_PAGE].data!!, pages[CFG1_PAGE].data!!) else protection.config
        val dyn = if (readableEnd >= DYNAMIC_LOCK_PAGE) DynamicLockBits.fromPage(pages[DYNAMIC_LOCK_PAGE].data!!) else null
        return MemoryDump(identity, protection, config, dyn, pages, authenticated, authError, packHex, exec.maxTransceiveLength, exec.fastReadSupported)
    }

    // ------------------------------------------------------------------ write

    private class Mutations {
        var dataWriteStarted = false
        var dataVerified = false
        var passwordWriteStarted = false
        var protectionConfigStarted = false
        var auth0Written = false
    }

    fun write(req: WriteRequest, listener: WriteProgressListener): WriteOutcome {
        var step = WriteStep.IDENTIFY
        val m = Mutations()
        var priorProtection: ProtectionInfo? = null
        fun start(s: WriteStep) { step = s; listener.onStep(s, StepStatus.RUNNING, null) }
        fun done(detail: String? = null) = listener.onStep(step, StepStatus.DONE, detail)

        try {
            // 3. Identify
            start(WriteStep.IDENTIFY)
            var identity = identify()
            done("${identity.version.productName}, UID ${identity.uidDisplay}")

            // 4. Detect protection
            start(WriteStep.DETECT_PROTECTION)
            val protection = probeProtection()
            priorProtection = protection
            done(if (protection.anyProtection) protection.summary() else "No password protection (AUTH0 disabled)")

            // 5. Authenticate if required (single attempt, user-supplied password only)
            if (protection.anyProtection) {
                start(WriteStep.AUTHENTICATE)
                val pwd = req.currentPassword ?: run {
                    listener.onStep(step, StepStatus.FAILED, "Current password required")
                    return WriteOutcome.NeedsPassword(uidHex, identity.uidDisplay, protection.summary(), tracker.failures(uidHex))
                }
                authenticator.authenticate(pwd, null)
                done("Password accepted")
            } else {
                listener.onStep(WriteStep.AUTHENTICATE, StepStatus.SKIPPED, "Not required")
            }

            // Full read access from here on.
            if (identity.header == null) identity = identity.withHeader(exec.read(0x00))
            val cc = identity.cc!!
            val staticLock = identity.staticLock!!
            val config = readConfig()
            val dynLock = readDynamicLock()
            val desired = config.withProtection(APP_AUTH0, readProtect = true)

            // 6. Writability
            start(WriteStep.CHECK_WRITABLE)
            if (!cc.allowsWrite) throw NtagException.WriteProtected("Capability container marks the tag read-only (CC = $cc). It cannot be changed back (OTP).")
            val appPages = PUBLIC_FIRST_PAGE..PRIVATE_LAST_PAGE
            val locked = (staticLock.lockedPages + dynLock.lockedPages).filter { it in appPages }.sorted()
            if (locked.isNotEmpty()) {
                throw NtagException.WriteProtected("Pages ${locked.joinToString { "0x" + Hex.byte(it) }} are permanently locked by lock bits.")
            }
            if (config.cfgLock && !config.sameAs(desired)) {
                throw NtagException.WriteProtected("Configuration is permanently locked (CFGLCK = 1) with settings that differ from the required AUTH0/PROT.")
            }
            done("No lock bits on pages 0x04-0x28; configuration writable")

            // 7. Layout safety + overwrite confirmation
            start(WriteStep.CHECK_LAYOUT)
            if (!cc.isNdefFormatted) {
                throw NtagException.InvalidConfiguration("Capability container ($cc) is not NDEF formatted. This app does not modify the OTP capability container.")
            }
            if (cc.dataAreaBytes < req.url.tlvSize) throw NtagException.InsufficientMemory("CC declares only ${cc.dataAreaBytes} bytes of NDEF memory.")
            if (!req.url.fitsPublicRegion) {
                throw NtagException.InsufficientMemory("Encoded URL needs ${req.url.tlvSize} bytes; the public region (0x04-0x1F) holds ${Ntag215Memory.PUBLIC_CAPACITY_BYTES}.")
            }
            if (config.mirrorOverlapsPages(appPages)) {
                throw NtagException.InvalidConfiguration("The tag's ASCII mirror (MIRROR_PAGE 0x${Hex.byte(config.mirrorPage)}) overlaps pages 0x04-0x28. Disable the mirror first.")
            }
            val existingPublic = readPublicArea(if (exec.isAuthenticated) null else protection.readProtectedFrom)
            val existingPrivate = readPrivateArea()
            val reasons = buildList {
                when {
                    existingPublic.hasContent -> add("Public area contains an NDEF message" + (existingPublic.url?.let { ": $it" } ?: ""))
                    existingPublic.tlv?.hasNdefTlv != true -> add("Public area does not contain a valid NDEF TLV (${existingPublic.error ?: "unknown data"})")
                }
                if (!existingPrivate.isBlank) {
                    add(
                        when (val id = existingPrivate.id) {
                            is PrivateId.Decoded.Valid -> "Private region contains data (ID ${id.id.value})"
                            else -> "Private region (0x20-0x28) contains data"
                        }
                    )
                }
                if (protection.anyProtection) add("Tag is already password-protected; it will be reconfigured with the new password")
            }
            if (reasons.isNotEmpty() && req.confirmedOverwriteUid != uidHex) {
                listener.onStep(step, StepStatus.FAILED, "Confirmation required")
                return WriteOutcome.NeedsConfirmation(uidHex, identity.uidDisplay, reasons)
            }
            done("URL uses ${req.url.tlvSize}/${Ntag215Memory.PUBLIC_CAPACITY_BYTES} bytes (pages 0x04-0x${Hex.byte(req.url.lastPage)})")

            // 8. URL: write NDEF TLV with length 0 first, then the body, then the real length.
            start(WriteStep.WRITE_URL)
            m.dataWriteStarted = true
            val image = req.url.publicRegionImage()
            val pages = Ntag215Memory.splitIntoPages(image)
            val first = pages[0].copyOf().also { it[1] = 0x00 }
            exec.write(PUBLIC_FIRST_PAGE, first)
            for (i in 1 until pages.size) exec.write(PUBLIC_FIRST_PAGE + i, pages[i])
            exec.write(PUBLIC_FIRST_PAGE, pages[0])
            done("${pages.size} pages written")

            // 9. ID
            start(WriteStep.WRITE_ID)
            exec.write(Ntag215Memory.PRIVATE_ID_PAGE, req.id.encode())
            done("Page 0x20")

            // 10. Secret
            start(WriteStep.WRITE_SECRET)
            req.secret.pages().forEachIndexed { i, p -> exec.write(Ntag215Memory.SECRET_FIRST_PAGE + i, p) }
            done("Pages 0x21-0x28")

            // 11. Verify data
            start(WriteStep.VERIFY_DATA)
            val expected = image + req.id.encode() + req.secret.encode()
            val actual = exec.readPages(PUBLIC_FIRST_PAGE, PRIVATE_LAST_PAGE, if (exec.isAuthenticated) reauth else null)
            compareImages(expected, actual, PUBLIC_FIRST_PAGE)
            m.dataVerified = true
            done("Pages 0x04-0x28 match")

            // 12. Configure protection: PWD, PACK, verify password, ACCESS, then AUTH0 last.
            start(WriteStep.CONFIGURE_PROTECTION)
            m.passwordWriteStarted = true
            exec.write(PWD_PAGE, req.newPassword.bytes())
            exec.write(PACK_PAGE, req.newPack.page())
            // Verify the stored password before enabling protection, so a corrupted PWD write can never
            // leave the tag protected by an unknown password.
            val pre = try {
                exec.pwdAuth(req.newPassword)
            } catch (e: NtagException.AuthenticationFailed) {
                throw NtagException.VerificationFailed("The tag rejected the newly written password before protection was enabled. Protection was NOT enabled.")
            }
            authenticator.passwordChanged(req.newPassword)
            if (!req.newPack.matches(pre)) throw NtagException.VerificationFailed("PACK read back as ${pre.toHex()} instead of the configured value. Protection was NOT enabled.")
            m.protectionConfigStarted = true
            if (!config.cfg1.contentEquals(desired.cfg1)) exec.write(CFG1_PAGE, desired.cfg1)
            if (!config.cfg0.contentEquals(desired.cfg0)) exec.write(CFG0_PAGE, desired.cfg0)
            m.auth0Written = true
            done("AUTH0 = 0x20, PROT = 1, AUTHLIM ${config.authLim} preserved")

            // 13. Verify protection
            start(WriteStep.VERIFY_PROTECTION)
            exec.deauthenticate()
            if (canRead(PRIVATE_FIRST_PAGE)) {
                throw NtagException.VerificationFailed("Page 0x20 is readable without authentication; protection is not effective.")
            }
            val auth = authenticator.authenticate(req.newPassword, req.newPack)
            if (auth.packMatches != true) throw NtagException.VerificationFailed("PACK mismatch after enabling protection.")
            val cfgBack = readConfig()
            if (!cfgBack.sameAs(desired)) throw NtagException.VerificationFailed("Configuration pages read back differently than written.")
            val privBack = exec.readPages(PRIVATE_FIRST_PAGE, PRIVATE_LAST_PAGE, reauth)
            compareImages(req.id.encode() + req.secret.encode(), privBack, PRIVATE_FIRST_PAGE)
            done("Unauthenticated read rejected; authenticated read matches")

            // 14. Verify public URL without authentication
            start(WriteStep.VERIFY_PUBLIC)
            exec.deauthenticate()
            val header = exec.read(0x00)
            if (!header.copyOfRange(12, 16).contentEquals(cc.raw)) throw NtagException.VerificationFailed("Capability container changed unexpectedly.")
            val pub = readPublicArea(APP_AUTH0)
            if (pub.url != req.url.url) throw NtagException.VerificationFailed("Public URL read without authentication does not match.")
            done("URL readable without password")

            return WriteOutcome.Success(
                WriteReport(
                    uidDisplay = identity.uidDisplay,
                    url = req.url.url,
                    id = req.id,
                    passwordHex = req.newPassword.hex(),
                    packHex = req.newPack.hex(),
                    tlvSize = req.url.tlvSize,
                    checks = listOf(
                        "Data pages 0x04-0x28 verified byte-for-byte",
                        "Unauthenticated read of page 0x20 rejected",
                        "Authentication with new password returned the expected PACK",
                        "AUTH0/ACCESS read back as configured",
                        "Public URL parsed without authentication",
                    ),
                    notes = buildList {
                        add("AUTHLIM preserved: ${config.describeAuthLim()}")
                        if (config.nfcCounterEnabled) add("NFC counter remains enabled")
                        add("No lock bits or CFGLCK were modified")
                    },
                ),
            )
        } catch (e: NtagException) {
            listener.onStep(step, StepStatus.FAILED, e.message)
            return WriteOutcome.Failure(step, e, describeState(m, priorProtection))
        }
    }

    private fun compareImages(expected: ByteArray, actual: ByteArray, firstPage: Int) {
        if (actual.size < expected.size) throw NtagException.VerificationFailed("Read-back returned too few bytes.")
        for (i in expected.indices) {
            if (expected[i] != actual[i]) {
                throw NtagException.VerificationFailed("Read-back mismatch at page 0x${Hex.byte(firstPage + i / 4)}.")
            }
        }
    }

    private fun describeState(m: Mutations, prior: ProtectionInfo?): String {
        val wasProtected = prior?.anyProtection == true
        return when {
            !m.dataWriteStarted -> "No data was written. The tag is unchanged."
            !m.passwordWriteStarted ->
                "Tag data may be partially written (the NDEF length is written last, so phones see an empty or the new message). " +
                    "Password settings were not changed" + (if (wasProtected) "; the existing password still applies." else ".") +
                    " Tap again to rewrite."
            !m.protectionConfigStarted ->
                if (wasProtected) {
                    "Data was written and verified. The PWD page may already contain the NEW password while the existing protection remains active. " +
                        "Try the new password first, then the previous one."
                } else {
                    "Data was written and verified. A new password may be stored, but protection is NOT enabled: private data is readable without a password. Tap again to finish."
                }
            !m.auth0Written ->
                "Protection configuration was interrupted. The tag may already be protected by the NEW password. Authenticate with the new password and re-run the write."
            else -> "Protection is enabled with the NEW password, but verification did not complete. Inspect the tag on the Read screen using the new password."
        }
    }

    // ------------------------------------------------------------------ remove protection

    fun removeProtection(password: Password): RemoveProtectionOutcome {
        var configWritten = false
        try {
            val identity = identify()
            val protection = probeProtection()
            if (!protection.anyProtection) return RemoveProtectionOutcome.Failure("Tag is not password-protected.", "Unchanged.")
            authenticator.authenticate(password, null)
            val config = readConfig()
            val desired = config.withoutProtection()
            if (config.cfgLock) return RemoveProtectionOutcome.Failure("Configuration is permanently locked (CFGLCK).", "Unchanged.")
            configWritten = true
            if (!config.cfg0.contentEquals(desired.cfg0)) exec.write(CFG0_PAGE, desired.cfg0)
            if (!config.cfg1.contentEquals(desired.cfg1)) exec.write(CFG1_PAGE, desired.cfg1)
            exec.deauthenticate()
            val back = Ntag215Config(exec.readPage(CFG0_PAGE), exec.readPage(CFG1_PAGE))
            if (!back.sameAs(desired)) return RemoveProtectionOutcome.Failure("Configuration did not read back as expected.", "Check the tag on the Advanced screen.")
            return RemoveProtectionOutcome.Success(identity.uidDisplay)
        } catch (e: NtagException) {
            return RemoveProtectionOutcome.Failure(
                e.message ?: "Failed",
                if (configWritten) "Configuration may be partially changed; protection might be disabled for some pages." else "Unchanged.",
            )
        }
    }
}
