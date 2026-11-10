package com.nfcshenanigans.ntag215.nfc

import com.nfcshenanigans.ntag215.core.CapabilityContainer
import com.nfcshenanigans.ntag215.core.DynamicLockBits
import com.nfcshenanigans.ntag215.core.EncodedUrl
import com.nfcshenanigans.ntag215.core.Hex
import com.nfcshenanigans.ntag215.core.NdefMessageParse
import com.nfcshenanigans.ntag215.core.NdefRecordInfo
import com.nfcshenanigans.ntag215.core.Ntag215Config
import com.nfcshenanigans.ntag215.core.Ntag215Memory
import com.nfcshenanigans.ntag215.core.Pack
import com.nfcshenanigans.ntag215.core.Password
import com.nfcshenanigans.ntag215.core.PrivateId
import com.nfcshenanigans.ntag215.core.Secret
import com.nfcshenanigans.ntag215.core.StaticLockBits
import com.nfcshenanigans.ntag215.core.TagVersion
import com.nfcshenanigans.ntag215.core.TlvParseResult
import com.nfcshenanigans.ntag215.core.toHex

class TagIdentity(uid: ByteArray, val version: TagVersion, header: ByteArray?) {
    val uid: ByteArray = uid.copyOf()
    /** Pages 0x00..0x03 (16 bytes), or null if read-protected (AUTH0 <= 3 with PROT = 1). */
    val header: ByteArray? = header?.copyOf()
    val uidHex: String get() = uid.toHex()
    val uidDisplay: String get() = uid.toHex(":")
    val cc: CapabilityContainer? get() = header?.let { CapabilityContainer(it.copyOfRange(12, 16)) }
    val staticLock: StaticLockBits? get() = header?.let { StaticLockBits.fromPage2(it.copyOfRange(8, 12)) }

    fun withHeader(h: ByteArray) = TagIdentity(uid, version, h)
}

/**
 * Protection state determined without authentication. When the configuration pages are readable
 * [config] is set; otherwise [firstReadProtectedPage] is found by probing (READ of a page below
 * AUTH0 succeeds, at/above AUTH0 NAKs, datasheet 10.2).
 */
class ProtectionInfo(val config: Ntag215Config?, val firstReadProtectedPage: Int?) {
    val configReadable get() = config != null
    val readProtectedFrom: Int? get() = firstReadProtectedPage ?: config?.readProtectedFrom
    val writeProtectedFrom: Int? get() = config?.writeProtectedFrom ?: firstReadProtectedPage
    val anyProtection get() = writeProtectedFrom != null
    val privateReadProtected get() = readProtectedFrom?.let { it <= Ntag215Memory.PRIVATE_LAST_PAGE } ?: false
    val publicReadProtected get() = readProtectedFrom?.let { it <= Ntag215Memory.PUBLIC_LAST_PAGE } ?: false
    val matchesAppLayout get() = readProtectedFrom == Ntag215Memory.APP_AUTH0

    fun summary(): String = when {
        config != null -> config.describeProtection()
        firstReadProtectedPage != null ->
            "Read + write protected from page 0x${Hex.byte(firstReadProtectedPage)} (configuration pages are protected)"
        else -> "Unknown"
    }
}

class PublicArea(
    /** Bytes read from page 0x04 onward (only unprotected pages). */
    val bytes: ByteArray,
    val lastPageRead: Int,
    val tlv: TlvParseResult?,
    val message: NdefMessageParse?,
    val unreadableReason: String? = null,
) {
    val records: List<NdefRecordInfo> get() = (message as? NdefMessageParse.Ok)?.records.orEmpty()
    val url: String? get() = records.firstNotNullOfOrNull { it.uri }
    val isEmpty get() = tlv?.isEmptyNdef == true
    val hasContent get() = tlv?.hasNdefTlv == true && !isEmpty

    /** NDEF TLV + Terminator end inside pages 0x04..0x1F (compatible with the private layout). */
    val fitsPublicRegion: Boolean
        get() = tlv?.hasNdefTlv == true && tlv.ndefEndOffset + 1 <= Ntag215Memory.PUBLIC_CAPACITY_BYTES

    val error: String?
        get() = unreadableReason ?: tlv?.error ?: (message as? NdefMessageParse.Error)?.reason
}

class PrivateArea(val raw: ByteArray) {
    val id: PrivateId.Decoded = PrivateId.decode(raw.copyOfRange(0, 4))
    val secret: Secret.Decoded = Secret.decode(raw.copyOfRange(4, 4 + Secret.LENGTH))
    val isBlank get() = raw.all { it.toInt() == 0 }
    val isWellFormed get() = id is PrivateId.Decoded.Valid && secret is Secret.Decoded.Valid
}

sealed interface PrivateState {
    data object Locked : PrivateState
    data class AuthFailed(val message: String, val failuresThisSession: Int, val blocked: Boolean) : PrivateState
    data class Unprotected(val area: PrivateArea) : PrivateState
    data class Authenticated(val area: PrivateArea, val packHex: String, val packMatches: Boolean?) : PrivateState
    data class Unavailable(val reason: String) : PrivateState
}

/** Result of Android's own NDEF detection for the scanned tag (what background scanning sees). */
data class SystemNdefStatus(val detected: Boolean, val url: String?, val maxSize: Int?, val writable: Boolean?)

class TagReport(
    val identity: TagIdentity,
    val protection: ProtectionInfo,
    /** Full configuration if readable or read after authentication. */
    val config: Ntag215Config?,
    val dynamicLock: DynamicLockBits?,
    val publicArea: PublicArea,
    val privateState: PrivateState,
    val systemNdef: SystemNdefStatus?,
    val warnings: List<String>,
)

enum class PageStatus { READ, PROTECTED }

class PageEntry(val page: Int, val data: ByteArray?, val status: PageStatus) {
    val name get() = Ntag215Memory.pageName(page)
}

class MemoryDump(
    val identity: TagIdentity,
    val protection: ProtectionInfo,
    val config: Ntag215Config?,
    val dynamicLock: DynamicLockBits?,
    val pages: List<PageEntry>,
    val authenticated: Boolean,
    val authError: String?,
    val packHex: String?,
    val maxTransceiveLength: Int,
    val fastReadUsed: Boolean,
)

// ---------------------------------------------------------------- Write pipeline

enum class WriteStep(val number: Int, val label: String) {
    VALIDATE(1, "Validate input"),
    WAIT_FOR_TAG(2, "Wait for NTAG215 tag"),
    IDENTIFY(3, "Identify tag and inspect configuration"),
    DETECT_PROTECTION(4, "Detect existing password protection"),
    AUTHENTICATE(5, "Authenticate with current password"),
    CHECK_WRITABLE(6, "Check that the tag is writable"),
    CHECK_LAYOUT(7, "Confirm memory layout is safe"),
    WRITE_URL(8, "Write public NDEF URL"),
    WRITE_ID(9, "Write private ID"),
    WRITE_SECRET(10, "Write private secret"),
    VERIFY_DATA(11, "Read back and verify data"),
    CONFIGURE_PROTECTION(12, "Configure password protection"),
    VERIFY_PROTECTION(13, "Verify authentication and protected access"),
    VERIFY_PUBLIC(14, "Verify public URL without authentication"),
}

enum class StepStatus { PENDING, RUNNING, DONE, SKIPPED, FAILED }

fun interface WriteProgressListener {
    fun onStep(step: WriteStep, status: StepStatus, detail: String?)
}

data class WriteRequest(
    val url: EncodedUrl,
    val id: PrivateId,
    val secret: Secret,
    val newPassword: Password,
    val newPack: Pack,
    /** Current password for tags that are already protected. Tried at most once. */
    val currentPassword: Password?,
    /** UID (hex) the user confirmed may be overwritten. */
    val confirmedOverwriteUid: String?,
)

class WriteReport(
    val uidDisplay: String,
    val url: String,
    val id: PrivateId,
    val passwordHex: String,
    val packHex: String,
    val tlvSize: Int,
    val checks: List<String>,
    val notes: List<String>,
)

sealed interface WriteOutcome {
    class Success(val report: WriteReport) : WriteOutcome
    class NeedsPassword(val uidHex: String, val uidDisplay: String, val protectionSummary: String, val failuresThisSession: Int) : WriteOutcome
    class NeedsConfirmation(val uidHex: String, val uidDisplay: String, val reasons: List<String>) : WriteOutcome
    class Failure(val step: WriteStep, val error: NtagException, val tagState: String) : WriteOutcome
}

sealed interface RemoveProtectionOutcome {
    data class Success(val uidDisplay: String) : RemoveProtectionOutcome
    data class Failure(val message: String, val tagState: String) : RemoveProtectionOutcome
}
