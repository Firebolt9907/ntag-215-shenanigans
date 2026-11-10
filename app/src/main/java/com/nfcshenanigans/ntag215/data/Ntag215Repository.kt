package com.nfcshenanigans.ntag215.data

import android.nfc.Tag
import android.nfc.tech.Ndef
import android.nfc.tech.NfcA
import com.nfcshenanigans.ntag215.core.Pack
import com.nfcshenanigans.ntag215.core.Password
import com.nfcshenanigans.ntag215.core.toHex
import com.nfcshenanigans.ntag215.nfc.AndroidNfcTransport
import com.nfcshenanigans.ntag215.nfc.AuthAttemptTracker
import com.nfcshenanigans.ntag215.nfc.CommandLog
import com.nfcshenanigans.ntag215.nfc.MemoryDump
import com.nfcshenanigans.ntag215.nfc.NfcCommandExecutor
import com.nfcshenanigans.ntag215.nfc.Ntag215Manager
import com.nfcshenanigans.ntag215.nfc.NtagException
import com.nfcshenanigans.ntag215.nfc.RemoveProtectionOutcome
import com.nfcshenanigans.ntag215.nfc.SystemNdefStatus
import com.nfcshenanigans.ntag215.nfc.TagReport
import com.nfcshenanigans.ntag215.nfc.TransportException
import com.nfcshenanigans.ntag215.nfc.WriteOutcome
import com.nfcshenanigans.ntag215.nfc.WriteProgressListener
import com.nfcshenanigans.ntag215.nfc.WriteRequest
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

enum class AppScreen { READ, WRITE, ADVANCED }

enum class NfcAvailability { UNKNOWN, UNSUPPORTED, DISABLED, ENABLED }

data class TagEvent(val tag: Tag, val screen: AppScreen, val uidHex: String)

data class TagTechInfo(val techs: List<String>, val atqa: String?, val sak: String?)

/**
 * Single entry point for tag I/O. Tags discovered by reader mode are routed to the visible screen.
 * Every operation runs on [io] and is serialized by a mutex, so NFC never blocks the main thread
 * and two operations never interleave on one tag.
 */
class Ntag215Repository(private val io: CoroutineDispatcher = Dispatchers.IO) {
    val commandLog = CommandLog()
    val attemptTracker = AuthAttemptTracker()
    private val mutex = Mutex()

    private val _tags = MutableSharedFlow<TagEvent>(extraBufferCapacity = 4)
    val tags: SharedFlow<TagEvent> = _tags.asSharedFlow()

    private val _activeScreen = MutableStateFlow(AppScreen.READ)
    val activeScreen: StateFlow<AppScreen> = _activeScreen.asStateFlow()

    private val _nfc = MutableStateFlow(NfcAvailability.UNKNOWN)
    val nfcAvailability: StateFlow<NfcAvailability> = _nfc.asStateFlow()

    /** Most recently discovered tag; operations may retry on it while it is still in the field. */
    @Volatile
    var lastTag: Tag? = null
        private set

    fun setActiveScreen(screen: AppScreen) { _activeScreen.value = screen }
    fun setNfcAvailability(state: NfcAvailability) { _nfc.value = state }

    /** Called from the reader-mode binder thread. */
    fun onTagDiscovered(tag: Tag) {
        lastTag = tag
        _tags.tryEmit(TagEvent(tag, _activeScreen.value, tag.id.toHex()))
    }

    private suspend fun <T> session(tag: Tag, block: (Ntag215Manager) -> T): T = mutex.withLock {
        withContext(io) {
            val transport = try {
                AndroidNfcTransport.open(tag)
            } catch (e: TransportException) {
                throw NtagException.TagRemoved("connect")
            } ?: throw NtagException.UnsupportedTag("This tag does not support NFC-A (ISO/IEC 14443-3A); it is not an NTAG215.")
            try {
                commandLog.note("Session: UID ${tag.id.toHex(":")}, max transceive ${transport.maxTransceiveLength} bytes")
                block(Ntag215Manager(NfcCommandExecutor(transport, commandLog), tag.id, attemptTracker))
            } finally {
                transport.close()
            }
        }
    }

    suspend fun inspect(tag: Tag, password: Password?, expectedPack: Pack?, includeSystemNdef: Boolean): TagReport {
        val system = if (includeSystemNdef) systemNdefStatus(tag) else null
        return session(tag) { it.inspect(password, expectedPack, system) }
    }

    suspend fun write(tag: Tag, request: WriteRequest, listener: WriteProgressListener): WriteOutcome =
        try {
            session(tag) { it.write(request, listener) }
        } catch (e: NtagException) {
            WriteOutcome.Failure(com.nfcshenanigans.ntag215.nfc.WriteStep.IDENTIFY, e, "No data was written. The tag is unchanged.")
        }

    suspend fun dump(tag: Tag, password: Password?, expectedPack: Pack?): MemoryDump =
        session(tag) { it.dump(password, expectedPack) }

    suspend fun removeProtection(tag: Tag, password: Password): RemoveProtectionOutcome =
        try {
            session(tag) { it.removeProtection(password) }
        } catch (e: NtagException) {
            RemoveProtectionOutcome.Failure(e.message ?: "Failed", "Unchanged.")
        }

    /** What Android's own NDEF detection found during discovery (no I/O; uses cached data). */
    fun systemNdefStatus(tag: Tag): SystemNdefStatus {
        val ndef = Ndef.get(tag) ?: return SystemNdefStatus(detected = false, url = null, maxSize = null, writable = null)
        val url = runCatching { ndef.cachedNdefMessage?.records?.firstNotNullOfOrNull { it.toUri()?.toString() } }.getOrNull()
        return SystemNdefStatus(detected = true, url = url, maxSize = ndef.maxSize, writable = ndef.isWritable)
    }

    fun techInfo(tag: Tag): TagTechInfo {
        val a = NfcA.get(tag)
        return TagTechInfo(
            techs = tag.techList.map { it.substringAfterLast('.') },
            atqa = a?.atqa?.toHex(),
            sak = a?.sak?.let { "%02X".format(it.toInt() and 0xFF) },
        )
    }
}
