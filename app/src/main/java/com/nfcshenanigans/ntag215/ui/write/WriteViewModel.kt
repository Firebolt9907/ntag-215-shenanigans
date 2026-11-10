package com.nfcshenanigans.ntag215.ui.write

import android.nfc.Tag
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.nfcshenanigans.ntag215.core.EncodedUrl
import com.nfcshenanigans.ntag215.core.Hex
import com.nfcshenanigans.ntag215.core.NdefUrlEncoder
import com.nfcshenanigans.ntag215.core.Ntag215Memory
import com.nfcshenanigans.ntag215.core.Pack
import com.nfcshenanigans.ntag215.core.Password
import com.nfcshenanigans.ntag215.core.PrivateId
import com.nfcshenanigans.ntag215.core.Secret
import com.nfcshenanigans.ntag215.core.UrlValidation
import com.nfcshenanigans.ntag215.core.toHex
import com.nfcshenanigans.ntag215.data.AppScreen
import com.nfcshenanigans.ntag215.data.Ntag215Repository
import com.nfcshenanigans.ntag215.nfc.NtagException
import com.nfcshenanigans.ntag215.nfc.StepStatus
import com.nfcshenanigans.ntag215.nfc.WriteOutcome
import com.nfcshenanigans.ntag215.nfc.WriteRequest
import com.nfcshenanigans.ntag215.nfc.WriteStep
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.filter
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.security.SecureRandom

data class WriteForm(
    val url: String = "",
    val id: String = "",
    val secret: String = "",
    val password: String = "",
    val pack: String = "",
    val currentPassword: String = "",
    val autoIncrementId: Boolean = true,
    val newSecretPerTag: Boolean = true,
    val newPasswordPerTag: Boolean = true,
)

data class StepUi(val status: StepStatus = StepStatus.PENDING, val detail: String? = null)

sealed interface WritePhase {
    data object Editing : WritePhase
    data class WaitingForTag(val message: String) : WritePhase
    data object Running : WritePhase
    data class NeedsPassword(val outcome: WriteOutcome.NeedsPassword) : WritePhase
    data class NeedsConfirmation(val outcome: WriteOutcome.NeedsConfirmation) : WritePhase
    data class Succeeded(val outcome: WriteOutcome.Success) : WritePhase
    data class Failed(val outcome: WriteOutcome.Failure) : WritePhase
}

data class FieldErrors(
    val url: String? = null,
    val id: String? = null,
    val secret: String? = null,
    val password: String? = null,
    val pack: String? = null,
    val currentPassword: String? = null,
) {
    val any get() = listOf(url, id, secret, password, pack, currentPassword).any { it != null }
}

data class WriteUiState(
    val form: WriteForm = WriteForm(),
    val errors: FieldErrors = FieldErrors(),
    val encoded: EncodedUrl? = null,
    val sizeInfo: String? = null,
    val phase: WritePhase = WritePhase.Editing,
    val steps: Map<WriteStep, StepUi> = WriteStep.entries.associateWith { StepUi() },
    val tagsWritten: Int = 0,
)

class WriteViewModel(private val repo: Ntag215Repository) : ViewModel() {
    private val random = SecureRandom()
    private val _state = MutableStateFlow(
        WriteUiState(form = WriteForm(password = Password.generate(random).hex(), pack = Pack.generate(random).hex())),
    )
    val state: StateFlow<WriteUiState> = _state.asStateFlow()

    private var request: WriteRequest? = null

    init {
        viewModelScope.launch {
            repo.tags.filter { it.screen == AppScreen.WRITE }.collect { ev ->
                if (_state.value.phase is WritePhase.WaitingForTag) {
                    request?.let { execute(ev.tag, it, heldTag = false) }
                }
            }
        }
    }

    // ------------------------------------------------------------------ form editing

    private fun editForm(transform: (WriteForm) -> WriteForm) {
        _state.update { s ->
            val f = transform(s.form)
            val (encoded, sizeInfo, urlErr) = describeUrl(f.url)
            s.copy(form = f, encoded = encoded, sizeInfo = sizeInfo, errors = s.errors.copy(url = if (f.url.isEmpty()) null else urlErr))
        }
    }

    fun onUrl(v: String) = editForm { it.copy(url = v.trim()) }
    fun onId(v: String) { editForm { it.copy(id = v.filter(Char::isDigit).take(3)) }; clearError { it.copy(id = null) } }
    fun onSecret(v: String) { editForm { it.copy(secret = v) }; clearError { it.copy(secret = null) } }
    fun onPassword(v: String) { editForm { it.copy(password = hex(v, Password.HEX_LENGTH)) }; clearError { it.copy(password = null) } }
    fun onPack(v: String) { editForm { it.copy(pack = hex(v, Pack.HEX_LENGTH)) }; clearError { it.copy(pack = null) } }
    fun onCurrentPassword(v: String) { editForm { it.copy(currentPassword = hex(v, Password.HEX_LENGTH)) }; clearError { it.copy(currentPassword = null) } }
    fun onAutoIncrement(v: Boolean) = editForm { it.copy(autoIncrementId = v) }
    fun onNewSecretPerTag(v: Boolean) = editForm { it.copy(newSecretPerTag = v) }
    fun onNewPasswordPerTag(v: Boolean) = editForm { it.copy(newPasswordPerTag = v) }
    fun generateSecret() { editForm { it.copy(secret = Secret.generate(random).value) }; clearError { it.copy(secret = null) } }
    fun generatePassword() { editForm { it.copy(password = Password.generate(random).hex()) }; clearError { it.copy(password = null) } }
    fun generatePack() { editForm { it.copy(pack = Pack.generate(random).hex()) }; clearError { it.copy(pack = null) } }

    private fun clearError(f: (FieldErrors) -> FieldErrors) = _state.update { it.copy(errors = f(it.errors)) }

    private fun hex(v: String, max: Int) = v.filter { Character.digit(it, 16) >= 0 }.uppercase().take(max)

    private fun describeUrl(url: String): Triple<EncodedUrl?, String?, String?> {
        if (url.isEmpty()) return Triple(null, null, null)
        return when (val v = NdefUrlEncoder.validate(url)) {
            is UrlValidation.Invalid -> Triple(null, null, v.reason)
            is UrlValidation.Valid -> {
                val e = NdefUrlEncoder.encode(v.url)
                val prefix = if (e.prefixCode == 0) "no prefix compression" else "prefix \"${e.prefix}\" compressed to 0x${Hex.byte(e.prefixCode)}"
                if (e.fitsPublicRegion) {
                    Triple(
                        e,
                        "${e.tlvSize} of ${Ntag215Memory.PUBLIC_CAPACITY_BYTES} bytes (pages 0x04-0x${Hex.byte(e.lastPage)}, ${e.bytesRemaining} free) · NDEF message ${e.messageSize} B · $prefix",
                        null,
                    )
                } else {
                    Triple(
                        e,
                        null,
                        "Too long: encodes to ${e.tlvSize} bytes, but only ${Ntag215Memory.PUBLIC_CAPACITY_BYTES} bytes fit before the protected region (page 0x20). Shorten by ${e.tlvSize - Ntag215Memory.PUBLIC_CAPACITY_BYTES} byte(s).",
                    )
                }
            }
        }
    }

    // ------------------------------------------------------------------ write flow

    /** Step 1: validate everything; on success arm the writer and wait for a tag (step 2). */
    fun startWrite() {
        val f = _state.value.form
        val urlValidation = NdefUrlEncoder.validate(f.url)
        val encoded = (urlValidation as? UrlValidation.Valid)?.let { NdefUrlEncoder.encode(it.url) }
        val errors = FieldErrors(
            url = when {
                urlValidation is UrlValidation.Invalid -> urlValidation.reason
                encoded != null && !encoded.fitsPublicRegion -> "URL too long for the public region (${encoded.tlvSize}/${Ntag215Memory.PUBLIC_CAPACITY_BYTES} bytes)"
                else -> null
            },
            id = PrivateId.validate(f.id),
            secret = Secret.validate(f.secret),
            password = Password.validate(f.password),
            pack = Pack.validate(f.pack),
            currentPassword = if (f.currentPassword.isEmpty()) null else Password.validate(f.currentPassword),
        )
        if (errors.any || encoded == null) {
            _state.update { it.copy(errors = errors) }
            return
        }
        request = WriteRequest(
            url = encoded,
            id = PrivateId.parse(f.id)!!,
            secret = Secret.parse(f.secret)!!,
            newPassword = Password.parse(f.password)!!,
            newPack = Pack.parse(f.pack)!!,
            currentPassword = f.currentPassword.takeIf { it.isNotEmpty() }?.let { Password.parse(it) },
            confirmedOverwriteUid = null,
        )
        resetSteps()
        _state.update { it.copy(errors = FieldErrors(), phase = WritePhase.WaitingForTag("Hold an NTAG215 tag to the phone")) }
    }

    private fun resetSteps() = _state.update { s ->
        s.copy(
            steps = WriteStep.entries.associateWith { StepUi() } +
                (WriteStep.VALIDATE to StepUi(StepStatus.DONE, "All fields valid")) +
                (WriteStep.WAIT_FOR_TAG to StepUi(StepStatus.RUNNING, null)),
        )
    }

    fun cancel() {
        request = null
        _state.update { it.copy(phase = WritePhase.Editing) }
    }

    /** Re-arms the same request (e.g. after a recoverable failure). */
    fun retry() {
        if (request == null) return startWrite()
        resetSteps()
        _state.update { it.copy(phase = WritePhase.WaitingForTag("Hold the tag to the phone to try again")) }
    }

    fun confirmOverwrite(uidHex: String) {
        val r = request ?: return
        request = r.copy(confirmedOverwriteUid = uidHex)
        continueOnSameTag(uidHex)
    }

    fun supplyCurrentPassword(hexValue: String) {
        val r = request ?: return
        val pwd = Password.parse(hexValue) ?: return
        _state.update { it.copy(form = it.form.copy(currentPassword = hexValue)) }
        request = r.copy(currentPassword = pwd)
        val uid = (_state.value.phase as? WritePhase.NeedsPassword)?.outcome?.uidHex ?: return
        continueOnSameTag(uid)
    }

    fun failuresFor(uidHex: String) = repo.attemptTracker.failures(uidHex)

    private fun continueOnSameTag(uidHex: String) {
        val tag = repo.lastTag
        val r = request ?: return
        resetSteps()
        if (tag != null && tag.id.toHex() == uidHex) {
            viewModelScope.launch { execute(tag, r, heldTag = true) }
        } else {
            _state.update { it.copy(phase = WritePhase.WaitingForTag("Hold the same tag to the phone again")) }
        }
    }

    private suspend fun execute(tag: Tag, req: WriteRequest, heldTag: Boolean) {
        _state.update {
            it.copy(
                phase = WritePhase.Running,
                steps = it.steps + (WriteStep.WAIT_FOR_TAG to StepUi(StepStatus.DONE, "UID ${tag.id.toHex(":")}")),
            )
        }
        val outcome = repo.write(tag, req) { step, status, detail ->
            _state.update { it.copy(steps = it.steps + (step to StepUi(status, detail))) }
        }
        _state.update { s ->
            when (outcome) {
                is WriteOutcome.Success -> s.copy(phase = WritePhase.Succeeded(outcome), tagsWritten = s.tagsWritten + 1)
                is WriteOutcome.NeedsPassword -> s.copy(phase = WritePhase.NeedsPassword(outcome))
                is WriteOutcome.NeedsConfirmation -> s.copy(phase = WritePhase.NeedsConfirmation(outcome))
                is WriteOutcome.Failure ->
                    if (heldTag && outcome.step == WriteStep.IDENTIFY && outcome.error is NtagException.TagRemoved) {
                        // The held tag left the field before anything was written: just wait for it.
                        s.copy(
                            phase = WritePhase.WaitingForTag("Hold the same tag to the phone again"),
                            steps = s.steps + (WriteStep.IDENTIFY to StepUi()) + (WriteStep.WAIT_FOR_TAG to StepUi(StepStatus.RUNNING)),
                        )
                    } else {
                        s.copy(phase = WritePhase.Failed(outcome))
                    }
            }
        }
    }

    /** After a success: prepare the next tag (increment ID, regenerate secret/password) and arm. */
    fun nextTag() {
        editForm { f ->
            f.copy(
                id = if (f.autoIncrementId) PrivateId.parse(f.id)?.next()?.value ?: f.id else f.id,
                secret = if (f.newSecretPerTag) Secret.generate(random).value else f.secret,
                password = if (f.newPasswordPerTag) Password.generate(random).hex() else f.password,
                pack = if (f.newPasswordPerTag) Pack.generate(random).hex() else f.pack,
                currentPassword = "",
            )
        }
        startWrite()
    }

    fun finish() = cancel()
}
