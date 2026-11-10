package com.nfcshenanigans.ntag215.ui.read

import android.nfc.Tag
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.nfcshenanigans.ntag215.core.Pack
import com.nfcshenanigans.ntag215.core.Password
import com.nfcshenanigans.ntag215.core.toHex
import com.nfcshenanigans.ntag215.data.AppScreen
import com.nfcshenanigans.ntag215.data.Ntag215Repository
import com.nfcshenanigans.ntag215.nfc.NtagException
import com.nfcshenanigans.ntag215.nfc.PrivateState
import com.nfcshenanigans.ntag215.nfc.TagReport
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.filter
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

data class ReadUiState(
    val busy: Boolean = false,
    val report: TagReport? = null,
    val error: String? = null,
    val info: String? = null,
    val password: String = "",
    val pack: String = "",
    val passwordError: String? = null,
    val packError: String? = null,
    /** Next tap of the reported tag will authenticate with [password]. */
    val awaitingAuthTap: Boolean = false,
    /** Non-null asks the user to confirm another attempt after [retryConfirmFailures] failures. */
    val retryConfirmFailures: Int? = null,
) {
    /** The password field holds a complete password, so every scan uses it. */
    val hasSavedPassword get() = Password.validate(password) == null
}

class ReadViewModel(private val repo: Ntag215Repository) : ViewModel() {
    private val _state = MutableStateFlow(ReadUiState())
    val state: StateFlow<ReadUiState> = _state.asStateFlow()

    /**
     * (UID, password) pairs that failed during a scan. A saved password is never sent again
     * automatically to a tag that already rejected it, because tags with AUTHLIM != 0 count every
     * failure toward a permanent lock. Editing the password or pressing Authenticate tries again.
     */
    private val autoFailed = mutableSetOf<Pair<String, String>>()

    init {
        viewModelScope.launch {
            repo.tags.filter { it.screen == AppScreen.READ }.collect { ev ->
                val s = _state.value
                if (s.busy) return@collect
                val reportUid = s.report?.identity?.uidHex
                val explicitAuth = s.awaitingAuthTap && (reportUid == null || reportUid == ev.uidHex)
                val skipSaved = s.hasSavedPassword && !explicitAuth && (ev.uidHex to s.password) in autoFailed
                val password = if (skipSaved) null else Password.parse(s.password)
                inspect(ev.tag, password, heldTag = false)
                if (skipSaved && _state.value.report?.privateState == PrivateState.Locked) {
                    _state.update {
                        it.copy(info = "The saved password was not tried because it already failed on this tag. Edit it, or press Authenticate to try it again.")
                    }
                }
            }
        }
    }

    fun onPasswordChange(v: String) = _state.update {
        it.copy(password = v.filter { c -> Character.digit(c, 16) >= 0 }.uppercase().take(Password.HEX_LENGTH), passwordError = null)
    }

    fun onPackChange(v: String) = _state.update {
        it.copy(pack = v.filter { c -> Character.digit(c, 16) >= 0 }.uppercase().take(Pack.HEX_LENGTH), packError = null)
    }

    fun clearPassword() = _state.update { it.copy(password = "", pack = "", passwordError = null, packError = null) }

    fun dismissRetryDialog() = _state.update { it.copy(retryConfirmFailures = null) }

    fun cancelAuthWait() = _state.update { it.copy(awaitingAuthTap = false, info = null) }

    /** Authenticate against the scanned tag: immediately if still in the field, else on the next tap. */
    fun authenticate(confirmedRetry: Boolean = false) {
        val s = _state.value
        val pwdErr = Password.validate(s.password)
        val packErr = if (s.pack.isEmpty()) null else Pack.validate(s.pack)
        if (pwdErr != null || packErr != null) {
            _state.update { it.copy(passwordError = pwdErr, packError = packErr) }
            return
        }
        val uid = s.report?.identity?.uidHex
        val failures = uid?.let { repo.attemptTracker.failures(it) } ?: 0
        if (failures > 0 && !confirmedRetry) {
            _state.update { it.copy(retryConfirmFailures = failures) }
            return
        }
        _state.update { it.copy(retryConfirmFailures = null) }
        val held = repo.lastTag
        if (held != null && uid != null && held.id.toHex() == uid) {
            viewModelScope.launch { inspect(held, Password.parse(s.password), heldTag = true) }
        } else {
            _state.update { it.copy(awaitingAuthTap = true, info = "Hold the tag to the phone to authenticate.") }
        }
    }

    private suspend fun inspect(tag: Tag, password: Password?, heldTag: Boolean) {
        val pack = _state.value.pack.takeIf { Pack.validate(it) == null }?.let { Pack.parse(it) }
        _state.update { it.copy(busy = true, error = null, info = null) }
        try {
            val report = repo.inspect(tag, password, if (password != null) pack else null, includeSystemNdef = true)
            if (password != null) {
                val key = report.identity.uidHex to password.hex().uppercase()
                if (report.privateState is PrivateState.AuthFailed) autoFailed += key else autoFailed -= key
            }
            _state.update { it.copy(busy = false, report = report, awaitingAuthTap = false) }
        } catch (e: NtagException.TagRemoved) {
            if (heldTag && password != null) {
                _state.update { it.copy(busy = false, awaitingAuthTap = true, info = "The tag is no longer in range. Hold it to the phone to authenticate.") }
            } else {
                _state.update { it.copy(busy = false, error = e.message) }
            }
        } catch (e: NtagException) {
            _state.update { it.copy(busy = false, error = e.message, report = null, awaitingAuthTap = false) }
        }
    }
}
