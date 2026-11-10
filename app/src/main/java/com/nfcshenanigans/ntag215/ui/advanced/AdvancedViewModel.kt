package com.nfcshenanigans.ntag215.ui.advanced

import android.nfc.Tag
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.nfcshenanigans.ntag215.core.Pack
import com.nfcshenanigans.ntag215.core.Password
import com.nfcshenanigans.ntag215.core.toHex
import com.nfcshenanigans.ntag215.data.AppScreen
import com.nfcshenanigans.ntag215.data.Ntag215Repository
import com.nfcshenanigans.ntag215.data.TagTechInfo
import com.nfcshenanigans.ntag215.nfc.CommandLog
import com.nfcshenanigans.ntag215.nfc.MemoryDump
import com.nfcshenanigans.ntag215.nfc.NtagException
import com.nfcshenanigans.ntag215.nfc.RemoveProtectionOutcome
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.filter
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

enum class ArmedAction { NONE, AUTH_DUMP, REMOVE_PROTECTION }

data class AdvancedUiState(
    val busy: Boolean = false,
    val dump: MemoryDump? = null,
    val tech: TagTechInfo? = null,
    val error: String? = null,
    val info: String? = null,
    val password: String = "",
    val pack: String = "",
    val passwordError: String? = null,
    val armed: ArmedAction = ArmedAction.NONE,
    val revealPrivate: Boolean = false,
    val confirmRemove: Boolean = false,
    val log: List<CommandLog.Entry> = emptyList(),
)

class AdvancedViewModel(private val repo: Ntag215Repository) : ViewModel() {
    private val _state = MutableStateFlow(AdvancedUiState())
    val state: StateFlow<AdvancedUiState> = _state.asStateFlow()

    init {
        viewModelScope.launch {
            repo.tags.filter { it.screen == AppScreen.ADVANCED }.collect { ev ->
                if (!_state.value.busy) run(ev.tag, _state.value.armed)
            }
        }
        refreshLog()
    }

    fun onPassword(v: String) = _state.update {
        it.copy(password = v.filter { c -> Character.digit(c, 16) >= 0 }.uppercase().take(8), passwordError = null)
    }

    fun onPack(v: String) = _state.update { it.copy(pack = v.filter { c -> Character.digit(c, 16) >= 0 }.uppercase().take(4)) }

    fun toggleReveal() = _state.update { it.copy(revealPrivate = !it.revealPrivate) }
    fun askRemove() { if (validatePassword()) _state.update { it.copy(confirmRemove = true) } }
    fun dismissRemove() = _state.update { it.copy(confirmRemove = false) }
    fun disarm() = _state.update { it.copy(armed = ArmedAction.NONE, info = null) }

    fun refreshLog() = _state.update { it.copy(log = repo.commandLog.snapshot().takeLast(150).reversed()) }
    fun clearLog() { repo.commandLog.clear(); refreshLog() }

    fun authenticateAndDump() { if (validatePassword()) arm(ArmedAction.AUTH_DUMP) }

    fun confirmRemove() {
        _state.update { it.copy(confirmRemove = false) }
        arm(ArmedAction.REMOVE_PROTECTION)
    }

    private fun validatePassword(): Boolean {
        val err = Password.validate(_state.value.password)
        _state.update { it.copy(passwordError = err) }
        return err == null
    }

    private fun arm(action: ArmedAction) {
        val held = repo.lastTag
        val dumpUid = _state.value.dump?.identity?.uidHex
        if (held != null && dumpUid != null && held.id.toHex() == dumpUid) {
            viewModelScope.launch { run(held, action, heldTag = true) }
        } else {
            _state.update { it.copy(armed = action, info = "Hold the tag to the phone") }
        }
    }

    private suspend fun run(tag: Tag, action: ArmedAction, heldTag: Boolean = false) {
        val s = _state.value
        val pwd = Password.parse(s.password)
        val pack = s.pack.takeIf { it.length == 4 }?.let { Pack.parse(it) }
        _state.update { it.copy(busy = true, error = null, info = null, tech = repo.techInfo(tag)) }
        try {
            when (action) {
                ArmedAction.REMOVE_PROTECTION -> {
                    val result = repo.removeProtection(tag, pwd!!)
                    val dump = runCatching { repo.dump(tag, null, null) }.getOrNull()
                    _state.update {
                        it.copy(
                            dump = dump ?: it.dump,
                            armed = ArmedAction.NONE,
                            info = when (result) {
                                is RemoveProtectionOutcome.Success -> "Protection removed from ${result.uidDisplay}. All pages are now readable and writable without a password."
                                is RemoveProtectionOutcome.Failure -> null
                            },
                            error = (result as? RemoveProtectionOutcome.Failure)?.let { f -> "${f.message} ${f.tagState}" },
                        )
                    }
                }
                ArmedAction.AUTH_DUMP -> {
                    val dump = repo.dump(tag, pwd, pack)
                    _state.update { it.copy(dump = dump, armed = ArmedAction.NONE, revealPrivate = false) }
                }
                ArmedAction.NONE -> {
                    val dump = repo.dump(tag, null, null)
                    _state.update { it.copy(dump = dump, revealPrivate = false) }
                }
            }
        } catch (e: NtagException.TagRemoved) {
            if (heldTag) _state.update { it.copy(armed = action, info = "The tag is no longer in range. Hold it to the phone.") }
            else _state.update { it.copy(error = e.message) }
        } catch (e: NtagException) {
            _state.update { it.copy(error = e.message, armed = ArmedAction.NONE) }
        } finally {
            _state.update { it.copy(busy = false) }
            refreshLog()
        }
    }
}
