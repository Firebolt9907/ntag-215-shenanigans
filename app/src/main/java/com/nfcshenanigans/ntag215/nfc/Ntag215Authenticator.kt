package com.nfcshenanigans.ntag215.nfc

import com.nfcshenanigans.ntag215.core.Pack
import com.nfcshenanigans.ntag215.core.Password
import java.util.concurrent.ConcurrentHashMap

/**
 * Tracks failed PWD_AUTH attempts per tag UID for this app session. The UI uses this to require an
 * explicit decision before another attempt, because tags with AUTHLIM != 0 permanently lock their
 * protected area after a number of failures (datasheet 8.8.2).
 */
class AuthAttemptTracker {
    private val failures = ConcurrentHashMap<String, Int>()

    fun failures(uidHex: String): Int = failures[uidHex] ?: 0
    fun recordFailure(uidHex: String) { failures.merge(uidHex, 1, Int::plus) }
    fun recordSuccess(uidHex: String) { failures.remove(uidHex) }
}

data class AuthResult(val pack: ByteArray, val packMatches: Boolean?)

/**
 * Password authentication policy:
 *  - exactly one PWD_AUTH per user request, never automatic retries with guessed passwords;
 *  - re-authentication only with a password the tag has already accepted in this session
 *    (successful attempts reset the AUTHLIM counter, so this cannot exhaust attempts);
 *  - PACK is compared when known, but it is only a weak sanity check, not authentication of the tag.
 */
class Ntag215Authenticator(
    private val exec: NfcCommandExecutor,
    private val tracker: AuthAttemptTracker,
    private val uidHex: String,
) {
    /** Password most recently accepted by this tag in this session. */
    var acceptedPassword: Password? = null
        private set

    val isAuthenticated get() = exec.isAuthenticated

    fun authenticate(password: Password, expectedPack: Pack?): AuthResult {
        val pack = try {
            exec.pwdAuth(password)
        } catch (e: NtagException.AuthenticationFailed) {
            tracker.recordFailure(uidHex)
            throw e
        }
        tracker.recordSuccess(uidHex)
        acceptedPassword = password
        return AuthResult(pack, expectedPack?.matches(pack))
    }

    /** Re-establishes the session after a reconnect/NAK, using only an already accepted password. */
    fun ensureAuthenticated() {
        if (exec.isAuthenticated) return
        val pwd = acceptedPassword ?: throw NtagException.PasswordRequired()
        exec.pwdAuth(pwd)
    }

    /** Called after the tag's PWD page was rewritten while authenticated. */
    fun passwordChanged(newPassword: Password) {
        acceptedPassword = newPassword
    }
}
