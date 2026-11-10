package com.nfcshenanigans.ntag215.nfc

/**
 * Errors raised by the NTAG215 layer. Messages never contain passwords, secrets or page contents.
 * [recoverable] is true when retrying (e.g. tapping again) can succeed without changing anything.
 */
sealed class NtagException(message: String, val recoverable: Boolean = true) : Exception(message) {

    class TagRemoved(command: String) :
        NtagException("Tag was removed or connection lost during $command. Hold the phone steady on the tag and try again.")

    /** 4-bit NAK (code known) or a rejected command reported by Android as a transceive failure (code null). */
    class Nak(val command: String, val code: Int?) : NtagException(
        "$command was rejected by the tag (${describe(code)})."
    ) {
        companion object {
            fun describe(code: Int?): String = when (code) {
                null -> "NAK or no response"
                0x0 -> "NAK 0h: invalid argument or access denied"
                0x1 -> "NAK 1h: parity/CRC error"
                0x4 -> "NAK 4h: authentication counter overflow"
                0x5 -> "NAK 5h: EEPROM write error"
                else -> "NAK ${Integer.toHexString(code)}h"
            }
        }
    }

    class MalformedResponse(command: String, got: Int, expected: Int) :
        NtagException("Unexpected response to $command: $got bytes (expected $expected).")

    class AuthenticationFailed(val counterOverflow: Boolean) : NtagException(
        if (counterOverflow) {
            "Authentication blocked: the tag's attempt limit (AUTHLIM) has been reached. Protected memory is permanently inaccessible."
        } else {
            "Authentication failed: the password was rejected. No further attempts were made."
        },
        recoverable = !counterOverflow,
    )

    class UnsupportedTag(reason: String) : NtagException(reason)

    class WriteProtected(reason: String) : NtagException(reason, recoverable = false)

    class InvalidConfiguration(reason: String) : NtagException(reason, recoverable = false)

    class InsufficientMemory(reason: String) : NtagException(reason, recoverable = false)

    class CorruptedData(reason: String) : NtagException(reason)

    class VerificationFailed(reason: String) : NtagException(reason)

    class PasswordRequired : NtagException("This tag is password-protected. Enter its current password.")

    class SafetyViolation(reason: String) : NtagException(reason, recoverable = false)
}
