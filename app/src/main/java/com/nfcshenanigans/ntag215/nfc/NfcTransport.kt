package com.nfcshenanigans.ntag215.nfc

import android.nfc.Tag
import android.nfc.tech.NfcA
import java.io.IOException

/** Raw ISO 14443-3A frame exchange with a tag. Implementations are blocking; call off the main thread. */
interface NfcTransport {
    /** Maximum command length accepted by the controller. Used to size FAST_READ requests. */
    val maxTransceiveLength: Int

    /** Sends [command] (CRC is added by the controller) and returns the raw response. */
    @Throws(TransportException::class)
    fun transceive(command: ByteArray): ByteArray

    /**
     * Re-activates the tag (HLTA + WUPA/select). Resets NTAG21x to ACTIVE state, which clears any
     * PWD_AUTH session and recovers from the IDLE state entered after a NAK (datasheet 8.4).
     */
    @Throws(TransportException::class)
    fun reconnect()

    fun close()
}

sealed class TransportException(message: String, cause: Throwable?) : Exception(message, cause) {
    /** The tag left the RF field or the handle became stale. */
    class TagLost(cause: Throwable? = null) : TransportException("Tag connection lost", cause)

    /** No valid response: NAK (Android reports T2T NAKs as transceive failures), timeout, or RF error. */
    class IoFailure(cause: Throwable? = null) : TransportException("No valid response from tag", cause)
}

/** Android [NfcA] implementation. */
class AndroidNfcTransport private constructor(
    private val nfcA: NfcA,
    private val timeoutMs: Int,
) : NfcTransport {

    override val maxTransceiveLength: Int get() = nfcA.maxTransceiveLength
    val atqa: ByteArray get() = nfcA.atqa
    val sak: Short get() = nfcA.sak

    override fun transceive(command: ByteArray): ByteArray {
        try {
            return nfcA.transceive(command) ?: throw TransportException.IoFailure()
        } catch (e: android.nfc.TagLostException) {
            throw TransportException.TagLost(e)
        } catch (e: SecurityException) {
            // "Tag ... is out of date" when the tag object is stale.
            throw TransportException.TagLost(e)
        } catch (e: IllegalStateException) {
            throw TransportException.TagLost(e)
        } catch (e: IOException) {
            throw TransportException.IoFailure(e)
        }
    }

    override fun reconnect() {
        // BasicTagTechnology.close() asks the NFC service to reconnect (re-select) the tag
        // "to reset its state"; for Type 2 tags AOSP performs reSelect(NFA_INTERFACE_FRAME).
        try {
            runCatching { nfcA.close() }
            nfcA.connect()
            nfcA.timeout = timeoutMs
        } catch (e: IOException) {
            throw TransportException.TagLost(e)
        } catch (e: SecurityException) {
            throw TransportException.TagLost(e)
        } catch (e: IllegalStateException) {
            throw TransportException.TagLost(e)
        }
    }

    override fun close() {
        runCatching { nfcA.close() }
    }

    companion object {
        const val DEFAULT_TIMEOUT_MS = 1000

        /** @return null if the tag does not support NfcA. @throws TransportException.TagLost if connect fails. */
        fun open(tag: Tag, timeoutMs: Int = DEFAULT_TIMEOUT_MS): AndroidNfcTransport? {
            val nfcA = NfcA.get(tag) ?: return null
            try {
                nfcA.connect()
                nfcA.timeout = timeoutMs
            } catch (e: IOException) {
                throw TransportException.TagLost(e)
            } catch (e: SecurityException) {
                throw TransportException.TagLost(e)
            }
            return AndroidNfcTransport(nfcA, timeoutMs)
        }
    }
}
