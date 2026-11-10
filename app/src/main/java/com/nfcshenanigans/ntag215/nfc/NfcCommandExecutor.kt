package com.nfcshenanigans.ntag215.nfc

import com.nfcshenanigans.ntag215.core.Hex
import com.nfcshenanigans.ntag215.core.Ntag215Memory
import com.nfcshenanigans.ntag215.core.Password
import com.nfcshenanigans.ntag215.core.u

/**
 * Builds and executes raw NTAG21x commands (datasheet section 10) and interprets responses.
 *
 * NAK handling: after a NAK the NTAG enters IDLE/HALT (datasheet 8.4.4) and any PWD_AUTH session is
 * lost. Android's JNI layer re-selects T2T tags after a NAK and reports it as an IOException; some
 * controllers instead return the 4-bit NAK as a single byte. Both cases are handled, and the executor
 * reconnects so subsequent commands work, marking the session as unauthenticated.
 */
class NfcCommandExecutor(
    private val transport: NfcTransport,
    val log: CommandLog = CommandLog(),
) {
    var isAuthenticated: Boolean = false
        private set

    var fastReadSupported: Boolean = true
        private set

    val maxTransceiveLength: Int get() = transport.maxTransceiveLength

    /** Max pages per FAST_READ, leaving headroom for controller framing. Capped at 32 pages (128 bytes). */
    val fastReadMaxPages: Int
        get() = ((maxTransceiveLength - 2) / Ntag215Memory.PAGE_SIZE).coerceIn(1, 32)

    fun getVersion(): ByteArray = exchange("GET_VERSION", byteArrayOf(CMD_GET_VERSION), 8)

    /** READ (30h): 16 bytes = 4 pages from [page], with roll-over semantics (datasheet 10.2). */
    fun read(page: Int): ByteArray {
        require(Ntag215Memory.isValidPage(page)) { "Invalid page $page" }
        return exchange("READ ${label(page)}", byteArrayOf(CMD_READ, page.toByte()), 16)
    }

    /** Reads a single page using READ and discarding the rolled-over pages. */
    fun readPage(page: Int): ByteArray = read(page).copyOf(Ntag215Memory.PAGE_SIZE)

    /** FAST_READ (3Ah) of pages [start]..[end] inclusive. */
    fun fastRead(start: Int, end: Int): ByteArray {
        require(Ntag215Memory.isValidPage(start) && Ntag215Memory.isValidPage(end) && end >= start)
        val count = end - start + 1
        require(count <= fastReadMaxPages) { "FAST_READ of $count pages exceeds transceive limit" }
        return exchange("FAST_READ ${label(start)}-${label(end)}", byteArrayOf(CMD_FAST_READ, start.toByte(), end.toByte()), count * 4)
    }

    /**
     * Reads pages [start]..[end] inclusive. Uses FAST_READ in chunks within the transceive limit and
     * falls back to READ if FAST_READ is not usable. The caller must ensure every page is accessible
     * (a protected page triggers a NAK, which also ends an authenticated session).
     */
    fun readPages(start: Int, end: Int, reauthenticate: (() -> Unit)? = null): ByteArray {
        require(end >= start)
        val out = ByteArray((end - start + 1) * Ntag215Memory.PAGE_SIZE)
        var page = start
        while (page <= end) {
            if (fastReadSupported) {
                val last = minOf(end, page + fastReadMaxPages - 1)
                val wasAuthenticated = isAuthenticated
                try {
                    fastRead(page, last).copyInto(out, (page - start) * 4)
                    page = last + 1
                    continue
                } catch (e: NtagException.Nak) {
                    // Some controller paths reject FAST_READ; READ is the fallback. A NAK ends the
                    // PWD_AUTH session, so restore it with the already accepted password if needed.
                    fastReadSupported = false
                    log.note("FAST_READ unavailable, falling back to READ")
                    if (wasAuthenticated) reauthenticate?.invoke()
                } catch (e: NtagException.MalformedResponse) {
                    fastReadSupported = false
                    log.note("FAST_READ response malformed, falling back to READ")
                    if (wasAuthenticated && !isAuthenticated) reauthenticate?.invoke()
                }
            }
            val chunk = read(page)
            val take = minOf(4, end - page + 1)
            chunk.copyInto(out, (page - start) * 4, 0, take * 4)
            page += take
        }
        return out
    }

    /** WRITE (A2h) of one 4-byte page. Refuses UID, static lock, CC and dynamic lock pages. */
    fun write(page: Int, data: ByteArray) {
        require(data.size == Ntag215Memory.PAGE_SIZE) { "WRITE needs exactly 4 bytes" }
        if (!Ntag215Memory.isValidPage(page) || Ntag215Memory.isNeverWritable(page)) {
            throw NtagException.SafetyViolation("Refusing to write protected system page ${label(page)} (UID, lock bits or capability container).")
        }
        exchangeAck("WRITE ${label(page)}", byteArrayOf(CMD_WRITE, page.toByte()) + data)
    }

    /**
     * PWD_AUTH (1Bh). Returns the 2-byte PACK on success.
     * @throws NtagException.AuthenticationFailed when the tag rejects the password.
     */
    fun pwdAuth(password: Password): ByteArray {
        val cmd = byteArrayOf(CMD_PWD_AUTH) + password.bytes()
        try {
            val pack = exchange("PWD_AUTH ********", cmd, 2)
            isAuthenticated = true
            return pack
        } catch (e: NtagException.Nak) {
            throw NtagException.AuthenticationFailed(counterOverflow = e.code == 0x4)
        } catch (e: NtagException.MalformedResponse) {
            throw NtagException.AuthenticationFailed(counterOverflow = false)
        }
    }

    /** Re-activates the tag; ends any authenticated session. */
    fun reconnect() {
        isAuthenticated = false
        try {
            transport.reconnect()
            log.note("Reconnected (session reset)")
        } catch (e: TransportException) {
            throw NtagException.TagRemoved("reconnect")
        }
    }

    /**
     * Guarantees an unauthenticated session. Sends READ of an out-of-range address (always NAK per
     * datasheet 10.2), which returns NTAG21x to IDLE, then re-activates the tag. This does not depend
     * on how a particular Android build implements reconnect.
     */
    fun deauthenticate() {
        val start = System.nanoTime()
        try {
            val resp = transport.transceive(byteArrayOf(CMD_READ, 0xFF.toByte()))
            log.add("READ 0xFF (de-auth)", "${resp.size}-byte response", elapsed(start))
        } catch (e: TransportException.TagLost) {
            isAuthenticated = false
            throw NtagException.TagRemoved("de-authentication")
        } catch (e: TransportException.IoFailure) {
            log.add("READ 0xFF (de-auth)", "rejected (expected)", elapsed(start))
        }
        reconnect()
    }

    private fun exchangeAck(name: String, cmd: ByteArray) {
        val resp = transceive(name, cmd)
        when {
            resp.size == 1 && (resp[0].u() and 0x0F) == ACK -> log.add(name, "ACK", lastDuration)
            resp.isEmpty() -> log.add(name, "empty response (treated as ACK; verified later)", lastDuration)
            resp.size == 1 -> nak(name, resp[0].u() and 0x0F)
            else -> {
                log.add(name, "unexpected ${resp.size}-byte response", lastDuration)
                throw NtagException.MalformedResponse(name, resp.size, 1)
            }
        }
    }

    private fun exchange(name: String, cmd: ByteArray, expected: Int): ByteArray {
        val resp = transceive(name, cmd)
        return when {
            resp.size == expected -> { log.add(name, "OK ($expected bytes)", lastDuration); resp }
            resp.size == 1 -> nak(name, resp[0].u() and 0x0F)
            else -> {
                log.add(name, "unexpected ${resp.size} bytes", lastDuration)
                throw NtagException.MalformedResponse(name, resp.size, expected)
            }
        }
    }

    private var lastDuration = 0L

    private fun transceive(name: String, cmd: ByteArray): ByteArray {
        val start = System.nanoTime()
        try {
            return transport.transceive(cmd).also { lastDuration = elapsed(start) }
        } catch (e: TransportException.TagLost) {
            isAuthenticated = false
            log.add(name, "tag lost", elapsed(start))
            throw NtagException.TagRemoved(name)
        } catch (e: TransportException.IoFailure) {
            // Android reports T2T NAKs this way (after re-selecting the tag itself). Distinguish from
            // a removed tag by reconnecting: if that fails, the tag is gone.
            isAuthenticated = false
            log.add(name, "rejected / no response", elapsed(start))
            try {
                transport.reconnect()
            } catch (t: TransportException) {
                throw NtagException.TagRemoved(name)
            }
            throw NtagException.Nak(name, null)
        }
    }

    private fun nak(name: String, code: Int): Nothing {
        isAuthenticated = false
        log.add(name, "NAK ${Integer.toHexString(code)}h", lastDuration)
        try {
            transport.reconnect()
        } catch (t: TransportException) {
            throw NtagException.TagRemoved(name)
        }
        throw NtagException.Nak(name, code)
    }

    private fun elapsed(startNs: Long) = (System.nanoTime() - startNs) / 1_000_000

    private fun label(page: Int) = "0x" + Hex.byte(page)

    companion object {
        const val CMD_GET_VERSION: Byte = 0x60
        const val CMD_READ: Byte = 0x30
        const val CMD_FAST_READ: Byte = 0x3A
        const val CMD_WRITE: Byte = 0xA2.toByte()
        const val CMD_PWD_AUTH: Byte = 0x1B
        const val ACK = 0xA
    }
}
