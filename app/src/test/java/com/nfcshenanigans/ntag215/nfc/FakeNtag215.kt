package com.nfcshenanigans.ntag215.nfc

import com.nfcshenanigans.ntag215.core.u

/**
 * Software model of an NTAG215 following NXP datasheet Rev. 3.2 semantics, used as a fake
 * [NfcTransport] for tests without hardware:
 *  - READ roll-over at end of memory, or just before AUTH0 when read-protected and unauthenticated;
 *  - FAST_READ NAK if any requested page is protected;
 *  - WRITE NAK on protected/locked pages, OTP OR semantics for CC and lock bytes, CFGLCK;
 *  - PWD/PACK write-only (read as 00), PWD_AUTH with AUTHLIM counter;
 *  - after a NAK the tag is IDLE until re-activated.
 */
class FakeNtag215(
    uid: ByteArray = byteArrayOf(0x04, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66),
    var nakStyle: NakStyle = NakStyle.ANDROID_EXCEPTION,
    override var maxTransceiveLength: Int = 253,
    var version: ByteArray = byteArrayOf(0x00, 0x04, 0x04, 0x02, 0x01, 0x00, 0x11, 0x03),
) : NfcTransport {

    enum class NakStyle {
        /** 4-bit NAK delivered as a single byte; tag stays IDLE until reconnect. */
        RAW_BYTE,
        /** AOSP behaviour: JNI re-selects the tag and Java sees an IOException. */
        ANDROID_EXCEPTION,
    }

    private enum class State { ACTIVE, AUTHENTICATED, IDLE }

    val uid: ByteArray = uid.copyOf()
    val pages: Array<ByteArray> = Array(0x87) { ByteArray(4) }
    var password: ByteArray = byteArrayOf(-1, -1, -1, -1)
    var pack: ByteArray = byteArrayOf(0, 0)
    private var state = State.ACTIVE
    private var failedAuths = 0
    var cfgLockActive = false

    /** Number of further commands accepted before the tag "leaves the field" (null = never). */
    var commandsUntilRemoval: Int? = null
    var removed = false
        private set
    val commandHistory = mutableListOf<String>()
    var pwdAuthAttempts = 0
        private set

    init {
        pages[0] = byteArrayOf(uid[0], uid[1], uid[2], (0x88 xor uid[0].u() xor uid[1].u() xor uid[2].u()).toByte())
        pages[1] = byteArrayOf(uid[3], uid[4], uid[5], uid[6])
        pages[2] = byteArrayOf((uid[3].u() xor uid[4].u() xor uid[5].u() xor uid[6].u()).toByte(), 0x48, 0x00, 0x00)
        pages[3] = byteArrayOf(0xE1.toByte(), 0x10, 0x3E, 0x00)
        pages[4] = byteArrayOf(0x03, 0x00, 0xFE.toByte(), 0x00)
        pages[0x82] = byteArrayOf(0x00, 0x00, 0x00, 0xBD.toByte())
        pages[0x83] = byteArrayOf(0x04, 0x00, 0x00, 0xFF.toByte())
        pages[0x84] = byteArrayOf(0x00, 0x00, 0x00, 0x00)
    }

    val auth0 get() = pages[0x83][3].u()
    val access get() = pages[0x84][0].u()
    val prot get() = access and 0x80 != 0
    private val authLim get() = access and 0x07
    private val authed get() = state == State.AUTHENTICATED
    private fun readProtected(page: Int) = prot && auth0 <= 0x86 && page >= auth0 && !authed
    private fun writeProtected(page: Int) = auth0 <= 0x86 && page >= auth0 && !authed

    fun reinsert() { removed = false; commandsUntilRemoval = null; state = State.ACTIVE }

    fun page(p: Int) = pages[p].copyOf()

    override fun transceive(command: ByteArray): ByteArray {
        if (removed) throw TransportException.TagLost()
        commandsUntilRemoval?.let {
            if (it <= 0) { removed = true; throw TransportException.TagLost() }
            commandsUntilRemoval = it - 1
        }
        commandHistory += "%02X".format(command[0].u()) + if (command.size > 1 && command[0].toInt() != 0x1B) " %02X".format(command[1].u()) else ""
        if (state == State.IDLE) throw TransportException.IoFailure() // no response until re-activated
        return when (command[0].u()) {
            0x60 -> version.copyOf()
            0x30 -> read(command[1].u())
            0x3A -> fastRead(command[1].u(), command[2].u())
            0xA2 -> write(command[1].u(), command.copyOfRange(2, 6))
            0x1B -> pwdAuth(command.copyOfRange(1, 5))
            else -> nak(0x0)
        }
    }

    private fun read(addr: Int): ByteArray {
        if (addr > 0x86 || readProtected(addr)) return nak(0x0)
        val limit = if (prot && auth0 <= 0x86 && !authed) auth0 else 0x87
        val out = ByteArray(16)
        var p = addr
        for (i in 0 until 4) {
            pageContent(p).copyInto(out, i * 4)
            p++
            if (p >= limit) p = 0
        }
        return out
    }

    private fun fastRead(start: Int, end: Int): ByteArray {
        if (start > 0x86 || end > 0x86 || end < start) return nak(0x0)
        if ((start..end).any { readProtected(it) }) return nak(0x0)
        if ((end - start + 1) * 4 > maxTransceiveLength + 16) throw TransportException.IoFailure()
        val out = ByteArray((end - start + 1) * 4)
        for (p in start..end) pageContent(p).copyInto(out, (p - start) * 4)
        return out
    }

    private fun pageContent(p: Int): ByteArray = if (p == 0x85 || p == 0x86) ByteArray(4) else pages[p]

    private fun staticLocked(p: Int): Boolean {
        val l0 = pages[2][2].u(); val l1 = pages[2][3].u()
        return when (p) {
            3 -> l0 and 0x08 != 0
            in 4..7 -> l0 and (1 shl p) != 0
            in 8..15 -> l1 and (1 shl (p - 8)) != 0
            else -> false
        }
    }

    private fun dynamicLocked(p: Int): Boolean {
        val d0 = pages[0x82][0].u()
        if (p in 16..127) return d0 and (1 shl ((p - 16) / 16)) != 0
        if (p in 128..129) return d0 and 0x80 != 0
        return false
    }

    private fun write(addr: Int, data: ByteArray): ByteArray {
        if (addr < 2 || addr > 0x86 || writeProtected(addr)) return nak(0x0)
        if (staticLocked(addr) || dynamicLocked(addr)) return nak(0x0)
        when (addr) {
            2 -> { pages[2][2] = (pages[2][2].u() or data[2].u()).toByte(); pages[2][3] = (pages[2][3].u() or data[3].u()).toByte() }
            3 -> for (i in 0..3) pages[3][i] = (pages[3][i].u() or data[i].u()).toByte()
            0x82 -> for (i in 0..2) pages[0x82][i] = (pages[0x82][i].u() or data[i].u()).toByte()
            0x83, 0x84 -> { if (cfgLockActive) return nak(0x0); pages[addr] = data.copyOf() }
            0x85 -> password = data.copyOf()
            0x86 -> pack = data.copyOf(2)
            else -> pages[addr] = data.copyOf()
        }
        return byteArrayOf(0x0A)
    }

    private fun pwdAuth(pwd: ByteArray): ByteArray {
        pwdAuthAttempts++
        if (authLim != 0 && failedAuths >= authLim) return nak(0x4)
        if (pwd.contentEquals(password)) {
            failedAuths = 0
            state = State.AUTHENTICATED
            return pack.copyOf()
        }
        if (authLim != 0) failedAuths++
        return nak(0x0)
    }

    private fun nak(code: Int): ByteArray = when (nakStyle) {
        NakStyle.RAW_BYTE -> { state = State.IDLE; byteArrayOf(code.toByte()) }
        NakStyle.ANDROID_EXCEPTION -> { state = State.ACTIVE; throw TransportException.IoFailure() }
    }

    override fun reconnect() {
        if (removed) throw TransportException.TagLost()
        state = State.ACTIVE
    }

    override fun close() {}
}
