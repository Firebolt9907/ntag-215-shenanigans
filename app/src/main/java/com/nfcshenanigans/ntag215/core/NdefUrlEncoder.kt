package com.nfcshenanigans.ntag215.core

import java.net.URI
import java.net.URISyntaxException

/** NFC Forum URI Record Type Definition prefix table (identifier codes 0x00..0x23). */
object UriPrefixes {
    val TABLE: List<String> = listOf(
        "", "http://www.", "https://www.", "http://", "https://", "tel:", "mailto:",
        "ftp://anonymous:anonymous@", "ftp://ftp.", "ftps://", "sftp://", "smb://", "nfs://", "ftp://",
        "dav://", "news:", "telnet://", "imap:", "rtsp://", "urn:", "pop:", "sip:", "sips:", "tftp:",
        "btspp://", "btl2cap://", "btgoep://", "tcpobex://", "irdaobex://", "file://", "urn:epc:id:",
        "urn:epc:tag:", "urn:epc:pat:", "urn:epc:raw:", "urn:epc:", "urn:nfc:",
    )

    /** Longest matching prefix (case-sensitive, as prefix expansion is literal). */
    fun bestMatch(uri: String): Pair<Int, String> {
        var best = 0
        for (i in 1 until TABLE.size) {
            if (uri.startsWith(TABLE[i]) && TABLE[i].length > TABLE[best].length) best = i
        }
        return best to TABLE[best]
    }

    fun expand(code: Int): String? = TABLE.getOrNull(code)
}

sealed interface UrlValidation {
    data class Valid(val url: String) : UrlValidation
    data class Invalid(val reason: String) : UrlValidation
}

/** Result of encoding a URL as an NDEF URI record inside an NDEF TLV for a Type 2 Tag. */
class EncodedUrl(
    val url: String,
    val prefixCode: Int,
    val prefix: String,
    val payload: ByteArray,
    val ndefMessage: ByteArray,
    /** NDEF TLV (T, L, V) followed by the Terminator TLV (0xFE). */
    val tlvBytes: ByteArray,
) {
    val payloadSize get() = payload.size
    val messageSize get() = ndefMessage.size
    val tlvSize get() = tlvBytes.size
    val pagesUsed get() = Ntag215Memory.pagesFor(tlvSize)
    val lastPage get() = Ntag215Memory.PUBLIC_FIRST_PAGE + pagesUsed - 1
    val fitsPublicRegion get() = tlvSize <= Ntag215Memory.PUBLIC_CAPACITY_BYTES
    val bytesRemaining get() = Ntag215Memory.PUBLIC_CAPACITY_BYTES - tlvSize

    /** TLV area padded with zeros to exactly the public region (pages 0x04..0x1F). */
    fun publicRegionImage(): ByteArray {
        check(fitsPublicRegion) { "URL does not fit the public region" }
        return tlvBytes.copyOf(Ntag215Memory.PUBLIC_CAPACITY_BYTES)
    }
}

object NdefUrlEncoder {
    const val TNF_WELL_KNOWN = 0x01
    const val TNF_ABSOLUTE_URI = 0x03
    const val NDEF_TLV = 0x03
    const val TERMINATOR_TLV = 0xFE
    const val NULL_TLV = 0x00
    private const val FLAG_MB = 0x80
    private const val FLAG_ME = 0x40
    private const val FLAG_SR = 0x10
    private const val RTD_URI = 'U'.code

    /** Largest NDEF message that fits pages 0x04..0x1F with 2-byte TLV header and terminator. */
    const val MAX_PUBLIC_MESSAGE_BYTES = Ntag215Memory.PUBLIC_CAPACITY_BYTES - 3 // 109

    fun validate(input: String): UrlValidation {
        if (input.isEmpty()) return UrlValidation.Invalid("Enter a URL")
        if (input.any { it.isWhitespace() }) return UrlValidation.Invalid("URL must not contain spaces or whitespace")
        if (input.any { it.isISOControl() }) return UrlValidation.Invalid("URL contains control characters")
        val uri = try {
            URI(input)
        } catch (e: URISyntaxException) {
            return UrlValidation.Invalid("Invalid URL syntax: ${e.reason}")
        }
        val scheme = uri.scheme?.lowercase()
        if (scheme != "http" && scheme != "https") return UrlValidation.Invalid("URL must start with http:// or https://")
        if (!input.substring(scheme.length).startsWith("://")) return UrlValidation.Invalid("URL must start with $scheme://")
        if (uri.host.isNullOrEmpty()) return UrlValidation.Invalid("URL must contain a valid host name")
        if (uri.port > 65535) return UrlValidation.Invalid("Invalid port")
        return UrlValidation.Valid(input)
    }

    /** Encodes [url] (assumed validated) as a single NDEF URI record with prefix compression. */
    fun encode(url: String): EncodedUrl {
        val (code, prefix) = UriPrefixes.bestMatch(url)
        val remainder = url.substring(prefix.length).toByteArray(Charsets.UTF_8)
        val payload = ByteArray(1 + remainder.size).also {
            it[0] = code.toByte()
            remainder.copyInto(it, 1)
        }
        val message = buildRecord(TNF_WELL_KNOWN, byteArrayOf(RTD_URI.toByte()), payload)
        return EncodedUrl(url, code, prefix, payload, message, wrapTlv(message))
    }

    /** Single record message (MB=ME=1), short record when payload <= 255 bytes. */
    fun buildRecord(tnf: Int, type: ByteArray, payload: ByteArray): ByteArray {
        val short = payload.size <= 255
        val header = FLAG_MB or FLAG_ME or (if (short) FLAG_SR else 0) or tnf
        val out = ArrayList<Byte>()
        out += header.toByte()
        out += type.size.toByte()
        if (short) {
            out += payload.size.toByte()
        } else {
            out += (payload.size ushr 24).toByte(); out += (payload.size ushr 16).toByte()
            out += (payload.size ushr 8).toByte(); out += payload.size.toByte()
        }
        type.forEach { out += it }
        payload.forEach { out += it }
        return out.toByteArray()
    }

    /** NDEF TLV with 1-byte length (< 0xFF) or 3-byte length format, followed by a Terminator TLV. */
    fun wrapTlv(message: ByteArray): ByteArray {
        val header = if (message.size < 0xFF) {
            byteArrayOf(NDEF_TLV.toByte(), message.size.toByte())
        } else {
            byteArrayOf(NDEF_TLV.toByte(), 0xFF.toByte(), (message.size shr 8).toByte(), message.size.toByte())
        }
        return header + message + byteArrayOf(TERMINATOR_TLV.toByte())
    }

    fun tlvSizeFor(url: String): Int = encode(url).tlvSize
}

/** A parsed NDEF record. */
class NdefRecordInfo(
    val tnf: Int,
    val type: ByteArray,
    val id: ByteArray,
    val payload: ByteArray,
) {
    val typeString: String get() = String(type, Charsets.US_ASCII)
    val isUri get() = tnf == NdefUrlEncoder.TNF_WELL_KNOWN && typeString == "U"

    /** Decoded URI for well-known 'U' records or absolute-URI records, else null. */
    val uri: String?
        get() = when {
            isUri && payload.isNotEmpty() -> UriPrefixes.expand(payload[0].u())?.let {
                it + String(payload, 1, payload.size - 1, Charsets.UTF_8)
            }
            tnf == NdefUrlEncoder.TNF_ABSOLUTE_URI -> typeString
            else -> null
        }

    val tnfName: String
        get() = when (tnf) {
            0 -> "Empty"; 1 -> "Well-known"; 2 -> "Media type"; 3 -> "Absolute URI"
            4 -> "External"; 5 -> "Unknown"; 6 -> "Unchanged"; else -> "Reserved"
        }

    fun describe(): String = "TNF $tnfName, type \"$typeString\", ${payload.size}-byte payload"
}

class TlvInfo(val type: Int, val offset: Int, val length: Int) {
    val name: String
        get() = when (type) {
            0x00 -> "NULL"; 0x01 -> "Lock Control"; 0x02 -> "Memory Control"; 0x03 -> "NDEF"
            0xFD -> "Proprietary"; 0xFE -> "Terminator"; else -> "Unknown 0x${Hex.byte(type)}"
        }
}

class TlvParseResult(
    val tlvs: List<TlvInfo>,
    /** Offset of the NDEF TLV's value within the parsed area, or -1. */
    val ndefValueOffset: Int,
    val ndefLength: Int,
    val ndefMessage: ByteArray?,
    /** NDEF TLV declares more bytes than were available (e.g. extends into protected memory). */
    val truncated: Boolean,
    val error: String?,
) {
    val hasNdefTlv get() = ndefValueOffset >= 0
    val isEmptyNdef get() = hasNdefTlv && ndefLength == 0
    /** Byte offset just past the NDEF TLV value, relative to the parsed area. */
    val ndefEndOffset get() = if (hasNdefTlv) ndefValueOffset + ndefLength else -1
}

sealed interface NdefMessageParse {
    data class Ok(val records: List<NdefRecordInfo>) : NdefMessageParse
    data class Error(val reason: String) : NdefMessageParse
}

object NdefParser {
    /** Parses the T2T TLV area. [area] must start at page 0x04 (first data byte). */
    fun parseTlvArea(area: ByteArray): TlvParseResult {
        val tlvs = mutableListOf<TlvInfo>()
        var i = 0
        while (i < area.size) {
            val t = area[i].u()
            when (t) {
                NdefUrlEncoder.NULL_TLV -> { tlvs += TlvInfo(t, i, 0); i++; continue }
                NdefUrlEncoder.TERMINATOR_TLV -> { tlvs += TlvInfo(t, i, 0); return TlvParseResult(tlvs, -1, 0, null, false, "No NDEF TLV before Terminator TLV") }
            }
            if (i + 1 >= area.size) return TlvParseResult(tlvs, -1, 0, null, true, "TLV length byte missing")
            var len = area[i + 1].u()
            var valueStart = i + 2
            if (len == 0xFF) {
                if (i + 3 >= area.size) return TlvParseResult(tlvs, -1, 0, null, true, "3-byte TLV length truncated")
                len = (area[i + 2].u() shl 8) or area[i + 3].u()
                valueStart = i + 4
            }
            tlvs += TlvInfo(t, i, len)
            if (t == NdefUrlEncoder.NDEF_TLV) {
                val end = valueStart + len
                return if (end > area.size) {
                    TlvParseResult(tlvs, valueStart, len, null, true, "NDEF TLV declares $len bytes but only ${area.size - valueStart} are readable")
                } else {
                    TlvParseResult(tlvs, valueStart, len, area.copyOfRange(valueStart, end), false, null)
                }
            }
            i = valueStart + len
        }
        return TlvParseResult(tlvs, -1, 0, null, false, "No NDEF TLV found")
    }

    fun parseMessage(message: ByteArray): NdefMessageParse {
        if (message.isEmpty()) return NdefMessageParse.Ok(emptyList())
        val records = mutableListOf<NdefRecordInfo>()
        var i = 0
        var first = true
        while (i < message.size) {
            val header = message[i].u()
            val mb = header and 0x80 != 0
            val me = header and 0x40 != 0
            val cf = header and 0x20 != 0
            val sr = header and 0x10 != 0
            val il = header and 0x08 != 0
            val tnf = header and 0x07
            if (first && !mb) return NdefMessageParse.Error("First record lacks MB flag")
            if (cf) return NdefMessageParse.Error("Chunked records are not supported")
            i++
            fun need(n: Int) = i + n <= message.size
            if (!need(1)) return NdefMessageParse.Error("Truncated record header")
            val typeLen = message[i++].u()
            val payloadLen: Long = if (sr) {
                if (!need(1)) return NdefMessageParse.Error("Truncated payload length")
                message[i++].u().toLong()
            } else {
                if (!need(4)) return NdefMessageParse.Error("Truncated payload length")
                var v = 0L
                repeat(4) { v = (v shl 8) or message[i++].u().toLong() }
                v
            }
            val idLen = if (il) {
                if (!need(1)) return NdefMessageParse.Error("Truncated ID length")
                message[i++].u()
            } else 0
            val total = typeLen.toLong() + idLen + payloadLen
            if (i + total > message.size) return NdefMessageParse.Error("Record extends beyond NDEF message")
            val type = message.copyOfRange(i, i + typeLen); i += typeLen
            val id = message.copyOfRange(i, i + idLen); i += idLen
            val payload = message.copyOfRange(i, i + payloadLen.toInt()); i += payloadLen.toInt()
            records += NdefRecordInfo(tnf, type, id, payload)
            first = false
            if (me) {
                return if (i == message.size) NdefMessageParse.Ok(records)
                else NdefMessageParse.Error("Data after last record (ME) flag")
            }
        }
        return NdefMessageParse.Error("Last record lacks ME flag")
    }
}
