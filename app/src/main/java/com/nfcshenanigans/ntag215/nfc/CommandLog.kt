package com.nfcshenanigans.ntag215.nfc

import java.util.concurrent.CopyOnWriteArrayList

/**
 * In-memory diagnostic log of NFC commands. Entries contain the command name, page address,
 * response length and outcome only. Payload bytes, passwords and secrets are never recorded.
 * Nothing is written to logcat.
 */
class CommandLog(private val capacity: Int = 400) {
    data class Entry(val timestampMs: Long, val command: String, val outcome: String, val durationMs: Long)

    private val entries = CopyOnWriteArrayList<Entry>()

    fun add(command: String, outcome: String, durationMs: Long) {
        entries += Entry(System.currentTimeMillis(), command, outcome, durationMs)
        while (entries.size > capacity) entries.removeAt(0)
    }

    fun note(message: String) = add("·", message, 0)

    fun snapshot(): List<Entry> = entries.toList()

    fun clear() = entries.clear()
}
