package com.nfcshenanigans.ntag215.core

/**
 * Obviously fake tag credentials for unit tests. They are built from bytes rather than string
 * literals so that secret scanners don't mistake test fixtures for leaked credentials.
 */
object TestCredentials {
    /** 4-byte tag password where every byte is [n] (e.g. 0x01010101). */
    fun pwd(n: Int): Password = Password.of(ByteArray(4) { n.toByte() })

    /** 2-byte PACK where every byte is [n]. */
    fun pack(n: Int): Pack = Pack.of(ByteArray(2) { n.toByte() })

    /** 32-character secret made of a single repeated [fill] character. */
    fun secret(fill: Char): Secret = Secret.parse(fill.toString().repeat(Secret.LENGTH))!!
}
