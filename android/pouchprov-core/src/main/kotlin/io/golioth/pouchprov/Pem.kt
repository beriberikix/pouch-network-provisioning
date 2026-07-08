// Copyright (c) 2026 Jonathan Beri
// SPDX-License-Identifier: Apache-2.0

package io.golioth.pouchprov

import java.util.Base64

/**
 * Certificate/key input helpers. The provisioning protocol carries credentials
 * as DER; callers may hold PEM. [toDer] normalizes either form to DER, matching
 * the CLI's acceptance of "PEM or DER".
 */
object Pem {
    private val PEM_LINE = Regex("-----(BEGIN|END)[^-]*-----")

    /** Return DER bytes for [input], which may be PEM (base64 with headers) or already DER. */
    fun toDer(input: ByteArray): ByteArray {
        if (!looksLikePem(input)) return input
        val text = String(input, Charsets.US_ASCII)
        val base64 = PEM_LINE.replace(text, "").replace(Regex("\\s"), "")
        return Base64.getDecoder().decode(base64)
    }

    /** A DER SEQUENCE starts with 0x30; PEM starts with the ASCII "-----". */
    private fun looksLikePem(input: ByteArray): Boolean {
        if (input.isEmpty() || input[0] == 0x30.toByte()) return false
        val prefix = String(input.copyOf(minOf(input.size, 11)), Charsets.US_ASCII)
        return prefix.startsWith("-----BEGIN")
    }
}
