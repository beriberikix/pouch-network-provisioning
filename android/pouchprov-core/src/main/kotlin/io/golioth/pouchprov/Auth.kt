// Copyright (c) 2026 Jonathan Beri
// SPDX-License-Identifier: Apache-2.0

package io.golioth.pouchprov

import io.golioth.pouchprov.session.ProvSession
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Proof-of-possession mutual authorization (.prov/auth).
 *
 * Both proofs are HMAC-SHA256 keyed with the UTF-8 PoP secret:
 *
 *   dev_proof = HMAC(pop, "dev" + cli_nonce + dev_nonce)
 *   cli_proof = HMAC(pop, "cli" + dev_nonce + cli_nonce)
 *
 * The client verifies the device's proof before sending its own, so a device
 * that doesn't know the PoP learns nothing and receives no credentials.
 * Mirrors the Python `auth`.
 */
object Auth {
    private val random = SecureRandom()

    class AuthException(message: String) : Exception(message)

    fun deviceProof(pop: String, cliNonce: ByteArray, devNonce: ByteArray): ByteArray =
        proof(pop, "dev".toByteArray(), cliNonce, devNonce)

    fun clientProof(pop: String, devNonce: ByteArray, cliNonce: ByteArray): ByteArray =
        proof(pop, "cli".toByteArray(), devNonce, cliNonce)

    private fun proof(pop: String, tag: ByteArray, first: ByteArray, second: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(pop.toByteArray(Charsets.UTF_8), "HmacSHA256"))
        mac.update(tag)
        mac.update(first)
        mac.update(second)
        return mac.doFinal()
    }

    /** Run the mutual PoP handshake. Throws [AuthException] on mismatch. */
    suspend fun authorize(session: ProvSession, pop: String, timeoutMs: Long = 15_000) {
        val cliNonce = ByteArray(16).also { random.nextBytes(it) }
        val (devNonce, devProof) = Messages.decodeAuthChallengeRsp(
            session.request(Messages.PATH_AUTH, Messages.encodeAuthChallenge(cliNonce), timeoutMs),
        )
        val expected = deviceProof(pop, cliNonce, devNonce)
        if (!constantTimeEquals(devProof, expected)) {
            throw AuthException("device proof mismatch — wrong PoP or impostor device")
        }
        val cliProof = clientProof(pop, devNonce, cliNonce)
        Messages.decodeAuthProofRsp(
            session.request(Messages.PATH_AUTH, Messages.encodeAuthProof(cliProof), timeoutMs),
        )
    }

    /** Constant-time comparison to avoid leaking the proof via timing. */
    private fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        var diff = 0
        for (i in a.indices) diff = diff or (a[i].toInt() xor b[i].toInt())
        return diff == 0
    }
}
