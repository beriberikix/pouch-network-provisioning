// Copyright (c) 2026 Jonathan Beri
// SPDX-License-Identifier: Apache-2.0

package io.golioth.pouchprov.saead

import io.golioth.pouchprov.pouch.Entry
import io.golioth.pouchprov.pouch.Pouch
import io.golioth.pouchprov.pouch.PouchHeader
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.modes.ChaCha20Poly1305
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.crypto.params.KeyParameter
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPrivateKeySpec
import java.security.spec.ECPublicKeySpec
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Pouch saead session crypto — the server (client-terminated) side. A faithful
 * port of the Python reference (`cli/src/pouchprov/pouchlink/saead.py`), pinned
 * to the shared vectors in `tests/vectors/saead_kdf.json`.
 *
 * A session key is derived as:
 *
 *     shared = ECDH(our_private_key, peer_public_key)          # P-256
 *     key    = HKDF-SHA256(ikm=shared, salt="", info=INFO)     # no salt
 *     INFO   = "E0:{D|S}:{b64(session_id)}:C{C|A}R:{block_log:02X}"
 *
 * where the D/S letter and session id are the session *initiator*'s. Each block
 * is AEAD-sealed (ChaCha20-Poly1305 or AES-GCM) with:
 *
 *     nonce = be16(pouch_id) | be16(block_index) | sender_role | 00*7
 *     aad   = previous block's 16-byte auth tag (empty for block 0)
 *
 * ChaCha20-Poly1305 uses Bouncy Castle's lightweight API (the JCA cipher needs
 * Android API 28+, and Android's preinstalled BC provider is crippled); AES-GCM
 * and ECDH use the platform JCA.
 */
object Saead {
    const val AUTH_TAG_LEN = 16
    const val SESSION_ID_LEN = 16
    const val CERT_REF_LEN = 6

    class SaeadException(message: String, cause: Throwable? = null) : Exception(message, cause)

    fun keySize(algorithm: Int): Int = if (algorithm == Pouch.ALG_CHACHA20_POLY1305) 32 else 16

    /** Derive the AEAD key for one session (matches the reference `derive_session_key`). */
    fun deriveSessionKey(
        ourPrivate: PrivateKey,
        peerPublic: PublicKey,
        sessionId: ByteArray,
        initiator: Int,
        algorithm: Int,
        maxBlockSizeLog: Int,
    ): ByteArray {
        val agreement = KeyAgreement.getInstance("ECDH")
        agreement.init(ourPrivate)
        agreement.doPhase(peerPublic, true)
        val shared = agreement.generateSecret()

        val info = infoString(initiator, sessionId, algorithm, maxBlockSizeLog)
        val hkdf = HKDFBytesGenerator(SHA256Digest())
        hkdf.init(HKDFParameters(shared, null, info.toByteArray(Charsets.US_ASCII)))
        val key = ByteArray(keySize(algorithm))
        hkdf.generateBytes(key, 0, key.size)
        return key
    }

    fun infoString(initiator: Int, sessionId: ByteArray, algorithm: Int, maxBlockSizeLog: Int): String {
        val d = if (initiator == Pouch.ROLE_DEVICE) "D" else "S"
        val alg = if (algorithm == Pouch.ALG_CHACHA20_POLY1305) "C" else "A"
        val sid = Base64.getEncoder().encodeToString(sessionId)
        return "E0:$d:$sid:C${alg}R:%02X".format(maxBlockSizeLog)
    }

    fun nonce(pouchId: Int, blockIndex: Int, senderRole: Int): ByteArray {
        val out = ByteArray(12)
        out[0] = ((pouchId ushr 8) and 0xFF).toByte()
        out[1] = (pouchId and 0xFF).toByte()
        out[2] = ((blockIndex ushr 8) and 0xFF).toByte()
        out[3] = (blockIndex and 0xFF).toByte()
        out[4] = (senderRole and 0xFF).toByte()
        return out
    }

    /** AEAD-seal [plaintext]; returns ciphertext || 16-byte tag. */
    fun seal(algorithm: Int, key: ByteArray, nonce: ByteArray, plaintext: ByteArray, aad: ByteArray): ByteArray =
        if (algorithm == Pouch.ALG_CHACHA20_POLY1305) {
            chacha(true, key, nonce, aad, plaintext)
        } else {
            aesGcm(Cipher.ENCRYPT_MODE, key, nonce, aad, plaintext)
        }

    /** Open a sealed block; throws [SaeadException] on tag mismatch. */
    fun open(algorithm: Int, key: ByteArray, nonce: ByteArray, ciphertext: ByteArray, aad: ByteArray): ByteArray =
        try {
            if (algorithm == Pouch.ALG_CHACHA20_POLY1305) {
                chacha(false, key, nonce, aad, ciphertext)
            } else {
                aesGcm(Cipher.DECRYPT_MODE, key, nonce, aad, ciphertext)
            }
        } catch (e: SaeadException) {
            throw e
        } catch (e: Exception) {
            throw SaeadException("saead open failed: ${e.message}", e)
        }

    private fun chacha(forEncryption: Boolean, key: ByteArray, nonce: ByteArray, aad: ByteArray, input: ByteArray): ByteArray {
        val cipher = ChaCha20Poly1305()
        cipher.init(forEncryption, AEADParameters(KeyParameter(key), AUTH_TAG_LEN * 8, nonce, aad))
        val out = ByteArray(cipher.getOutputSize(input.size))
        val n = cipher.processBytes(input, 0, input.size, out, 0)
        try {
            cipher.doFinal(out, n)
        } catch (e: Exception) {
            throw SaeadException("saead open failed: ${e.message}", e)
        }
        return out
    }

    private fun aesGcm(mode: Int, key: ByteArray, nonce: ByteArray, aad: ByteArray, input: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(mode, SecretKeySpec(key, "AES"), GCMParameterSpec(AUTH_TAG_LEN * 8, nonce))
        if (aad.isNotEmpty()) cipher.updateAAD(aad)
        return cipher.doFinal(input)
    }

    // ---- P-256 key helpers (TOFU cert exchange, fixed-scalar tests) --------

    private val p256: ECParameterSpec by lazy {
        AlgorithmParameters.getInstance("EC")
            .apply { init(ECGenParameterSpec("secp256r1")) }
            .getParameterSpec(ECParameterSpec::class.java)
    }

    fun privateKeyFromScalar(scalar: ByteArray): PrivateKey =
        KeyFactory.getInstance("EC")
            .generatePrivate(ECPrivateKeySpec(BigInteger(1, scalar), p256))

    fun publicKeyFromUncompressed(point: ByteArray): PublicKey {
        require(point.size == 65 && point[0].toInt() == 0x04) { "not an uncompressed P-256 point" }
        val x = BigInteger(1, point.copyOfRange(1, 33))
        val y = BigInteger(1, point.copyOfRange(33, 65))
        return KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(ECPoint(x, y), p256))
    }

    // ---- pouch-level helpers ------------------------------------------------

    /**
     * Encode an encrypted downlink pouch carrying [entries]. Entries are packed
     * into entry blocks whose plaintext (id byte + entries) is sealed per block.
     */
    fun buildDownlinkPouch(
        session: SaeadSession,
        sessionId: ByteArray,
        entries: List<Entry>,
        pouchId: Int = 0,
        blockSize: Int = Pouch.DEFAULT_BLOCK_SIZE,
    ): ByteArray {
        val info = session.newDownlink(sessionId)
        val header = PouchHeader(Pouch.ENCRYPTION_SAEAD, sessionInfo = info.toCborObj(), pouchId = pouchId.toLong())

        val plaintextBlocks = ArrayList<ByteArray>()
        var current = ByteArrayOutputStream()
        for (entry in entries) {
            val encoded = entry.encode()
            if (current.size() > 0 && current.size() + encoded.size > blockSize) {
                plaintextBlocks.add(current.toByteArray())
                current = ByteArrayOutputStream()
            }
            current.write(encoded)
        }
        plaintextBlocks.add(current.toByteArray())

        val out = ByteArrayOutputStream()
        out.write(header.encode())
        var prevTag = ByteArray(0)
        for ((i, payload) in plaintextBlocks.withIndex()) {
            var idByte = Pouch.BLOCK_ID_ENTRY
            if (i == 0) idByte = idByte or Pouch.BLOCK_FIRST
            if (i == plaintextBlocks.size - 1) idByte = idByte or Pouch.BLOCK_LAST
            val blockPlaintext = byteArrayOf(idByte.toByte()) + payload
            val (sealed, tag) = session.encryptDownlinkBlock(blockPlaintext, i, pouchId, prevTag)
            prevTag = tag
            out.write((sealed.size ushr 8) and 0xFF)
            out.write(sealed.size and 0xFF)
            out.write(sealed)
        }
        return out.toByteArray()
    }

    /** Decode an encrypted uplink pouch into its entries. */
    fun parseUplinkPouch(session: SaeadSession, data: ByteArray): List<Entry> {
        val (header, consumed) = PouchHeader.decode(data)
        if (header.encryption != Pouch.ENCRYPTION_SAEAD || header.sessionInfo == null) {
            throw Pouch.DecodeException("uplink pouch is not saead")
        }
        session.adoptUplink(SessionInfo.fromCborObj(header.sessionInfo))

        val payloads = ArrayList<ByteArray>()
        var pos = consumed
        var blockIndex = 0
        var prevTag = ByteArray(0)
        while (pos < data.size) {
            if (data.size - pos < 2) throw Pouch.DecodeException("truncated sealed block")
            val size = ((data[pos].toInt() and 0xFF) shl 8) or (data[pos + 1].toInt() and 0xFF)
            pos += 2
            if (data.size - pos < size) throw Pouch.DecodeException("truncated sealed block")
            val sealed = data.copyOfRange(pos, pos + size)
            pos += size
            val (plaintext, tag) = session.decryptUplinkBlock(sealed, blockIndex, header.pouchId.toInt(), prevTag)
            prevTag = tag
            blockIndex++
            if (plaintext.isNotEmpty() && (plaintext[0].toInt() and Pouch.BLOCK_ID_MASK) == Pouch.BLOCK_ID_ENTRY) {
                payloads.add(plaintext.copyOfRange(1, plaintext.size))
            }
        }
        return Pouch.parseEntryBlocks(payloads)
    }
}

/** saead session parameters carried in the pouch header. */
data class SessionInfo(
    val sessionId: ByteArray,
    val initiator: Int,
    val algorithm: Int,
    val maxBlockSizeLog: Int,
    val certRef: ByteArray,
    val sequentialSeq: Long? = null,
) {
    fun toCborObj(): List<Any?> {
        val sid: List<Any?> = if (sequentialSeq != null) listOf(sessionId, sequentialSeq) else listOf(sessionId)
        return listOf(sid, initiator.toLong(), algorithm.toLong(), maxBlockSizeLog.toLong(), certRef)
    }

    companion object {
        fun fromCborObj(obj: List<Any?>): SessionInfo {
            val sid = obj[0] as List<*>
            return SessionInfo(
                sessionId = sid[0] as ByteArray,
                initiator = (obj[1] as Long).toInt(),
                algorithm = (obj[2] as Long).toInt(),
                maxBlockSizeLog = (obj[3] as Long).toInt(),
                certRef = obj[4] as ByteArray,
                sequentialSeq = if (sid.size == 2) sid[1] as Long else null,
            )
        }
    }

    override fun equals(other: Any?): Boolean =
        other is SessionInfo && sessionId.contentEquals(other.sessionId) && initiator == other.initiator &&
            algorithm == other.algorithm && maxBlockSizeLog == other.maxBlockSizeLog &&
            certRef.contentEquals(other.certRef) && sequentialSeq == other.sequentialSeq

    override fun hashCode(): Int = sessionId.contentHashCode()
}

/**
 * Client-side (server-role) saead session over one BLE connection. The downlink
 * session is created by us (the server); the uplink session is adopted from the
 * device's uplink pouch header.
 */
class SaeadSession(
    private val serverPrivate: PrivateKey,
    private val devicePublic: PublicKey,
    serverCertRef: ByteArray,
    private val algorithm: Int = Pouch.ALG_CHACHA20_POLY1305,
    private val maxBlockSizeLog: Int = 9,
) {
    private val certRef = serverCertRef.copyOf(Saead.CERT_REF_LEN) // truncate + zero-pad

    private class State(val key: ByteArray, val algorithm: Int)

    private var down: State? = null
    private var up: State? = null

    /** Start a fresh server-initiated downlink session; returns the header SessionInfo. */
    fun newDownlink(sessionId: ByteArray): SessionInfo {
        require(sessionId.size == Saead.SESSION_ID_LEN) { "bad session id length" }
        val key = Saead.deriveSessionKey(
            serverPrivate, devicePublic, sessionId, Pouch.ROLE_SERVER, algorithm, maxBlockSizeLog,
        )
        down = State(key, algorithm)
        return SessionInfo(sessionId, Pouch.ROLE_SERVER, algorithm, maxBlockSizeLog, certRef)
    }

    /** Seal one downlink block; returns (ciphertext_with_tag, this_tag). */
    fun encryptDownlinkBlock(plaintext: ByteArray, blockIndex: Int, pouchId: Int, prevTag: ByteArray): Pair<ByteArray, ByteArray> {
        val state = down ?: throw IllegalStateException("no downlink session")
        val nonce = Saead.nonce(pouchId, blockIndex, Pouch.ROLE_SERVER)
        val aad = if (blockIndex > 0) prevTag else ByteArray(0)
        val sealed = Saead.seal(state.algorithm, state.key, nonce, plaintext, aad)
        return sealed to sealed.copyOfRange(sealed.size - Saead.AUTH_TAG_LEN, sealed.size)
    }

    /** Derive the uplink key from the device's uplink pouch header. */
    fun adoptUplink(info: SessionInfo) {
        if (info.initiator != Pouch.ROLE_DEVICE) throw Saead.SaeadException("uplink header initiator is not the device")
        val key = Saead.deriveSessionKey(
            serverPrivate, devicePublic, info.sessionId, Pouch.ROLE_DEVICE, info.algorithm, info.maxBlockSizeLog,
        )
        up = State(key, info.algorithm)
    }

    /** Open one uplink block; returns (plaintext, this_tag). */
    fun decryptUplinkBlock(ciphertext: ByteArray, blockIndex: Int, pouchId: Int, prevTag: ByteArray): Pair<ByteArray, ByteArray> {
        val state = up ?: throw IllegalStateException("no uplink session")
        val nonce = Saead.nonce(pouchId, blockIndex, Pouch.ROLE_DEVICE)
        val aad = if (blockIndex > 0) prevTag else ByteArray(0)
        val plaintext = Saead.open(state.algorithm, state.key, nonce, ciphertext, aad)
        return plaintext to ciphertext.copyOfRange(ciphertext.size - Saead.AUTH_TAG_LEN, ciphertext.size)
    }
}
