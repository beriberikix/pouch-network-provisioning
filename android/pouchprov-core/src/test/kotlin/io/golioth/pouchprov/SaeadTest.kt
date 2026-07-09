// Copyright (c) 2026 Jonathan Beri
// SPDX-License-Identifier: Apache-2.0

package io.golioth.pouchprov

import io.golioth.pouchprov.pouch.Entry
import io.golioth.pouchprov.pouch.Pouch
import io.golioth.pouchprov.pouch.PouchHeader
import io.golioth.pouchprov.saead.Saead
import io.golioth.pouchprov.saead.SaeadSession
import io.golioth.pouchprov.saead.SessionInfo
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.spec.ECGenParameterSpec

/**
 * saead against the frozen cross-client vectors (tests/vectors/saead_kdf.json)
 * plus mirror-derivation round trips. The vectors pin this port to the Python
 * reference byte-for-byte (INFO string, HKDF, nonce layout, tag-chained AAD).
 */
class SaeadTest {

    private val vectors = GoldenVectorsTest.loadVectors("saead_kdf.json")
    private val blockLog = vectors.getInt("block_log")
    private val pouchId = vectors.getInt("pouch_id")

    private fun hex(s: String) = GoldenVectorsTest.hex(s)

    private fun case(name: String): JSONObject = vectors.getJSONObject("cases").getJSONObject(name)

    @Test fun fixedScalarsMatchPublicPoints() {
        val server = Saead.privateKeyFromScalar(hex(vectors.getString("server_private")))
        val device = Saead.privateKeyFromScalar(hex(vectors.getString("device_private")))
        // Sanity: an ECDH between the derived keys works both ways.
        val serverPub = Saead.publicKeyFromUncompressed(hex(vectors.getString("server_public_uncompressed")))
        val devicePub = Saead.publicKeyFromUncompressed(hex(vectors.getString("device_public_uncompressed")))
        val k1 = Saead.deriveSessionKey(server, devicePub, ByteArray(16), Pouch.ROLE_SERVER, Pouch.ALG_AES_GCM, 9)
        val k2 = Saead.deriveSessionKey(device, serverPub, ByteArray(16), Pouch.ROLE_SERVER, Pouch.ALG_AES_GCM, 9)
        assertArrayEquals(k1, k2)
    }

    @Test fun kdfAndSealChainMatchVectors() {
        val server = Saead.privateKeyFromScalar(hex(vectors.getString("server_private")))
        val device = Saead.privateKeyFromScalar(hex(vectors.getString("device_private")))
        val devicePub = Saead.publicKeyFromUncompressed(hex(vectors.getString("device_public_uncompressed")))
        val serverPub = Saead.publicKeyFromUncompressed(hex(vectors.getString("server_public_uncompressed")))

        for (name in listOf("chacha_downlink", "aes_downlink", "chacha_uplink", "aes_uplink")) {
            val c = case(name)
            val algorithm = c.getInt("algorithm")
            val initiator = c.getInt("initiator")
            val sessionId = hex(c.getString("session_id"))

            assertEquals(name, c.getString("info"), Saead.infoString(initiator, sessionId, algorithm, blockLog))

            val key = Saead.deriveSessionKey(server, devicePub, sessionId, initiator, algorithm, blockLog)
            assertArrayEquals(name, hex(c.getString("key")), key)
            // Mirror derivation (the device's view) must agree.
            val mirror = Saead.deriveSessionKey(device, serverPub, sessionId, initiator, algorithm, blockLog)
            assertArrayEquals(name, key, mirror)

            var prevTag = ByteArray(0)
            val blocks = c.getJSONArray("blocks")
            for (i in 0 until blocks.length()) {
                val b = blocks.getJSONObject(i)
                val nonce = Saead.nonce(pouchId, b.getInt("index"), initiator)
                assertArrayEquals(name, hex(b.getString("nonce")), nonce)
                val aad = if (b.getInt("index") > 0) prevTag else ByteArray(0)
                assertArrayEquals(name, hex(b.getString("aad")), aad)
                val sealed = Saead.seal(algorithm, key, nonce, hex(b.getString("plaintext")), aad)
                assertArrayEquals(name, hex(b.getString("sealed")), sealed)
                prevTag = sealed.copyOfRange(sealed.size - Saead.AUTH_TAG_LEN, sealed.size)
            }
        }
    }

    @Test fun downlinkPouchRoundTripsThroughDeviceMirror() {
        val (serverKp, deviceKp) = randomKeyPairs()
        val session = SaeadSession(serverKp.private, deviceKp.public, ByteArray(6) { 0xAA.toByte() })

        val entries = listOf(
            Entry(".prov/ver", Pouch.CONTENT_TYPE_CBOR, Messages.encodeVerReq()),
            Entry(".prov/ctrl", Pouch.CONTENT_TYPE_CBOR, Messages.encodeCtrl(CtrlOp.END)),
        )
        val sessionId = ByteArray(16) { it.toByte() }
        val pouchBytes = Saead.buildDownlinkPouch(session, sessionId, entries, blockSize = 24) // force 2 blocks

        // Device side: adopt the downlink header, mirror-derive, decrypt.
        val (header, consumed) = PouchHeader.decode(pouchBytes)
        assertEquals(Pouch.ENCRYPTION_SAEAD, header.encryption)
        val info = SessionInfo.fromCborObj(header.sessionInfo!!)
        assertEquals(Pouch.ROLE_SERVER, info.initiator)
        val key = Saead.deriveSessionKey(
            deviceKp.private, serverKp.public, info.sessionId, info.initiator, info.algorithm, info.maxBlockSizeLog,
        )

        val payloads = ArrayList<ByteArray>()
        var pos = consumed
        var index = 0
        var prevTag = ByteArray(0)
        while (pos < pouchBytes.size) {
            val size = ((pouchBytes[pos].toInt() and 0xFF) shl 8) or (pouchBytes[pos + 1].toInt() and 0xFF)
            pos += 2
            val sealed = pouchBytes.copyOfRange(pos, pos + size)
            pos += size
            val aad = if (index > 0) prevTag else ByteArray(0)
            val plaintext = Saead.open(info.algorithm, key, Saead.nonce(0, index, Pouch.ROLE_SERVER), sealed, aad)
            prevTag = sealed.copyOfRange(sealed.size - Saead.AUTH_TAG_LEN, sealed.size)
            index++
            payloads.add(plaintext.copyOfRange(1, plaintext.size))
        }
        assertEquals(2, index) // blockSize forced a 2-block chain
        assertEquals(entries, Pouch.parseEntryBlocks(payloads))
    }

    @Test fun uplinkPouchParsesAndTamperFails() {
        val (serverKp, deviceKp) = randomKeyPairs()
        val session = SaeadSession(serverKp.private, deviceKp.public, ByteArray(6))

        // Device side: build an uplink pouch (initiator = device).
        val sessionId = ByteArray(16) { (0x10 + it).toByte() }
        val algorithm = Pouch.ALG_AES_GCM
        val info = SessionInfo(sessionId, Pouch.ROLE_DEVICE, algorithm, 9, ByteArray(6))
        val key = Saead.deriveSessionKey(
            deviceKp.private, serverKp.public, sessionId, Pouch.ROLE_DEVICE, algorithm, 9,
        )
        val entries = listOf(Entry(".prov/ver", Pouch.CONTENT_TYPE_CBOR, byteArrayOf(0x42)))
        val blockPlaintext = byteArrayOf((Pouch.BLOCK_ID_ENTRY or Pouch.BLOCK_FIRST or Pouch.BLOCK_LAST).toByte()) +
            entries[0].encode()
        val sealed = Saead.seal(algorithm, key, Saead.nonce(0, 0, Pouch.ROLE_DEVICE), blockPlaintext, ByteArray(0))
        val out = ByteArrayOutputStream()
        out.write(PouchHeader(Pouch.ENCRYPTION_SAEAD, sessionInfo = info.toCborObj(), pouchId = 0).encode())
        out.write((sealed.size ushr 8) and 0xFF)
        out.write(sealed.size and 0xFF)
        out.write(sealed)
        val pouchBytes = out.toByteArray()

        assertEquals(entries, Saead.parseUplinkPouch(session, pouchBytes))

        // Tampering with the ciphertext must fail authentication.
        val tampered = pouchBytes.copyOf()
        tampered[tampered.size - 1] = (tampered.last().toInt() xor 0x01).toByte()
        assertThrows(Saead.SaeadException::class.java) {
            Saead.parseUplinkPouch(session, tampered)
        }
    }

    private fun randomKeyPairs(): Pair<java.security.KeyPair, java.security.KeyPair> {
        val gen = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"), SecureRandom())
        }
        return gen.generateKeyPair() to gen.generateKeyPair()
    }
}
