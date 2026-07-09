// Copyright (c) 2026 Jonathan Beri
// SPDX-License-Identifier: Apache-2.0

package io.golioth.pouchprov

import io.golioth.pouchprov.cbor.Cbor
import io.golioth.pouchprov.pouch.Block
import io.golioth.pouchprov.pouch.Entry
import io.golioth.pouchprov.pouch.Pouch
import io.golioth.pouchprov.pouch.PouchHeader
import io.golioth.pouchprov.saead.Saead
import io.golioth.pouchprov.saead.SessionInfo
import io.golioth.pouchprov.saead.Tofu
import io.golioth.pouchprov.sar.CODE_ACK
import io.golioth.pouchprov.sar.FLAG_FIN
import io.golioth.pouchprov.sar.FLAG_FIRST
import io.golioth.pouchprov.sar.FLAG_LAST
import io.golioth.pouchprov.sar.HEADER_LEN
import io.golioth.pouchprov.transport.Channel
import io.golioth.pouchprov.transport.Transport
import java.io.ByteArrayOutputStream
import java.security.PublicKey

/** Request handler: (path, payload) -> response payload, or null to not respond. */
typealias Handler = (String, ByteArray) -> ByteArray?

/**
 * In-memory mock of a provisioning device (plaintext path) for tests.
 *
 * Implements the device side of the SAR + pouch RPC contract faithfully enough
 * to exercise the full client stack: initial-ack-on-subscribe, in-order acking,
 * LAST/FIN handshake ([0x04, 0x00] success FIN), and the one-transaction-per-
 * subscribe rule. A port of the Python `transport.mock` (plaintext only).
 */
class MockDeviceTransport(
    private val handler: Handler,
    private val deviceId: String = "mock-dev",
    private val window: Int = 3,
    private var defer: Int = 0,
    private val saeadIdentity: Tofu.ServerIdentity? = null,
    private val saeadAlgorithm: Int = Pouch.ALG_CHACHA20_POLY1305,
) : Transport {

    override val downlink = MockChannel()
    override val uplink = MockChannel()

    // saead builds: TOFU endpoints + device-side crypto state.
    override var info: Channel? = null
    override var serverCert: Channel? = null
    override var deviceCert: Channel? = null
    var storedServerCert: ByteArray? = null
        private set
    private var serverPublic: PublicKey? = null
    private val uplinkSid = ByteArray(16) { it.toByte() }

    private val responses = ArrayList<Entry>()

    // downlink (device is SAR receiver) state
    private var rxChunks = ArrayList<ByteArray>()
    private var rxExpected = 0
    private var rxEnded = false

    // uplink (device is SAR sender) state
    private var ulFrags: List<ByteArray> = emptyList()
    private var ulSeq = 0
    private var ulFinished = false

    init {
        downlink.onSubscribe = { dlOpen() }
        downlink.onWrite = { dlWrite(it) }
        uplink.onSubscribe = { ulOpen() }
        uplink.onWrite = { ulWrite(it) }
        if (saeadIdentity != null) {
            val infoCh = MockChannel()
            val serverCh = MockChannel()
            val deviceCh = MockChannel()
            DeviceSarSender(infoCh) { infoPayload() }
            DeviceSarSender(deviceCh) { saeadIdentity.certDer }
            DeviceSarReceiver(serverCh, onData = { storeServerCert(it) })
            info = infoCh
            serverCert = serverCh
            deviceCert = deviceCh
        }
    }

    override suspend fun connect() {}
    override suspend fun disconnect() {}

    // -- TOFU endpoints (saead builds) ----------------------------------------

    private fun infoPayload(): ByteArray {
        // BigInteger.toByteArray() keeps the sign byte, like mbedtls' DER serial.
        val serial = storedServerCert?.let { Tofu.certSerial(it) } ?: ByteArray(0)
        return Cbor.encode(linkedMapOf<String, Any?>("flags" to 0L, "server_cert_snr" to serial))
    }

    private fun storeServerCert(der: ByteArray) {
        storedServerCert = der
        serverPublic = Tofu.devicePublicKey(der)
    }

    private fun saeadActive(): Boolean = saeadIdentity != null && serverPublic != null

    // -- downlink: device is the SAR receiver --------------------------------

    private fun dlAck(seq: Int) = downlink.notify(byteArrayOf(CODE_ACK.toByte(), seq.toByte(), window.toByte()))

    private fun dlOpen() {
        rxChunks = ArrayList()
        rxExpected = 0
        rxEnded = false
        dlAck(0xFF)
    }

    private fun dlWrite(pkt: ByteArray) {
        val flags = pkt[0].toInt() and 0xFF
        if (flags and FLAG_FIN != 0) {
            check(rxEnded) { "FIN before LAST" }
            if ((pkt[1].toInt() and 0xFF) == CODE_ACK) processRequest(concat(rxChunks))
            return
        }
        val seq = pkt[1].toInt() and 0xFF
        check(seq == rxExpected) { "mock expects in-order (got $seq)" }
        rxChunks.add(pkt.copyOfRange(HEADER_LEN, pkt.size))
        rxExpected = (seq + 1) and 0xFF
        if (flags and FLAG_LAST != 0) rxEnded = true
        dlAck(seq)
    }

    private fun processRequest(data: ByteArray) {
        val entries = if (saeadActive()) decryptDownlink(data) else Pouch.parsePouch(data).second
        for (entry in entries) {
            handler(entry.path, entry.data)?.let { responses.add(Entry(entry.path, entry.contentType, it)) }
        }
    }

    // -- device-side saead (mirrors the Python mock's DeviceSaead) ------------

    private fun decryptDownlink(data: ByteArray): List<Entry> {
        val (header, consumed) = PouchHeader.decode(data)
        val info = SessionInfo.fromCborObj(header.sessionInfo!!)
        val key = Saead.deriveSessionKey(
            checkNotNull(saeadIdentity).privateKey, checkNotNull(serverPublic),
            info.sessionId, Pouch.ROLE_SERVER, info.algorithm, info.maxBlockSizeLog,
        )
        val payloads = ArrayList<ByteArray>()
        var pos = consumed
        var idx = 0
        var prevTag = ByteArray(0)
        while (pos < data.size) {
            val size = ((data[pos].toInt() and 0xFF) shl 8) or (data[pos + 1].toInt() and 0xFF)
            pos += 2
            val sealed = data.copyOfRange(pos, pos + size)
            pos += size
            val nonce = Saead.nonce(header.pouchId.toInt(), idx, Pouch.ROLE_SERVER)
            val aad = if (idx > 0) prevTag else ByteArray(0)
            val plain = Saead.open(info.algorithm, key, nonce, sealed, aad)
            prevTag = sealed.copyOfRange(sealed.size - Saead.AUTH_TAG_LEN, sealed.size)
            payloads.add(plain.copyOfRange(1, plain.size))
            idx += 1
        }
        return Pouch.parseEntryBlocks(payloads)
    }

    private fun encryptUplink(entries: List<Entry>, pouchId: Int = 1): ByteArray {
        val key = Saead.deriveSessionKey(
            checkNotNull(saeadIdentity).privateKey, checkNotNull(serverPublic),
            uplinkSid, Pouch.ROLE_DEVICE, saeadAlgorithm, 9,
        )
        val info = SessionInfo(uplinkSid, Pouch.ROLE_DEVICE, saeadAlgorithm, 9, ByteArray(6))
        val header = PouchHeader(Pouch.ENCRYPTION_SAEAD, sessionInfo = info.toCborObj(), pouchId = pouchId.toLong())
        val payload = ByteArrayOutputStream().apply { entries.forEach { write(it.encode()) } }.toByteArray()
        val idByte = Pouch.BLOCK_ID_ENTRY or Pouch.BLOCK_FIRST or Pouch.BLOCK_LAST
        val blockPlain = byteArrayOf(idByte.toByte()) + payload
        val nonce = Saead.nonce(pouchId, 0, Pouch.ROLE_DEVICE)
        val sealed = Saead.seal(saeadAlgorithm, key, nonce, blockPlain, ByteArray(0))
        val out = ByteArrayOutputStream()
        out.write(header.encode())
        out.write((sealed.size ushr 8) and 0xFF)
        out.write(sealed.size and 0xFF)
        out.write(sealed)
        return out.toByteArray()
    }


    // -- uplink: device is the SAR sender ------------------------------------

    private fun ulOpen() {
        val entries: List<Entry> = if (defer > 0) {
            defer -= 1
            emptyList()
        } else {
            val r = ArrayList(responses)
            responses.clear()
            r
        }
        val data = if (saeadActive()) {
            if (entries.isNotEmpty()) {
                encryptUplink(entries)
            } else {
                // header-only saead pouch = the "responses not ready" empty pouch
                val info = SessionInfo(uplinkSid, Pouch.ROLE_DEVICE, saeadAlgorithm, 9, ByteArray(6))
                PouchHeader(Pouch.ENCRYPTION_SAEAD, sessionInfo = info.toCborObj(), pouchId = 1).encode()
            }
        } else if (entries.isNotEmpty()) {
            Pouch.buildEntryPouch(deviceId, entries)
        } else {
            // header + one empty block = the "responses not ready" empty pouch
            val out = java.io.ByteArrayOutputStream()
            out.write(PouchHeader.plaintext(deviceId).encode())
            out.write(Block(ByteArray(0)).encode())
            out.toByteArray()
        }
        val frag = 244 - HEADER_LEN
        ulFrags = (data.indices step frag).map { data.copyOfRange(it, minOf(it + frag, data.size)) }
            .ifEmpty { listOf(ByteArray(0)) }
        ulSeq = 0
        ulFinished = false
    }

    private fun ulWrite(ack: ByteArray) {
        val ackSeq = ack[1].toInt() and 0xFF
        val window = ack[2].toInt() and 0xFF
        check((ack[0].toInt() and 0xFF) == CODE_ACK)
        if (ulFinished) return
        if (ulSeq >= ulFrags.size) {
            if (ackSeq == (ulSeq - 1) and 0xFF) {
                ulFinished = true
                uplink.notify(byteArrayOf(FLAG_FIN.toByte(), CODE_ACK.toByte()))
            }
            return
        }
        val target = (ackSeq + window + 1) and 0xFF
        while (ulSeq != target && ulSeq < ulFrags.size) {
            var flags = 0
            if (ulSeq == 0) flags = flags or FLAG_FIRST
            if (ulSeq == ulFrags.size - 1) flags = flags or FLAG_LAST
            uplink.notify(byteArrayOf(flags.toByte(), ulSeq.toByte()) + ulFrags[ulSeq])
            ulSeq += 1
        }
    }

    private fun concat(chunks: List<ByteArray>): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        for (c in chunks) out.write(c)
        return out.toByteArray()
    }
}

/** A mock channel that invokes device hooks synchronously, as the Python mock does. */
class MockChannel : Channel {
    private var notify: ((ByteArray) -> Unit)? = null
    var onWrite: ((ByteArray) -> Unit)? = null
    var onSubscribe: (() -> Unit)? = null
    var onUnsubscribe: (() -> Unit)? = null

    override suspend fun write(data: ByteArray) {
        onWrite!!.invoke(data.copyOf())
    }

    override suspend fun subscribe(onNotify: (ByteArray) -> Unit) {
        notify = onNotify
        onSubscribe?.invoke()
    }

    override suspend fun unsubscribe() {
        notify = null
        onUnsubscribe?.invoke()
    }

    fun notify(data: ByteArray) {
        notify?.invoke(data.copyOf())
    }
}

/** Device-side SAR sender behind a mock channel (info / device_cert). */
class DeviceSarSender(
    private val channel: MockChannel,
    private val payloadFn: () -> ByteArray,
) {
    private val frag = 244 - HEADER_LEN
    private var frags: List<ByteArray> = emptyList()
    private var seq = 0
    private var finished = false

    init {
        channel.onSubscribe = { open() }
        channel.onWrite = { onAck(it) }
    }

    private fun open() {
        val data = payloadFn()
        frags = (data.indices step frag).map { data.copyOfRange(it, minOf(it + frag, data.size)) }
            .ifEmpty { listOf(ByteArray(0)) }
        seq = 0
        finished = false
    }

    private fun onAck(ack: ByteArray) {
        val ackSeq = ack[1].toInt() and 0xFF
        val window = ack[2].toInt() and 0xFF
        check((ack[0].toInt() and 0xFF) == CODE_ACK)
        if (finished) return
        if (seq >= frags.size) {
            if (ackSeq == (seq - 1) and 0xFF) {
                finished = true
                channel.notify(byteArrayOf(FLAG_FIN.toByte(), CODE_ACK.toByte()))
            }
            return
        }
        val target = (ackSeq + window + 1) and 0xFF
        while (seq != target && seq < frags.size) {
            var flags = 0
            if (seq == 0) flags = flags or FLAG_FIRST
            if (seq == frags.size - 1) flags = flags or FLAG_LAST
            channel.notify(byteArrayOf(flags.toByte(), seq.toByte()) + frags[seq])
            seq += 1
        }
    }
}

/** Device-side SAR receiver behind a mock channel (server_cert). */
class DeviceSarReceiver(
    private val channel: MockChannel,
    private val onData: (ByteArray) -> Unit,
    private val window: Int = 3,
) {
    private var chunks = ArrayList<ByteArray>()
    private var expected = 0
    private var ended = false

    init {
        channel.onSubscribe = { open() }
        channel.onWrite = { onWrite(it) }
    }

    private fun ack(seq: Int) = channel.notify(byteArrayOf(CODE_ACK.toByte(), seq.toByte(), window.toByte()))

    private fun open() {
        chunks = ArrayList()
        expected = 0
        ended = false
        ack(0xFF)
    }

    private fun onWrite(pkt: ByteArray) {
        val flags = pkt[0].toInt() and 0xFF
        if (flags and FLAG_FIN != 0) {
            check(ended) { "FIN before LAST" }
            if ((pkt[1].toInt() and 0xFF) == CODE_ACK) {
                val out = java.io.ByteArrayOutputStream()
                for (c in chunks) out.write(c)
                onData(out.toByteArray())
            }
            return
        }
        val seq = pkt[1].toInt() and 0xFF
        check(seq == expected) { "mock expects in-order (got $seq)" }
        chunks.add(pkt.copyOfRange(HEADER_LEN, pkt.size))
        expected = (seq + 1) and 0xFF
        if (flags and FLAG_LAST != 0) ended = true
        ack(seq)
    }
}
