// Copyright (c) 2026 Jonathan Beri
// SPDX-License-Identifier: Apache-2.0

package io.golioth.pouchprov

import io.golioth.pouchprov.pouch.Block
import io.golioth.pouchprov.pouch.Entry
import io.golioth.pouchprov.pouch.Pouch
import io.golioth.pouchprov.pouch.PouchHeader
import io.golioth.pouchprov.sar.CODE_ACK
import io.golioth.pouchprov.sar.FLAG_FIN
import io.golioth.pouchprov.sar.FLAG_FIRST
import io.golioth.pouchprov.sar.FLAG_LAST
import io.golioth.pouchprov.sar.HEADER_LEN
import io.golioth.pouchprov.transport.Channel
import io.golioth.pouchprov.transport.Transport

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
) : Transport {

    override val downlink = MockChannel()
    override val uplink = MockChannel()

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
    }

    override suspend fun connect() {}
    override suspend fun disconnect() {}

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
        val (_, entries) = Pouch.parsePouch(data)
        for (entry in entries) {
            handler(entry.path, entry.data)?.let { responses.add(Entry(entry.path, entry.contentType, it)) }
        }
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
        val data = if (entries.isNotEmpty()) {
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
