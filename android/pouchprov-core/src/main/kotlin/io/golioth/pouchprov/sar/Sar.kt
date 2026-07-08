// Copyright (c) 2026 Jonathan Beri
// SPDX-License-Identifier: Apache-2.0

package io.golioth.pouchprov.sar

import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull

/**
 * Pouch SAR (segmentation and reassembly) — client side.
 *
 * A faithful port of the Python `pouchlink.sar`. Wire format per pouch
 * src/transport/sar/packet.{h,c}:
 *
 * TX packet (sender -> receiver):
 *   byte 0: flags — FIRST=0x01, LAST=0x02, FIN=0x04
 *   byte 1: sequence number (mod 256); for FIN packets a code byte instead
 *           (0 on the first FIN = success, 2 on retransmits)
 *   2..:    fragment payload
 *
 * ACK packet (receiver -> sender):
 *   byte 0: code — 0 ACK, 1 NACK_UNKNOWN, 2 NACK_IDLE
 *   byte 1: last in-order sequence received (0xFF before any)
 *   byte 2: window (<= 127)
 */

const val FLAG_FIRST = 0x01
const val FLAG_LAST = 0x02
const val FLAG_FIN = 0x04

const val CODE_ACK = 0
const val CODE_NACK_UNKNOWN = 1
const val CODE_NACK_IDLE = 2

const val SEQ_MASK = 0xFF
const val HEADER_LEN = 2

/** Suspending "write toward the peer" callback. */
typealias WriteCb = suspend (ByteArray) -> Unit

class SarError(message: String) : Exception(message)

/** Send one blob as a SAR transaction. */
class SarSender(private val write: WriteCb, maxlen: Int) {
    init {
        require(maxlen > HEADER_LEN) { "maxlen too small" }
    }

    private val frag = maxlen - HEADER_LEN
    private val acks = Channel<ByteArray>(Channel.UNLIMITED)

    /** Feed an incoming ACK notification (safe to call from a callback). */
    fun feed(pkt: ByteArray) {
        acks.trySend(pkt.copyOf())
    }

    suspend fun send(data: ByteArray, timeoutMs: Long = 10_000) {
        val frags = if (data.isEmpty()) {
            listOf(ByteArray(0))
        } else {
            (data.indices step frag).map { data.copyOfRange(it, minOf(it + frag, data.size)) }
        }
        var seq = 0
        var sentLast = false

        while (true) {
            val ack = try {
                withTimeout(timeoutMs) { acks.receive() }
            } catch (e: TimeoutCancellationException) {
                throw SarError("timed out waiting for ack")
            }
            if (ack.size != 3) throw SarError("bad ack length ${ack.size}")
            val code = ack[0].toInt() and 0xFF
            val ackSeq = ack[1].toInt() and 0xFF
            val window = ack[2].toInt() and 0xFF
            if (code != CODE_ACK) throw SarError("receiver NACK (code $code)")
            val target = (ackSeq + window + 1) and SEQ_MASK

            if (sentLast) {
                if (ackSeq == (seq - 1) and SEQ_MASK) {
                    // The receiver has already ACKed every data fragment, so the
                    // blob is fully delivered. The FIN is a courtesy close: the
                    // device processes it and tears down its SAR endpoint, which
                    // can make the ATT write-response for this very packet come
                    // back as an error (e.g. "Unlikely Error" 0x0E). Treat the
                    // FIN write as best-effort so that doesn't fail the transfer.
                    try {
                        write(byteArrayOf(FLAG_FIN.toByte(), CODE_ACK.toByte()))
                    } catch (_: Exception) {
                        // ignore — data already delivered and acknowledged
                    }
                    return
                }
                continue // stale ack; wait for the ack of the LAST fragment
            }

            while (seq != target && !sentLast) {
                val idx = seq // fragments are < 256 for provisioning payloads
                var flags = 0
                if (idx == 0) flags = flags or FLAG_FIRST
                if (idx == frags.size - 1) {
                    flags = flags or FLAG_LAST
                    sentLast = true
                }
                write(byteArrayOf(flags.toByte(), seq.toByte()) + frags[idx])
                seq = (seq + 1) and SEQ_MASK
            }
        }
    }
}

/** Receive one blob as a SAR transaction. */
class SarReceiver(
    private val write: WriteCb,
    private val window: Int = 8,
    private val reackIntervalMs: Long = 500,
) {
    init {
        require(window in 1..127) { "window out of range" }
    }

    private val pkts = Channel<ByteArray>(Channel.UNLIMITED)

    /** Feed an incoming TX-packet notification (safe to call from a callback). */
    fun feed(pkt: ByteArray) {
        pkts.trySend(pkt.copyOf())
    }

    private suspend fun ack(seq: Int) {
        write(byteArrayOf(CODE_ACK.toByte(), seq.toByte(), window.toByte()))
    }

    /** Run the transaction to completion; returns the reassembled blob. */
    suspend fun receive(timeoutMs: Long = 15_000): ByteArray {
        val chunks = ArrayList<ByteArray>()
        var expected = 0
        var last = 0xFF
        var ended = false
        val deadline = nowMs() + timeoutMs

        ack(last)

        while (true) {
            val remaining = deadline - nowMs()
            if (remaining <= 0) throw SarError("timed out waiting for data")
            val pkt = withTimeoutOrNull(minOf(reackIntervalMs, remaining)) { pkts.receive() }
            if (pkt == null) {
                ack(last) // periodic re-ack doubles as a poll
                continue
            }
            if (pkt.size < HEADER_LEN) throw SarError("short packet")
            val flags = pkt[0].toInt() and 0xFF

            if (flags and FLAG_FIN != 0) {
                if (!ended) throw SarError("FIN before LAST fragment")
                if ((pkt[1].toInt() and 0xFF) == CODE_ACK) return concat(chunks)
                throw SarError("transfer failed (FIN code ${pkt[1].toInt() and 0xFF})")
            }

            val seq = pkt[1].toInt() and 0xFF
            if (seq != expected) {
                ack(last) // out of order: re-ack last in-order
                continue
            }
            if (ended) throw SarError("fragment after LAST")

            chunks.add(pkt.copyOfRange(HEADER_LEN, pkt.size))
            last = seq
            expected = (seq + 1) and SEQ_MASK
            if (flags and FLAG_LAST != 0) ended = true
            ack(last)
        }
    }

    private fun nowMs(): Long = System.nanoTime() / 1_000_000

    private fun concat(chunks: List<ByteArray>): ByteArray {
        val size = chunks.sumOf { it.size }
        val out = ByteArray(size)
        var p = 0
        for (c in chunks) {
            c.copyInto(out, p)
            p += c.size
        }
        return out
    }
}
