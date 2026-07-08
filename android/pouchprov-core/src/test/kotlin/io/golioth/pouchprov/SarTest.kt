// Copyright (c) 2026 Jonathan Beri
// SPDX-License-Identifier: Apache-2.0

package io.golioth.pouchprov

import io.golioth.pouchprov.sar.SarReceiver
import io.golioth.pouchprov.sar.SarSender
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import org.junit.Assert.assertArrayEquals
import org.junit.Test

/**
 * SAR sender <-> receiver loopback. The sender's writes feed the receiver and
 * vice-versa; a multi-fragment payload exercises windowing, LAST/FIN and the
 * opening ack.
 */
class SarTest {

    private fun roundTrip(payload: ByteArray, maxlen: Int, window: Int): ByteArray = runBlocking {
        withContext(Dispatchers.Default) {
            lateinit var sender: SarSender
            val receiver = SarReceiver(write = { sender.feed(it) }, window = window, reackIntervalMs = 50)
            sender = SarSender(write = { receiver.feed(it) }, maxlen = maxlen)

            val recvJob = async { receiver.receive(timeoutMs = 10_000) }
            val sendJob = async { sender.send(payload, timeoutMs = 10_000) }
            sendJob.await()
            recvJob.await()
        }
    }

    @Test fun multiFragment() {
        val payload = ByteArray(1000) { (it * 7 + 3).toByte() }
        assertArrayEquals(payload, roundTrip(payload, maxlen = 10, window = 4))
    }

    @Test fun singleFragment() {
        val payload = byteArrayOf(1, 2, 3)
        assertArrayEquals(payload, roundTrip(payload, maxlen = 244, window = 8))
    }

    @Test fun emptyPayload() {
        assertArrayEquals(ByteArray(0), roundTrip(ByteArray(0), maxlen = 244, window = 8))
    }

    @Test fun windowOne() {
        val payload = ByteArray(300) { it.toByte() }
        assertArrayEquals(payload, roundTrip(payload, maxlen = 12, window = 1))
    }
}
