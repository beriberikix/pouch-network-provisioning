// Copyright (c) 2026 Jonathan Beri
// SPDX-License-Identifier: Apache-2.0

package io.golioth.pouchprov.session

import io.golioth.pouchprov.pouch.Entry
import io.golioth.pouchprov.pouch.Pouch
import io.golioth.pouchprov.pouch.PouchHeader
import io.golioth.pouchprov.saead.Saead
import io.golioth.pouchprov.saead.SaeadSession
import io.golioth.pouchprov.sar.SarReceiver
import io.golioth.pouchprov.sar.SarSender
import io.golioth.pouchprov.transport.Transport
import java.security.SecureRandom
import kotlinx.coroutines.delay
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Seam between the RPC engine and the pouch framing/crypto. The plaintext
 * implementation frames encryption-none pouches; a saead implementation can be
 * dropped in later without reshaping [ProvSession] (see the plan's crypto seam).
 */
interface SessionCrypto {
    /** Build the request (downlink) pouch bytes carrying [entries]. */
    fun buildRequest(entries: List<Entry>, deviceId: String, blockSize: Int): ByteArray

    /** Parse a response (uplink) pouch into its header and entries. */
    fun parseResponse(data: ByteArray): Pair<PouchHeader, List<Entry>>
}

/** Plaintext (encryption-none) framing — parity with the CLI's live path. */
object PlaintextCrypto : SessionCrypto {
    override fun buildRequest(entries: List<Entry>, deviceId: String, blockSize: Int): ByteArray =
        Pouch.buildEntryPouch(deviceId.ifEmpty { "?" }, entries, blockSize)

    override fun parseResponse(data: ByteArray): Pair<PouchHeader, List<Entry>> = Pouch.parsePouch(data)
}

/**
 * Encrypted (saead) framing over a [SaeadSession]. Each request pouch starts a
 * fresh random downlink session; the uplink session is adopted from the device's
 * response header. An empty (header-only) uplink pouch means "not ready".
 */
class SaeadCrypto(
    private val saead: SaeadSession,
    private val sessionIdSource: () -> ByteArray = {
        ByteArray(Saead.SESSION_ID_LEN).also { SecureRandom().nextBytes(it) }
    },
) : SessionCrypto {
    override fun buildRequest(entries: List<Entry>, deviceId: String, blockSize: Int): ByteArray =
        Saead.buildDownlinkPouch(saead, sessionIdSource(), entries, blockSize = blockSize)

    override fun parseResponse(data: ByteArray): Pair<PouchHeader, List<Entry>> {
        val (header, consumed) = PouchHeader.decode(data)
        if (header.encryption == Pouch.ENCRYPTION_SAEAD) {
            // A header-only uplink pouch still parses to no entries ("not ready").
            return if (data.size > consumed) header to Saead.parseUplinkPouch(saead, data) else header to emptyList()
        }
        return Pouch.parsePouch(data)
    }
}

class SessionError(message: String) : Exception(message)

/**
 * Lockstep request/response engine. One request pouch at a time.
 *
 * Implements the client-driven RPC cycle (docs/protocol.md): request = subscribe
 * downlink -> SAR-send one pouch -> unsubscribe; response = subscribe uplink ->
 * SAR-receive one pouch -> unsubscribe. An empty response pouch means "not
 * ready, retry". A faithful port of the Python `session.ProvSession`.
 */
class ProvSession(
    private val transport: Transport,
    var deviceId: String = "",
    private val maxlen: Int = DEFAULT_MAXLEN,
    private val crypto: SessionCrypto = PlaintextCrypto,
) {
    var blockSize: Int = Pouch.DEFAULT_BLOCK_SIZE

    private val lock = Mutex()

    /** Send request entries in one pouch, return the response entries. */
    suspend fun requestEntries(
        entries: List<Entry>,
        timeoutMs: Long = 15_000,
        pollAttempts: Int = 5,
    ): List<Entry> = lock.withLock {
        sendPouch(entries, timeoutMs)

        var backoff = 200L
        repeat(pollAttempts) {
            val (header, rsp) = receivePouch(timeoutMs)
            deviceId = header.deviceId ?: deviceId
            if (rsp.isNotEmpty()) return@withLock rsp
            // Empty pouch: responses were not ready; back off and re-poll.
            delay(backoff)
            backoff = minOf(backoff * 2, 2_000L)
        }
        throw SessionError("no response after retries")
    }

    /** Single-entry convenience: request [msg] on [path], return the response bytes. */
    suspend fun request(path: String, msg: ByteArray, timeoutMs: Long = 15_000): ByteArray {
        val entries = requestEntries(listOf(Entry(path, Pouch.CONTENT_TYPE_CBOR, msg)), timeoutMs)
        return entries.firstOrNull { it.path == path }?.data
            ?: throw SessionError("no response entry for $path")
    }

    private suspend fun sendPouch(entries: List<Entry>, timeoutMs: Long) {
        val data = crypto.buildRequest(entries, deviceId, blockSize)
        val ch = transport.downlink
        val sender = SarSender(ch::write, maxlen)
        ch.subscribe(sender::feed)
        try {
            sender.send(data, timeoutMs)
        } finally {
            ch.unsubscribe()
        }
    }

    private suspend fun receivePouch(timeoutMs: Long): Pair<PouchHeader, List<Entry>> {
        val ch = transport.uplink
        val receiver = SarReceiver(ch::write)
        ch.subscribe(receiver::feed)
        val data = try {
            receiver.receive(timeoutMs)
        } finally {
            ch.unsubscribe()
        }
        return crypto.parseResponse(data)
    }

    companion object {
        // ATT MTU 247 => 244-byte payloads on notification / write.
        const val DEFAULT_MAXLEN = 244
    }
}
