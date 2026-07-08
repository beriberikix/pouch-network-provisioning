// Copyright (c) 2026 Jonathan Beri
// SPDX-License-Identifier: Apache-2.0

package io.golioth.pouchprov

import io.golioth.pouchprov.session.ProvSession
import kotlinx.coroutines.delay

/**
 * High-level provisioning flows composed over a [ProvSession]. A faithful port
 * of the Python `flows` module.
 */
object Flows {

    suspend fun getVersion(session: ProvSession): VersionInfo {
        val info = Messages.decodeVerRsp(session.request(Messages.PATH_VER, Messages.encodeVerReq()))
        if (info.proto != Messages.PROTO_VERSION) {
            throw IllegalStateException("unsupported device protocol v${info.proto}")
        }
        session.blockSize = info.blockSize
        return info
    }

    suspend fun authorizeIfNeeded(session: ProvSession, info: VersionInfo, pop: String?) {
        if (info.popRequired) {
            if (pop.isNullOrEmpty()) throw IllegalStateException("device requires a proof-of-possession (pop)")
            Auth.authorize(session, pop)
        }
    }

    /** Trigger a scan, poll until finished, and collect all result pages. */
    suspend fun scan(session: ProvSession, timeoutMs: Long = 20_000): List<ScanEntry> {
        Messages.decodeScanStartRsp(session.request(Messages.PATH_SCAN, Messages.encodeScanStart()))

        val deadline = nowMs() + timeoutMs
        var total: Int
        while (true) {
            val (finished, t) = Messages.decodeScanStatusRsp(
                session.request(Messages.PATH_SCAN, Messages.encodeScanGetStatus()),
            )
            total = t
            if (finished) break
            if (nowMs() > deadline) throw IllegalStateException("scan did not finish")
            delay(500)
        }

        val results = ArrayList<ScanEntry>()
        while (results.size < total) {
            val page = Messages.decodeScanResultsRsp(
                session.request(Messages.PATH_SCAN, Messages.encodeScanGetResults(results.size, 6)),
            )
            if (page.isEmpty()) break
            results.addAll(page)
        }
        return results
    }

    /** Set + apply credentials, then poll status until connected or failed. */
    suspend fun configureWifi(
        session: ProvSession,
        ssid: ByteArray,
        password: ByteArray?,
        timeoutMs: Long = 40_000,
    ): WifiStatus {
        Messages.decodeConfigSetRsp(
            session.request(Messages.PATH_CONFIG, Messages.encodeConfigSet(ssid, password)),
        )
        Messages.decodeConfigApplyRsp(
            session.request(Messages.PATH_CONFIG, Messages.encodeConfigApply()),
        )

        val deadline = nowMs() + timeoutMs
        while (true) {
            val status = Messages.decodeConfigStatusRsp(
                session.request(Messages.PATH_CONFIG, Messages.encodeConfigGetStatus()),
            )
            if (status.state == StaState.CONNECTED || status.state == StaState.FAILED) return status
            if (nowMs() > deadline) throw IllegalStateException("connection did not settle")
            delay(1_000)
        }
    }

    /** Write one DER credential to the device in ordered chunks. */
    suspend fun pushCredential(session: ProvSession, kind: CredKind, der: ByteArray, chunk: Int = 256) {
        val total = der.size
        var off = 0
        while (off < total) {
            val piece = der.copyOfRange(off, minOf(off + chunk, total))
            val received = Messages.decodeCredWriteRsp(
                session.request(Messages.PATH_CRED, Messages.encodeCredWrite(kind, off, total, piece)),
            )
            off += piece.size
            if (received != off) throw IllegalStateException("cred write desync: device has $received, sent $off")
        }
    }

    /** Push device cert + key (+ optional CA), then finalize. */
    suspend fun bootstrapCredentials(
        session: ProvSession,
        certDer: ByteArray,
        keyDer: ByteArray,
        caDer: ByteArray? = null,
    ) {
        pushCredential(session, CredKind.DEVICE_CERT, certDer)
        pushCredential(session, CredKind.PRIVATE_KEY, keyDer)
        if (caDer != null) pushCredential(session, CredKind.CA_CERT, caDer)
        Messages.decodeCredFinalizeRsp(session.request(Messages.PATH_CRED, Messages.encodeCredFinalize()))
    }

    suspend fun endSession(session: ProvSession) {
        Messages.decodeCtrlRsp(
            session.request(Messages.PATH_CTRL, Messages.encodeCtrl(CtrlOp.END)),
            CtrlOp.END,
        )
    }

    private fun nowMs(): Long = System.nanoTime() / 1_000_000
}
