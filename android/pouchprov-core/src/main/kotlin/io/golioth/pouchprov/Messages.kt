// Copyright (c) 2026 Jonathan Beri
// SPDX-License-Identifier: Apache-2.0

package io.golioth.pouchprov

import io.golioth.pouchprov.cbor.Cbor

/**
 * Provisioning message codec (cddl/prov.cddl, protocol version 1).
 *
 * Every message is a CBOR array `[op, ...]`. This mirrors the Python `codec.py`
 * and is pinned to the device's zcbor codec via the shared golden vectors in
 * `tests/vectors/`.
 */
object Messages {
    const val PROTO_VERSION = 1

    // Reserved provisioning paths (pouch downlink/uplink entry paths).
    const val PATH_VER = ".prov/ver"
    const val PATH_AUTH = ".prov/auth"
    const val PATH_CONFIG = ".prov/config"
    const val PATH_SCAN = ".prov/scan"
    const val PATH_CRED = ".prov/cred"
    const val PATH_CTRL = ".prov/ctrl"

    // ---- .prov/ver -------------------------------------------------------

    fun encodeVerReq(): ByteArray = Cbor.encode(listOf(0L))

    fun decodeVerRsp(data: ByteArray): VersionInfo {
        val msg = decode(data, 0, "ver")
        @Suppress("UNCHECKED_CAST")
        val info = msg[2] as Map<Any?, Any?>
        return VersionInfo(
            proto = (info["proto"] as Long).toInt(),
            caps = (info["caps"] as List<*>).map { it as String },
            blockSize = (info["blk"] as Long).toInt(),
            lib = info["lib"] as String,
            popRequired = (info["pop"] as? Boolean) ?: false,
        )
    }

    // ---- .prov/auth ------------------------------------------------------

    fun encodeAuthChallenge(cliNonce: ByteArray): ByteArray {
        require(cliNonce.size == 16)
        return Cbor.encode(listOf(0L, cliNonce))
    }

    /** Returns (devNonce, devProof). */
    fun decodeAuthChallengeRsp(data: ByteArray): Pair<ByteArray, ByteArray> {
        val msg = decode(data, 0, "auth")
        val devNonce = msg[2] as ByteArray
        val devProof = msg[3] as ByteArray
        if (devNonce.size != 16 || devProof.size != 32) throw DecodeError("auth: bad nonce/proof size")
        return devNonce to devProof
    }

    fun encodeAuthProof(cliProof: ByteArray): ByteArray {
        require(cliProof.size == 32)
        return Cbor.encode(listOf(1L, cliProof))
    }

    fun decodeAuthProofRsp(data: ByteArray) {
        decode(data, 1, "auth")
    }

    // ---- .prov/config ----------------------------------------------------

    fun encodeConfigGetStatus(): ByteArray = Cbor.encode(listOf(0L))

    fun encodeConfigSet(
        ssid: ByteArray,
        password: ByteArray? = null,
        bssid: ByteArray? = null,
        channel: Int? = null,
    ): ByteArray {
        val cfg = LinkedHashMap<String, Any?>()
        cfg["ssid"] = ssid
        if (password != null) cfg["pass"] = password
        if (bssid != null) cfg["bssid"] = bssid
        if (channel != null) cfg["ch"] = channel.toLong()
        return Cbor.encode(listOf(1L, cfg))
    }

    fun encodeConfigApply(): ByteArray = Cbor.encode(listOf(2L))

    fun decodeConfigStatusRsp(data: ByteArray): WifiStatus {
        val msg = decode(data, 0, "config")
        val state = StaState.from((msg[2] as Long).toInt())
        var status = WifiStatus(state)
        if (msg.size > 3) {
            when (val detail = msg[3]) {
                is Long -> status = status.copy(failReason = FailReason.from(detail.toInt()))
                is Map<*, *> -> status = status.copy(
                    ip4 = detail["ip4"] as ByteArray,
                    ssid = detail["ssid"] as ByteArray,
                    rssi = (detail["rssi"] as? Long)?.toInt(),
                )
                else -> throw DecodeError("config: bad status detail")
            }
        }
        return status
    }

    fun decodeConfigSetRsp(data: ByteArray) {
        decode(data, 1, "config")
    }

    fun decodeConfigApplyRsp(data: ByteArray) {
        decode(data, 2, "config")
    }

    // ---- .prov/scan ------------------------------------------------------

    fun encodeScanStart(passive: Boolean? = null, periodMs: Int? = null): ByteArray {
        val params = LinkedHashMap<String, Any?>()
        if (passive != null) params["passive"] = passive
        if (periodMs != null) params["period-ms"] = periodMs.toLong()
        return Cbor.encode(listOf(0L, params))
    }

    fun encodeScanGetStatus(): ByteArray = Cbor.encode(listOf(1L))

    fun encodeScanGetResults(start: Int, count: Int): ByteArray =
        Cbor.encode(listOf(2L, start.toLong(), count.toLong()))

    fun decodeScanStartRsp(data: ByteArray) {
        decode(data, 0, "scan")
    }

    /** Returns (finished, total). */
    fun decodeScanStatusRsp(data: ByteArray): Pair<Boolean, Int> {
        val msg = decode(data, 1, "scan")
        return (msg[2] as Boolean) to (msg[3] as Long).toInt()
    }

    fun decodeScanResultsRsp(data: ByteArray): List<ScanEntry> {
        val msg = decode(data, 2, "scan")
        @Suppress("UNCHECKED_CAST")
        val list = msg[2] as List<Map<Any?, Any?>>
        return list.map { e ->
            ScanEntry(
                ssid = e["ssid"] as ByteArray,
                bssid = e["bssid"] as ByteArray,
                channel = (e["ch"] as Long).toInt(),
                rssi = (e["rssi"] as Long).toInt(),
                auth = (e["auth"] as Long).toInt(),
            )
        }
    }

    // ---- .prov/cred ------------------------------------------------------

    fun encodeCredWrite(kind: CredKind, offset: Int, total: Int, data: ByteArray): ByteArray {
        val map = LinkedHashMap<String, Any?>()
        map["kind"] = kind.code.toLong()
        map["off"] = offset.toLong()
        map["total"] = total.toLong()
        map["data"] = data
        return Cbor.encode(listOf(0L, map))
    }

    fun encodeCredFinalize(): ByteArray = Cbor.encode(listOf(1L))

    fun encodeCredGetStatus(): ByteArray = Cbor.encode(listOf(2L))

    /** Returns total bytes received for the written kind. */
    fun decodeCredWriteRsp(data: ByteArray): Int {
        val msg = decode(data, 0, "cred")
        return (msg[2] as Long).toInt()
    }

    fun decodeCredFinalizeRsp(data: ByteArray) {
        decode(data, 1, "cred")
    }

    fun decodeCredStatusRsp(data: ByteArray): Map<CredKind, Int> {
        val msg = decode(data, 2, "cred")
        @Suppress("UNCHECKED_CAST")
        val map = msg[2] as Map<Any?, Any?>
        return map.entries.associate { (k, v) -> CredKind.from((k as String).toInt()) to (v as Long).toInt() }
    }

    // ---- .prov/ctrl ------------------------------------------------------

    fun encodeCtrl(op: CtrlOp): ByteArray = Cbor.encode(listOf(op.code.toLong()))

    fun decodeCtrlRsp(data: ByteArray, op: CtrlOp) {
        decode(data, op.code, "ctrl")
    }

    // ---- shared ----------------------------------------------------------

    private fun decode(data: ByteArray, expectOp: Int, context: String): List<Any?> {
        val msg = try {
            Cbor.decode(data)
        } catch (e: Exception) {
            throw DecodeError("$context: bad CBOR: ${e.message}")
        }
        if (msg !is List<*> || msg.size < 2) throw DecodeError("$context: not a response array")
        if ((msg[0] as? Long)?.toInt() != expectOp) throw DecodeError("$context: op ${msg[0]}, expected $expectOp")
        val status = Status.from((msg[1] as Long).toInt())
        if (status != Status.OK) throw ProvError(status, context)
        return msg
    }
}

// ---- enums ---------------------------------------------------------------

enum class Status(val code: Int) {
    OK(0),
    INVALID_PROTO(1),
    INVALID_ARGUMENT(2),
    INTERNAL_ERROR(3),
    UNAUTHORIZED(4),
    INVALID_STATE(5),
    BUSY(6),
    ;

    companion object {
        fun from(code: Int): Status = entries.firstOrNull { it.code == code }
            ?: throw DecodeError("unknown status $code")
    }
}

enum class StaState(val code: Int) {
    CONNECTED(0),
    CONNECTING(1),
    DISCONNECTED(2),
    FAILED(3),
    ;

    companion object {
        fun from(code: Int): StaState = entries.firstOrNull { it.code == code }
            ?: throw DecodeError("unknown sta-state $code")
    }
}

enum class FailReason(val code: Int) {
    AUTH_ERROR(0),
    NETWORK_NOT_FOUND(1),
    ;

    companion object {
        fun from(code: Int): FailReason = entries.firstOrNull { it.code == code }
            ?: throw DecodeError("unknown fail-reason $code")
    }
}

enum class CredKind(val code: Int) {
    DEVICE_CERT(0),
    PRIVATE_KEY(1),
    CA_CERT(2),
    ;

    companion object {
        fun from(code: Int): CredKind = entries.firstOrNull { it.code == code }
            ?: throw DecodeError("unknown cred kind $code")
    }
}

enum class CtrlOp(val code: Int) {
    RESET(0),
    REPROVISION(1),
    END(2),
}

// ---- value types ---------------------------------------------------------

data class VersionInfo(
    val proto: Int,
    val caps: List<String>,
    val blockSize: Int,
    val lib: String,
    val popRequired: Boolean,
) {
    fun hasCap(cap: String): Boolean = cap in caps
}

data class WifiStatus(
    val state: StaState,
    val failReason: FailReason? = null,
    val ip4: ByteArray? = null,
    val ssid: ByteArray? = null,
    val rssi: Int? = null,
) {
    override fun equals(other: Any?): Boolean =
        other is WifiStatus && state == other.state && failReason == other.failReason &&
            (ip4?.contentEquals(other.ip4) ?: (other.ip4 == null)) &&
            (ssid?.contentEquals(other.ssid) ?: (other.ssid == null)) && rssi == other.rssi

    override fun hashCode(): Int = state.hashCode()
}

data class ScanEntry(
    val ssid: ByteArray,
    val bssid: ByteArray,
    val channel: Int,
    val rssi: Int,
    val auth: Int,
) {
    val authName: String get() = securityName(auth)

    override fun equals(other: Any?): Boolean =
        other is ScanEntry && ssid.contentEquals(other.ssid) && bssid.contentEquals(other.bssid) &&
            channel == other.channel && rssi == other.rssi && auth == other.auth

    override fun hashCode(): Int = ssid.contentHashCode()
}

/** Human-readable name for a Wi-Fi security type (Zephyr enum wifi_security_type). */
fun securityName(auth: Int): String = when (auth) {
    0 -> "Open"
    1 -> "WPA2-PSK"
    2 -> "WPA2-PSK-SHA256"
    3 -> "WPA3-SAE"
    4 -> "WPA3-SAE-H2E"
    5 -> "WPA3-SAE-AUTO"
    6 -> "WAPI"
    7 -> "EAP-TLS"
    8 -> "WEP"
    9 -> "WPA-PSK"
    10 -> "WPA/WPA2-Auto"
    11 -> "DPP"
    else -> "unknown($auth)"
}

// ---- exceptions ----------------------------------------------------------

/** Protocol-level error reported by the device. */
class ProvError(val status: Status, context: String = "") :
    Exception(if (context.isNotEmpty()) "$context: $status" else status.toString())

/** Response did not match the schema. */
class DecodeError(message: String) : Exception(message)
