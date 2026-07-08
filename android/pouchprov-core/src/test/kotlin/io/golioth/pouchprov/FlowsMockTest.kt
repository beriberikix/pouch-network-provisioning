// Copyright (c) 2026 Jonathan Beri
// SPDX-License-Identifier: Apache-2.0

package io.golioth.pouchprov

import io.golioth.pouchprov.cbor.Cbor
import io.golioth.pouchprov.session.ProvSession
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Full client stack over the mock device: SAR + pouch + session + flows, for the
 * Wi-Fi and BLE-only (cred-only) provisioning paths. Mirrors the Python
 * `test_provision_e2e` / `test_flows_cred_only`.
 */
class FlowsMockTest {

    private val pop = "abcd1234"

    @Test fun wifiDeviceFullProvision() = runBlocking {
        val device = DeviceSim(pop = pop, caps = listOf("wifi", "scan", "cred", "auth"))
        val session = ProvSession(MockDeviceTransport(device::handle))

        val info = Flows.getVersion(session)
        assertEquals(1, info.proto)
        assertTrue(info.hasCap("wifi"))
        assertTrue(info.popRequired)

        Flows.authorizeIfNeeded(session, info, pop)
        assertTrue(device.authorized)

        val scan = Flows.scan(session)
        assertEquals(2, scan.size)
        assertArrayEquals("myssid".toByteArray(), scan[0].ssid)

        val status = Flows.configureWifi(session, "myssid".toByteArray(), "hunter22".toByteArray())
        assertEquals(StaState.CONNECTED, status.state)
        assertArrayEquals("myssid".toByteArray(), device.wifiSsid)

        Flows.bootstrapCredentials(session, certDer = ByteArray(500) { 1 }, keyDer = ByteArray(120) { 2 })
        assertEquals(500, device.credLen(CredKind.DEVICE_CERT))
        assertEquals(120, device.credLen(CredKind.PRIVATE_KEY))
        assertTrue(device.credFinalized)

        Flows.endSession(session)
        assertTrue(device.ended)
    }

    @Test fun credOnlyDeviceSkipsWifi() = runBlocking {
        val device = DeviceSim(pop = pop, caps = listOf("cred", "auth")) // no "wifi"
        val session = ProvSession(MockDeviceTransport(device::handle))

        val info = Flows.getVersion(session)
        assertTrue(info.hasCap("cred"))
        assertTrue(!info.hasCap("wifi"))

        Flows.authorizeIfNeeded(session, info, pop)
        Flows.bootstrapCredentials(
            session,
            certDer = ByteArray(300) { 1 },
            keyDer = ByteArray(120) { 2 },
            caDer = ByteArray(64) { 3 },
        )
        assertEquals(300, device.credLen(CredKind.DEVICE_CERT))
        assertEquals(64, device.credLen(CredKind.CA_CERT))
        Flows.endSession(session)
        assertTrue(device.ended)
    }

    @Test fun wrongPopFailsBeforeSendingClientProof() = runBlocking {
        val device = DeviceSim(pop = "correct", caps = listOf("cred", "auth"))
        val session = ProvSession(MockDeviceTransport(device::handle))
        val info = Flows.getVersion(session)
        assertThrows(Auth.AuthException::class.java) {
            runBlocking { Flows.authorizeIfNeeded(session, info, "wrong") }
        }
        assertTrue("client proof must not be sent on device-proof mismatch", !device.authorized)
    }
}

/**
 * A minimal device-side responder. Encodes response CBOR arrays the way the
 * firmware/CLI vectors do and tracks enough state to validate the client flows.
 */
private class DeviceSim(val pop: String, val caps: List<String>) {
    var authorized = false
    var wifiSsid: ByteArray? = null
    var credFinalized = false
    var ended = false
    private val creds = HashMap<CredKind, Int>()
    private val devNonce = ByteArray(16) { (0x40 + it).toByte() }

    fun credLen(kind: CredKind): Int = creds[kind] ?: 0

    fun handle(path: String, data: ByteArray): ByteArray? {
        val msg = Cbor.decode(data) as List<*>
        val op = (msg[0] as Long).toInt()
        return when (path) {
            Messages.PATH_VER -> Cbor.encode(
                listOf(
                    0L, 0L,
                    linkedMapOf<String, Any?>(
                        "proto" to 1L,
                        "caps" to caps,
                        "blk" to 512L,
                        "lib" to "0.1.0",
                        "pop" to true,
                    ),
                ),
            )
            Messages.PATH_AUTH -> when (op) {
                0 -> {
                    val cliNonce = msg[1] as ByteArray
                    val proof = Auth.deviceProof(pop, cliNonce, devNonce)
                    Cbor.encode(listOf(0L, 0L, devNonce, proof))
                }
                else -> {
                    authorized = true
                    Cbor.encode(listOf(1L, 0L))
                }
            }
            Messages.PATH_SCAN -> when (op) {
                0 -> Cbor.encode(listOf(0L, 0L))
                1 -> Cbor.encode(listOf(1L, 0L, true, 2L))
                else -> Cbor.encode(listOf(2L, 0L, listOf(scanEntry("myssid", -41, 1), scanEntry("guest", -73, 0))))
            }
            Messages.PATH_CONFIG -> when (op) {
                0 -> Cbor.encode( // status: connected
                    listOf(
                        0L, 0L, 0L,
                        linkedMapOf<String, Any?>(
                            "ip4" to byteArrayOf(192.toByte(), 168.toByte(), 1, 7),
                            "ssid" to (wifiSsid ?: ByteArray(0)),
                            "rssi" to (-41).toLong(),
                        ),
                    ),
                )
                1 -> { wifiSsid = (msg[1] as Map<*, *>)["ssid"] as ByteArray; Cbor.encode(listOf(1L, 0L)) }
                else -> Cbor.encode(listOf(2L, 0L))
            }
            Messages.PATH_CRED -> when (op) {
                0 -> {
                    val m = msg[1] as Map<*, *>
                    val kind = CredKind.from((m["kind"] as Long).toInt())
                    val off = (m["off"] as Long).toInt()
                    val len = (m["data"] as ByteArray).size
                    creds[kind] = off + len
                    Cbor.encode(listOf(0L, 0L, (off + len).toLong()))
                }
                1 -> { credFinalized = true; Cbor.encode(listOf(1L, 0L)) }
                else -> Cbor.encode(listOf(2L, 0L, creds.entries.associate { it.key.code.toString() to it.value.toLong() }))
            }
            Messages.PATH_CTRL -> { if (op == CtrlOp.END.code) ended = true; Cbor.encode(listOf(op.toLong(), 0L)) }
            else -> null
        }
    }

    private fun scanEntry(ssid: String, rssi: Int, auth: Int) = linkedMapOf<String, Any?>(
        "ssid" to ssid.toByteArray(),
        "bssid" to ByteArray(6),
        "ch" to 11L,
        "rssi" to rssi.toLong(),
        "auth" to auth.toLong(),
    )
}
