// Copyright (c) 2026 Jonathan Beri
// SPDX-License-Identifier: Apache-2.0

package io.golioth.pouchprov

import io.golioth.pouchprov.pouch.Entry
import io.golioth.pouchprov.pouch.Pouch
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Conformance against the shared golden vectors in the repo-root `tests/vectors/`
 * — the same fixtures the Python CLI and the Zephyr device codec are pinned to.
 * Every request encoder must reproduce its hex byte-for-byte, and every response
 * decoder must round-trip the device's bytes.
 */
class GoldenVectorsTest {

    private val messages = loadVectors("prov_messages.json")
    private val frames = loadVectors("pouch_frames.json")

    private fun requests() = messages.getJSONObject("requests")
    private fun responses() = messages.getJSONObject("responses")

    // ---- request encoders (client -> device) -----------------------------

    @Test fun verReq() = assertHex("ver_req", Messages.encodeVerReq())

    @Test fun authChallenge() =
        assertHex("auth_challenge", Messages.encodeAuthChallenge(bytes(0, 16)))

    @Test fun authProof() =
        assertHex("auth_proof", Messages.encodeAuthProof(bytes(0, 32)))

    @Test fun configGetStatus() = assertHex("config_get_status", Messages.encodeConfigGetStatus())

    @Test fun configSetFull() = assertHex(
        "config_set_full",
        Messages.encodeConfigSet(
            ssid = "myssid".toByteArray(),
            password = "hunter22".toByteArray(),
            bssid = hex("a1b2c3d4e5f6"),
            channel = 11,
        ),
    )

    @Test fun configSetMinimal() =
        assertHex("config_set_minimal", Messages.encodeConfigSet(ssid = "open-net".toByteArray()))

    @Test fun configApply() = assertHex("config_apply", Messages.encodeConfigApply())

    @Test fun scanStartDefaults() = assertHex("scan_start_defaults", Messages.encodeScanStart())

    @Test fun scanStartPassive() =
        assertHex("scan_start_passive", Messages.encodeScanStart(passive = true, periodMs = 120))

    @Test fun scanGetStatus() = assertHex("scan_get_status", Messages.encodeScanGetStatus())

    @Test fun scanGetResults() = assertHex("scan_get_results", Messages.encodeScanGetResults(4, 6))

    @Test fun credWrite() = assertHex(
        "cred_write",
        Messages.encodeCredWrite(CredKind.DEVICE_CERT, 0, 6, hex("30820102aabb")),
    )

    @Test fun credFinalize() = assertHex("cred_finalize", Messages.encodeCredFinalize())

    @Test fun credGetStatus() = assertHex("cred_get_status", Messages.encodeCredGetStatus())

    @Test fun ctrl() {
        assertHex("ctrl_reset", Messages.encodeCtrl(CtrlOp.RESET))
        assertHex("ctrl_reprov", Messages.encodeCtrl(CtrlOp.REPROVISION))
        assertHex("ctrl_end", Messages.encodeCtrl(CtrlOp.END))
    }

    // ---- response decoders (device -> client) -----------------------------

    @Test fun verRsp() {
        val info = Messages.decodeVerRsp(rsp("ver_rsp"))
        assertEquals(1, info.proto)
        assertEquals(listOf("wifi", "scan", "cred", "auth"), info.caps)
        assertEquals(512, info.blockSize)
        assertEquals("0.1.0", info.lib)
        assertTrue(info.popRequired)
    }

    @Test fun authChallengeRsp() {
        val (devNonce, devProof) = Messages.decodeAuthChallengeRsp(rsp("auth_challenge_rsp"))
        assertArrayEquals(bytes(0x10, 16), devNonce)
        assertArrayEquals(bytes(0x20, 32), devProof)
    }

    @Test fun authProofRspOk() = Messages.decodeAuthProofRsp(rsp("auth_proof_rsp"))

    @Test fun authProofRspUnauthorized() {
        val e = assertThrows(ProvError::class.java) {
            Messages.decodeAuthProofRsp(rsp("auth_proof_rsp_unauthorized"))
        }
        assertEquals(Status.UNAUTHORIZED, e.status)
    }

    @Test fun configStatusConnecting() {
        val s = Messages.decodeConfigStatusRsp(rsp("config_status_connecting"))
        assertEquals(StaState.CONNECTING, s.state)
    }

    @Test fun configStatusFailedAuth() {
        val s = Messages.decodeConfigStatusRsp(rsp("config_status_failed_auth"))
        assertEquals(StaState.FAILED, s.state)
        assertEquals(FailReason.AUTH_ERROR, s.failReason)
    }

    @Test fun configStatusConnected() {
        val s = Messages.decodeConfigStatusRsp(rsp("config_status_connected"))
        assertEquals(StaState.CONNECTED, s.state)
        assertArrayEquals(hex("c0a80107"), s.ip4)
        assertArrayEquals("myssid".toByteArray(), s.ssid)
        assertEquals(-41, s.rssi)
    }

    @Test fun scanStatusRsp() {
        val (finished, total) = Messages.decodeScanStatusRsp(rsp("scan_status_rsp"))
        assertTrue(finished)
        assertEquals(9, total)
    }

    @Test fun scanResultsRsp() {
        val entries = Messages.decodeScanResultsRsp(rsp("scan_results_rsp"))
        assertEquals(2, entries.size)
        assertArrayEquals("myssid".toByteArray(), entries[0].ssid)
        assertEquals(11, entries[0].channel)
        assertEquals(-41, entries[0].rssi)
        assertEquals(1, entries[0].auth)
        assertArrayEquals("guest".toByteArray(), entries[1].ssid)
        assertEquals(-73, entries[1].rssi)
    }

    @Test fun credWriteRsp() = assertEquals(6, Messages.decodeCredWriteRsp(rsp("cred_write_rsp")))

    @Test fun credStatusRsp() {
        val status = Messages.decodeCredStatusRsp(rsp("cred_status_rsp"))
        assertEquals(1042, status[CredKind.DEVICE_CERT])
        assertEquals(121, status[CredKind.PRIVATE_KEY])
    }

    @Test fun ctrlEndRsp() = Messages.decodeCtrlRsp(rsp("ctrl_end_rsp"), CtrlOp.END)

    // ---- pouch framing ----------------------------------------------------

    @Test fun singleEntry() = assertFrame(
        "single_entry",
        Pouch.buildEntryPouch("dev-1", listOf(Entry(Messages.PATH_VER, 60, Messages.encodeVerReq()))),
    )

    @Test fun twoEntriesOneBlock() = assertFrame(
        "two_entries_one_block",
        Pouch.buildEntryPouch(
            "dev-1",
            listOf(
                Entry(
                    Messages.PATH_CONFIG,
                    60,
                    Messages.encodeConfigSet("myssid".toByteArray(), "hunter22".toByteArray()),
                ),
                Entry(Messages.PATH_CONFIG, 60, Messages.encodeConfigApply()),
            ),
        ),
    )

    @Test fun twoBlocks() {
        val zeros = ByteArray(24)
        // block_size forces each cred entry into its own block (entry1=68B, entry2=69B).
        val pouch = Pouch.buildEntryPouch(
            "dev-1",
            listOf(
                Entry(Messages.PATH_CRED, 60, Messages.encodeCredWrite(CredKind.DEVICE_CERT, 0, 48, zeros)),
                Entry(Messages.PATH_CRED, 60, Messages.encodeCredWrite(CredKind.DEVICE_CERT, 24, 48, zeros)),
            ),
            blockSize = 100,
        )
        assertFrame("two_blocks", pouch)
    }

    @Test fun emptyPouch() =
        assertFrame("empty", Pouch.buildEntryPouch("dev-1", emptyList()))

    @Test fun roundTripSingleEntry() {
        val (header, entries) = Pouch.parsePouch(hex(frames.getString("single_entry")))
        assertEquals("dev-1", header.deviceId)
        assertEquals(1, entries.size)
        assertEquals(Messages.PATH_VER, entries[0].path)
        assertArrayEquals(Messages.encodeVerReq(), entries[0].data)
    }

    // ---- helpers ----------------------------------------------------------

    private fun assertHex(name: String, actual: ByteArray) =
        assertArrayEquals("request $name", hex(requests().getString(name)), actual)

    private fun rsp(name: String): ByteArray = hex(responses().getString(name))

    private fun assertFrame(name: String, actual: ByteArray) =
        assertArrayEquals("frame $name", hex(frames.getString(name)), actual)

    private fun bytes(start: Int, len: Int) = ByteArray(len) { (start + it).toByte() }

    companion object {
        fun loadVectors(fileName: String): JSONObject {
            val dir = System.getProperty("pouchprov.vectors.dir")
                ?: error("pouchprov.vectors.dir system property not set")
            return JSONObject(File(dir, fileName).readText())
        }

        fun hex(s: String): ByteArray {
            val clean = s.trim()
            return ByteArray(clean.length / 2) {
                ((Character.digit(clean[it * 2], 16) shl 4) + Character.digit(clean[it * 2 + 1], 16)).toByte()
            }
        }
    }
}
