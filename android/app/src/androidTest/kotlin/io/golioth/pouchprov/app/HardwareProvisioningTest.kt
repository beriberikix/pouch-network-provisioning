// Copyright (c) 2026 Jonathan Beri
// SPDX-License-Identifier: Apache-2.0

package io.golioth.pouchprov.app

import android.content.Context
import android.util.Log
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.golioth.pouchprov.ble.PouchProvDevice
import io.golioth.pouchprov.ble.PouchProvManager
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.firstOrNull
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test
import org.junit.runner.RunWith

/**
 * On-device end-to-end test against a real ESP32-S3 running `samples/basic`
 * (plaintext). Exercises the full BLE stack that unit tests cannot reach: scan
 * by service data, GATT connect + LE Secure-Connections pairing, MTU, SAR over
 * notifications, pouch framing, and the lockstep session — via `.prov/ver` and
 * `.prov/ctrl`. Requires the board powered and advertising nearby.
 */
@RunWith(AndroidJUnit4::class)
class HardwareProvisioningTest {

    // Permissions are granted to the app package via adb before the run (see the
    // harness), so no GrantPermissionRule — that would contend for UiAutomation
    // with the consent-dialog auto-tapper.
    private val tag = "PouchHwTest"

    @Test
    fun scanConnectAndReadVersion() = runBlocking<Unit> {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        val manager = PouchProvManager(ctx)

        // Optionally target a specific device by name substring (e.g. when
        // multiple boards advertise): -e deviceName PVN-98fa8e
        val wantName = InstrumentationRegistry.getArguments().getString("deviceName")
        Log.i(tag, "scanning for a provisioning device… (target=${wantName ?: "any"})")
        val device: PouchProvDevice? = withTimeout(25_000) {
            manager.scan(timeoutMs = 25_000)
                .firstOrNull { wantName == null || (it.name?.contains(wantName) == true) }
        }
        assertNotNull("no pouch provisioning device found — is the board advertising?", device)
        Log.i(tag, "found ${device!!.name} (${device.address}) rssi=${device.rssi}")

        try {
            Log.i(tag, "connecting (pairing consent may be required on first run)…")
            device.connect()

            Log.i(tag, "reading .prov/ver…")
            val info = device.version()
            Log.i(tag, "version: proto=${info.proto} caps=${info.caps} blk=${info.blockSize} lib=${info.lib} pop=${info.popRequired}")
            assertEquals("unexpected protocol version", 1, info.proto)

            Log.i(tag, "ending session (.prov/ctrl end)…")
            device.end()
            Log.i(tag, "SUCCESS: full BLE round-trip against real hardware")
        } finally {
            device.disconnect()
        }
    }
}
