// Copyright (c) 2026 Jonathan Beri
// SPDX-License-Identifier: Apache-2.0

package io.golioth.pouchprov

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Wi-Fi security-type names. The integers are Zephyr's enum wifi_security_type,
 * carried verbatim in ScanEntry.auth; names must match the other clients.
 */
class SecurityNameTest {

    @Test
    fun knownTypes() {
        val expected = mapOf(
            0 to "Open",
            1 to "WPA2-PSK",
            2 to "WPA2-PSK-SHA256",
            3 to "WPA3-SAE",
            4 to "WPA3-SAE-H2E",
            5 to "WPA3-SAE-AUTO",
            6 to "WAPI",
            7 to "EAP-TLS",
            8 to "WEP",
            9 to "WPA-PSK",
            10 to "WPA/WPA2-Auto",
            11 to "DPP",
        )
        for ((auth, name) in expected) {
            assertEquals(name, securityName(auth))
        }
    }

    @Test
    fun unknownTypes() {
        assertEquals("unknown(42)", securityName(42))
        assertEquals("unknown(-1)", securityName(-1))
    }

    @Test
    fun scanEntryAuthName() {
        val entry = ScanEntry(
            ssid = "x".toByteArray(),
            bssid = ByteArray(0),
            channel = 1,
            rssi = -40,
            auth = 3,
        )
        assertEquals("WPA3-SAE", entry.authName)
    }
}
