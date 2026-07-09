// Copyright (c) 2026 Jonathan Beri
// SPDX-License-Identifier: Apache-2.0

package io.golioth.pouchprov.ble

import android.os.ParcelUuid
import java.util.UUID

/**
 * Pouch BLE GATT identifiers and advertising flags (from the pouch GATT
 * transport and this project's `transport/ble.py`). The device is the GATT
 * server; the client is central.
 */
object BleUuids {
    /** 16-bit service UUID used in advertising service data. */
    val SERVICE_UUID16: ParcelUuid = ParcelUuid.fromString("0000fc49-0000-1000-8000-00805f9b34fb")

    /**
     * The peripheral's primary GATT service UUID. The pouch Zephyr peripheral
     * declares it with the 16-bit `0xFC49` (expanded to the Bluetooth base UUID),
     * so that — not the 128-bit form below — is what a central discovers.
     */
    val SERVICE: UUID = SERVICE_UUID16.uuid

    /** 128-bit pouch service UUID (used by pouch's central/broker code, not the peripheral). */
    val SERVICE_128: UUID = UUID.fromString("89a316ae-89b7-4ef6-b1d3-5c9a6e27d272")

    /** device -> client responses (notify). */
    val UPLINK: UUID = UUID.fromString("89a316ae-89b7-4ef6-b1d3-5c9a6e27d273")

    /** client -> device requests (write + notify). */
    val DOWNLINK: UUID = UUID.fromString("89a316ae-89b7-4ef6-b1d3-5c9a6e27d274")

    /** info SAR endpoint ({flags, server_cert_snr}; device-side sender). */
    val INFO: UUID = UUID.fromString("89a316ae-89b7-4ef6-b1d3-5c9a6e27d275")

    /** server-cert SAR endpoint (client pushes its cert; saead builds only). */
    val SERVER_CERT: UUID = UUID.fromString("89a316ae-89b7-4ef6-b1d3-5c9a6e27d276")

    /** device-cert SAR endpoint (device sends its identity cert; saead builds only). */
    val DEVICE_CERT: UUID = UUID.fromString("89a316ae-89b7-4ef6-b1d3-5c9a6e27d277")

    /** Client Characteristic Configuration descriptor (enables notifications). */
    val CCC: UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")

    // Advertising flags byte (pouch service data): bit1 = provisioning available.
    const val ADV_FLAG_SYNC_REQUEST = 0x01
    const val ADV_FLAG_PROVISIONING = 0x02
}
