// Copyright (c) 2026 Jonathan Beri
// SPDX-License-Identifier: Apache-2.0

package io.golioth.pouchprov.transport

/**
 * Transport abstraction.
 *
 * A provisioning transport exposes the pouch uplink and downlink characteristics
 * as [Channel]s. A channel supports writing toward the device and a
 * subscribe/unsubscribe cycle delivering notifications; one subscribe == one SAR
 * transaction (pouch CCC semantics). Mirrors the Python `transport.base`.
 */
interface Channel {
    /** Write toward the device (Write With Response on real BLE). */
    suspend fun write(data: ByteArray)

    /** Enable notifications; the device side opens its SAR endpoint. */
    suspend fun subscribe(onNotify: (ByteArray) -> Unit)

    /** Disable notifications; the device side closes its SAR endpoint. */
    suspend fun unsubscribe()
}

interface Transport {
    /** client -> device requests */
    val downlink: Channel

    /** device -> client responses */
    val uplink: Channel

    // saead-only SAR endpoints (pouch GATT exposes them only on saead builds;
    // null when absent). info is a device-side sender, serverCert a receiver,
    // deviceCert a sender — all raw payloads, not pouch-framed.
    val info: Channel? get() = null
    val serverCert: Channel? get() = null
    val deviceCert: Channel? get() = null

    /**
     * Whether the device firmware is a saead build (compile-time feature,
     * detected from the presence of the server-cert endpoint).
     */
    val supportsSaead: Boolean get() = serverCert != null

    suspend fun connect()

    suspend fun disconnect()
}
