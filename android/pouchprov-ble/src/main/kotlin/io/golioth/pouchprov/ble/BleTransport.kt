// Copyright (c) 2026 Jonathan Beri
// SPDX-License-Identifier: Apache-2.0

package io.golioth.pouchprov.ble

import android.bluetooth.BluetoothDevice
import android.content.Context
import io.golioth.pouchprov.transport.Channel
import io.golioth.pouchprov.transport.Transport
import java.util.UUID

/**
 * A pouch [Transport] over Android BLE GATT. Each pouch characteristic (uplink,
 * downlink) is exposed as a [Channel]: writes go to that characteristic and a
 * subscribe/unsubscribe cycle toggles its notifications — one subscribe == one
 * SAR transaction (pouch CCC semantics). Mirrors the Python `transport.ble`.
 */
class BleTransport(context: Context, device: BluetoothDevice) : Transport {

    private val gatt = GattClient(context, device)

    override val downlink: Channel = BleChannel(gatt, BleUuids.DOWNLINK)
    override val uplink: Channel = BleChannel(gatt, BleUuids.UPLINK)

    override suspend fun connect() = gatt.connect()

    override suspend fun disconnect() = gatt.disconnect()

    /** Remove any existing bond, forcing a fresh pairing on the next connect. */
    fun forgetBond() = gatt.forgetBond()
}

private class BleChannel(private val gatt: GattClient, private val uuid: UUID) : Channel {
    override suspend fun write(data: ByteArray) = gatt.write(uuid, data)

    override suspend fun subscribe(onNotify: (ByteArray) -> Unit) = gatt.setNotify(uuid, true, onNotify)

    override suspend fun unsubscribe() = gatt.setNotify(uuid, false, null)
}
