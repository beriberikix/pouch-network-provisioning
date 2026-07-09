// Copyright (c) 2026 Jonathan Beri
// SPDX-License-Identifier: Apache-2.0

package io.golioth.pouchprov.ble

import android.annotation.SuppressLint
import android.bluetooth.BluetoothManager
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.os.ParcelUuid
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.launch

/**
 * Entry point for discovering and provisioning pouch devices over BLE — the
 * pouch-branded analogue of Espressif's `ESPProvisionManager`.
 *
 * The caller is responsible for holding the runtime BLE permissions
 * (BLUETOOTH_SCAN/CONNECT on API 31+, or location on older releases) before
 * calling [scan].
 */
@SuppressLint("MissingPermission")
class PouchProvManager(private val context: Context) {

    private val adapter by lazy {
        (context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager).adapter
    }

    /**
     * Scan for devices advertising the pouch service with the provisioning flag
     * set. Emits a [PouchProvDevice] the first time each device is seen. The flow
     * runs until cancelled or [timeoutMs] elapses.
     *
     * With [includeAll], pouch devices *not* in provisioning mode are emitted too
     * (mirrors the CLI's `discover --all`); check [PouchProvDevice.provisioning]
     * before connecting.
     */
    fun scan(timeoutMs: Long = 10_000, includeAll: Boolean = false): Flow<PouchProvDevice> = callbackFlow {
        val scanner = adapter?.bluetoothLeScanner ?: throw BleError("Bluetooth is off or unavailable")
        val seen = HashSet<String>()

        val callback = object : ScanCallback() {
            override fun onScanResult(callbackType: Int, result: ScanResult) {
                val record = result.scanRecord ?: return
                val serviceData = record.getServiceData(BleUuids.SERVICE_UUID16) ?: return
                if (serviceData.size < 2) return
                val version = serviceData[0].toInt() and 0xFF
                val flags = serviceData[1].toInt() and 0xFF
                val provisioning = flags and BleUuids.ADV_FLAG_PROVISIONING != 0
                if (!includeAll && !provisioning) return
                if (!seen.add(result.device.address)) return
                trySend(
                    PouchProvDevice(
                        context = context,
                        device = result.device,
                        name = record.deviceName ?: result.device.name,
                        rssi = result.rssi,
                        provisioning = provisioning,
                        pouchVersion = version shr 4,
                        gattVersion = version and 0x0F,
                    ),
                )
            }
        }

        val filter = ScanFilter.Builder().setServiceData(BleUuids.SERVICE_UUID16, byteArrayOf()).build()
        val settings = ScanSettings.Builder().setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY).build()
        scanner.startScan(listOf(filter), settings, callback)

        val closer = launch {
            delay(timeoutMs)
            close()
        }

        awaitClose {
            closer.cancel()
            scanner.stopScan(callback)
        }
    }

    /** Wrap an already-known [android.bluetooth.BluetoothDevice] (e.g. from a QR/paired list). */
    fun device(device: android.bluetooth.BluetoothDevice): PouchProvDevice =
        PouchProvDevice(context, device, device.name, rssi = 0)

    companion object {
        @Suppress("unused")
        private fun serviceUuid(): ParcelUuid = BleUuids.SERVICE_UUID16
    }
}
