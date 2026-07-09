// Copyright (c) 2026 Jonathan Beri
// SPDX-License-Identifier: Apache-2.0

package io.golioth.pouchprov.ble

import android.annotation.SuppressLint
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.bluetooth.BluetoothStatusCodes
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.util.Log
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.delay
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeout
import java.util.UUID

/**
 * A thin, coroutine-friendly wrapper over Android's callback-based
 * [BluetoothGatt]. Android permits only one outstanding GATT operation, so every
 * operation is serialized through [opLock] and awaited via a [CompletableDeferred]
 * completed from the [BluetoothGattCallback].
 *
 * It also handles the pouch link's mandatory encryption: pouch characteristics
 * require an encrypted (bonded) LE Secure-Connections link and the device sends
 * the SMP Security Request, so we let bonding settle before I/O and retry writes
 * through the transient "Insufficient Encryption" window (mirrors `ble.py`).
 */
@SuppressLint("MissingPermission")
class GattClient(private val context: Context, private val device: BluetoothDevice) {

    companion object {
        private const val TAG = "PouchGatt"
        private const val GATT_INSUFFICIENT_ENCRYPTION = 15
        private const val GATT_INSUFFICIENT_AUTHENTICATION = 5
        // ATT "Unlikely Error" (0x0E). The pouch device returns this transiently
        // at SAR endpoint transitions (e.g. subscribing uplink right after the
        // downlink transfer closes) while its state machine catches up; retry.
        private const val GATT_UNLIKELY_ERROR = 14
        private const val ENCRYPTION_RETRY_MS = 12_000L
        private const val TARGET_MTU = 247
        // Pairing may surface a system consent dialog the user must accept.
        private const val PAIRING_TIMEOUT_MS = 90_000L
    }

    private var gatt: BluetoothGatt? = null
    private val opLock = Mutex()

    private var connected: CompletableDeferred<Unit>? = null
    private var servicesDiscovered: CompletableDeferred<Unit>? = null
    private var mtuChanged: CompletableDeferred<Int>? = null
    private var writeDone: CompletableDeferred<Int>? = null
    private var descriptorDone: CompletableDeferred<Int>? = null
    private var readDone: CompletableDeferred<Pair<Int, ByteArray>>? = null
    private var bonded: CompletableDeferred<Unit>? = null

    /** Per-characteristic notification sinks. */
    private val notifySinks = HashMap<UUID, (ByteArray) -> Unit>()

    private val bondReceiver = object : BroadcastReceiver() {
        override fun onReceive(ctx: Context, intent: Intent) {
            if (intent.action != BluetoothDevice.ACTION_BOND_STATE_CHANGED) return
            val dev = intent.getParcelableExtra<BluetoothDevice>(BluetoothDevice.EXTRA_DEVICE)
            if (dev?.address != device.address) return
            val state = intent.getIntExtra(BluetoothDevice.EXTRA_BOND_STATE, BluetoothDevice.BOND_NONE)
            if (state == BluetoothDevice.BOND_BONDED) bonded?.complete(Unit)
        }
    }

    private val callback = object : BluetoothGattCallback() {
        override fun onConnectionStateChange(g: BluetoothGatt, status: Int, newState: Int) {
            if (newState == BluetoothProfile.STATE_CONNECTED) {
                connected?.complete(Unit)
            } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                connected?.completeExceptionally(BleError("disconnected (status $status)"))
            }
        }

        override fun onServicesDiscovered(g: BluetoothGatt, status: Int) {
            servicesDiscovered?.complete(Unit)
        }

        override fun onMtuChanged(g: BluetoothGatt, mtu: Int, status: Int) {
            mtuChanged?.complete(mtu)
        }

        override fun onCharacteristicWrite(g: BluetoothGatt, c: BluetoothGattCharacteristic, status: Int) {
            writeDone?.complete(status)
        }

        // API 33+ delivers the value directly; the deprecated variant fires on older releases.
        override fun onCharacteristicChanged(g: BluetoothGatt, c: BluetoothGattCharacteristic, value: ByteArray) {
            notifySinks[c.uuid]?.invoke(value)
        }

        @Suppress("DEPRECATION")
        @Deprecated("Fallback for API < 33")
        override fun onCharacteristicChanged(g: BluetoothGatt, c: BluetoothGattCharacteristic) {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
                notifySinks[c.uuid]?.invoke(c.value ?: return)
            }
        }

        override fun onCharacteristicRead(g: BluetoothGatt, c: BluetoothGattCharacteristic, value: ByteArray, status: Int) {
            readDone?.complete(status to value)
        }

        @Suppress("DEPRECATION")
        @Deprecated("Fallback for API < 33")
        override fun onCharacteristicRead(g: BluetoothGatt, c: BluetoothGattCharacteristic, status: Int) {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
                readDone?.complete(status to (c.value ?: ByteArray(0)))
            }
        }

        override fun onDescriptorWrite(g: BluetoothGatt, d: BluetoothGattDescriptor, status: Int) {
            descriptorDone?.complete(status)
        }
    }

    // ---- lifecycle -------------------------------------------------------

    suspend fun connect(timeoutMs: Long = 20_000) {
        context.registerReceiver(bondReceiver, IntentFilter(BluetoothDevice.ACTION_BOND_STATE_CHANGED))
        connected = CompletableDeferred()
        gatt = device.connectGatt(context, false, callback, BluetoothDevice.TRANSPORT_LE)
        withTimeout(timeoutMs) { connected!!.await() }

        servicesDiscovered = CompletableDeferred()
        gatt!!.discoverServices()
        withTimeout(timeoutMs) { servicesDiscovered!!.await() }

        mtuChanged = CompletableDeferred()
        gatt!!.requestMtu(TARGET_MTU)
        runCatching { withTimeout(5_000) { mtuChanged!!.await() } }

        ensureEncrypted(timeoutMs)
    }

    /**
     * Ensure the link is encrypted before any pouch I/O — the pouch
     * characteristics require an encrypted LE Secure-Connections link. The
     * peripheral sends an SMP Security Request on connect, so the link encrypts
     * automatically when already bonded, or pairs when not.
     *
     * We deliberately do NOT call [BluetoothDevice.createBond] when a bond
     * already exists: doing so on an already-encrypted link makes the device drop
     * the connection. [BluetoothDevice.getBondState] on a scan-derived device is
     * also unreliable, so bond status is checked against the adapter's
     * authoritative bonded list.
     */
    private suspend fun ensureEncrypted(timeoutMs: Long) {
        if (isBonded()) {
            // Bonded: let the peripheral-initiated re-encryption settle.
            delay(1200)
            return
        }
        // Not bonded: nudge pairing and wait for it (best-effort — the write path
        // also retries through the transient insufficient-encryption window).
        bonded = CompletableDeferred()
        if (device.bondState == BluetoothDevice.BOND_NONE) runCatching { device.createBond() }
        runCatching { withTimeout(PAIRING_TIMEOUT_MS) { bonded!!.await() } }
        delay(500)
    }

    private fun isBonded(): Boolean {
        if (device.bondState == BluetoothDevice.BOND_BONDED) return true
        val adapter = (context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager)?.adapter
        return adapter?.bondedDevices?.any { it.address == device.address } == true
    }

    /** GATT statuses that are transient at pouch SAR boundaries and worth retrying. */
    private fun Int.isRetryable(): Boolean =
        this == GATT_INSUFFICIENT_ENCRYPTION ||
            this == GATT_INSUFFICIENT_AUTHENTICATION ||
            this == GATT_UNLIKELY_ERROR

    /** Remove any existing bond to this device (forces a fresh pairing on next connect). */
    fun forgetBond() {
        if (device.bondState == BluetoothDevice.BOND_NONE) return
        runCatching { BluetoothDevice::class.java.getMethod("removeBond").invoke(device) }
    }

    fun disconnect() {
        runCatching { context.unregisterReceiver(bondReceiver) }
        gatt?.disconnect()
        gatt?.close()
        gatt = null
    }

    // ---- operations ------------------------------------------------------

    /** Whether the discovered services expose [uuid] (call after connect). */
    fun hasCharacteristic(uuid: UUID): Boolean = runCatching { characteristic(uuid) }.isSuccess

    private fun characteristic(uuid: UUID): BluetoothGattCharacteristic {
        // The pouch peripheral declares its primary service with the 16-bit UUID
        // 0xFC49 (the 128-bit ...d272 is only used by pouch's central/broker
        // code), so look the characteristic up across all discovered services
        // rather than assuming a single service UUID.
        val g = gatt ?: throw BleError("not connected")
        g.getService(BleUuids.SERVICE)?.getCharacteristic(uuid)?.let { return it }
        for (service in g.services) {
            service.getCharacteristic(uuid)?.let { return it }
        }
        throw BleError("characteristic $uuid not found (service not discovered?)")
    }

    /** Write with response, retrying through the transient insufficient-encryption window. */
    suspend fun write(uuid: UUID, data: ByteArray): Unit = opLock.withLock {
        val c = characteristic(uuid)
        val deadline = System.nanoTime() / 1_000_000 + ENCRYPTION_RETRY_MS
        while (true) {
            writeDone = CompletableDeferred()
            val g = gatt ?: throw BleError("not connected")
            val initiated = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                g.writeCharacteristic(c, data, BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT) ==
                    BluetoothStatusCodes.SUCCESS
            } else {
                @Suppress("DEPRECATION")
                run {
                    c.writeType = BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT // Write With Response
                    c.value = data
                    g.writeCharacteristic(c)
                }
            }
            if (!initiated) throw BleError("writeCharacteristic($uuid) rejected")
            val status = withTimeout(10_000) { writeDone!!.await() }
            when {
                status == BluetoothGatt.GATT_SUCCESS -> return@withLock
                // "Unlikely Error" (14) on a characteristic write is ambiguous but
                // the write has, in practice, already been delivered to the pouch
                // SAR endpoint. Do NOT re-send (a duplicate SAR fragment wedges the
                // receiver with "Invalid state") and do NOT fail — treat it as sent
                // and let the SAR ack/re-ack confirm delivery.
                status == GATT_UNLIKELY_ERROR -> return@withLock
                (status == GATT_INSUFFICIENT_ENCRYPTION || status == GATT_INSUFFICIENT_AUTHENTICATION) &&
                    System.nanoTime() / 1_000_000 < deadline -> {
                    Log.d(TAG, "write($uuid) pending encryption (status $status); retrying")
                    delay(300)
                }
                else -> throw BleError("write($uuid) failed with status $status")
            }
        }
    }

    @Suppress("DEPRECATION")
    private suspend fun readCharacteristic(uuid: UUID): ByteArray = opLock.withLock {
        val c = characteristic(uuid)
        readDone = CompletableDeferred()
        if (gatt?.readCharacteristic(c) != true) throw BleError("readCharacteristic($uuid) rejected")
        val (status, value) = withTimeout(10_000) { readDone!!.await() }
        if (status != BluetoothGatt.GATT_SUCCESS) throw BleError("read($uuid) failed with status $status")
        value
    }

    /** Enable or disable notifications (writes the CCC descriptor). */
    suspend fun setNotify(uuid: UUID, enable: Boolean, onNotify: ((ByteArray) -> Unit)?): Unit = opLock.withLock {
        val c = characteristic(uuid)
        val g = gatt ?: throw BleError("not connected")
        g.setCharacteristicNotification(c, enable)
        if (enable && onNotify != null) notifySinks[uuid] = onNotify else notifySinks.remove(uuid)
        val ccc = c.getDescriptor(BleUuids.CCC) ?: throw BleError("CCC descriptor missing on $uuid")
        val value = if (enable) {
            BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
        } else {
            BluetoothGattDescriptor.DISABLE_NOTIFICATION_VALUE
        }
        // Disabling notifications is per-transaction SAR cleanup: the pouch device
        // tears down its SAR endpoint on its own, and the disable-CCC write often
        // comes back with "Unlikely Error" as it does. It's best-effort — never
        // fail the transaction on it.
        if (!enable) {
            descriptorDone = CompletableDeferred()
            runCatching {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    g.writeDescriptor(ccc, value)
                } else {
                    @Suppress("DEPRECATION") run { ccc.value = value; g.writeDescriptor(ccc) }
                }
                withTimeout(3_000) { descriptorDone!!.await() }
            }
            return@withLock
        }
        // The CCC descriptor also requires encryption; retry through the transient
        // window while the peripheral-initiated encryption settles.
        val deadline = System.nanoTime() / 1_000_000 + ENCRYPTION_RETRY_MS
        while (true) {
            descriptorDone = CompletableDeferred()
            val rc: Int = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                g.writeDescriptor(ccc, value)
            } else {
                @Suppress("DEPRECATION")
                run {
                    ccc.value = value
                    if (g.writeDescriptor(ccc)) BluetoothStatusCodes.SUCCESS else -1
                }
            }
            if (rc != BluetoothStatusCodes.SUCCESS) {
                if (System.nanoTime() / 1_000_000 < deadline) {
                    delay(500)
                    continue
                }
                throw BleError("writeDescriptor($uuid CCC) rejected (rc=$rc)")
            }
            val status = withTimeout(10_000) { descriptorDone!!.await() }
            when {
                status == BluetoothGatt.GATT_SUCCESS -> return@withLock
                status.isRetryable() && System.nanoTime() / 1_000_000 < deadline -> delay(300)
                else -> throw BleError("CCC write on $uuid failed with status $status")
            }
        }
    }
}

class BleError(message: String) : Exception(message)
