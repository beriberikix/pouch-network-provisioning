// Copyright (c) 2026 Jonathan Beri
// SPDX-License-Identifier: Apache-2.0

package io.golioth.pouchprov.ble

import android.annotation.SuppressLint
import android.bluetooth.BluetoothDevice
import android.content.Context
import io.golioth.pouchprov.Auth
import io.golioth.pouchprov.Flows
import io.golioth.pouchprov.Pem
import io.golioth.pouchprov.ScanEntry
import io.golioth.pouchprov.VersionInfo
import io.golioth.pouchprov.WifiStatus
import io.golioth.pouchprov.session.ProvSession
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * A virtual handle to a physical pouch device — the pouch-branded analogue of
 * Espressif's `ESPDevice`. Wraps a [BleTransport] and a [ProvSession] and exposes
 * provisioning verbs that mirror the Python CLI (`discover`/`version`/`wifi-scan`/
 * `provision`). All methods are `suspend`; run them off the main thread.
 */
@SuppressLint("MissingPermission")
class PouchProvDevice internal constructor(
    private val context: Context,
    val device: BluetoothDevice,
    val name: String?,
    val rssi: Int,
) {
    private val transport = BleTransport(context, device)
    private var session: ProvSession? = null

    /** Whether the mutual PoP handshake has already succeeded on this session. */
    private var authorized = false

    private val _state = MutableStateFlow<ProvisionState>(ProvisionState.Idle)

    /** Live provisioning progress, primarily for driving a UI. */
    val state: StateFlow<ProvisionState> = _state.asStateFlow()

    val address: String get() = device.address

    private fun requireSession(): ProvSession =
        session ?: throw IllegalStateException("not connected — call connect() first")

    /** Connect, pair/encrypt, discover the pouch service, and open a session. */
    suspend fun connect() {
        _state.value = ProvisionState.Connecting
        transport.connect()
        session = ProvSession(transport)
        authorized = false
    }

    suspend fun disconnect() {
        transport.disconnect()
        session = null
        authorized = false
    }

    /** Remove any stale bond to this device so the next [connect] pairs afresh. */
    fun forgetBond() = transport.forgetBond()

    /** Query `.prov/ver`. */
    suspend fun version(): VersionInfo = Flows.getVersion(requireSession())

    /** Run the mutual proof-of-possession handshake once per session (idempotent). */
    suspend fun authorize(pop: String) {
        if (authorized) return
        Auth.authorize(requireSession(), pop)
        authorized = true
    }

    /** Scan for Wi-Fi networks visible to the device (Wi-Fi devices only). */
    suspend fun scanWifi(): List<ScanEntry> = Flows.scan(requireSession())

    /** Set + apply Wi-Fi credentials and wait for the connection to settle. */
    suspend fun provisionWifi(ssid: String, password: String?): WifiStatus =
        Flows.configureWifi(requireSession(), ssid.toByteArray(), password?.toByteArray())

    /** Push device cert + key (+ optional CA) as DER (PEM inputs are accepted). */
    suspend fun provisionCredentials(cert: ByteArray, key: ByteArray, ca: ByteArray? = null) =
        Flows.bootstrapCredentials(requireSession(), Pem.toDer(cert), Pem.toDer(key), ca?.let { Pem.toDer(it) })

    /** End the session; the device proceeds to normal operation. */
    suspend fun end() = Flows.endSession(requireSession())

    /**
     * One-shot provisioning mirroring `pouchprov provision`: version -> authorize
     * (if required) -> credentials (if present) -> Wi-Fi (if present and
     * supported) -> end. Branches on advertised caps so BLE-only devices skip
     * Wi-Fi. Progress is published to [state].
     */
    suspend fun provision(request: ProvisionRequest): ProvisionResult {
        try {
            if (session == null) connect()
            val s = requireSession()

            _state.value = ProvisionState.Querying
            val info = Flows.getVersion(s)

            _state.value = ProvisionState.Authorizing
            if (info.popRequired) {
                val pop = request.pop?.takeIf { it.isNotEmpty() }
                    ?: throw IllegalStateException("device requires a proof-of-possession (pop)")
                authorize(pop) // guarded: no-op if already authorized (e.g. for scanWifi)
            }

            var credentialsStored = false
            if (request.certificate != null && request.privateKey != null) {
                _state.value = ProvisionState.PushingCredentials
                provisionCredentials(request.certificate, request.privateKey, request.caCertificate)
                credentialsStored = true
            }

            var wifi: WifiStatus? = null
            if (request.ssid != null) {
                if (!info.hasCap("wifi")) throw IllegalArgumentException("device does not support Wi-Fi provisioning")
                _state.value = ProvisionState.ConfiguringWifi(null)
                wifi = provisionWifi(request.ssid, request.password)
                _state.value = ProvisionState.ConfiguringWifi(wifi)
            }

            _state.value = ProvisionState.Finishing
            Flows.endSession(s)

            val result = ProvisionResult(info, wifi, credentialsStored)
            _state.value = ProvisionState.Done(result)
            return result
        } catch (e: Exception) {
            _state.value = ProvisionState.Failed(e)
            throw e
        }
    }
}

/**
 * A provisioning request mirroring the CLI's `provision` options. Provide
 * [ssid] and/or [certificate]+[privateKey]; certificates/keys may be PEM or DER.
 */
data class ProvisionRequest(
    val pop: String? = null,
    val ssid: String? = null,
    val password: String? = null,
    val certificate: ByteArray? = null,
    val privateKey: ByteArray? = null,
    val caCertificate: ByteArray? = null,
)

data class ProvisionResult(
    val version: VersionInfo,
    val wifi: WifiStatus?,
    val credentialsStored: Boolean,
)

/** Provisioning progress, suitable for driving a UI via [PouchProvDevice.state]. */
sealed interface ProvisionState {
    data object Idle : ProvisionState
    data object Connecting : ProvisionState
    data object Querying : ProvisionState
    data object Authorizing : ProvisionState
    data object PushingCredentials : ProvisionState
    data class ConfiguringWifi(val status: WifiStatus?) : ProvisionState
    data object Finishing : ProvisionState
    data class Done(val result: ProvisionResult) : ProvisionState
    data class Failed(val error: Throwable) : ProvisionState
}
