// Copyright (c) 2026 Jonathan Beri
// SPDX-License-Identifier: Apache-2.0

package io.golioth.pouchprov.app

import android.app.Application
import android.content.Context
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import io.golioth.pouchprov.ScanEntry
import io.golioth.pouchprov.VersionInfo
import io.golioth.pouchprov.cert.DeviceCert
import io.golioth.pouchprov.ble.PouchProvDevice
import io.golioth.pouchprov.ble.PouchProvManager
import io.golioth.pouchprov.ble.ProvisionRequest
import io.golioth.pouchprov.ble.ProvisionState
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Drives the reference provisioning flow: discover devices, connect + read the
 * device's capabilities, optionally scan Wi-Fi, then provision. Progress is
 * surfaced from the SDK's [PouchProvDevice.state].
 */
class ProvViewModel(app: Application) : AndroidViewModel(app) {

    private val manager = PouchProvManager(app)

    // -- settings (persisted) ----------------------------------------------
    private val prefs = app.getSharedPreferences("pouchprov", Context.MODE_PRIVATE)

    /** Golioth project API key — used by the (separate) CA-upload step. */
    private val _goliothApiKey = MutableStateFlow(prefs.getString(KEY_API, "").orEmpty())
    val goliothApiKey: StateFlow<String> = _goliothApiKey.asStateFlow()

    /** Generated-certificate validity, in days from creation (default 7). */
    private val _certValidityDays = MutableStateFlow(prefs.getInt(KEY_VALIDITY, DEFAULT_VALIDITY_DAYS))
    val certValidityDays: StateFlow<Int> = _certValidityDays.asStateFlow()

    fun setGoliothApiKey(value: String) {
        prefs.edit().putString(KEY_API, value).apply()
        _goliothApiKey.value = value
        golioth = null // rebuild the provider (and re-register a CA) with the new key
    }

    fun setCertValidityDays(days: Int) {
        val clamped = days.coerceIn(1, 3650)
        prefs.edit().putInt(KEY_VALIDITY, clamped).apply()
        _certValidityDays.value = clamped
    }

    // -- discovery ---------------------------------------------------------
    private val _devices = MutableStateFlow<List<PouchProvDevice>>(emptyList())
    val devices: StateFlow<List<PouchProvDevice>> = _devices.asStateFlow()

    private val _scanning = MutableStateFlow(false)
    val scanning: StateFlow<Boolean> = _scanning.asStateFlow()

    // -- selected device ---------------------------------------------------
    private val _selected = MutableStateFlow<PouchProvDevice?>(null)
    val selected: StateFlow<PouchProvDevice?> = _selected.asStateFlow()

    private val _connecting = MutableStateFlow(false)
    val connecting: StateFlow<Boolean> = _connecting.asStateFlow()

    private val _connectError = MutableStateFlow<String?>(null)
    val connectError: StateFlow<String?> = _connectError.asStateFlow()

    private val _version = MutableStateFlow<VersionInfo?>(null)
    val version: StateFlow<VersionInfo?> = _version.asStateFlow()

    // -- Wi-Fi scan --------------------------------------------------------
    private val _wifiScanning = MutableStateFlow(false)
    val wifiScanning: StateFlow<Boolean> = _wifiScanning.asStateFlow()

    private val _wifiNetworks = MutableStateFlow<List<ScanEntry>?>(null)
    val wifiNetworks: StateFlow<List<ScanEntry>?> = _wifiNetworks.asStateFlow()

    private val _wifiError = MutableStateFlow<String?>(null)
    val wifiError: StateFlow<String?> = _wifiError.asStateFlow()

    // -- locally-generated device certificate ------------------------------
    private val _generating = MutableStateFlow(false)
    val generating: StateFlow<Boolean> = _generating.asStateFlow()

    /** Non-null (the CN) once a certificate has been generated locally. */
    private val _generatedCn = MutableStateFlow<String?>(null)
    val generatedCn: StateFlow<String?> = _generatedCn.asStateFlow()

    /** Non-null when local/Golioth cert generation failed. */
    private val _certError = MutableStateFlow<String?>(null)
    val certError: StateFlow<String?> = _certError.asStateFlow()

    private var generatedCert: ByteArray? = null
    private var generatedKey: ByteArray? = null
    private var golioth: GoliothCertProvider? = null

    /** Generate a self-signed device cert/key locally (CN = device identifier). */
    fun generateCert(commonName: String) {
        _generating.value = true
        _certError.value = null
        viewModelScope.launch {
            try {
                val cn = commonName.ifBlank { "pouch-device" }
                val creds = withContext(Dispatchers.Default) {
                    DeviceCert.generateSelfSigned(cn, validityDays = _certValidityDays.value)
                }
                generatedCert = creds.certificatePem
                generatedKey = creds.privateKeyPem
                _generatedCn.value = cn
            } catch (e: Exception) {
                _certError.value = e.message ?: e.toString()
            } finally {
                _generating.value = false
            }
        }
    }

    /**
     * Mint a Golioth-ready device cert: register a demo CA (once) and sign a device
     * cert with it, using the API key from Settings. See `docs/golioth-demo-certs.md`.
     */
    fun mintGoliothCert(commonName: String) {
        val apiKey = _goliothApiKey.value
        if (apiKey.isBlank()) {
            _certError.value = "Set a Golioth API key in Settings first"
            return
        }
        _generating.value = true
        _certError.value = null
        viewModelScope.launch {
            try {
                val cn = commonName.ifBlank { "pouch-device" }
                val provider = golioth ?: GoliothCertProvider(apiKey).also { golioth = it }
                val creds = provider.mintDeviceCredentials(cn, _certValidityDays.value)
                generatedCert = creds.certificatePem
                generatedKey = creds.privateKeyPem
                _generatedCn.value = "$cn (Golioth)"
            } catch (e: Exception) {
                _certError.value = e.message ?: e.toString()
            } finally {
                _generating.value = false
            }
        }
    }

    /** The locally-generated (cert, key) PEM pair, or null if none generated. */
    fun generatedCredentials(): Pair<ByteArray, ByteArray>? {
        val c = generatedCert ?: return null
        val k = generatedKey ?: return null
        return c to k
    }

    private fun clearGenerated() {
        generatedCert = null
        generatedKey = null
        _generatedCn.value = null
        _certError.value = null
    }

    // -- provisioning progress --------------------------------------------
    private val _provisionState = MutableStateFlow<ProvisionState>(ProvisionState.Idle)
    val provisionState: StateFlow<ProvisionState> = _provisionState.asStateFlow()

    /** True once a provision run has been started (drives the progress UI). */
    private val _provisioning = MutableStateFlow(false)
    val provisioning: StateFlow<Boolean> = _provisioning.asStateFlow()

    private var scanJob: Job? = null
    private var stateJob: Job? = null

    fun startScan() {
        scanJob?.cancel()
        _devices.value = emptyList()
        _scanning.value = true
        scanJob = viewModelScope.launch {
            try {
                manager.scan(timeoutMs = 12_000).collect { device ->
                    if (_devices.value.none { it.address == device.address }) {
                        _devices.value = _devices.value + device
                    }
                }
            } finally {
                _scanning.value = false
            }
        }
    }

    /** Select a device, connect, and read its version/capabilities. */
    fun select(device: PouchProvDevice) {
        scanJob?.cancel()
        _scanning.value = false
        _selected.value = device
        _version.value = null
        _connectError.value = null
        _wifiNetworks.value = null
        _wifiError.value = null
        _provisionState.value = ProvisionState.Idle
        clearGenerated()

        stateJob?.cancel()
        stateJob = viewModelScope.launch { device.state.collect { _provisionState.value = it } }

        _connecting.value = true
        viewModelScope.launch {
            try {
                withContext(Dispatchers.IO) {
                    device.connect()
                    _version.value = device.version()
                }
            } catch (e: Exception) {
                _connectError.value = e.message ?: e.toString()
            } finally {
                _connecting.value = false
            }
        }
    }

    /** Authorize (if the device requires PoP) then scan for visible Wi-Fi networks. */
    fun scanWifi(pop: String) {
        val device = _selected.value ?: return
        _wifiError.value = null
        _wifiScanning.value = true
        viewModelScope.launch {
            try {
                withContext(Dispatchers.IO) {
                    if (_version.value?.popRequired == true) device.authorize(pop)
                    _wifiNetworks.value = device.scanWifi()
                }
            } catch (e: Exception) {
                _wifiError.value = e.message ?: e.toString()
            } finally {
                _wifiScanning.value = false
            }
        }
    }

    fun provision(
        pop: String?,
        ssid: String?,
        password: String?,
        cert: ByteArray?,
        key: ByteArray?,
        ca: ByteArray?,
    ) {
        val device = _selected.value ?: return
        _provisioning.value = true
        viewModelScope.launch {
            withContext(Dispatchers.IO) {
                runCatching {
                    device.provision(
                        ProvisionRequest(
                            pop = pop?.ifBlank { null },
                            ssid = ssid?.ifBlank { null },
                            password = password?.ifBlank { null },
                            certificate = cert,
                            privateKey = key,
                            caCertificate = ca,
                        ),
                    )
                }
                // Terminal state (Done/Failed) is published via device.state.
            }
        }
    }

    /** Forget the bond so the device can be paired from scratch, then return to scan. */
    fun forgetAndRepair() {
        _selected.value?.forgetBond()
        back()
    }

    /** Return to the editable form after a finished/failed run (keeps the connection). */
    fun resetProvision() {
        _provisioning.value = false
        _provisionState.value = ProvisionState.Idle
    }

    fun back() {
        stateJob?.cancel()
        _provisioning.value = false
        val device = _selected.value
        _selected.value = null
        _version.value = null
        _wifiNetworks.value = null
        _connectError.value = null
        _provisionState.value = ProvisionState.Idle
        clearGenerated()
        viewModelScope.launch { runCatching { withContext(Dispatchers.IO) { device?.disconnect() } } }
    }

    companion object {
        private const val KEY_API = "golioth_api_key"
        private const val KEY_VALIDITY = "cert_validity_days"
        const val DEFAULT_VALIDITY_DAYS = 7
    }
}
