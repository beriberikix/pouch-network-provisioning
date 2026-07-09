// Copyright (c) 2026 Jonathan Beri
// SPDX-License-Identifier: Apache-2.0

package io.golioth.pouchprov.app

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import io.golioth.pouchprov.ScanEntry
import io.golioth.pouchprov.VersionInfo
import io.golioth.pouchprov.ble.ProvisionState

/** How the device credential is obtained. */
private enum class CertMode { Golioth, SelfSigned, Upload }

@Composable
fun DeviceScreen(vm: ProvViewModel) {
    val device by vm.selected.collectAsState()
    val connecting by vm.connecting.collectAsState()
    val connectError by vm.connectError.collectAsState()
    val version by vm.version.collectAsState()
    val provisioning by vm.provisioning.collectAsState()
    val provisionState by vm.provisionState.collectAsState()

    val dev = device ?: return

    Column(Modifier.fillMaxWidth().verticalScroll(rememberScrollState())) {
        // Header
        Row(
            Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Column(Modifier.padding(end = 8.dp)) {
                Text(dev.name ?: "(unnamed)", style = MaterialTheme.typography.titleLarge)
                Text(dev.address, style = MaterialTheme.typography.bodySmall)
            }
            TextButton(onClick = { vm.back() }) { Text("Back") }
        }

        when {
            connecting -> ConnectingCard()
            connectError != null -> ConnectErrorCard(connectError!!, onRetry = { vm.select(dev) }, onRepair = { vm.forgetAndRepair() })
            version != null -> {
                val encrypted by vm.sessionEncrypted.collectAsState()
                DeviceInfoCard(version!!, encrypted)
                if (provisioning) {
                    ProvisionProgress(provisionState, onDone = { vm.back() }, onAgain = { vm.resetProvision() })
                } else {
                    ProvisionForm(vm, version!!, defaultCn = dev.name ?: dev.address)
                }
            }
        }
    }
}

@Composable
private fun ConnectingCard() {
    Card(Modifier.fillMaxWidth().padding(top = 16.dp)) {
        Column(Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp)
                Text("Connecting & pairing…", Modifier.padding(start = 12.dp))
            }
            Text(
                "If prompted, accept the pairing request on your phone.",
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.padding(top = 8.dp),
            )
        }
    }
}

@Composable
private fun ConnectErrorCard(message: String, onRetry: () -> Unit, onRepair: () -> Unit) {
    Card(
        Modifier.fillMaxWidth().padding(top = 16.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer),
    ) {
        Column(Modifier.padding(16.dp)) {
            Text("Couldn't connect", style = MaterialTheme.typography.titleMedium)
            Text(message, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(top = 4.dp))
            Text(
                "If pairing failed, forget the device and try again.",
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.padding(top = 8.dp),
            )
            Row(Modifier.padding(top = 12.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = onRetry) { Text("Retry") }
                OutlinedButton(onClick = onRepair) { Text("Forget & re-pair") }
            }
        }
    }
}

@Composable
private fun DeviceInfoCard(info: VersionInfo, encrypted: Boolean) {
    Card(Modifier.fillMaxWidth().padding(top = 16.dp)) {
        Column(Modifier.padding(16.dp)) {
            Text("Device", style = MaterialTheme.typography.titleMedium)
            Text(
                "protocol v${info.proto} · lib ${info.lib} · block ${info.blockSize} B · " +
                    if (encrypted) "encrypted (saead)" else "plaintext session",
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.padding(top = 2.dp),
            )
            Row(
                Modifier.fillMaxWidth().padding(top = 8.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                val caps = info.caps.ifEmpty { listOf("none") }
                caps.forEach { cap -> AssistChip(onClick = {}, label = { Text(cap) }) }
            }
            if (info.popRequired) {
                AssistChip(
                    onClick = {},
                    label = { Text("PoP required") },
                    colors = AssistChipDefaults.assistChipColors(),
                    modifier = Modifier.padding(top = 4.dp),
                )
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ProvisionForm(vm: ProvViewModel, info: VersionInfo, defaultCn: String) {
    val context = LocalContext.current
    val wifiNetworks by vm.wifiNetworks.collectAsState()
    val wifiScanning by vm.wifiScanning.collectAsState()
    val wifiError by vm.wifiError.collectAsState()
    val generating by vm.generating.collectAsState()
    val generatedCn by vm.generatedCn.collectAsState()
    val validityDays by vm.certValidityDays.collectAsState()
    val apiKey by vm.goliothApiKey.collectAsState()
    val certError by vm.certError.collectAsState()

    var pop by remember { mutableStateOf("") }
    var ssid by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var certMode by remember { mutableStateOf(if (apiKey.isBlank()) CertMode.SelfSigned else CertMode.Golioth) }
    var cn by remember { mutableStateOf(defaultCn) }
    var cert by remember { mutableStateOf<ByteArray?>(null) }
    var key by remember { mutableStateOf<ByteArray?>(null) }
    var ca by remember { mutableStateOf<ByteArray?>(null) }

    fun read(uri: Uri?): ByteArray? =
        uri?.let { context.contentResolver.openInputStream(it)?.use { s -> s.readBytes() } }

    val pickCert = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { cert = read(it) }
    val pickKey = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { key = read(it) }
    val pickCa = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { ca = read(it) }

    val hasCred = info.hasCap("cred")
    val hasWifi = info.hasCap("wifi")

    Column(Modifier.fillMaxWidth().padding(top = 12.dp)) {
        if (info.popRequired) {
            OutlinedTextField(
                pop, { pop = it },
                label = { Text("Proof-of-possession") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
        }

        if (hasCred) {
            SectionTitle("Cloud credentials")
            Row(Modifier.fillMaxWidth().padding(top = 4.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilterChip(certMode == CertMode.Golioth, { certMode = CertMode.Golioth }, label = { Text("Golioth") })
                FilterChip(certMode == CertMode.SelfSigned, { certMode = CertMode.SelfSigned }, label = { Text("Self-signed") })
                FilterChip(certMode == CertMode.Upload, { certMode = CertMode.Upload }, label = { Text("Upload") })
            }
            when (certMode) {
                CertMode.Upload -> Row(
                    Modifier.fillMaxWidth().padding(top = 8.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    OutlinedButton(onClick = { pickCert.launch(arrayOf("*/*")) }) { Text(if (cert != null) "Cert ✓" else "Cert") }
                    OutlinedButton(onClick = { pickKey.launch(arrayOf("*/*")) }) { Text(if (key != null) "Key ✓" else "Key") }
                    OutlinedButton(onClick = { pickCa.launch(arrayOf("*/*")) }) { Text(if (ca != null) "CA ✓" else "CA") }
                }
                else -> {
                    OutlinedTextField(
                        cn, { cn = it },
                        label = { Text("Device ID (certificate CN)") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                    )
                    Row(
                        Modifier.fillMaxWidth().padding(top = 8.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        val golioth = certMode == CertMode.Golioth
                        OutlinedButton(
                            onClick = { if (golioth) vm.mintGoliothCert(cn) else vm.generateCert(cn) },
                            enabled = !generating,
                        ) {
                            Text(if (generating) "Working…" else if (golioth) "Mint from Golioth" else "Generate certificate")
                        }
                        if (generating) CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
                        generatedCn?.let { Text("Ready ✓ CN=$it", style = MaterialTheme.typography.bodySmall) }
                    }
                    val note = if (certMode == CertMode.Golioth) {
                        if (apiKey.isBlank()) "Set a Golioth API key in Settings to mint."
                        else "Registers a demo CA and signs a device cert · valid $validityDays days."
                    } else {
                        "Self-signed · valid $validityDays days (change in Settings)."
                    }
                    Text(note, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(top = 4.dp))
                    certError?.let {
                        Text("Error: $it", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                    }
                }
            }
        }

        if (hasWifi) {
            SectionTitle("Wi-Fi")
            Row(
                Modifier.fillMaxWidth().padding(top = 4.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                OutlinedButton(onClick = { vm.scanWifi(pop) }, enabled = !wifiScanning) {
                    Text(if (wifiScanning) "Scanning…" else "Scan networks")
                }
                if (wifiScanning) CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
            }
            wifiError?.let { Text("Scan failed: $it", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
            val networks = wifiNetworks
            if (networks != null) {
                SsidPicker(networks, selected = ssid, onSelect = { ssid = it })
            }
            OutlinedTextField(
                ssid, { ssid = it },
                label = { Text("SSID") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
            )
            OutlinedTextField(
                password, { password = it },
                label = { Text("Wi-Fi password") },
                singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
                modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
            )
        }

        if (!hasCred && !hasWifi) {
            Text(
                "This device advertises no provisionable capabilities. You can still end " +
                    "the provisioning session.",
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.padding(top = 8.dp),
            )
        }

        Button(
            onClick = {
                val gen = if (hasCred && certMode != CertMode.Upload) vm.generatedCredentials() else null
                vm.provision(
                    pop = pop,
                    ssid = if (hasWifi) ssid else null,
                    password = if (hasWifi) password else null,
                    cert = gen?.first ?: cert,
                    key = gen?.second ?: key,
                    ca = if (hasCred && certMode == CertMode.Upload) ca else null,
                )
            },
            modifier = Modifier.fillMaxWidth().padding(top = 16.dp),
        ) { Text(if (!hasCred && !hasWifi) "Finish" else "Provision") }

        DeviceControls(vm, pop = pop)
    }
}

@Composable
private fun DeviceControls(vm: ProvViewModel, pop: String) {
    val busy by vm.ctrlBusy.collectAsState()
    val error by vm.ctrlError.collectAsState()
    val done by vm.ctrlDone.collectAsState()
    var confirmReprovision by remember { mutableStateOf(false) }

    SectionTitle("Device controls")
    Row(
        Modifier.fillMaxWidth().padding(top = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        OutlinedButton(onClick = { vm.deviceControl(pop, reprovision = false) }, enabled = !busy) {
            Text("Reset Wi-Fi")
        }
        OutlinedButton(onClick = { confirmReprovision = true }, enabled = !busy) {
            Text("Factory reset")
        }
        if (busy) CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
    }
    done?.let { Text(it, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(top = 4.dp)) }
    error?.let {
        Text("Error: $it", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
    }

    if (confirmReprovision) {
        AlertDialog(
            onDismissRequest = { confirmReprovision = false },
            title = { Text("Factory reset provisioning?") },
            text = { Text("This wipes ALL stored Wi-Fi and cloud credentials on the device.") },
            confirmButton = {
                TextButton(onClick = {
                    confirmReprovision = false
                    vm.deviceControl(pop, reprovision = true)
                }) { Text("Wipe") }
            },
            dismissButton = {
                TextButton(onClick = { confirmReprovision = false }) { Text("Cancel") }
            },
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun SsidPicker(networks: List<ScanEntry>, selected: String, onSelect: (String) -> Unit) {
    var expanded by remember { mutableStateOf(false) }
    ExposedDropdownMenuBox(
        expanded = expanded,
        onExpandedChange = { expanded = it },
        modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
    ) {
        OutlinedTextField(
            value = if (selected.isEmpty()) "Select a network (${networks.size})" else selected,
            onValueChange = {},
            readOnly = true,
            label = { Text("Discovered networks") },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
            modifier = Modifier.fillMaxWidth().menuAnchor(),
        )
        ExposedDropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
            networks.forEach { entry ->
                val name = String(entry.ssid)
                DropdownMenuItem(
                    text = {
                        Text(
                            if (name.isEmpty()) "(hidden)"
                            else "$name   ${entry.rssi} dBm   ${entry.authName}",
                        )
                    },
                    onClick = { onSelect(name); expanded = false },
                )
            }
        }
    }
}

@Composable
private fun ProvisionProgress(state: ProvisionState, onDone: () -> Unit, onAgain: () -> Unit) {
    Card(Modifier.fillMaxWidth().padding(top = 16.dp)) {
        Column(Modifier.padding(16.dp)) {
            when (state) {
                is ProvisionState.Done -> {
                    Text("Provisioned ✓", style = MaterialTheme.typography.titleMedium, color = Color(0xFF2E7D32))
                    val r = state.result
                    if (r.credentialsStored) Text("Cloud credentials stored.", Modifier.padding(top = 4.dp))
                    r.wifi?.let { Text("Wi-Fi: ${it.state}", Modifier.padding(top = 4.dp)) }
                    if (!r.credentialsStored && r.wifi == null) Text("Session ended.", Modifier.padding(top = 4.dp))
                    Button(onClick = onDone, modifier = Modifier.padding(top = 12.dp)) { Text("Done") }
                }
                is ProvisionState.Failed -> {
                    Text("Provisioning failed", style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.error)
                    Text(state.error.message ?: state.error.toString(), style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(top = 4.dp))
                    Button(onClick = onAgain, modifier = Modifier.padding(top = 12.dp)) { Text("Try again") }
                }
                else -> {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp)
                        Text(stepLabel(state), Modifier.padding(start = 12.dp))
                    }
                }
            }
        }
    }
}

private fun stepLabel(state: ProvisionState): String = when (state) {
    ProvisionState.Idle -> "Preparing…"
    ProvisionState.Connecting -> "Connecting…"
    ProvisionState.Querying -> "Reading device version…"
    ProvisionState.Authorizing -> "Authorizing (proof-of-possession)…"
    ProvisionState.PushingCredentials -> "Pushing credentials…"
    is ProvisionState.ConfiguringWifi -> state.status?.let { "Wi-Fi: ${it.state}" } ?: "Configuring Wi-Fi…"
    ProvisionState.Finishing -> "Finishing…"
    else -> "Working…"
}

@Composable
private fun SectionTitle(text: String) {
    Text(text, style = MaterialTheme.typography.titleSmall, modifier = Modifier.padding(top = 16.dp))
}
