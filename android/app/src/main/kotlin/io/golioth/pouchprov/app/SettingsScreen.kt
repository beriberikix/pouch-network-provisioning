// Copyright (c) 2026 Jonathan Beri
// SPDX-License-Identifier: Apache-2.0

package io.golioth.pouchprov.app

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.unit.dp
import java.time.LocalDate
import java.time.format.DateTimeFormatter

@Composable
fun SettingsScreen(vm: ProvViewModel) {
    val apiKey by vm.goliothApiKey.collectAsState()
    val validityDays by vm.certValidityDays.collectAsState()

    Column(Modifier.fillMaxWidth()) {
        // -- Golioth --------------------------------------------------------
        Text("Golioth", style = MaterialTheme.typography.titleMedium)
        var showKey by remember { mutableStateOf(false) }
        OutlinedTextField(
            value = apiKey,
            onValueChange = { vm.setGoliothApiKey(it) },
            label = { Text("Project API key") },
            singleLine = true,
            visualTransformation = if (showKey) VisualTransformation.None else PasswordVisualTransformation(),
            trailingIcon = {
                TextButton(onClick = { showKey = !showKey }) { Text(if (showKey) "Hide" else "Show") }
            },
            modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
        )
        Text(
            "Used to register a temporary CA when minting device certificates.",
            style = MaterialTheme.typography.bodySmall,
            modifier = Modifier.padding(top = 4.dp),
        )

        // -- Certificate ----------------------------------------------------
        Text(
            "Certificate",
            style = MaterialTheme.typography.titleMedium,
            modifier = Modifier.padding(top = 24.dp),
        )
        var daysText by remember(validityDays) { mutableStateOf(validityDays.toString()) }
        OutlinedTextField(
            value = daysText,
            onValueChange = { input ->
                daysText = input.filter { it.isDigit() }.take(4)
                daysText.toIntOrNull()?.let { vm.setCertValidityDays(it) }
            },
            label = { Text("Expiration (days from creation)") },
            singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
            modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
        )
        val expiry = remember(validityDays) {
            LocalDate.now().plusDays(validityDays.toLong()).format(DateTimeFormatter.ISO_LOCAL_DATE)
        }
        Text(
            "A certificate generated today would expire $expiry.",
            style = MaterialTheme.typography.bodySmall,
            modifier = Modifier.padding(top = 4.dp),
        )
    }
}
