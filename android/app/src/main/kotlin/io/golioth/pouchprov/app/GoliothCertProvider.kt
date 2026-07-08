// Copyright (c) 2026 Jonathan Beri
// SPDX-License-Identifier: Apache-2.0

package io.golioth.pouchprov.app

import io.golioth.pouchprov.cert.DeviceCert
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.util.Base64

/**
 * Mints Golioth-ready device credentials: generates a demo root CA, registers it
 * with the project (the same public-API flow the console's "temporary
 * certificate" button uses — see `docs/golioth-demo-certs.md`), then signs a
 * per-device certificate (CN = device ID) with that CA.
 *
 * The CA is generated + registered once and reused for subsequent devices in this
 * provider instance. The project is discovered from the API key.
 */
class GoliothCertProvider(
    private val apiKey: String,
    private val baseUrl: String = "https://api.golioth.io",
) {
    /** Device credentials plus the CA cert that signed them (for the optional CA slot). */
    data class DeviceCredentials(
        val certificatePem: ByteArray,
        val privateKeyPem: ByteArray,
        val caCertificatePem: ByteArray,
    )

    private var project: String? = null
    private var ca: DeviceCert.Credentials? = null
    private var caCertId: String? = null

    /** The project id the API key belongs to (discovered + cached). */
    suspend fun projectId(): String = project ?: withContext(Dispatchers.IO) {
        val resp = http("GET", "$baseUrl/v1/projects", null)
        val id = firstMatch(""""id"\s*:\s*"([^"]+)"""", resp)
            ?: throw IOException("no Golioth project found for this API key")
        project = id
        id
    }

    /**
     * Mint (device cert, device key, CA cert) for [deviceId], valid [validityDays].
     * Registers the demo CA on first call and reuses it after.
     */
    suspend fun mintDeviceCredentials(deviceId: String, validityDays: Int): DeviceCredentials =
        withContext(Dispatchers.IO) {
            val pid = projectId()
            val root = ca ?: DeviceCert.generateCa("pouch-demo-CA").also {
                ca = it
                caCertId = registerCa(pid, it.certificatePem)
            }
            val device = DeviceCert.signDeviceCert(root, deviceId, validityDays)
            DeviceCredentials(device.certificatePem, device.privateKeyPem, root.certificatePem)
        }

    /** POST the CA as a temporary (demo) root cert; returns its certificate id. */
    private fun registerCa(pid: String, caCertPem: ByteArray): String {
        val body = """{"certType":"root","certFile":"${base64(caCertPem)}","demo":true}"""
        val resp = http("POST", "$baseUrl/v1/projects/$pid/certificates", body)
        return firstMatch(""""id"\s*:\s*"([^"]+)"""", resp) ?: ""
    }

    /** List registered certificate ids (for cleanup). */
    suspend fun listCertIds(): List<String> = withContext(Dispatchers.IO) {
        val resp = http("GET", "$baseUrl/v1/projects/${projectId()}/certificates", null)
        Regex(""""id"\s*:\s*"([^"]+)"""").findAll(resp).map { it.groupValues[1] }.toList()
    }

    /** Delete a registered certificate (e.g. to garbage-collect a demo CA). */
    suspend fun deleteCert(certId: String) = withContext(Dispatchers.IO) {
        http("DELETE", "$baseUrl/v1/projects/${projectId()}/certificates/$certId", null)
        Unit
    }

    private fun http(method: String, url: String, body: String?): String {
        val conn = URL(url).openConnection() as HttpURLConnection
        return try {
            conn.requestMethod = method
            conn.connectTimeout = 15_000
            conn.readTimeout = 15_000
            conn.setRequestProperty("x-api-key", apiKey)
            conn.setRequestProperty("Accept", "application/json")
            if (body != null) {
                conn.doOutput = true
                conn.setRequestProperty("Content-Type", "application/json")
                conn.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
            }
            val code = conn.responseCode
            val text = (if (code in 200..299) conn.inputStream else conn.errorStream)
                ?.bufferedReader()?.use { it.readText() }.orEmpty()
            if (code !in 200..299) throw IOException("Golioth API $method $url -> $code: $text")
            text
        } finally {
            conn.disconnect()
        }
    }

    private fun base64(bytes: ByteArray): String = Base64.getEncoder().encodeToString(bytes)

    private fun firstMatch(regex: String, s: String): String? =
        Regex(regex).find(s)?.groupValues?.getOrNull(1)
}
