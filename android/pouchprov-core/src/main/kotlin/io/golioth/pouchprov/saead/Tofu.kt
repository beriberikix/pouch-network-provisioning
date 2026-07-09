// Copyright (c) 2026 Jonathan Beri
// SPDX-License-Identifier: Apache-2.0

package io.golioth.pouchprov.saead

import io.golioth.pouchprov.Pem
import io.golioth.pouchprov.cbor.Cbor
import io.golioth.pouchprov.cert.DeviceCert
import io.golioth.pouchprov.sar.SarReceiver
import io.golioth.pouchprov.sar.SarSender
import io.golioth.pouchprov.transport.Channel
import io.golioth.pouchprov.transport.Transport
import java.io.ByteArrayInputStream
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/**
 * TOFU server-certificate exchange and saead session setup. A port of the CLI's
 * `tofu.py`.
 *
 * On saead firmware builds the pouch GATT service exposes three extra SAR
 * endpoints (raw payloads, not pouch-framed): `info` (device sender, CBOR
 * `{flags, server_cert_snr}`), `server_cert` (device receiver — we SAR-write
 * our self-signed server cert when the stored serial differs), and
 * `device_cert` (device sender — its self-signed identity cert, collected
 * trust-on-first-use). The exchanged public keys drive the ECDH session-key
 * derivation in [Saead].
 */
object Tofu {

    /** The pouch GATT info payload: `{flags, server_cert_snr}`. */
    data class GattInfo(val flags: Int, val serverCertSerial: ByteArray) {
        val hasServerCert: Boolean get() = serverCertSerial.isNotEmpty()

        override fun equals(other: Any?): Boolean =
            other is GattInfo && flags == other.flags && serverCertSerial.contentEquals(other.serverCertSerial)

        override fun hashCode(): Int = flags * 31 + serverCertSerial.contentHashCode()

        companion object {
            fun decode(data: ByteArray): GattInfo {
                @Suppress("UNCHECKED_CAST")
                val obj = Cbor.decode(data) as Map<Any?, Any?>
                return GattInfo(
                    flags = ((obj["flags"] as? Long) ?: 0L).toInt(),
                    serverCertSerial = (obj["server_cert_snr"] as? ByteArray) ?: ByteArray(0),
                )
            }
        }
    }

    /** The client's pouch "server" identity: a P-256 key pair + self-signed cert. */
    class ServerIdentity(val privateKey: PrivateKey, val certDer: ByteArray) {
        /** First 6 bytes of SHA-256(cert DER), per pouch cert_ref. */
        val certRef: ByteArray
            get() = MessageDigest.getInstance("SHA-256").digest(certDer).copyOf(Saead.CERT_REF_LEN)
    }

    /** Generate a fresh self-signed server identity (reuses [DeviceCert]). */
    fun generateServerIdentity(commonName: String = "pouchprov-android"): ServerIdentity {
        val creds = DeviceCert.generateSelfSigned(commonName, validityDays = 3650)
        return ServerIdentity(DeviceCert.loadPrivateKey(creds.privateKeyPem), Pem.toDer(creds.certificatePem))
    }

    /**
     * Strip leading zero bytes: mbedtls keeps the DER sign byte, most big-int
     * serializations do not. Normalized forms compare equal.
     */
    fun normalizeSerial(serial: ByteArray): ByteArray {
        val stripped = serial.dropWhile { it == 0.toByte() }.toByteArray()
        return if (stripped.isEmpty()) byteArrayOf(0) else stripped
    }

    /** The X.509 serial number bytes of a DER certificate. */
    fun certSerial(certDer: ByteArray): ByteArray {
        val cert = CertificateFactory.getInstance("X.509")
            .generateCertificate(ByteArrayInputStream(certDer)) as X509Certificate
        return cert.serialNumber.toByteArray()
    }

    /** Extract the P-256 public key from a device certificate (DER or PEM). */
    fun devicePublicKey(certDer: ByteArray): PublicKey {
        val cert = CertificateFactory.getInstance("X.509")
            .generateCertificate(ByteArrayInputStream(certDer)) as X509Certificate
        return cert.publicKey
    }

    /** One SAR receive cycle on a device-sender endpoint (info, device_cert). */
    suspend fun sarRead(channel: Channel, timeoutMs: Long = 15_000): ByteArray {
        val receiver = SarReceiver(channel::write)
        channel.subscribe(receiver::feed)
        return try {
            receiver.receive(timeoutMs)
        } finally {
            channel.unsubscribe()
        }
    }

    /** One SAR send cycle on a device-receiver endpoint (server_cert). */
    suspend fun sarWrite(channel: Channel, data: ByteArray, maxlen: Int, timeoutMs: Long = 15_000) {
        val sender = SarSender(channel::write, maxlen)
        channel.subscribe(sender::feed)
        try {
            sender.send(data, timeoutMs)
        } finally {
            channel.unsubscribe()
        }
    }

    /** Read the pouch GATT info endpoint (a SAR cycle, not a GATT read). */
    suspend fun readInfo(transport: Transport, timeoutMs: Long = 15_000): GattInfo =
        GattInfo.decode(sarRead(checkNotNull(transport.info) { "no info endpoint" }, timeoutMs))

    /**
     * Run the TOFU cert exchange; returns the device certificate (DER). Pushes
     * our server certificate only when the device's stored serial differs from
     * ours (or it has none).
     */
    suspend fun exchangeCerts(
        transport: Transport,
        identity: ServerIdentity,
        maxlen: Int,
        timeoutMs: Long = 15_000,
    ): ByteArray {
        val info = readInfo(transport, timeoutMs)
        val ours = normalizeSerial(certSerial(identity.certDer))
        val theirs = normalizeSerial(info.serverCertSerial)
        if (!info.hasServerCert || !theirs.contentEquals(ours)) {
            sarWrite(checkNotNull(transport.serverCert), identity.certDer, maxlen, timeoutMs)
        }
        return sarRead(checkNotNull(transport.deviceCert), timeoutMs)
    }

    /** TOFU exchange + build the [SaeadSession] keyed to the device. */
    suspend fun secureSession(
        transport: Transport,
        identity: ServerIdentity,
        maxlen: Int,
        timeoutMs: Long = 15_000,
    ): SaeadSession {
        val deviceDer = exchangeCerts(transport, identity, maxlen, timeoutMs)
        return SaeadSession(identity.privateKey, devicePublicKey(deviceDer), identity.certRef)
    }
}
