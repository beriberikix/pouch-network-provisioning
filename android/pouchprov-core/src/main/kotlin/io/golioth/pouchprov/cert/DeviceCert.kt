// Copyright (c) 2026 Jonathan Beri
// SPDX-License-Identifier: Apache-2.0

package io.golioth.pouchprov.cert

import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x500.X500NameBuilder
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.time.Instant
import java.util.Base64
import java.util.Date

/**
 * Generates a device identity locally: an ECDSA P-256 key pair and a self-signed
 * X.509 certificate, ready to feed into the credential-bootstrap provisioning
 * path (`PouchProvDevice.provisionCredentials` / `ProvisionRequest`).
 *
 * The certificate's Common Name is the device identifier; for Golioth
 * certificate auth this is the device name/ID (see `docs/golioth-demo-certs.md`).
 * A self-signed cert works for local/test provisioning; the Golioth CA-signed
 * flow (register a demo CA, sign the device cert) is a separate step.
 *
 * Bouncy Castle builds the X.509 ASN.1; the key generation and signature use the
 * platform JCA (`EC` / `SHA256withECDSA`), so no security provider is registered.
 */
object DeviceCert {

    /** PEM-encoded device credentials (accepted directly by the provision path). */
    data class Credentials(val certificatePem: ByteArray, val privateKeyPem: ByteArray) {
        override fun equals(other: Any?): Boolean =
            other is Credentials && certificatePem.contentEquals(other.certificatePem) &&
                privateKeyPem.contentEquals(other.privateKeyPem)

        override fun hashCode(): Int = certificatePem.contentHashCode() * 31 + privateKeyPem.contentHashCode()
    }

    /**
     * Generate a P-256 key pair and a self-signed certificate with CN=[commonName],
     * valid for [validityDays] (default 28). Works for local/test provisioning.
     */
    fun generateSelfSigned(commonName: String, validityDays: Int = 28): Credentials {
        val kp = newKeyPair()
        val subject = cn(commonName)
        val cert = buildCert(subject, subject, kp.public, kp.private, validityDays, ca = false)
        return Credentials(pem("CERTIFICATE", cert.encoded), pem("PRIVATE KEY", kp.private.encoded))
    }

    /**
     * Generate a P-256 key pair and a self-signed **CA** certificate (BasicConstraints
     * CA:TRUE, keyUsage keyCertSign) — e.g. the demo root CA registered with Golioth.
     */
    fun generateCa(commonName: String, validityDays: Int = 28): Credentials {
        val kp = newKeyPair()
        val subject = cn(commonName)
        val cert = buildCert(subject, subject, kp.public, kp.private, validityDays, ca = true)
        return Credentials(pem("CERTIFICATE", cert.encoded), pem("PRIVATE KEY", kp.private.encoded))
    }

    /**
     * Generate a device key pair and a certificate with CN=[deviceCommonName] signed
     * by [ca] (the CA's cert + key PEM). For Golioth, the CN is the device ID.
     */
    fun signDeviceCert(ca: Credentials, deviceCommonName: String, validityDays: Int = 28): Credentials {
        val caCert = loadCertificate(ca.certificatePem)
        val caKey = loadPrivateKey(ca.privateKeyPem)
        val kp = newKeyPair()
        val subject = cn(deviceCommonName)
        val issuer = X500Name(caCert.subjectX500Principal.name)
        val cert = buildCert(subject, issuer, kp.public, caKey, validityDays, ca = false)
        return Credentials(pem("CERTIFICATE", cert.encoded), pem("PRIVATE KEY", kp.private.encoded))
    }

    private fun newKeyPair() = KeyPairGenerator.getInstance("EC").apply {
        initialize(ECGenParameterSpec("secp256r1"), SecureRandom())
    }.generateKeyPair()

    private fun cn(commonName: String) =
        X500NameBuilder(BCStyle.INSTANCE).addRDN(BCStyle.CN, commonName).build()

    private fun buildCert(
        subject: X500Name,
        issuer: X500Name,
        subjectPublicKey: PublicKey,
        signingKey: PrivateKey,
        validityDays: Int,
        ca: Boolean,
    ): X509Certificate {
        val now = Instant.now()
        val notBefore = Date.from(now.minusSeconds(60)) // small backdate for clock skew
        val notAfter = Date.from(now.plusSeconds(validityDays.toLong() * 24 * 60 * 60))
        val serial = BigInteger(64, SecureRandom()).abs()
        val builder = JcaX509v3CertificateBuilder(issuer, serial, notBefore, notAfter, subject, subjectPublicKey)
        if (ca) {
            builder.addExtension(Extension.basicConstraints, true, BasicConstraints(true))
            builder.addExtension(Extension.keyUsage, true, KeyUsage(KeyUsage.keyCertSign or KeyUsage.cRLSign))
        }
        val signer = JcaContentSignerBuilder("SHA256withECDSA").build(signingKey)
        return JcaX509CertificateConverter().getCertificate(builder.build(signer))
    }

    private fun loadCertificate(pem: ByteArray): X509Certificate =
        CertificateFactory.getInstance("X.509")
            .generateCertificate(ByteArrayInputStream(pem)) as X509Certificate

    private fun loadPrivateKey(pem: ByteArray): PrivateKey =
        KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(io.golioth.pouchprov.Pem.toDer(pem)))

    private fun pem(type: String, der: ByteArray): ByteArray {
        val body = Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(der)
        return "-----BEGIN $type-----\n$body\n-----END $type-----\n".toByteArray(Charsets.US_ASCII)
    }
}
