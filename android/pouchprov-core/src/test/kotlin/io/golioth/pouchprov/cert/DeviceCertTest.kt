// Copyright (c) 2026 Jonathan Beri
// SPDX-License-Identifier: Apache-2.0

package io.golioth.pouchprov.cert

import io.golioth.pouchprov.Pem
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.security.KeyFactory
import java.security.cert.CertificateFactory
import java.security.spec.PKCS8EncodedKeySpec

class DeviceCertTest {

    @Test fun generatesParseableSelfSignedP256Cert() {
        val creds = DeviceCert.generateSelfSigned("my-device-1234")

        // Cert: PEM parses to an X.509 cert with the right CN, self-signed, EC key.
        val cert = CertificateFactory.getInstance("X.509")
            .generateCertificate(ByteArrayInputStream(creds.certificatePem)) as java.security.cert.X509Certificate
        assertTrue(cert.subjectX500Principal.name.contains("CN=my-device-1234"))
        assertEquals(cert.subjectX500Principal, cert.issuerX500Principal) // self-signed
        assertEquals("EC", cert.publicKey.algorithm)
        cert.verify(cert.publicKey) // signature checks out against its own key

        // Key: PEM → DER parses as a PKCS#8 EC private key.
        val keyDer = Pem.toDer(creds.privateKeyPem)
        val key = KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(keyDer))
        assertEquals("EC", key.algorithm)

        // Cert PEM → DER round-trips (what the provision path feeds the device).
        assertTrue(Pem.toDer(creds.certificatePem).isNotEmpty())
    }

    @Test fun distinctKeysEachCall() {
        val a = DeviceCert.generateSelfSigned("dev")
        val b = DeviceCert.generateSelfSigned("dev")
        assertTrue(!a.privateKeyPem.contentEquals(b.privateKeyPem))
    }

    @Test fun caSignedDeviceCertChainsToCa() {
        val ca = DeviceCert.generateCa("pouch-demo-CA")
        val device = DeviceCert.signDeviceCert(ca, deviceCommonName = "device-42")

        val cf = CertificateFactory.getInstance("X.509")
        val caCert = cf.generateCertificate(ByteArrayInputStream(ca.certificatePem)) as java.security.cert.X509Certificate
        val devCert = cf.generateCertificate(ByteArrayInputStream(device.certificatePem)) as java.security.cert.X509Certificate

        assertTrue(devCert.subjectX500Principal.name.contains("CN=device-42"))
        assertEquals(caCert.subjectX500Principal, devCert.issuerX500Principal) // issued by the CA
        devCert.verify(caCert.publicKey) // signature verifies against the CA key
        assertTrue("CA must be a CA cert", caCert.basicConstraints >= 0)
    }

    @Test fun honorsValidityDays() {
        val creds = DeviceCert.generateSelfSigned("dev", validityDays = 7)
        val cert = CertificateFactory.getInstance("X.509")
            .generateCertificate(ByteArrayInputStream(creds.certificatePem)) as java.security.cert.X509Certificate
        val days = java.time.Duration.between(
            cert.notBefore.toInstant(), cert.notAfter.toInstant(),
        ).toDays()
        assertTrue("expected ~7 day validity, got $days", days in 6..8)
        assertTrue(cert.notAfter.toInstant().isAfter(java.time.Instant.now()))
    }
}
