// Copyright (c) 2026 Jonathan Beri
// SPDX-License-Identifier: Apache-2.0

import Crypto
import Foundation
import SwiftASN1
import X509

/// Generates a device identity locally: an ECDSA P-256 key pair and a self-signed
/// X.509 certificate, ready to feed into the credential-bootstrap provisioning
/// path (`PouchProvDevice.provisionCredentials` / `ProvisionRequest`).
///
/// The certificate's Common Name is the device identifier; for Golioth
/// certificate auth this is the device name/ID (see `docs/golioth-demo-certs.md`).
/// A self-signed cert works for local/test provisioning; the Golioth CA-signed
/// flow (register a demo CA, sign the device cert) is a separate step.
///
/// swift-certificates builds the X.509 ASN.1; key generation and signatures use
/// swift-crypto P-256 (`ecdsa-with-SHA256`) — the analogue of the Kotlin
/// Bouncy Castle + JCA implementation.
public enum DeviceCert {

    public struct CertError: Error, CustomStringConvertible {
        public let message: String

        public init(_ message: String) {
            self.message = message
        }

        public var description: String { message }
    }

    /// PEM-encoded device credentials (accepted directly by the provision path).
    public struct Credentials: Equatable, Sendable {
        public let certificatePem: Data
        public let privateKeyPem: Data

        public init(certificatePem: Data, privateKeyPem: Data) {
            self.certificatePem = certificatePem
            self.privateKeyPem = privateKeyPem
        }
    }

    /// Generate a P-256 key pair and a self-signed certificate with CN=`commonName`,
    /// valid for `validityDays` (default 28). Works for local/test provisioning.
    public static func generateSelfSigned(commonName: String, validityDays: Int = 28) throws -> Credentials {
        let key = P256.Signing.PrivateKey()
        let subject = try cn(commonName)
        let cert = try buildCert(
            subject: subject,
            issuer: subject,
            subjectPublicKey: Certificate.PublicKey(key.publicKey),
            signingKey: key,
            validityDays: validityDays,
            isCa: false
        )
        return Credentials(certificatePem: try certPem(cert), privateKeyPem: keyPem(key))
    }

    /// Generate a P-256 key pair and a self-signed **CA** certificate (BasicConstraints
    /// CA:TRUE, keyUsage keyCertSign) — e.g. the demo root CA registered with Golioth.
    public static func generateCa(commonName: String, validityDays: Int = 28) throws -> Credentials {
        let key = P256.Signing.PrivateKey()
        let subject = try cn(commonName)
        let cert = try buildCert(
            subject: subject,
            issuer: subject,
            subjectPublicKey: Certificate.PublicKey(key.publicKey),
            signingKey: key,
            validityDays: validityDays,
            isCa: true
        )
        return Credentials(certificatePem: try certPem(cert), privateKeyPem: keyPem(key))
    }

    /// Generate a device key pair and a certificate with CN=`deviceCommonName` signed
    /// by `ca` (the CA's cert + key PEM). For Golioth, the CN is the device ID.
    public static func signDeviceCert(
        ca: Credentials,
        deviceCommonName: String,
        validityDays: Int = 28
    ) throws -> Credentials {
        let caCert = try loadCertificate(ca.certificatePem)
        let caKey = try loadPrivateKey(ca.privateKeyPem)
        let key = P256.Signing.PrivateKey()
        let subject = try cn(deviceCommonName)
        let cert = try buildCert(
            subject: subject,
            issuer: caCert.subject,
            subjectPublicKey: Certificate.PublicKey(key.publicKey),
            signingKey: caKey,
            validityDays: validityDays,
            isCa: false
        )
        return Credentials(certificatePem: try certPem(cert), privateKeyPem: keyPem(key))
    }

    public static func loadCertificate(_ pem: Data) throws -> Certificate {
        guard let text = String(data: pem, encoding: .utf8) else {
            throw CertError("certificate PEM is not text")
        }
        return try Certificate(pemEncoded: text)
    }

    public static func loadPrivateKey(_ pem: Data) throws -> P256.Signing.PrivateKey {
        guard let text = String(data: pem, encoding: .utf8) else {
            throw CertError("private-key PEM is not text")
        }
        return try P256.Signing.PrivateKey(pemRepresentation: text)
    }

    private static func cn(_ commonName: String) throws -> DistinguishedName {
        try DistinguishedName {
            CommonName(commonName)
        }
    }

    private static func buildCert(
        subject: DistinguishedName,
        issuer: DistinguishedName,
        subjectPublicKey: Certificate.PublicKey,
        signingKey: P256.Signing.PrivateKey,
        validityDays: Int,
        isCa: Bool
    ) throws -> Certificate {
        let now = Date()
        let notBefore = now.addingTimeInterval(-60) // small backdate for clock skew
        let notAfter = now.addingTimeInterval(TimeInterval(validityDays) * 24 * 60 * 60)
        let extensions: Certificate.Extensions
        if isCa {
            extensions = try Certificate.Extensions {
                Critical(BasicConstraints.isCertificateAuthority(maxPathLength: nil))
                Critical(KeyUsage(keyCertSign: true, cRLSign: true))
            }
        } else {
            extensions = Certificate.Extensions()
        }
        return try Certificate(
            version: .v3,
            serialNumber: Certificate.SerialNumber(),
            publicKey: subjectPublicKey,
            notValidBefore: notBefore,
            notValidAfter: notAfter,
            issuer: issuer,
            subject: subject,
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: extensions,
            issuerPrivateKey: Certificate.PrivateKey(signingKey)
        )
    }

    private static func certPem(_ certificate: Certificate) throws -> Data {
        Data((try certificate.serializeAsPEM().pemString + "\n").utf8)
    }

    private static func keyPem(_ key: P256.Signing.PrivateKey) -> Data {
        Data((key.pemRepresentation + "\n").utf8)
    }
}
