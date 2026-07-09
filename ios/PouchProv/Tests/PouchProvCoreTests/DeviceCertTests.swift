// Copyright (c) 2026 Jonathan Beri
// SPDX-License-Identifier: Apache-2.0

import Crypto
import Foundation
import X509
import XCTest
@testable import PouchProvCore

final class DeviceCertTests: XCTestCase {

    func testGeneratesParseableSelfSignedP256Cert() throws {
        let creds = try DeviceCert.generateSelfSigned(commonName: "my-device-1234")

        // The PEM headers are load-bearing: Pem.toDer strips them and the
        // provision path accepts these blobs directly.
        XCTAssertTrue(String(decoding: creds.certificatePem, as: UTF8.self)
            .hasPrefix("-----BEGIN CERTIFICATE-----"))
        XCTAssertTrue(String(decoding: creds.privateKeyPem, as: UTF8.self)
            .hasPrefix("-----BEGIN PRIVATE KEY-----"))

        // Cert: PEM parses to an X.509 cert with the right CN, self-signed.
        let cert = try DeviceCert.loadCertificate(creds.certificatePem)
        XCTAssertTrue(cert.subject.description.contains("CN=my-device-1234"))
        XCTAssertEqual(cert.subject, cert.issuer) // self-signed
        XCTAssertTrue(cert.publicKey.isValidSignature(cert.signature, for: cert))

        // Key: PEM parses as a P-256 private key.
        _ = try DeviceCert.loadPrivateKey(creds.privateKeyPem)

        // PEM → DER round-trips (what the provision path feeds the device).
        XCTAssertFalse(try Pem.toDer(creds.certificatePem).isEmpty)
        XCTAssertFalse(try Pem.toDer(creds.privateKeyPem).isEmpty)
    }

    func testDistinctKeysEachCall() throws {
        let a = try DeviceCert.generateSelfSigned(commonName: "dev")
        let b = try DeviceCert.generateSelfSigned(commonName: "dev")
        XCTAssertNotEqual(a.privateKeyPem, b.privateKeyPem)
    }

    func testCaSignedDeviceCertChainsToCa() throws {
        let ca = try DeviceCert.generateCa(commonName: "pouch-demo-CA")
        let device = try DeviceCert.signDeviceCert(ca: ca, deviceCommonName: "device-42")

        let caCert = try DeviceCert.loadCertificate(ca.certificatePem)
        let devCert = try DeviceCert.loadCertificate(device.certificatePem)

        XCTAssertTrue(devCert.subject.description.contains("CN=device-42"))
        XCTAssertEqual(caCert.subject, devCert.issuer) // issued by the CA
        XCTAssertTrue(caCert.publicKey.isValidSignature(devCert.signature, for: devCert))

        guard let bcExtension = caCert.extensions[oid: .X509ExtensionID.basicConstraints] else {
            XCTFail("CA must carry BasicConstraints")
            return
        }
        guard case .isCertificateAuthority = try BasicConstraints(bcExtension) else {
            XCTFail("CA must be a CA cert")
            return
        }
    }

    func testHonorsValidityDays() throws {
        let creds = try DeviceCert.generateSelfSigned(commonName: "dev", validityDays: 7)
        let cert = try DeviceCert.loadCertificate(creds.certificatePem)
        let days = cert.notValidAfter.timeIntervalSince(cert.notValidBefore) / 86_400
        XCTAssertTrue((6...8).contains(days), "expected ~7 day validity, got \(days)")
        XCTAssertTrue(cert.notValidAfter > Date())
    }
}
