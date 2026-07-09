// Copyright (c) 2026 Jonathan Beri
// SPDX-License-Identifier: Apache-2.0

import Foundation
import XCTest
@testable import PouchProvCore

/// TOFU server-cert exchange + autodetected saead sessions over the mock.
final class TofuTests: XCTestCase {

    private func simpleHandler(_ path: String, _ payload: Data) -> Data? {
        if path == Messages.pathVer {
            return Cbor.encode(.array([
                .int(0), .int(0),
                .map([
                    CborPair(.text("proto"), .int(1)),
                    CborPair(.text("caps"), .array([.text("cred")])),
                    CborPair(.text("blk"), .int(512)),
                    CborPair(.text("lib"), .text("tofu-test")),
                    CborPair(.text("pop"), .bool(false)),
                ]),
            ]))
        }
        if path == Messages.pathCtrl {
            let op = (try? Cbor.decode(payload))?.arrayValue?.first?.intValue ?? 0
            return Cbor.encode(.array([.int(Int64(op)), .int(0)]))
        }
        return nil
    }

    func testNormalizeSerial() {
        XCTAssertEqual(Data([1, 2]), Tofu.normalizeSerial(Data([0, 1, 2])))
        XCTAssertEqual(Data([1, 2]), Tofu.normalizeSerial(Data([1, 2])))
        XCTAssertEqual(Data([0]), Tofu.normalizeSerial(Data([0])))
        XCTAssertEqual(Data([0]), Tofu.normalizeSerial(Data()))
    }

    func testSupportsSaeadDetection() throws {
        let plain = MockDeviceTransport(handler: simpleHandler)
        XCTAssertFalse(plain.supportsSaead)

        let identity = try Tofu.generateServerIdentity(commonName: "mock-device")
        let saead = MockDeviceTransport(handler: simpleHandler, saeadIdentity: identity)
        XCTAssertTrue(saead.supportsSaead)
    }

    func testReadInfoEmptyThenStored() async throws {
        let identity = try Tofu.generateServerIdentity(commonName: "mock-device")
        let transport = MockDeviceTransport(handler: simpleHandler, saeadIdentity: identity)

        var info = try await Tofu.readInfo(transport)
        XCTAssertFalse(info.hasServerCert)

        let client = try Tofu.generateServerIdentity(commonName: "client")
        try await Tofu.sarWrite(transport.serverCert!, data: client.certDer, maxlen: 244)
        info = try await Tofu.readInfo(transport)
        XCTAssertTrue(info.hasServerCert)
        XCTAssertEqual(
            Tofu.normalizeSerial(try Tofu.certSerial(client.certDer)),
            Tofu.normalizeSerial(info.serverCertSerial)
        )
    }

    func testExchangePushesWhenMissingAndSkipsWhenStored() async throws {
        let identity = try Tofu.generateServerIdentity(commonName: "mock-device")
        let transport = MockDeviceTransport(handler: simpleHandler, saeadIdentity: identity)
        let client = try Tofu.generateServerIdentity(commonName: "client")

        let dev1 = try await Tofu.exchangeCerts(transport, identity: client, maxlen: 244)
        XCTAssertEqual(identity.certDer, dev1)
        XCTAssertEqual(client.certDer, transport.storedServerCert)

        // Same identity again: serials match, exchange succeeds without re-push.
        let dev2 = try await Tofu.exchangeCerts(transport, identity: client, maxlen: 244)
        XCTAssertEqual(identity.certDer, dev2)
        XCTAssertEqual(client.certDer, transport.storedServerCert)
    }

    func testSecureSessionEndToEnd() async throws {
        let identity = try Tofu.generateServerIdentity(commonName: "mock-device")
        let transport = MockDeviceTransport(handler: simpleHandler, saeadIdentity: identity)

        let client = try Tofu.generateServerIdentity(commonName: "client")
        let saead = try await Tofu.secureSession(transport, identity: client, maxlen: 244)

        let session = ProvSession(transport: transport, crypto: SaeadCrypto(saead))
        let info = try await Flows.getVersion(session)
        XCTAssertEqual("tofu-test", info.lib)
        try await Flows.endSession(session)
    }
}
