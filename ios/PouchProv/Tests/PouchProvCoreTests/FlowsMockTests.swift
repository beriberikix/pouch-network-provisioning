// Copyright (c) 2026 Jonathan Beri
// SPDX-License-Identifier: Apache-2.0

import Foundation
import XCTest
@testable import PouchProvCore

/// Full client stack over the mock device: SAR + pouch + session + flows, for the
/// Wi-Fi and BLE-only (cred-only) provisioning paths. Mirrors the Kotlin
/// `FlowsMockTest` / Python `test_provision_e2e`.
final class FlowsMockTests: XCTestCase {

    private let pop = "abcd1234"

    func testWifiDeviceFullProvision() async throws {
        let device = DeviceSim(pop: pop, caps: ["wifi", "scan", "cred", "auth"])
        let session = ProvSession(transport: MockDeviceTransport(handler: device.handle))

        let info = try await Flows.getVersion(session)
        XCTAssertEqual(1, info.proto)
        XCTAssertTrue(info.hasCap("wifi"))
        XCTAssertTrue(info.popRequired)

        try await Flows.authorizeIfNeeded(session, info: info, pop: pop)
        XCTAssertTrue(device.authorized)

        let scan = try await Flows.scan(session)
        XCTAssertEqual(2, scan.count)
        XCTAssertEqual(Data("myssid".utf8), scan[0].ssid)

        let status = try await Flows.configureWifi(
            session,
            ssid: Data("myssid".utf8),
            password: Data("hunter22".utf8)
        )
        XCTAssertEqual(.connected, status.state)
        XCTAssertEqual(Data("myssid".utf8), device.wifiSsid)

        try await Flows.bootstrapCredentials(
            session,
            certDer: Data(repeating: 1, count: 500),
            keyDer: Data(repeating: 2, count: 120)
        )
        XCTAssertEqual(500, device.credLen(.deviceCert))
        XCTAssertEqual(120, device.credLen(.privateKey))
        XCTAssertTrue(device.credFinalized)

        try await Flows.endSession(session)
        XCTAssertTrue(device.ended)
    }

    func testCredOnlyDeviceSkipsWifi() async throws {
        let device = DeviceSim(pop: pop, caps: ["cred", "auth"]) // no "wifi"
        let session = ProvSession(transport: MockDeviceTransport(handler: device.handle))

        let info = try await Flows.getVersion(session)
        XCTAssertTrue(info.hasCap("cred"))
        XCTAssertFalse(info.hasCap("wifi"))

        try await Flows.authorizeIfNeeded(session, info: info, pop: pop)
        try await Flows.bootstrapCredentials(
            session,
            certDer: Data(repeating: 1, count: 300),
            keyDer: Data(repeating: 2, count: 120),
            caDer: Data(repeating: 3, count: 64)
        )
        XCTAssertEqual(300, device.credLen(.deviceCert))
        XCTAssertEqual(64, device.credLen(.caCert))
        try await Flows.endSession(session)
        XCTAssertTrue(device.ended)
    }

    func testCtrlOpsAndCredStatus() async throws {
        let device = DeviceSim(pop: pop, caps: ["wifi", "scan", "cred", "auth"])
        let session = ProvSession(transport: MockDeviceTransport(handler: device.handle))

        let info = try await Flows.getVersion(session)
        try await Flows.authorizeIfNeeded(session, info: info, pop: pop)

        try await Flows.bootstrapCredentials(
            session,
            certDer: Data(repeating: 1, count: 500),
            keyDer: Data(repeating: 2, count: 120)
        )
        let before = try await Flows.credStatus(session)
        XCTAssertEqual([.deviceCert: 500, .privateKey: 120], before)

        try await Flows.reset(session)
        XCTAssertTrue(device.wifiReset)

        try await Flows.reprovision(session)
        XCTAssertTrue(device.reprovisioned)
        let after = try await Flows.credStatus(session)
        XCTAssertEqual([:], after)
    }

    func testWrongPopFailsBeforeSendingClientProof() async throws {
        let device = DeviceSim(pop: "correct", caps: ["cred", "auth"])
        let session = ProvSession(transport: MockDeviceTransport(handler: device.handle))
        let info = try await Flows.getVersion(session)
        do {
            try await Flows.authorizeIfNeeded(session, info: info, pop: "wrong")
            XCTFail("expected AuthException")
        } catch is Auth.AuthException {
            // expected
        }
        XCTAssertFalse(device.authorized, "client proof must not be sent on device-proof mismatch")
    }

    func testEmptyPouchDeferredResponse() async throws {
        // The first uplink poll returns an empty "not ready" pouch; the client
        // must back off and re-poll (docs/protocol.md empty-pouch rule).
        let device = DeviceSim(pop: pop, caps: ["cred", "auth"])
        let session = ProvSession(
            transport: MockDeviceTransport(handler: device.handle, deferResponses: 1)
        )
        let info = try await Flows.getVersion(session)
        XCTAssertEqual(1, info.proto)
    }
}

/// A minimal device-side responder. Encodes response CBOR arrays the way the
/// firmware/CLI vectors do and tracks enough state to validate the client flows.
private final class DeviceSim: @unchecked Sendable {
    let pop: String
    let caps: [String]
    var authorized = false
    var wifiSsid: Data?
    var credFinalized = false
    var ended = false
    var wifiReset = false
    var reprovisioned = false
    private var creds: [CredKind: Int] = [:]
    private let devNonce = Data((0..<16).map { UInt8(0x40 + $0) })

    init(pop: String, caps: [String]) {
        self.pop = pop
        self.caps = caps
    }

    func credLen(_ kind: CredKind) -> Int {
        creds[kind] ?? 0
    }

    func handle(_ path: String, _ data: Data) -> Data? {
        guard let msg = (try? Cbor.decode(data))?.arrayValue, let op = msg[0].intValue else {
            fatalError("mock device got bad CBOR")
        }
        switch path {
        case Messages.pathVer:
            return Cbor.encode(.array([
                .int(0), .int(0),
                .map([
                    CborPair(.text("proto"), .int(1)),
                    CborPair(.text("caps"), .array(caps.map { .text($0) })),
                    CborPair(.text("blk"), .int(512)),
                    CborPair(.text("lib"), .text("0.1.0")),
                    CborPair(.text("pop"), .bool(true)),
                ]),
            ]))
        case Messages.pathAuth:
            if op == 0 {
                let cliNonce = msg[1].bytesValue!
                let proof = Auth.deviceProof(pop: pop, cliNonce: cliNonce, devNonce: devNonce)
                return Cbor.encode(.array([.int(0), .int(0), .bytes(devNonce), .bytes(proof)]))
            }
            authorized = true
            return Cbor.encode(.array([.int(1), .int(0)]))
        case Messages.pathScan:
            switch op {
            case 0:
                return Cbor.encode(.array([.int(0), .int(0)]))
            case 1:
                return Cbor.encode(.array([.int(1), .int(0), .bool(true), .int(2)]))
            default:
                return Cbor.encode(.array([
                    .int(2), .int(0),
                    .array([scanEntry("myssid", rssi: -41, auth: 1), scanEntry("guest", rssi: -73, auth: 0)]),
                ]))
            }
        case Messages.pathConfig:
            switch op {
            case 0: // status: connected
                return Cbor.encode(.array([
                    .int(0), .int(0), .int(0),
                    .map([
                        CborPair(.text("ip4"), .bytes(Data([192, 168, 1, 7]))),
                        CborPair(.text("ssid"), .bytes(wifiSsid ?? Data())),
                        CborPair(.text("rssi"), .int(-41)),
                    ]),
                ]))
            case 1:
                wifiSsid = msg[1]["ssid"]?.bytesValue
                return Cbor.encode(.array([.int(1), .int(0)]))
            default:
                return Cbor.encode(.array([.int(2), .int(0)]))
            }
        case Messages.pathCred:
            switch op {
            case 0:
                let kind = CredKind(rawValue: msg[1]["kind"]!.intValue!)!
                let off = msg[1]["off"]!.intValue!
                let len = msg[1]["data"]!.bytesValue!.count
                creds[kind] = off + len
                return Cbor.encode(.array([.int(0), .int(0), .int(Int64(off + len))]))
            case 1:
                credFinalized = true
                return Cbor.encode(.array([.int(1), .int(0)]))
            default:
                let pairs = creds.map { CborPair(.text(String($0.key.rawValue)), .int(Int64($0.value))) }
                return Cbor.encode(.array([.int(2), .int(0), .map(pairs)]))
            }
        case Messages.pathCtrl:
            switch op {
            case CtrlOp.end.rawValue: ended = true
            case CtrlOp.reset.rawValue: wifiReset = true
            case CtrlOp.reprovision.rawValue:
                reprovisioned = true
                creds.removeAll()
            default: break
            }
            return Cbor.encode(.array([.int(Int64(op)), .int(0)]))
        default:
            return nil
        }
    }

    private func scanEntry(_ ssid: String, rssi: Int, auth: Int) -> CborValue {
        .map([
            CborPair(.text("ssid"), .bytes(Data(ssid.utf8))),
            CborPair(.text("bssid"), .bytes(Data(count: 6))),
            CborPair(.text("ch"), .int(11)),
            CborPair(.text("rssi"), .int(Int64(rssi))),
            CborPair(.text("auth"), .int(Int64(auth))),
        ])
    }
}
