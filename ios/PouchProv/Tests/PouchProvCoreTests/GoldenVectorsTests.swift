// Copyright (c) 2026 Jonathan Beri
// SPDX-License-Identifier: Apache-2.0

import Foundation
import XCTest
@testable import PouchProvCore

/// Conformance against the shared golden vectors in the repo-root `tests/vectors/`
/// — the same fixtures the Python CLI, the Kotlin SDK and the Zephyr device codec
/// are pinned to. Every request encoder must reproduce its hex byte-for-byte, and
/// every response decoder must round-trip the device's bytes.
final class GoldenVectorsTests: XCTestCase {

    private static let messages: Result<[String: Any], Error> = Result { try TestVectors.load("prov_messages.json") }
    private static let frames: Result<[String: Any], Error> = Result { try TestVectors.load("pouch_frames.json") }

    private func vector(_ section: String?, _ name: String, from source: Result<[String: Any], Error>) throws -> Data {
        var obj = try source.get()
        if let section {
            guard let nested = obj[section] as? [String: Any] else {
                throw TestVectorsError("missing section \(section)")
            }
            obj = nested
        }
        guard let hex = obj[name] as? String else { throw TestVectorsError("missing vector \(name)") }
        return try TestVectors.hex(hex)
    }

    private func request(_ name: String) throws -> Data {
        try vector("requests", name, from: Self.messages)
    }

    private func rsp(_ name: String) throws -> Data {
        try vector("responses", name, from: Self.messages)
    }

    private func frame(_ name: String) throws -> Data {
        try vector(nil, name, from: Self.frames)
    }

    private func assertHex(_ name: String, _ actual: Data, file: StaticString = #filePath, line: UInt = #line) throws {
        XCTAssertEqual(try request(name), actual, "request \(name)", file: file, line: line)
    }

    private func assertFrame(_ name: String, _ actual: Data, file: StaticString = #filePath, line: UInt = #line) throws {
        XCTAssertEqual(try frame(name), actual, "frame \(name)", file: file, line: line)
    }

    // MARK: - request encoders (client -> device)

    func testVerReq() throws {
        try assertHex("ver_req", Messages.encodeVerReq())
    }

    func testAuthChallenge() throws {
        try assertHex("auth_challenge", Messages.encodeAuthChallenge(cliNonce: TestVectors.bytes(start: 0, count: 16)))
    }

    func testAuthProof() throws {
        try assertHex("auth_proof", Messages.encodeAuthProof(cliProof: TestVectors.bytes(start: 0, count: 32)))
    }

    func testConfigGetStatus() throws {
        try assertHex("config_get_status", Messages.encodeConfigGetStatus())
    }

    func testConfigSetFull() throws {
        try assertHex(
            "config_set_full",
            Messages.encodeConfigSet(
                ssid: Data("myssid".utf8),
                password: Data("hunter22".utf8),
                bssid: try TestVectors.hex("a1b2c3d4e5f6"),
                channel: 11
            )
        )
    }

    func testConfigSetMinimal() throws {
        try assertHex("config_set_minimal", Messages.encodeConfigSet(ssid: Data("open-net".utf8)))
    }

    func testConfigApply() throws {
        try assertHex("config_apply", Messages.encodeConfigApply())
    }

    func testScanStartDefaults() throws {
        try assertHex("scan_start_defaults", Messages.encodeScanStart())
    }

    func testScanStartPassive() throws {
        try assertHex("scan_start_passive", Messages.encodeScanStart(passive: true, periodMs: 120))
    }

    func testScanGetStatus() throws {
        try assertHex("scan_get_status", Messages.encodeScanGetStatus())
    }

    func testScanGetResults() throws {
        try assertHex("scan_get_results", Messages.encodeScanGetResults(start: 4, count: 6))
    }

    func testCredWrite() throws {
        try assertHex(
            "cred_write",
            Messages.encodeCredWrite(kind: .deviceCert, offset: 0, total: 6, data: try TestVectors.hex("30820102aabb"))
        )
    }

    func testCredFinalize() throws {
        try assertHex("cred_finalize", Messages.encodeCredFinalize())
    }

    func testCredGetStatus() throws {
        try assertHex("cred_get_status", Messages.encodeCredGetStatus())
    }

    func testCtrl() throws {
        try assertHex("ctrl_reset", Messages.encodeCtrl(.reset))
        try assertHex("ctrl_reprov", Messages.encodeCtrl(.reprovision))
        try assertHex("ctrl_end", Messages.encodeCtrl(.end))
    }

    // MARK: - response decoders (device -> client)

    func testVerRsp() throws {
        let info = try Messages.decodeVerRsp(try rsp("ver_rsp"))
        XCTAssertEqual(1, info.proto)
        XCTAssertEqual(["wifi", "scan", "cred", "auth"], info.caps)
        XCTAssertEqual(512, info.blockSize)
        XCTAssertEqual("0.1.0", info.lib)
        XCTAssertTrue(info.popRequired)
    }

    func testAuthChallengeRsp() throws {
        let (devNonce, devProof) = try Messages.decodeAuthChallengeRsp(try rsp("auth_challenge_rsp"))
        XCTAssertEqual(TestVectors.bytes(start: 0x10, count: 16), devNonce)
        XCTAssertEqual(TestVectors.bytes(start: 0x20, count: 32), devProof)
    }

    func testAuthProofRspOk() throws {
        try Messages.decodeAuthProofRsp(try rsp("auth_proof_rsp"))
    }

    func testAuthProofRspUnauthorized() throws {
        let data = try rsp("auth_proof_rsp_unauthorized")
        XCTAssertThrowsError(try Messages.decodeAuthProofRsp(data)) { error in
            XCTAssertEqual(.unauthorized, (error as? ProvError)?.status)
        }
    }

    func testConfigStatusConnecting() throws {
        let status = try Messages.decodeConfigStatusRsp(try rsp("config_status_connecting"))
        XCTAssertEqual(.connecting, status.state)
    }

    func testConfigStatusFailedAuth() throws {
        let status = try Messages.decodeConfigStatusRsp(try rsp("config_status_failed_auth"))
        XCTAssertEqual(.failed, status.state)
        XCTAssertEqual(.authError, status.failReason)
    }

    func testConfigStatusConnected() throws {
        let status = try Messages.decodeConfigStatusRsp(try rsp("config_status_connected"))
        XCTAssertEqual(.connected, status.state)
        XCTAssertEqual(try TestVectors.hex("c0a80107"), status.ip4)
        XCTAssertEqual(Data("myssid".utf8), status.ssid)
        XCTAssertEqual(-41, status.rssi)
    }

    func testScanStatusRsp() throws {
        let (finished, total) = try Messages.decodeScanStatusRsp(try rsp("scan_status_rsp"))
        XCTAssertTrue(finished)
        XCTAssertEqual(9, total)
    }

    func testScanResultsRsp() throws {
        let entries = try Messages.decodeScanResultsRsp(try rsp("scan_results_rsp"))
        XCTAssertEqual(2, entries.count)
        XCTAssertEqual(Data("myssid".utf8), entries[0].ssid)
        XCTAssertEqual(11, entries[0].channel)
        XCTAssertEqual(-41, entries[0].rssi)
        XCTAssertEqual(1, entries[0].auth)
        XCTAssertEqual(Data("guest".utf8), entries[1].ssid)
        XCTAssertEqual(-73, entries[1].rssi)
    }

    func testCredWriteRsp() throws {
        XCTAssertEqual(6, try Messages.decodeCredWriteRsp(try rsp("cred_write_rsp")))
    }

    func testCredStatusRsp() throws {
        let status = try Messages.decodeCredStatusRsp(try rsp("cred_status_rsp"))
        XCTAssertEqual(1042, status[.deviceCert])
        XCTAssertEqual(121, status[.privateKey])
    }

    func testCtrlEndRsp() throws {
        try Messages.decodeCtrlRsp(try rsp("ctrl_end_rsp"), op: .end)
    }

    // MARK: - pouch framing

    func testSingleEntry() throws {
        try assertFrame(
            "single_entry",
            try Pouch.buildEntryPouch(
                deviceId: "dev-1",
                entries: [Entry(path: Messages.pathVer, contentType: 60, data: Messages.encodeVerReq())]
            )
        )
    }

    func testTwoEntriesOneBlock() throws {
        try assertFrame(
            "two_entries_one_block",
            try Pouch.buildEntryPouch(
                deviceId: "dev-1",
                entries: [
                    Entry(
                        path: Messages.pathConfig,
                        contentType: 60,
                        data: Messages.encodeConfigSet(ssid: Data("myssid".utf8), password: Data("hunter22".utf8))
                    ),
                    Entry(path: Messages.pathConfig, contentType: 60, data: Messages.encodeConfigApply()),
                ]
            )
        )
    }

    func testTwoBlocks() throws {
        let zeros = Data(count: 24)
        // block_size forces each cred entry into its own block (entry1=68B, entry2=69B).
        let pouch = try Pouch.buildEntryPouch(
            deviceId: "dev-1",
            entries: [
                Entry(
                    path: Messages.pathCred,
                    contentType: 60,
                    data: Messages.encodeCredWrite(kind: .deviceCert, offset: 0, total: 48, data: zeros)
                ),
                Entry(
                    path: Messages.pathCred,
                    contentType: 60,
                    data: Messages.encodeCredWrite(kind: .deviceCert, offset: 24, total: 48, data: zeros)
                ),
            ],
            blockSize: 100
        )
        try assertFrame("two_blocks", pouch)
    }

    func testEmptyPouch() throws {
        try assertFrame("empty", try Pouch.buildEntryPouch(deviceId: "dev-1", entries: []))
    }

    func testRoundTripSingleEntry() throws {
        let (header, entries) = try Pouch.parsePouch(try frame("single_entry"))
        XCTAssertEqual("dev-1", header.deviceId)
        XCTAssertEqual(1, entries.count)
        XCTAssertEqual(Messages.pathVer, entries[0].path)
        XCTAssertEqual(Messages.encodeVerReq(), entries[0].data)
    }
}
