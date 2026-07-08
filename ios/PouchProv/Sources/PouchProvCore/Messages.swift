// Copyright (c) 2026 Jonathan Beri
// SPDX-License-Identifier: Apache-2.0

import Foundation

/// Provisioning message codec (cddl/prov.cddl, protocol version 1).
///
/// Every message is a CBOR array `[op, ...]`. This mirrors the Kotlin
/// `Messages.kt` and the Python `codec.py`, and is pinned to the device's zcbor
/// codec via the shared golden vectors in `tests/vectors/`.
public enum Messages {
    public static let protoVersion = 1

    // Reserved provisioning paths (pouch downlink/uplink entry paths).
    public static let pathVer = ".prov/ver"
    public static let pathAuth = ".prov/auth"
    public static let pathConfig = ".prov/config"
    public static let pathScan = ".prov/scan"
    public static let pathCred = ".prov/cred"
    public static let pathCtrl = ".prov/ctrl"

    // MARK: - .prov/ver

    public static func encodeVerReq() -> Data {
        Cbor.encode(.array([.int(0)]))
    }

    public static func decodeVerRsp(_ data: Data) throws -> VersionInfo {
        let msg = try decodeResponse(data, expectOp: 0, context: "ver")
        guard msg.count > 2, case .map = msg[2],
              let proto = msg[2]["proto"]?.intValue,
              let rawCaps = msg[2]["caps"]?.arrayValue,
              let blockSize = msg[2]["blk"]?.intValue,
              let lib = msg[2]["lib"]?.textValue
        else { throw DecodeError("ver: bad info map") }
        let caps = try rawCaps.map { cap -> String in
            guard let text = cap.textValue else { throw DecodeError("ver: bad cap") }
            return text
        }
        return VersionInfo(
            proto: proto,
            caps: caps,
            blockSize: blockSize,
            lib: lib,
            popRequired: msg[2]["pop"]?.boolValue ?? false
        )
    }

    // MARK: - .prov/auth

    public static func encodeAuthChallenge(cliNonce: Data) -> Data {
        precondition(cliNonce.count == 16, "cli-nonce must be 16 bytes")
        return Cbor.encode(.array([.int(0), .bytes(cliNonce)]))
    }

    /// Returns (devNonce, devProof).
    public static func decodeAuthChallengeRsp(_ data: Data) throws -> (devNonce: Data, devProof: Data) {
        let msg = try decodeResponse(data, expectOp: 0, context: "auth")
        guard msg.count > 3,
              let devNonce = msg[2].bytesValue,
              let devProof = msg[3].bytesValue
        else { throw DecodeError("auth: bad challenge response") }
        guard devNonce.count == 16, devProof.count == 32 else {
            throw DecodeError("auth: bad nonce/proof size")
        }
        return (devNonce, devProof)
    }

    public static func encodeAuthProof(cliProof: Data) -> Data {
        precondition(cliProof.count == 32, "cli-proof must be 32 bytes")
        return Cbor.encode(.array([.int(1), .bytes(cliProof)]))
    }

    public static func decodeAuthProofRsp(_ data: Data) throws {
        _ = try decodeResponse(data, expectOp: 1, context: "auth")
    }

    // MARK: - .prov/config

    public static func encodeConfigGetStatus() -> Data {
        Cbor.encode(.array([.int(0)]))
    }

    public static func encodeConfigSet(
        ssid: Data,
        password: Data? = nil,
        bssid: Data? = nil,
        channel: Int? = nil
    ) -> Data {
        var cfg: [CborPair] = [CborPair(.text("ssid"), .bytes(ssid))]
        if let password { cfg.append(CborPair(.text("pass"), .bytes(password))) }
        if let bssid { cfg.append(CborPair(.text("bssid"), .bytes(bssid))) }
        if let channel { cfg.append(CborPair(.text("ch"), .int(Int64(channel)))) }
        return Cbor.encode(.array([.int(1), .map(cfg)]))
    }

    public static func encodeConfigApply() -> Data {
        Cbor.encode(.array([.int(2)]))
    }

    public static func decodeConfigStatusRsp(_ data: Data) throws -> WifiStatus {
        let msg = try decodeResponse(data, expectOp: 0, context: "config")
        guard msg.count > 2, let stateCode = msg[2].intValue else {
            throw DecodeError("config: bad sta-state")
        }
        let state = try StaState.from(stateCode)
        var failReason: FailReason?
        var ip4: Data?
        var ssid: Data?
        var rssi: Int?
        if msg.count > 3 {
            switch msg[3] {
            case .int(let reason):
                failReason = try FailReason.from(Int(reason))
            case .map:
                guard let detailIp4 = msg[3]["ip4"]?.bytesValue,
                      let detailSsid = msg[3]["ssid"]?.bytesValue
                else { throw DecodeError("config: bad status detail") }
                ip4 = detailIp4
                ssid = detailSsid
                rssi = msg[3]["rssi"]?.intValue
            default:
                throw DecodeError("config: bad status detail")
            }
        }
        return WifiStatus(state: state, failReason: failReason, ip4: ip4, ssid: ssid, rssi: rssi)
    }

    public static func decodeConfigSetRsp(_ data: Data) throws {
        _ = try decodeResponse(data, expectOp: 1, context: "config")
    }

    public static func decodeConfigApplyRsp(_ data: Data) throws {
        _ = try decodeResponse(data, expectOp: 2, context: "config")
    }

    // MARK: - .prov/scan

    public static func encodeScanStart(passive: Bool? = nil, periodMs: Int? = nil) -> Data {
        var params: [CborPair] = []
        if let passive { params.append(CborPair(.text("passive"), .bool(passive))) }
        if let periodMs { params.append(CborPair(.text("period-ms"), .int(Int64(periodMs)))) }
        return Cbor.encode(.array([.int(0), .map(params)]))
    }

    public static func encodeScanGetStatus() -> Data {
        Cbor.encode(.array([.int(1)]))
    }

    public static func encodeScanGetResults(start: Int, count: Int) -> Data {
        Cbor.encode(.array([.int(2), .int(Int64(start)), .int(Int64(count))]))
    }

    public static func decodeScanStartRsp(_ data: Data) throws {
        _ = try decodeResponse(data, expectOp: 0, context: "scan")
    }

    /// Returns (finished, total).
    public static func decodeScanStatusRsp(_ data: Data) throws -> (finished: Bool, total: Int) {
        let msg = try decodeResponse(data, expectOp: 1, context: "scan")
        guard msg.count > 3,
              let finished = msg[2].boolValue,
              let total = msg[3].intValue
        else { throw DecodeError("scan: bad status response") }
        return (finished, total)
    }

    public static func decodeScanResultsRsp(_ data: Data) throws -> [ScanEntry] {
        let msg = try decodeResponse(data, expectOp: 2, context: "scan")
        guard msg.count > 2, let list = msg[2].arrayValue else {
            throw DecodeError("scan: bad results response")
        }
        return try list.map { entry -> ScanEntry in
            guard case .map = entry,
                  let ssid = entry["ssid"]?.bytesValue,
                  let bssid = entry["bssid"]?.bytesValue,
                  let channel = entry["ch"]?.intValue,
                  let rssi = entry["rssi"]?.intValue,
                  let auth = entry["auth"]?.intValue
            else { throw DecodeError("scan: bad result entry") }
            return ScanEntry(ssid: ssid, bssid: bssid, channel: channel, rssi: rssi, auth: auth)
        }
    }

    // MARK: - .prov/cred

    public static func encodeCredWrite(kind: CredKind, offset: Int, total: Int, data: Data) -> Data {
        let map: [CborPair] = [
            CborPair(.text("kind"), .int(Int64(kind.rawValue))),
            CborPair(.text("off"), .int(Int64(offset))),
            CborPair(.text("total"), .int(Int64(total))),
            CborPair(.text("data"), .bytes(data)),
        ]
        return Cbor.encode(.array([.int(0), .map(map)]))
    }

    public static func encodeCredFinalize() -> Data {
        Cbor.encode(.array([.int(1)]))
    }

    public static func encodeCredGetStatus() -> Data {
        Cbor.encode(.array([.int(2)]))
    }

    /// Returns total bytes received for the written kind.
    public static func decodeCredWriteRsp(_ data: Data) throws -> Int {
        let msg = try decodeResponse(data, expectOp: 0, context: "cred")
        guard msg.count > 2, let received = msg[2].intValue else {
            throw DecodeError("cred: bad write response")
        }
        return received
    }

    public static func decodeCredFinalizeRsp(_ data: Data) throws {
        _ = try decodeResponse(data, expectOp: 1, context: "cred")
    }

    public static func decodeCredStatusRsp(_ data: Data) throws -> [CredKind: Int] {
        let msg = try decodeResponse(data, expectOp: 2, context: "cred")
        guard msg.count > 2, let pairs = msg[2].mapValue else {
            throw DecodeError("cred: bad status response")
        }
        var status: [CredKind: Int] = [:]
        for pair in pairs {
            guard let key = pair.key.textValue, let code = Int(key), let len = pair.value.intValue else {
                throw DecodeError("cred: bad status entry")
            }
            status[try CredKind.from(code)] = len
        }
        return status
    }

    // MARK: - .prov/ctrl

    public static func encodeCtrl(_ op: CtrlOp) -> Data {
        Cbor.encode(.array([.int(Int64(op.rawValue))]))
    }

    public static func decodeCtrlRsp(_ data: Data, op: CtrlOp) throws {
        _ = try decodeResponse(data, expectOp: op.rawValue, context: "ctrl")
    }

    // MARK: - shared

    private static func decodeResponse(_ data: Data, expectOp: Int, context: String) throws -> [CborValue] {
        let obj: CborValue
        do {
            obj = try Cbor.decode(data)
        } catch {
            throw DecodeError("\(context): bad CBOR: \(error)")
        }
        guard let msg = obj.arrayValue, msg.count >= 2 else {
            throw DecodeError("\(context): not a response array")
        }
        guard let op = msg[0].intValue, op == expectOp else {
            throw DecodeError("\(context): op \(msg[0]), expected \(expectOp)")
        }
        guard let statusCode = msg[1].intValue else {
            throw DecodeError("\(context): bad status")
        }
        let status = try Status.from(statusCode)
        guard status == .ok else { throw ProvError(status: status, context: context) }
        return msg
    }
}

// MARK: - enums

public enum Status: Int, Equatable, Sendable {
    case ok = 0
    case invalidProto = 1
    case invalidArgument = 2
    case internalError = 3
    case unauthorized = 4
    case invalidState = 5
    case busy = 6

    static func from(_ code: Int) throws -> Status {
        guard let status = Status(rawValue: code) else { throw DecodeError("unknown status \(code)") }
        return status
    }
}

public enum StaState: Int, Equatable, Sendable {
    case connected = 0
    case connecting = 1
    case disconnected = 2
    case failed = 3

    static func from(_ code: Int) throws -> StaState {
        guard let state = StaState(rawValue: code) else { throw DecodeError("unknown sta-state \(code)") }
        return state
    }
}

public enum FailReason: Int, Equatable, Sendable {
    case authError = 0
    case networkNotFound = 1

    static func from(_ code: Int) throws -> FailReason {
        guard let reason = FailReason(rawValue: code) else { throw DecodeError("unknown fail-reason \(code)") }
        return reason
    }
}

public enum CredKind: Int, Equatable, Sendable {
    case deviceCert = 0
    case privateKey = 1
    case caCert = 2

    static func from(_ code: Int) throws -> CredKind {
        guard let kind = CredKind(rawValue: code) else { throw DecodeError("unknown cred kind \(code)") }
        return kind
    }
}

public enum CtrlOp: Int, Equatable, Sendable {
    case reset = 0
    case reprovision = 1
    case end = 2
}

// MARK: - value types

public struct VersionInfo: Equatable, Sendable {
    public let proto: Int
    public let caps: [String]
    public let blockSize: Int
    public let lib: String
    public let popRequired: Bool

    public init(proto: Int, caps: [String], blockSize: Int, lib: String, popRequired: Bool) {
        self.proto = proto
        self.caps = caps
        self.blockSize = blockSize
        self.lib = lib
        self.popRequired = popRequired
    }

    public func hasCap(_ cap: String) -> Bool {
        caps.contains(cap)
    }
}

public struct WifiStatus: Equatable, Sendable {
    public let state: StaState
    public let failReason: FailReason?
    public let ip4: Data?
    public let ssid: Data?
    public let rssi: Int?

    public init(
        state: StaState,
        failReason: FailReason? = nil,
        ip4: Data? = nil,
        ssid: Data? = nil,
        rssi: Int? = nil
    ) {
        self.state = state
        self.failReason = failReason
        self.ip4 = ip4
        self.ssid = ssid
        self.rssi = rssi
    }
}

public struct ScanEntry: Equatable, Sendable {
    public let ssid: Data
    public let bssid: Data
    public let channel: Int
    public let rssi: Int
    public let auth: Int

    public init(ssid: Data, bssid: Data, channel: Int, rssi: Int, auth: Int) {
        self.ssid = ssid
        self.bssid = bssid
        self.channel = channel
        self.rssi = rssi
        self.auth = auth
    }
}

// MARK: - errors

/// Protocol-level error reported by the device.
public struct ProvError: Error, Equatable, CustomStringConvertible {
    public let status: Status
    public let context: String

    public init(status: Status, context: String = "") {
        self.status = status
        self.context = context
    }

    public var description: String {
        context.isEmpty ? "\(status)" : "\(context): \(status)"
    }
}

/// Response did not match the schema.
public struct DecodeError: Error, CustomStringConvertible {
    public let message: String

    public init(_ message: String) {
        self.message = message
    }

    public var description: String { message }
}
