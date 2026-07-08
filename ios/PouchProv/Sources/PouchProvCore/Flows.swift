// Copyright (c) 2026 Jonathan Beri
// SPDX-License-Identifier: Apache-2.0

import Foundation

/// A provisioning flow reached an unexpected state (the analogue of the
/// Kotlin `IllegalStateException` in `Flows.kt`).
public struct FlowError: Error, CustomStringConvertible {
    public let message: String

    public init(_ message: String) {
        self.message = message
    }

    public var description: String { message }
}

/// High-level provisioning flows composed over a ``ProvSession``. A faithful
/// port of the Kotlin/Python `Flows`.
public enum Flows {

    public static func getVersion(_ session: ProvSession) async throws -> VersionInfo {
        let info = try Messages.decodeVerRsp(
            try await session.request(path: Messages.pathVer, message: Messages.encodeVerReq())
        )
        guard info.proto == Messages.protoVersion else {
            throw FlowError("unsupported device protocol v\(info.proto)")
        }
        session.blockSize = info.blockSize
        return info
    }

    public static func authorizeIfNeeded(_ session: ProvSession, info: VersionInfo, pop: String?) async throws {
        if info.popRequired {
            guard let pop, !pop.isEmpty else {
                throw FlowError("device requires a proof-of-possession (pop)")
            }
            try await Auth.authorize(session: session, pop: pop)
        }
    }

    /// Trigger a scan, poll until finished, and collect all result pages.
    public static func scan(_ session: ProvSession, timeoutMs: Int64 = 20_000) async throws -> [ScanEntry] {
        try Messages.decodeScanStartRsp(
            try await session.request(path: Messages.pathScan, message: Messages.encodeScanStart())
        )

        let deadline = MonotonicClock.nowMs() + timeoutMs
        var total: Int
        while true {
            let (finished, t) = try Messages.decodeScanStatusRsp(
                try await session.request(path: Messages.pathScan, message: Messages.encodeScanGetStatus())
            )
            total = t
            if finished { break }
            guard MonotonicClock.nowMs() <= deadline else { throw FlowError("scan did not finish") }
            try await Task.sleep(nanoseconds: 500 * 1_000_000)
        }

        var results: [ScanEntry] = []
        while results.count < total {
            let page = try Messages.decodeScanResultsRsp(
                try await session.request(
                    path: Messages.pathScan,
                    message: Messages.encodeScanGetResults(start: results.count, count: 6)
                )
            )
            if page.isEmpty { break }
            results.append(contentsOf: page)
        }
        return results
    }

    /// Set + apply credentials, then poll status until connected or failed.
    public static func configureWifi(
        _ session: ProvSession,
        ssid: Data,
        password: Data?,
        timeoutMs: Int64 = 40_000
    ) async throws -> WifiStatus {
        try Messages.decodeConfigSetRsp(
            try await session.request(
                path: Messages.pathConfig,
                message: Messages.encodeConfigSet(ssid: ssid, password: password)
            )
        )
        try Messages.decodeConfigApplyRsp(
            try await session.request(path: Messages.pathConfig, message: Messages.encodeConfigApply())
        )

        let deadline = MonotonicClock.nowMs() + timeoutMs
        while true {
            let status = try Messages.decodeConfigStatusRsp(
                try await session.request(path: Messages.pathConfig, message: Messages.encodeConfigGetStatus())
            )
            if status.state == .connected || status.state == .failed { return status }
            guard MonotonicClock.nowMs() <= deadline else { throw FlowError("connection did not settle") }
            try await Task.sleep(nanoseconds: 1_000 * 1_000_000)
        }
    }

    /// Write one DER credential to the device in ordered chunks.
    public static func pushCredential(
        _ session: ProvSession,
        kind: CredKind,
        der: Data,
        chunk: Int = 256
    ) async throws {
        let bytes = [UInt8](der)
        let total = bytes.count
        var off = 0
        while off < total {
            let piece = Data(bytes[off..<min(off + chunk, total)])
            let received = try Messages.decodeCredWriteRsp(
                try await session.request(
                    path: Messages.pathCred,
                    message: Messages.encodeCredWrite(kind: kind, offset: off, total: total, data: piece)
                )
            )
            off += piece.count
            guard received == off else {
                throw FlowError("cred write desync: device has \(received), sent \(off)")
            }
        }
    }

    /// Push device cert + key (+ optional CA), then finalize.
    public static func bootstrapCredentials(
        _ session: ProvSession,
        certDer: Data,
        keyDer: Data,
        caDer: Data? = nil
    ) async throws {
        try await pushCredential(session, kind: .deviceCert, der: certDer)
        try await pushCredential(session, kind: .privateKey, der: keyDer)
        if let caDer {
            try await pushCredential(session, kind: .caCert, der: caDer)
        }
        try Messages.decodeCredFinalizeRsp(
            try await session.request(path: Messages.pathCred, message: Messages.encodeCredFinalize())
        )
    }

    public static func endSession(_ session: ProvSession) async throws {
        try Messages.decodeCtrlRsp(
            try await session.request(path: Messages.pathCtrl, message: Messages.encodeCtrl(.end)),
            op: .end
        )
    }
}
