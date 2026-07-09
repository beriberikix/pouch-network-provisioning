// Copyright (c) 2026 Jonathan Beri
// SPDX-License-Identifier: Apache-2.0

import Foundation

/// Seam between the RPC engine and the pouch framing/crypto. The plaintext
/// implementation frames encryption-none pouches; a saead implementation can be
/// dropped in later without reshaping ``ProvSession``.
public protocol SessionCrypto: Sendable {
    /// Build the request (downlink) pouch bytes carrying `entries`.
    func buildRequest(entries: [Entry], deviceId: String, blockSize: Int) throws -> Data

    /// Parse a response (uplink) pouch into its header and entries.
    func parseResponse(_ data: Data) throws -> (header: PouchHeader, entries: [Entry])
}

/// Plaintext (encryption-none) framing — parity with the CLI's live path.
public struct PlaintextCrypto: SessionCrypto {
    public init() {}

    public func buildRequest(entries: [Entry], deviceId: String, blockSize: Int) throws -> Data {
        try Pouch.buildEntryPouch(
            deviceId: deviceId.isEmpty ? "?" : deviceId,
            entries: entries,
            blockSize: blockSize
        )
    }

    public func parseResponse(_ data: Data) throws -> (header: PouchHeader, entries: [Entry]) {
        try Pouch.parsePouch(data)
    }
}

public struct SessionError: Error, CustomStringConvertible {
    public let message: String

    public init(_ message: String) {
        self.message = message
    }

    public var description: String { message }
}

/// Lockstep request/response engine. One request pouch at a time.
///
/// Implements the client-driven RPC cycle (docs/protocol.md): request = subscribe
/// downlink -> SAR-send one pouch -> unsubscribe; response = subscribe uplink ->
/// SAR-receive one pouch -> unsubscribe. An empty response pouch means "not
/// ready, retry". A faithful port of the Kotlin/Python `ProvSession`.
public final class ProvSession: @unchecked Sendable {
    // ATT MTU 247 => 244-byte payloads on notification / write.
    public static let defaultMaxlen = 244

    private let transport: any ProvTransport
    public var deviceId: String
    private let maxlen: Int
    private let crypto: any SessionCrypto

    public var blockSize: Int = Pouch.defaultBlockSize

    private let lock = AsyncMutex()

    public init(
        transport: any ProvTransport,
        deviceId: String = "",
        maxlen: Int = ProvSession.defaultMaxlen,
        crypto: any SessionCrypto = PlaintextCrypto()
    ) {
        self.transport = transport
        self.deviceId = deviceId
        self.maxlen = maxlen
        self.crypto = crypto
    }

    /// Send request entries in one pouch, return the response entries.
    public func requestEntries(
        _ entries: [Entry],
        timeoutMs: Int64 = 15_000,
        pollAttempts: Int = 5
    ) async throws -> [Entry] {
        try await lock.withLock {
            try await sendPouch(entries, timeoutMs: timeoutMs)

            var backoff: Int64 = 200
            for _ in 0..<pollAttempts {
                let (header, rsp) = try await receivePouch(timeoutMs: timeoutMs)
                deviceId = header.deviceId ?? deviceId
                if !rsp.isEmpty { return rsp }
                // Empty pouch: responses were not ready; back off and re-poll.
                try await Task.sleep(nanoseconds: UInt64(backoff) * 1_000_000)
                backoff = min(backoff * 2, 2_000)
            }
            throw SessionError("no response after retries")
        }
    }

    /// Single-entry convenience: request `message` on `path`, return the response bytes.
    public func request(path: String, message: Data, timeoutMs: Int64 = 15_000) async throws -> Data {
        let entries = try await requestEntries(
            [Entry(path: path, contentType: Pouch.contentTypeCbor, data: message)],
            timeoutMs: timeoutMs
        )
        guard let rsp = entries.first(where: { $0.path == path })?.data else {
            throw SessionError("no response entry for \(path)")
        }
        return rsp
    }

    private func sendPouch(_ entries: [Entry], timeoutMs: Int64) async throws {
        let data = try crypto.buildRequest(entries: entries, deviceId: deviceId, blockSize: blockSize)
        let channel = transport.downlink
        let sender = SarSender(write: { try await channel.write($0) }, maxlen: maxlen)
        try await channel.subscribe { sender.feed($0) }
        do {
            try await sender.send(data, timeoutMs: timeoutMs)
        } catch {
            await channel.unsubscribe()
            throw error
        }
        await channel.unsubscribe()
    }

    private func receivePouch(timeoutMs: Int64) async throws -> (header: PouchHeader, entries: [Entry]) {
        let channel = transport.uplink
        let receiver = SarReceiver(write: { try await channel.write($0) })
        try await channel.subscribe { receiver.feed($0) }
        let data: Data
        do {
            data = try await receiver.receive(timeoutMs: timeoutMs)
        } catch {
            await channel.unsubscribe()
            throw error
        }
        await channel.unsubscribe()
        return try crypto.parseResponse(data)
    }
}
