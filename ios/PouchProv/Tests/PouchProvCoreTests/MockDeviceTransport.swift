// Copyright (c) 2026 Jonathan Beri
// SPDX-License-Identifier: Apache-2.0

import Foundation
@testable import PouchProvCore

/// Request handler: (path, payload) -> response payload, or nil to not respond.
typealias MockHandler = (String, Data) -> Data?

/// A mock channel that invokes device hooks synchronously, as the Kotlin and
/// Python mocks do.
final class MockChannel: ProvChannel, @unchecked Sendable {
    private var notifyCallback: (@Sendable (Data) -> Void)?
    var onWrite: ((Data) -> Void)?
    var onSubscribe: (() -> Void)?
    var onUnsubscribe: (() -> Void)?

    func write(_ data: Data) async throws {
        onWrite!(Data(data))
    }

    func subscribe(_ onNotify: @escaping @Sendable (Data) -> Void) async throws {
        notifyCallback = onNotify
        onSubscribe?()
    }

    func unsubscribe() async {
        notifyCallback = nil
        onUnsubscribe?()
    }

    func notify(_ data: Data) {
        notifyCallback?(Data(data))
    }
}

/// In-memory mock of a provisioning device (plaintext path) for tests.
///
/// Implements the device side of the SAR + pouch RPC contract faithfully enough
/// to exercise the full client stack: initial-ack-on-subscribe, in-order acking,
/// LAST/FIN handshake ([0x04, 0x00] success FIN), and the one-transaction-per-
/// subscribe rule. A port of the Kotlin/Python mock (plaintext only).
final class MockDeviceTransport: ProvTransport, @unchecked Sendable {
    private let handler: MockHandler
    private let deviceId: String
    private let window: Int
    /// Number of uplink transactions to answer with an empty ("not ready")
    /// pouch before responding, exercising the client's re-poll path.
    private var deferResponses: Int

    private let downlinkChannel = MockChannel()
    private let uplinkChannel = MockChannel()

    var downlink: any ProvChannel { downlinkChannel }
    var uplink: any ProvChannel { uplinkChannel }

    private var responses: [Entry] = []

    // downlink (device is SAR receiver) state
    private var rxChunks: [Data] = []
    private var rxExpected = 0
    private var rxEnded = false

    // uplink (device is SAR sender) state
    private var ulFrags: [Data] = []
    private var ulSeq = 0
    private var ulFinished = false

    init(handler: @escaping MockHandler, deviceId: String = "mock-dev", window: Int = 3, deferResponses: Int = 0) {
        self.handler = handler
        self.deviceId = deviceId
        self.window = window
        self.deferResponses = deferResponses

        downlinkChannel.onSubscribe = { [unowned self] in dlOpen() }
        downlinkChannel.onWrite = { [unowned self] in dlWrite($0) }
        uplinkChannel.onSubscribe = { [unowned self] in ulOpen() }
        uplinkChannel.onWrite = { [unowned self] in ulWrite($0) }
    }

    func connect() async throws {}
    func disconnect() async {}

    // MARK: - downlink: device is the SAR receiver

    private func dlAck(_ seq: Int) {
        downlinkChannel.notify(Data([Sar.codeAck, UInt8(seq & 0xFF), UInt8(window)]))
    }

    private func dlOpen() {
        rxChunks = []
        rxExpected = 0
        rxEnded = false
        dlAck(0xFF)
    }

    private func dlWrite(_ pkt: Data) {
        let bytes = [UInt8](pkt)
        let flags = bytes[0]
        if flags & Sar.flagFin != 0 {
            precondition(rxEnded, "FIN before LAST")
            if bytes[1] == Sar.codeAck {
                processRequest(rxChunks.reduce(into: Data()) { $0.append($1) })
            }
            return
        }
        let seq = Int(bytes[1])
        precondition(seq == rxExpected, "mock expects in-order (got \(seq))")
        rxChunks.append(Data(bytes[Sar.headerLen...]))
        rxExpected = (seq + 1) & 0xFF
        if flags & Sar.flagLast != 0 { rxEnded = true }
        dlAck(seq)
    }

    private func processRequest(_ data: Data) {
        let (_, entries) = try! Pouch.parsePouch(data)
        for entry in entries {
            if let rsp = handler(entry.path, entry.data) {
                responses.append(Entry(path: entry.path, contentType: entry.contentType, data: rsp))
            }
        }
    }

    // MARK: - uplink: device is the SAR sender

    private func ulOpen() {
        let entries: [Entry]
        if deferResponses > 0 {
            deferResponses -= 1
            entries = []
        } else {
            entries = responses
            responses = []
        }
        let data: Data
        if !entries.isEmpty {
            data = try! Pouch.buildEntryPouch(deviceId: deviceId, entries: entries)
        } else {
            // header + one empty block = the "responses not ready" empty pouch
            var out = PouchHeader.plaintext(deviceId: deviceId).encode()
            out.append(Block(payload: Data()).encode())
            data = out
        }
        let frag = 244 - Sar.headerLen
        let bytes = [UInt8](data)
        var frags = stride(from: 0, to: bytes.count, by: frag).map {
            Data(bytes[$0..<min($0 + frag, bytes.count)])
        }
        if frags.isEmpty { frags = [Data()] }
        ulFrags = frags
        ulSeq = 0
        ulFinished = false
    }

    private func ulWrite(_ ack: Data) {
        let bytes = [UInt8](ack)
        let ackSeq = Int(bytes[1])
        let window = Int(bytes[2])
        precondition(bytes[0] == Sar.codeAck)
        if ulFinished { return }
        if ulSeq >= ulFrags.count {
            if ackSeq == (ulSeq - 1) & 0xFF {
                ulFinished = true
                uplinkChannel.notify(Data([Sar.flagFin, Sar.codeAck]))
            }
            return
        }
        let target = (ackSeq + window + 1) & 0xFF
        while ulSeq != target && ulSeq < ulFrags.count {
            var flags: UInt8 = 0
            if ulSeq == 0 { flags |= Sar.flagFirst }
            if ulSeq == ulFrags.count - 1 { flags |= Sar.flagLast }
            uplinkChannel.notify(Data([flags, UInt8(ulSeq)]) + ulFrags[ulSeq])
            ulSeq += 1
        }
    }
}
