// Copyright (c) 2026 Jonathan Beri
// SPDX-License-Identifier: Apache-2.0

import Crypto
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

    // saead builds: TOFU endpoints + device-side crypto state.
    private(set) var info: (any ProvChannel)?
    private(set) var serverCert: (any ProvChannel)?
    private(set) var deviceCert: (any ProvChannel)?
    private(set) var storedServerCert: Data?
    private let saeadIdentity: Tofu.ServerIdentity?
    private let saeadAlgorithm: Int
    private var serverPublic: P256.KeyAgreement.PublicKey?
    private let uplinkSid = Data((0..<16).map { UInt8($0) })
    private var infoSender: DeviceSarSender?
    private var deviceCertSender: DeviceSarSender?
    private var serverCertReceiver: DeviceSarReceiver?

    private var responses: [Entry] = []

    // downlink (device is SAR receiver) state
    private var rxChunks: [Data] = []
    private var rxExpected = 0
    private var rxEnded = false

    // uplink (device is SAR sender) state
    private var ulFrags: [Data] = []
    private var ulSeq = 0
    private var ulFinished = false

    init(
        handler: @escaping MockHandler,
        deviceId: String = "mock-dev",
        window: Int = 3,
        deferResponses: Int = 0,
        saeadIdentity: Tofu.ServerIdentity? = nil,
        saeadAlgorithm: Int = Pouch.algChacha20Poly1305
    ) {
        self.handler = handler
        self.deviceId = deviceId
        self.window = window
        self.deferResponses = deferResponses
        self.saeadIdentity = saeadIdentity
        self.saeadAlgorithm = saeadAlgorithm

        downlinkChannel.onSubscribe = { [unowned self] in dlOpen() }
        downlinkChannel.onWrite = { [unowned self] in dlWrite($0) }
        uplinkChannel.onSubscribe = { [unowned self] in ulOpen() }
        uplinkChannel.onWrite = { [unowned self] in ulWrite($0) }

        if saeadIdentity != nil {
            let infoCh = MockChannel()
            let serverCh = MockChannel()
            let deviceCh = MockChannel()
            infoSender = DeviceSarSender(channel: infoCh) { [unowned self] in infoPayload() }
            deviceCertSender = DeviceSarSender(channel: deviceCh) { saeadIdentity!.certDer }
            serverCertReceiver = DeviceSarReceiver(channel: serverCh) { [unowned self] in storeServerCert($0) }
            info = infoCh
            serverCert = serverCh
            deviceCert = deviceCh
        }
    }

    // MARK: - TOFU endpoints (saead builds)

    private func infoPayload() -> Data {
        let serial = storedServerCert.flatMap { try? Tofu.certSerial($0) } ?? Data()
        return Cbor.encode(.map([
            CborPair(.text("flags"), .int(0)),
            CborPair(.text("server_cert_snr"), .bytes(serial)),
        ]))
    }

    private func storeServerCert(_ der: Data) {
        storedServerCert = der
        serverPublic = try! Tofu.devicePublicKey(der)
    }

    private var saeadActive: Bool { saeadIdentity != nil && serverPublic != nil }

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
        let entries = saeadActive ? try! decryptDownlink(data) : try! Pouch.parsePouch(data).entries
        for entry in entries {
            if let rsp = handler(entry.path, entry.data) {
                responses.append(Entry(path: entry.path, contentType: entry.contentType, data: rsp))
            }
        }
    }

    // MARK: - device-side saead (mirrors the Python mock's DeviceSaead)

    private func decryptDownlink(_ data: Data) throws -> [Entry] {
        let (header, consumed) = try PouchHeader.decode(data)
        let info = try SessionInfo.fromCborObj(header.sessionInfo!)
        let key = try Saead.deriveSessionKey(
            ourPrivate: saeadIdentity!.privateKey, peerPublic: serverPublic!,
            sessionId: info.sessionId, initiator: Pouch.roleServer,
            algorithm: info.algorithm, maxBlockSizeLog: info.maxBlockSizeLog
        )
        let bytes = Data(data)
        var payloads: [Data] = []
        var pos = consumed
        var idx = 0
        var prevTag = Data()
        while pos < bytes.count {
            let size = (Int(bytes[pos]) << 8) | Int(bytes[pos + 1])
            pos += 2
            let sealed = bytes.subdata(in: pos..<(pos + size))
            pos += size
            let nonce = Saead.nonce(pouchId: Int(header.pouchId), blockIndex: idx, senderRole: Pouch.roleServer)
            let aad = idx > 0 ? prevTag : Data()
            let plain = try Saead.open(algorithm: info.algorithm, key: key, nonce: nonce, sealed: sealed, aad: aad)
            prevTag = sealed.suffix(Saead.authTagLen)
            payloads.append(plain.dropFirst())
            idx += 1
        }
        return try Pouch.parseEntryBlocks(payloads)
    }

    private func encryptUplink(_ entries: [Entry], pouchId: Int = 1) throws -> Data {
        let key = try Saead.deriveSessionKey(
            ourPrivate: saeadIdentity!.privateKey, peerPublic: serverPublic!,
            sessionId: uplinkSid, initiator: Pouch.roleDevice,
            algorithm: saeadAlgorithm, maxBlockSizeLog: 9
        )
        let info = SessionInfo(
            sessionId: uplinkSid, initiator: Pouch.roleDevice, algorithm: saeadAlgorithm,
            maxBlockSizeLog: 9, certRef: Data(count: 6)
        )
        let header = PouchHeader(
            encryption: Pouch.encryptionSaead, sessionInfo: info.toCborObj(), pouchId: Int64(pouchId)
        )
        var payload = Data()
        for entry in entries { payload.append(entry.encode()) }
        let idByte = UInt8(Pouch.blockIdEntry | Pouch.blockFirst | Pouch.blockLast)
        let blockPlain = Data([idByte]) + payload
        let nonce = Saead.nonce(pouchId: pouchId, blockIndex: 0, senderRole: Pouch.roleDevice)
        let sealed = try Saead.seal(algorithm: saeadAlgorithm, key: key, nonce: nonce, plaintext: blockPlain, aad: Data())
        var out = header.encode()
        out.append(UInt8((sealed.count >> 8) & 0xFF))
        out.append(UInt8(sealed.count & 0xFF))
        out.append(sealed)
        return out
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
        if saeadActive {
            if !entries.isEmpty {
                data = try! encryptUplink(entries)
            } else {
                // header-only saead pouch = the "responses not ready" empty pouch
                let info = SessionInfo(
                    sessionId: uplinkSid, initiator: Pouch.roleDevice, algorithm: saeadAlgorithm,
                    maxBlockSizeLog: 9, certRef: Data(count: 6)
                )
                data = PouchHeader(
                    encryption: Pouch.encryptionSaead, sessionInfo: info.toCborObj(), pouchId: 1
                ).encode()
            }
        } else if !entries.isEmpty {
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

/// Device-side SAR sender behind a mock channel (info / device_cert).
final class DeviceSarSender: @unchecked Sendable {
    private let channel: MockChannel
    private let payloadFn: () -> Data
    private let frag = 244 - Sar.headerLen
    private var frags: [Data] = []
    private var seq = 0
    private var finished = false

    init(channel: MockChannel, payloadFn: @escaping () -> Data) {
        self.channel = channel
        self.payloadFn = payloadFn
        channel.onSubscribe = { [unowned self] in open() }
        channel.onWrite = { [unowned self] in onAck($0) }
    }

    private func open() {
        let bytes = [UInt8](payloadFn())
        var out = stride(from: 0, to: bytes.count, by: frag).map {
            Data(bytes[$0..<min($0 + frag, bytes.count)])
        }
        if out.isEmpty { out = [Data()] }
        frags = out
        seq = 0
        finished = false
    }

    private func onAck(_ ack: Data) {
        let bytes = [UInt8](ack)
        let ackSeq = Int(bytes[1])
        let window = Int(bytes[2])
        precondition(bytes[0] == Sar.codeAck)
        if finished { return }
        if seq >= frags.count {
            if ackSeq == (seq - 1) & 0xFF {
                finished = true
                channel.notify(Data([Sar.flagFin, Sar.codeAck]))
            }
            return
        }
        let target = (ackSeq + window + 1) & 0xFF
        while seq != target && seq < frags.count {
            var flags: UInt8 = 0
            if seq == 0 { flags |= Sar.flagFirst }
            if seq == frags.count - 1 { flags |= Sar.flagLast }
            channel.notify(Data([flags, UInt8(seq)]) + frags[seq])
            seq += 1
        }
    }
}

/// Device-side SAR receiver behind a mock channel (server_cert).
final class DeviceSarReceiver: @unchecked Sendable {
    private let channel: MockChannel
    private let onData: (Data) -> Void
    private let window: Int
    private var chunks: [Data] = []
    private var expected = 0
    private var ended = false

    init(channel: MockChannel, window: Int = 3, onData: @escaping (Data) -> Void) {
        self.channel = channel
        self.window = window
        self.onData = onData
        channel.onSubscribe = { [unowned self] in open() }
        channel.onWrite = { [unowned self] in onWrite($0) }
    }

    private func ack(_ seq: Int) {
        channel.notify(Data([Sar.codeAck, UInt8(seq & 0xFF), UInt8(window)]))
    }

    private func open() {
        chunks = []
        expected = 0
        ended = false
        ack(0xFF)
    }

    private func onWrite(_ pkt: Data) {
        let bytes = [UInt8](pkt)
        let flags = bytes[0]
        if flags & Sar.flagFin != 0 {
            precondition(ended, "FIN before LAST")
            if bytes[1] == Sar.codeAck {
                onData(chunks.reduce(into: Data()) { $0.append($1) })
            }
            return
        }
        let seq = Int(bytes[1])
        precondition(seq == expected, "mock expects in-order (got \(seq))")
        chunks.append(Data(bytes[Sar.headerLen...]))
        expected = (seq + 1) & 0xFF
        if flags & Sar.flagLast != 0 { ended = true }
        ack(seq)
    }
}
