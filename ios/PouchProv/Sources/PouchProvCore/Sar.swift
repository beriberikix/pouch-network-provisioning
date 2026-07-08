// Copyright (c) 2026 Jonathan Beri
// SPDX-License-Identifier: Apache-2.0

import Foundation

/// Pouch SAR (segmentation and reassembly) — client side.
///
/// A faithful port of the Kotlin/Python `sar`. Wire format per pouch
/// src/transport/sar/packet.{h,c}:
///
/// TX packet (sender -> receiver):
///   byte 0: flags — FIRST=0x01, LAST=0x02, FIN=0x04
///   byte 1: sequence number (mod 256); for FIN packets a code byte instead
///           (0 on the first FIN = success, 2 on retransmits)
///   2..:    fragment payload
///
/// ACK packet (receiver -> sender):
///   byte 0: code — 0 ACK, 1 NACK_UNKNOWN, 2 NACK_IDLE
///   byte 1: last in-order sequence received (0xFF before any)
///   byte 2: window (<= 127)
public enum Sar {
    public static let flagFirst: UInt8 = 0x01
    public static let flagLast: UInt8 = 0x02
    public static let flagFin: UInt8 = 0x04

    public static let codeAck: UInt8 = 0
    public static let codeNackUnknown: UInt8 = 1
    public static let codeNackIdle: UInt8 = 2

    public static let seqMask = 0xFF
    public static let headerLen = 2
}

/// Async "write toward the peer" callback.
public typealias SarWriteCallback = @Sendable (Data) async throws -> Void

public struct SarError: Error, CustomStringConvertible {
    public let message: String

    public init(_ message: String) {
        self.message = message
    }

    public var description: String { message }
}

/// Send one blob as a SAR transaction.
public final class SarSender: @unchecked Sendable {
    private let write: SarWriteCallback
    private let frag: Int
    private let acks = PacketQueue()

    public init(write: @escaping SarWriteCallback, maxlen: Int) {
        precondition(maxlen > Sar.headerLen, "maxlen too small")
        self.write = write
        self.frag = maxlen - Sar.headerLen
    }

    /// Feed an incoming ACK notification (safe to call from a callback).
    public func feed(_ packet: Data) {
        acks.feed(Data(packet))
    }

    public func send(_ data: Data, timeoutMs: Int64 = 10_000) async throws {
        let bytes = [UInt8](data)
        let frags: [Data]
        if bytes.isEmpty {
            frags = [Data()]
        } else {
            frags = stride(from: 0, to: bytes.count, by: frag).map {
                Data(bytes[$0..<min($0 + frag, bytes.count)])
            }
        }
        var seq = 0
        var sentLast = false

        while true {
            guard let ack = await acks.receive(timeoutMs: timeoutMs) else {
                throw SarError("timed out waiting for ack")
            }
            guard ack.count == 3 else { throw SarError("bad ack length \(ack.count)") }
            let ackBytes = [UInt8](ack)
            let code = ackBytes[0]
            let ackSeq = Int(ackBytes[1])
            let window = Int(ackBytes[2])
            guard code == Sar.codeAck else { throw SarError("receiver NACK (code \(code))") }
            let target = (ackSeq + window + 1) & Sar.seqMask

            if sentLast {
                if ackSeq == (seq - 1) & Sar.seqMask {
                    // The receiver has already ACKed every data fragment, so the
                    // blob is fully delivered. The FIN is a courtesy close: the
                    // device processes it and tears down its SAR endpoint, which
                    // can make the ATT write-response for this very packet come
                    // back as an error (e.g. "Unlikely Error" 0x0E). Treat the
                    // FIN write as best-effort so that doesn't fail the transfer.
                    try? await write(Data([Sar.flagFin, Sar.codeAck]))
                    return
                }
                continue // stale ack; wait for the ack of the LAST fragment
            }

            while seq != target && !sentLast {
                let idx = seq // fragments are < 256 for provisioning payloads
                var flags: UInt8 = 0
                if idx == 0 { flags |= Sar.flagFirst }
                if idx == frags.count - 1 {
                    flags |= Sar.flagLast
                    sentLast = true
                }
                try await write(Data([flags, UInt8(seq)]) + frags[idx])
                seq = (seq + 1) & Sar.seqMask
            }
        }
    }
}

/// Receive one blob as a SAR transaction.
public final class SarReceiver: @unchecked Sendable {
    private let write: SarWriteCallback
    private let window: Int
    private let reackIntervalMs: Int64
    private let pkts = PacketQueue()

    public init(write: @escaping SarWriteCallback, window: Int = 8, reackIntervalMs: Int64 = 500) {
        precondition((1...127).contains(window), "window out of range")
        self.write = write
        self.window = window
        self.reackIntervalMs = reackIntervalMs
    }

    /// Feed an incoming TX-packet notification (safe to call from a callback).
    public func feed(_ packet: Data) {
        pkts.feed(Data(packet))
    }

    private func ack(_ seq: Int) async throws {
        try await write(Data([Sar.codeAck, UInt8(seq & 0xFF), UInt8(window)]))
    }

    /// Run the transaction to completion; returns the reassembled blob.
    public func receive(timeoutMs: Int64 = 15_000) async throws -> Data {
        var chunks: [Data] = []
        var expected = 0
        var last = 0xFF
        var ended = false
        let deadline = MonotonicClock.nowMs() + timeoutMs

        try await ack(last)

        while true {
            let remaining = deadline - MonotonicClock.nowMs()
            if remaining <= 0 { throw SarError("timed out waiting for data") }
            guard let pkt = await pkts.receive(timeoutMs: min(reackIntervalMs, remaining)) else {
                try await ack(last) // periodic re-ack doubles as a poll
                continue
            }
            guard pkt.count >= Sar.headerLen else { throw SarError("short packet") }
            let pktBytes = [UInt8](pkt)
            let flags = pktBytes[0]

            if flags & Sar.flagFin != 0 {
                if !ended { throw SarError("FIN before LAST fragment") }
                if pktBytes[1] == Sar.codeAck {
                    return chunks.reduce(into: Data()) { $0.append($1) }
                }
                throw SarError("transfer failed (FIN code \(pktBytes[1]))")
            }

            let seq = Int(pktBytes[1])
            if seq != expected {
                try await ack(last) // out of order: re-ack last in-order
                continue
            }
            if ended { throw SarError("fragment after LAST") }

            chunks.append(Data(pktBytes[Sar.headerLen...]))
            last = seq
            expected = (seq + 1) & Sar.seqMask
            if flags & Sar.flagLast != 0 { ended = true }
            try await ack(last)
        }
    }
}
