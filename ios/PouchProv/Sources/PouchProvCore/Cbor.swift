// Copyright (c) 2026 Jonathan Beri
// SPDX-License-Identifier: Apache-2.0

import Foundation

/// A CBOR value as encoded/decoded by ``Cbor``.
///
/// Maps are ordered key/value pairs — never a `Dictionary` — because the wire
/// format (and the shared golden vectors) pin map keys in insertion order.
public indirect enum CborValue: Equatable, Sendable {
    case int(Int64)
    case bytes(Data)
    case text(String)
    case array([CborValue])
    case map([CborPair])
    case bool(Bool)
    case null
}

/// An ordered map entry (see ``CborValue/map(_:)``).
public struct CborPair: Equatable, Sendable {
    public let key: CborValue
    public let value: CborValue

    public init(_ key: CborValue, _ value: CborValue) {
        self.key = key
        self.value = value
    }
}

extension CborValue {
    public var int64Value: Int64? {
        if case .int(let v) = self { return v }
        return nil
    }

    public var intValue: Int? {
        int64Value.flatMap { Int(exactly: $0) }
    }

    public var bytesValue: Data? {
        if case .bytes(let v) = self { return v }
        return nil
    }

    public var textValue: String? {
        if case .text(let v) = self { return v }
        return nil
    }

    public var arrayValue: [CborValue]? {
        if case .array(let v) = self { return v }
        return nil
    }

    public var mapValue: [CborPair]? {
        if case .map(let v) = self { return v }
        return nil
    }

    public var boolValue: Bool? {
        if case .bool(let v) = self { return v }
        return nil
    }

    /// Look up a text key in a map value (linear scan — protocol maps are tiny).
    public subscript(key: String) -> CborValue? {
        guard case .map(let pairs) = self else { return nil }
        return pairs.first { $0.key == .text(key) }?.value
    }
}

/// Minimal definite-length CBOR (RFC 8949) writer/reader for the fixed
/// provisioning message set and the pouch header.
///
/// Deliberately tiny and dependency-free. It mirrors the byte output of Python's
/// `cbor2.dumps` **defaults** — which this project's golden vectors were produced
/// with — so it is *not* canonical CBOR: map keys are emitted in insertion order
/// (never sorted), while integers and lengths always use the minimal-length form.
public enum Cbor {

    public struct DecodeException: Error, CustomStringConvertible {
        public let message: String

        public init(_ message: String) {
            self.message = message
        }

        public var description: String { message }
    }

    // MARK: - encode

    public static func encode(_ value: CborValue) -> Data {
        var out = Data()
        write(&out, value)
        return out
    }

    private static func write(_ out: inout Data, _ value: CborValue) {
        switch value {
        case .null:
            out.append(0xF6)
        case .bool(let b):
            out.append(b ? 0xF5 : 0xF4)
        case .int(let v):
            if v >= 0 {
                writeHead(&out, major: 0, arg: UInt64(v))
            } else {
                writeHead(&out, major: 1, arg: UInt64(-1 - v))
            }
        case .bytes(let data):
            writeHead(&out, major: 2, arg: UInt64(data.count))
            out.append(data)
        case .text(let text):
            let bytes = Data(text.utf8)
            writeHead(&out, major: 3, arg: UInt64(bytes.count))
            out.append(bytes)
        case .array(let items):
            writeHead(&out, major: 4, arg: UInt64(items.count))
            for item in items { write(&out, item) }
        case .map(let pairs):
            writeHead(&out, major: 5, arg: UInt64(pairs.count))
            for pair in pairs {
                write(&out, pair.key)
                write(&out, pair.value)
            }
        }
    }

    /// Write the major type and its (unsigned) argument in minimal-length form.
    private static func writeHead(_ out: inout Data, major: UInt8, arg: UInt64) {
        let m = major << 5
        switch arg {
        case ..<24:
            out.append(m | UInt8(arg))
        case ...0xFF:
            out.append(m | 24)
            out.append(UInt8(arg))
        case ...0xFFFF:
            out.append(m | 25)
            out.append(UInt8((arg >> 8) & 0xFF))
            out.append(UInt8(arg & 0xFF))
        case ...0xFFFF_FFFF:
            out.append(m | 26)
            for shift in stride(from: 24, through: 0, by: -8) {
                out.append(UInt8((arg >> UInt64(shift)) & 0xFF))
            }
        default:
            out.append(m | 27)
            for shift in stride(from: 56, through: 0, by: -8) {
                out.append(UInt8((arg >> UInt64(shift)) & 0xFF))
            }
        }
    }

    // MARK: - decode

    /// Decode a single CBOR item from the start of `data`. Extra trailing bytes are ignored.
    public static func decode(_ data: Data) throws -> CborValue {
        try Reader(data).read()
    }

    /// Decode a single item and also return how many bytes it consumed.
    public static func decodeWithLength(_ data: Data) throws -> (value: CborValue, consumed: Int) {
        let reader = Reader(data)
        let value = try reader.read()
        return (value, reader.pos)
    }

    private final class Reader {
        let data: [UInt8]
        var pos = 0

        init(_ data: Data) {
            self.data = [UInt8](data)
        }

        func read() throws -> CborValue {
            let initial = try u8()
            let major = initial >> 5
            let ai = initial & 0x1F
            switch major {
            case 0:
                let arg = try argument(ai)
                guard let v = Int64(exactly: arg) else { throw DecodeException("integer overflow") }
                return .int(v)
            case 1:
                let arg = try argument(ai)
                guard let v = Int64(exactly: arg) else { throw DecodeException("integer overflow") }
                return .int(-1 - v)
            case 2:
                return .bytes(Data(try bytes(count: try length(ai))))
            case 3:
                guard let s = String(bytes: try bytes(count: try length(ai)), encoding: .utf8) else {
                    throw DecodeException("invalid UTF-8 in text string")
                }
                return .text(s)
            case 4:
                let n = try length(ai)
                var list: [CborValue] = []
                list.reserveCapacity(n)
                for _ in 0..<n { list.append(try read()) }
                return .array(list)
            case 5:
                let n = try length(ai)
                var pairs: [CborPair] = []
                pairs.reserveCapacity(n)
                for _ in 0..<n {
                    let k = try read()
                    let v = try read()
                    pairs.append(CborPair(k, v))
                }
                return .map(pairs)
            case 7:
                switch ai {
                case 20: return .bool(false)
                case 21: return .bool(true)
                case 22: return .null
                default: throw DecodeException("unsupported simple value \(ai)")
                }
            default:
                throw DecodeException("unsupported major type \(major)")
            }
        }

        private func length(_ ai: UInt8) throws -> Int {
            let arg = try argument(ai)
            guard let n = Int(exactly: arg) else { throw DecodeException("length overflow") }
            return n
        }

        private func argument(_ ai: UInt8) throws -> UInt64 {
            switch ai {
            case ..<24: return UInt64(ai)
            case 24: return UInt64(try u8())
            case 25: return try readBE(2)
            case 26: return try readBE(4)
            case 27: return try readBE(8)
            default: throw DecodeException("bad additional info \(ai)")
            }
        }

        private func readBE(_ n: Int) throws -> UInt64 {
            var v: UInt64 = 0
            for _ in 0..<n { v = (v << 8) | UInt64(try u8()) }
            return v
        }

        private func u8() throws -> UInt8 {
            guard pos < data.count else { throw DecodeException("truncated CBOR") }
            defer { pos += 1 }
            return data[pos]
        }

        private func bytes(count n: Int) throws -> ArraySlice<UInt8> {
            guard n >= 0, data.count - pos >= n else { throw DecodeException("truncated CBOR string") }
            defer { pos += n }
            return data[pos..<(pos + n)]
        }
    }
}
