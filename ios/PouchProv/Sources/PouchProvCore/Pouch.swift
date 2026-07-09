// Copyright (c) 2026 Jonathan Beri
// SPDX-License-Identifier: Apache-2.0

import Foundation

/// Pouch wire framing: header, blocks and entries.
///
/// Formats mirror the pouch reference implementation (github.com/golioth/pouch:
/// src/header.cddl, src/block.c, src/entry.c) and the Kotlin/Python ports.
///
/// Block:
///   0..1  size (be16, excluding the size field itself, including the id byte)
///   2     id byte: low 5 bits stream id (0 = entry block), 0x40 = first, 0x80 = last
///   3..   payload
///
/// Entry (within an entry block):
///   0..1  data_len (be16)
///   2..3  content_type (be16, IANA CoAP content format)
///   4     path_len
///   5..   path, then data
public enum Pouch {
    public static let pouchVersion = 1

    public static let contentTypeOctetStream = 42
    public static let contentTypeJson = 50
    public static let contentTypeCbor = 60

    public static let blockIdEntry = 0x00
    public static let blockIdMask = 0x1F
    public static let blockFirst = 0x40
    public static let blockLast = 0x80
    public static let blockHeaderSize = 3

    public static let entryHeaderOverhead = 5

    public static let encryptionNone = 0
    public static let encryptionSaead = 1

    public static let roleDevice = 0
    public static let roleServer = 1

    public static let algChacha20Poly1305 = 1
    public static let algAesGcm = 2

    public static let defaultBlockSize = 512

    public struct DecodeException: Error, CustomStringConvertible {
        public let message: String

        public init(_ message: String) {
            self.message = message
        }

        public var description: String { message }
    }

    public struct EncodeException: Error, CustomStringConvertible {
        public let message: String

        public init(_ message: String) {
            self.message = message
        }

        public var description: String { message }
    }

    /// Build a plaintext (encryption-none) pouch carrying `entries`.
    ///
    /// Entries are packed into entry blocks of at most `blockSize` payload bytes;
    /// an entry never spans blocks (pouch src/entry.c contract).
    public static func buildEntryPouch(
        deviceId: String,
        entries: [Entry],
        blockSize: Int = defaultBlockSize
    ) throws -> Data {
        var blocks: [Block] = []
        var current = Data()
        for entry in entries {
            let encoded = entry.encode()
            if encoded.count > blockSize {
                throw EncodeException("entry for \(entry.path) exceeds block size \(blockSize)")
            }
            if !current.isEmpty && current.count + encoded.count > blockSize {
                blocks.append(Block(payload: current, first: blocks.isEmpty, last: false))
                current = Data()
            }
            current.append(encoded)
        }
        blocks.append(Block(payload: current, first: blocks.isEmpty, last: true))

        var out = PouchHeader.plaintext(deviceId: deviceId).encode()
        for block in blocks { out.append(block.encode()) }
        return out
    }

    /// Parse entries out of concatenated entry-block payloads.
    public static func parseEntryBlocks(_ payloads: [Data]) throws -> [Entry] {
        var data = Data()
        for payload in payloads { data.append(payload) }
        let bytes = [UInt8](data)
        var entries: [Entry] = []
        var pos = 0
        while pos < bytes.count {
            guard bytes.count - pos >= entryHeaderOverhead else {
                throw DecodeException("truncated entry header")
            }
            let dataLen = be16(bytes, pos)
            let contentType = be16(bytes, pos + 2)
            let pathLen = Int(bytes[pos + 4])
            pos += entryHeaderOverhead
            guard bytes.count - pos >= pathLen + dataLen else {
                throw DecodeException("truncated entry")
            }
            guard let path = String(bytes: bytes[pos..<(pos + pathLen)], encoding: .utf8) else {
                throw DecodeException("bad entry path")
            }
            pos += pathLen
            let payload = Data(bytes[pos..<(pos + dataLen)])
            pos += dataLen
            entries.append(Entry(path: path, contentType: contentType, data: payload))
        }
        return entries
    }

    /// Parse a plaintext pouch into its header and entries. saead pouches must
    /// have their blocks decrypted first (out of scope for the plaintext path).
    public static func parsePouch(_ data: Data) throws -> (header: PouchHeader, entries: [Entry]) {
        let (header, consumed) = try PouchHeader.decode(data)
        let rawBlocks = try splitBlocks(data.dropFirst(consumed))
        guard header.encryption == encryptionNone else {
            throw DecodeException("encrypted pouch passed to parsePouch")
        }
        let payloads = rawBlocks.filter { $0.streamId == blockIdEntry }.map(\.payload)
        return (header, try parseEntryBlocks(payloads))
    }

    public struct RawBlock: Equatable, Sendable {
        public let streamId: Int
        public let first: Bool
        public let last: Bool
        public let payload: Data
    }

    /// Split the block section into raw blocks.
    public static func splitBlocks(_ data: Data) throws -> [RawBlock] {
        let bytes = [UInt8](data)
        var blocks: [RawBlock] = []
        var pos = 0
        while pos < bytes.count {
            guard bytes.count - pos >= blockHeaderSize else {
                throw DecodeException("truncated block header")
            }
            let size = be16(bytes, pos)
            let idByte = Int(bytes[pos + 2])
            let payloadLen = size - 1 // size includes the id byte
            pos += blockHeaderSize
            guard payloadLen >= 0, bytes.count - pos >= payloadLen else {
                throw DecodeException("truncated block payload")
            }
            blocks.append(RawBlock(
                streamId: idByte & blockIdMask,
                first: idByte & blockFirst != 0,
                last: idByte & blockLast != 0,
                payload: Data(bytes[pos..<(pos + payloadLen)])
            ))
            pos += payloadLen
        }
        return blocks
    }

    private static func be16(_ bytes: [UInt8], _ offset: Int) -> Int {
        (Int(bytes[offset]) << 8) | Int(bytes[offset + 1])
    }
}

/// A single pouch entry: a message on a reserved `.prov/` path.
public struct Entry: Equatable, Sendable {
    public let path: String
    public let contentType: Int
    public let data: Data

    public init(path: String, contentType: Int = Pouch.contentTypeCbor, data: Data) {
        self.path = path
        self.contentType = contentType
        self.data = data
    }

    public func encode() -> Data {
        let pathBytes = Data(path.utf8)
        precondition(pathBytes.count <= 255, "path too long")
        var out = Data()
        out.append(UInt8((data.count >> 8) & 0xFF))
        out.append(UInt8(data.count & 0xFF))
        out.append(UInt8((contentType >> 8) & 0xFF))
        out.append(UInt8(contentType & 0xFF))
        out.append(UInt8(pathBytes.count))
        out.append(pathBytes)
        out.append(data)
        return out
    }
}

/// A pouch block: an id byte plus a payload.
public struct Block: Equatable, Sendable {
    public let payload: Data
    public let streamId: Int
    public let first: Bool
    public let last: Bool

    public init(payload: Data, streamId: Int = Pouch.blockIdEntry, first: Bool = true, last: Bool = true) {
        self.payload = payload
        self.streamId = streamId
        self.first = first
        self.last = last
    }

    public func encode() -> Data {
        var idByte = streamId & Pouch.blockIdMask
        if first { idByte |= Pouch.blockFirst }
        if last { idByte |= Pouch.blockLast }
        // size excludes the 2-byte size field but includes the id byte
        let size = payload.count + 1
        var out = Data()
        out.append(UInt8((size >> 8) & 0xFF))
        out.append(UInt8(size & 0xFF))
        out.append(UInt8(idByte))
        out.append(payload)
        return out
    }
}

/// Pouch header per src/header.cddl.
///
/// Plaintext: `[1, [0, device_id]]`
/// saead:     `[1, [1, session_info, pouch_id]]` (decoded for detection; the
///            encrypted payload path is a follow-up — see the `SessionCrypto` seam).
public struct PouchHeader: Equatable, Sendable {
    public let encryption: Int
    public let deviceId: String?
    public let sessionInfo: [CborValue]?
    public let pouchId: Int64

    public init(
        encryption: Int = Pouch.encryptionNone,
        deviceId: String? = nil,
        sessionInfo: [CborValue]? = nil,
        pouchId: Int64 = 0
    ) {
        self.encryption = encryption
        self.deviceId = deviceId
        self.sessionInfo = sessionInfo
        self.pouchId = pouchId
    }

    public static func plaintext(deviceId: String) -> PouchHeader {
        PouchHeader(encryption: Pouch.encryptionNone, deviceId: deviceId)
    }

    public func encode() -> Data {
        let info: CborValue
        if encryption == Pouch.encryptionNone {
            guard let deviceId else { preconditionFailure("plaintext header requires device_id") }
            info = .array([.int(Int64(Pouch.encryptionNone)), .text(deviceId)])
        } else {
            guard let sessionInfo else { preconditionFailure("saead header requires session info") }
            info = .array([.int(Int64(Pouch.encryptionSaead)), .array(sessionInfo), .int(pouchId)])
        }
        return Cbor.encode(.array([.int(Int64(Pouch.pouchVersion)), info]))
    }

    /// Decode a header from the start of `data`; returns it and bytes consumed.
    public static func decode(_ data: Data) throws -> (header: PouchHeader, consumed: Int) {
        let obj: CborValue
        let consumed: Int
        do {
            (obj, consumed) = try Cbor.decodeWithLength(data)
        } catch {
            throw Pouch.DecodeException("bad pouch header: \(error)")
        }
        guard let outer = obj.arrayValue, outer.count == 2 else {
            throw Pouch.DecodeException("pouch header is not a 2-element array")
        }
        guard let version = outer[0].intValue, version == Pouch.pouchVersion else {
            throw Pouch.DecodeException("unsupported pouch version \(outer[0])")
        }
        guard let info = outer[1].arrayValue, !info.isEmpty else {
            throw Pouch.DecodeException("bad encryption info")
        }
        switch info[0].intValue {
        case Pouch.encryptionNone:
            guard info.count > 1 else { throw Pouch.DecodeException("bad encryption info") }
            return (PouchHeader(encryption: Pouch.encryptionNone, deviceId: info[1].textValue), consumed)
        case Pouch.encryptionSaead:
            guard info.count > 2, let sessionInfo = info[1].arrayValue else {
                throw Pouch.DecodeException("bad encryption info")
            }
            return (
                PouchHeader(
                    encryption: Pouch.encryptionSaead,
                    sessionInfo: sessionInfo,
                    pouchId: info[2].int64Value ?? 0
                ),
                consumed
            )
        default:
            throw Pouch.DecodeException("unknown encryption type \(info[0])")
        }
    }
}
