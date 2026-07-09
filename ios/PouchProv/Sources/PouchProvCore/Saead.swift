// Copyright (c) 2026 Jonathan Beri
// SPDX-License-Identifier: Apache-2.0

import Crypto
import Foundation

/// Pouch saead session crypto — the server (client-terminated) side. A faithful
/// port of the Python reference (`cli/src/pouchprov/pouchlink/saead.py`), pinned
/// to the shared vectors in `tests/vectors/saead_kdf.json`.
///
/// A session key is derived as:
///
///     shared = ECDH(our_private_key, peer_public_key)          # P-256
///     key    = HKDF-SHA256(ikm=shared, salt="", info=INFO)     # no salt
///     INFO   = "E0:{D|S}:{b64(session_id)}:C{C|A}R:{block_log:02X}"
///
/// where the D/S letter and session id are the session *initiator*'s. Each block
/// is AEAD-sealed (ChaCha20-Poly1305 or AES-GCM) with:
///
///     nonce = be16(pouch_id) | be16(block_index) | sender_role | 00*7
///     aad   = previous block's 16-byte auth tag (empty for block 0)
public enum Saead {
    public static let authTagLen = 16
    public static let sessionIdLen = 16
    public static let certRefLen = 6

    public struct SaeadError: Error, CustomStringConvertible {
        public let message: String

        public init(_ message: String) {
            self.message = message
        }

        public var description: String { message }
    }

    public static func keySize(_ algorithm: Int) -> Int {
        algorithm == Pouch.algChacha20Poly1305 ? 32 : 16
    }

    /// Derive the AEAD key for one session (matches the reference `derive_session_key`).
    public static func deriveSessionKey(
        ourPrivate: P256.KeyAgreement.PrivateKey,
        peerPublic: P256.KeyAgreement.PublicKey,
        sessionId: Data,
        initiator: Int,
        algorithm: Int,
        maxBlockSizeLog: Int
    ) throws -> Data {
        let shared = try ourPrivate.sharedSecretFromKeyAgreement(with: peerPublic)
        let info = infoString(
            initiator: initiator, sessionId: sessionId,
            algorithm: algorithm, maxBlockSizeLog: maxBlockSizeLog
        )
        let key = shared.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data(),
            sharedInfo: Data(info.utf8),
            outputByteCount: keySize(algorithm)
        )
        return key.withUnsafeBytes { Data($0) }
    }

    public static func infoString(initiator: Int, sessionId: Data, algorithm: Int, maxBlockSizeLog: Int) -> String {
        let d = initiator == Pouch.roleDevice ? "D" : "S"
        let alg = algorithm == Pouch.algChacha20Poly1305 ? "C" : "A"
        let sid = sessionId.base64EncodedString()
        return "E0:\(d):\(sid):C\(alg)R:" + String(format: "%02X", maxBlockSizeLog)
    }

    public static func nonce(pouchId: Int, blockIndex: Int, senderRole: Int) -> Data {
        var out = Data(count: 12)
        out[0] = UInt8((pouchId >> 8) & 0xFF)
        out[1] = UInt8(pouchId & 0xFF)
        out[2] = UInt8((blockIndex >> 8) & 0xFF)
        out[3] = UInt8(blockIndex & 0xFF)
        out[4] = UInt8(senderRole & 0xFF)
        return out
    }

    /// AEAD-seal `plaintext`; returns ciphertext || 16-byte tag.
    public static func seal(algorithm: Int, key: Data, nonce: Data, plaintext: Data, aad: Data) throws -> Data {
        let symmetric = SymmetricKey(data: key)
        if algorithm == Pouch.algChacha20Poly1305 {
            let box = try ChaChaPoly.seal(
                plaintext, using: symmetric,
                nonce: ChaChaPoly.Nonce(data: nonce), authenticating: aad
            )
            return box.ciphertext + box.tag
        }
        let box = try AES.GCM.seal(
            plaintext, using: symmetric,
            nonce: AES.GCM.Nonce(data: nonce), authenticating: aad
        )
        return box.ciphertext + box.tag
    }

    /// Open a sealed block (ciphertext || tag); throws ``SaeadError`` on tag mismatch.
    public static func open(algorithm: Int, key: Data, nonce: Data, sealed: Data, aad: Data) throws -> Data {
        guard sealed.count >= authTagLen else { throw SaeadError("sealed block too short") }
        let ciphertext = sealed.prefix(sealed.count - authTagLen)
        let tag = sealed.suffix(authTagLen)
        let symmetric = SymmetricKey(data: key)
        do {
            if algorithm == Pouch.algChacha20Poly1305 {
                let box = try ChaChaPoly.SealedBox(
                    nonce: ChaChaPoly.Nonce(data: nonce), ciphertext: ciphertext, tag: tag
                )
                return try ChaChaPoly.open(box, using: symmetric, authenticating: aad)
            }
            let box = try AES.GCM.SealedBox(
                nonce: AES.GCM.Nonce(data: nonce), ciphertext: ciphertext, tag: tag
            )
            return try AES.GCM.open(box, using: symmetric, authenticating: aad)
        } catch let error as SaeadError {
            throw error
        } catch {
            throw SaeadError("saead open failed: \(error)")
        }
    }

    // MARK: - pouch-level helpers

    /// Encode an encrypted downlink pouch carrying `entries`. Entries are packed
    /// into entry blocks whose plaintext (id byte + entries) is sealed per block.
    public static func buildDownlinkPouch(
        session: SaeadSession,
        sessionId: Data,
        entries: [Entry],
        pouchId: Int = 0,
        blockSize: Int = Pouch.defaultBlockSize
    ) throws -> Data {
        let info = try session.newDownlink(sessionId: sessionId)
        let header = PouchHeader(
            encryption: Pouch.encryptionSaead,
            sessionInfo: info.toCborObj(),
            pouchId: Int64(pouchId)
        )

        var plaintextBlocks: [Data] = []
        var current = Data()
        for entry in entries {
            let encoded = entry.encode()
            if !current.isEmpty && current.count + encoded.count > blockSize {
                plaintextBlocks.append(current)
                current = Data()
            }
            current.append(encoded)
        }
        plaintextBlocks.append(current)

        var out = header.encode()
        var prevTag = Data()
        for (index, payload) in plaintextBlocks.enumerated() {
            var idByte = Pouch.blockIdEntry
            if index == 0 { idByte |= Pouch.blockFirst }
            if index == plaintextBlocks.count - 1 { idByte |= Pouch.blockLast }
            let blockPlaintext = Data([UInt8(idByte)]) + payload
            let (sealed, tag) = try session.encryptDownlinkBlock(
                blockPlaintext, blockIndex: index, pouchId: pouchId, prevTag: prevTag
            )
            prevTag = tag
            out.append(UInt8((sealed.count >> 8) & 0xFF))
            out.append(UInt8(sealed.count & 0xFF))
            out.append(sealed)
        }
        return out
    }

    /// Decode an encrypted uplink pouch into its entries.
    public static func parseUplinkPouch(session: SaeadSession, _ data: Data) throws -> [Entry] {
        let (header, consumed) = try PouchHeader.decode(data)
        guard header.encryption == Pouch.encryptionSaead, let rawInfo = header.sessionInfo else {
            throw Pouch.DecodeException("uplink pouch is not saead")
        }
        try session.adoptUplink(SessionInfo.fromCborObj(rawInfo))

        let bytes = Data(data) // normalize indices
        var payloads: [Data] = []
        var pos = consumed
        var blockIndex = 0
        var prevTag = Data()
        while pos < bytes.count {
            guard bytes.count - pos >= 2 else { throw Pouch.DecodeException("truncated sealed block") }
            let size = (Int(bytes[pos]) << 8) | Int(bytes[pos + 1])
            pos += 2
            guard bytes.count - pos >= size else { throw Pouch.DecodeException("truncated sealed block") }
            let sealed = bytes.subdata(in: pos..<(pos + size))
            pos += size
            let (plaintext, tag) = try session.decryptUplinkBlock(
                sealed, blockIndex: blockIndex, pouchId: Int(header.pouchId), prevTag: prevTag
            )
            prevTag = tag
            blockIndex += 1
            if let first = plaintext.first, Int(first) & Pouch.blockIdMask == Pouch.blockIdEntry {
                payloads.append(plaintext.dropFirst())
            }
        }
        return try Pouch.parseEntryBlocks(payloads)
    }
}

/// saead session parameters carried in the pouch header.
public struct SessionInfo: Equatable, Sendable {
    public let sessionId: Data
    public let initiator: Int
    public let algorithm: Int
    public let maxBlockSizeLog: Int
    public let certRef: Data
    public let sequentialSeq: Int64?

    public init(
        sessionId: Data,
        initiator: Int,
        algorithm: Int,
        maxBlockSizeLog: Int,
        certRef: Data,
        sequentialSeq: Int64? = nil
    ) {
        self.sessionId = sessionId
        self.initiator = initiator
        self.algorithm = algorithm
        self.maxBlockSizeLog = maxBlockSizeLog
        self.certRef = certRef
        self.sequentialSeq = sequentialSeq
    }

    public func toCborObj() -> [CborValue] {
        let sid: CborValue = sequentialSeq.map { .array([.bytes(sessionId), .int($0)]) }
            ?? .array([.bytes(sessionId)])
        return [
            sid,
            .int(Int64(initiator)),
            .int(Int64(algorithm)),
            .int(Int64(maxBlockSizeLog)),
            .bytes(certRef),
        ]
    }

    public static func fromCborObj(_ obj: [CborValue]) throws -> SessionInfo {
        guard obj.count >= 5,
              let sid = obj[0].arrayValue, let sessionId = sid.first?.bytesValue,
              let initiator = obj[1].intValue,
              let algorithm = obj[2].intValue,
              let maxBlockSizeLog = obj[3].intValue,
              let certRef = obj[4].bytesValue
        else { throw Pouch.DecodeException("bad saead session info") }
        let seq: Int64? = sid.count == 2 ? sid[1].intValue.map(Int64.init) : nil
        return SessionInfo(
            sessionId: sessionId,
            initiator: initiator,
            algorithm: algorithm,
            maxBlockSizeLog: maxBlockSizeLog,
            certRef: certRef,
            sequentialSeq: seq
        )
    }
}

/// Client-side (server-role) saead session over one BLE connection. The downlink
/// session is created by us (the server); the uplink session is adopted from the
/// device's uplink pouch header. State transitions happen under the session's
/// lockstep request cycle, so no internal locking is needed.
public final class SaeadSession: @unchecked Sendable {
    private let serverPrivate: P256.KeyAgreement.PrivateKey
    private let devicePublic: P256.KeyAgreement.PublicKey
    private let certRef: Data
    private let algorithm: Int
    private let maxBlockSizeLog: Int

    private struct State {
        let key: Data
        let algorithm: Int
    }

    private var down: State?
    private var up: State?

    public init(
        serverPrivate: P256.KeyAgreement.PrivateKey,
        devicePublic: P256.KeyAgreement.PublicKey,
        serverCertRef: Data,
        algorithm: Int = Pouch.algChacha20Poly1305,
        maxBlockSizeLog: Int = 9
    ) {
        self.serverPrivate = serverPrivate
        self.devicePublic = devicePublic
        // Truncate + zero-pad to 6 bytes, mirroring the reference.
        self.certRef = Data(serverCertRef.prefix(Saead.certRefLen))
            + Data(count: max(0, Saead.certRefLen - serverCertRef.count))
        self.algorithm = algorithm
        self.maxBlockSizeLog = maxBlockSizeLog
    }

    /// Start a fresh server-initiated downlink session; returns the header SessionInfo.
    public func newDownlink(sessionId: Data) throws -> SessionInfo {
        guard sessionId.count == Saead.sessionIdLen else { throw Saead.SaeadError("bad session id length") }
        let key = try Saead.deriveSessionKey(
            ourPrivate: serverPrivate, peerPublic: devicePublic, sessionId: sessionId,
            initiator: Pouch.roleServer, algorithm: algorithm, maxBlockSizeLog: maxBlockSizeLog
        )
        down = State(key: key, algorithm: algorithm)
        return SessionInfo(
            sessionId: sessionId, initiator: Pouch.roleServer, algorithm: algorithm,
            maxBlockSizeLog: maxBlockSizeLog, certRef: certRef
        )
    }

    /// Seal one downlink block; returns (ciphertext_with_tag, this_tag).
    public func encryptDownlinkBlock(
        _ plaintext: Data, blockIndex: Int, pouchId: Int, prevTag: Data
    ) throws -> (sealed: Data, tag: Data) {
        guard let state = down else { throw Saead.SaeadError("no downlink session") }
        let nonce = Saead.nonce(pouchId: pouchId, blockIndex: blockIndex, senderRole: Pouch.roleServer)
        let aad = blockIndex > 0 ? prevTag : Data()
        let sealed = try Saead.seal(
            algorithm: state.algorithm, key: state.key, nonce: nonce, plaintext: plaintext, aad: aad
        )
        return (sealed, sealed.suffix(Saead.authTagLen))
    }

    /// Derive the uplink key from the device's uplink pouch header.
    public func adoptUplink(_ info: SessionInfo) throws {
        guard info.initiator == Pouch.roleDevice else {
            throw Saead.SaeadError("uplink header initiator is not the device")
        }
        let key = try Saead.deriveSessionKey(
            ourPrivate: serverPrivate, peerPublic: devicePublic, sessionId: info.sessionId,
            initiator: Pouch.roleDevice, algorithm: info.algorithm, maxBlockSizeLog: info.maxBlockSizeLog
        )
        up = State(key: key, algorithm: info.algorithm)
    }

    /// Open one uplink block; returns (plaintext, this_tag).
    public func decryptUplinkBlock(
        _ sealed: Data, blockIndex: Int, pouchId: Int, prevTag: Data
    ) throws -> (plaintext: Data, tag: Data) {
        guard let state = up else { throw Saead.SaeadError("no uplink session") }
        let nonce = Saead.nonce(pouchId: pouchId, blockIndex: blockIndex, senderRole: Pouch.roleDevice)
        let aad = blockIndex > 0 ? prevTag : Data()
        let plaintext = try Saead.open(
            algorithm: state.algorithm, key: state.key, nonce: nonce, sealed: sealed, aad: aad
        )
        return (plaintext, sealed.suffix(Saead.authTagLen))
    }
}

/// Encrypted (saead) framing over a ``SaeadSession``. Each request pouch starts a
/// fresh random downlink session; the uplink session is adopted from the device's
/// response header. An empty (header-only) uplink pouch means "not ready".
public struct SaeadCrypto: SessionCrypto {
    private let saead: SaeadSession
    private let sessionIdSource: @Sendable () -> Data

    public init(
        _ saead: SaeadSession,
        sessionIdSource: @escaping @Sendable () -> Data = {
            Data((0..<Saead.sessionIdLen).map { _ in UInt8.random(in: 0...255) })
        }
    ) {
        self.saead = saead
        self.sessionIdSource = sessionIdSource
    }

    public func buildRequest(entries: [Entry], deviceId: String, blockSize: Int) throws -> Data {
        try Saead.buildDownlinkPouch(
            session: saead, sessionId: sessionIdSource(), entries: entries, blockSize: blockSize
        )
    }

    public func parseResponse(_ data: Data) throws -> (header: PouchHeader, entries: [Entry]) {
        let (header, consumed) = try PouchHeader.decode(data)
        if header.encryption == Pouch.encryptionSaead {
            // A header-only uplink pouch still parses to no entries ("not ready").
            if data.count > consumed {
                return (header, try Saead.parseUplinkPouch(session: saead, data))
            }
            return (header, [])
        }
        return try Pouch.parsePouch(data)
    }
}
