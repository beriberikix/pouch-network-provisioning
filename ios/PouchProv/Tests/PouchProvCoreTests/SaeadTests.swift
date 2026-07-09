// Copyright (c) 2026 Jonathan Beri
// SPDX-License-Identifier: Apache-2.0

import Crypto
import Foundation
import XCTest
@testable import PouchProvCore

/// saead against the frozen cross-client vectors (tests/vectors/saead_kdf.json)
/// plus mirror-derivation round trips. The vectors pin this port to the Python
/// reference byte-for-byte (INFO string, HKDF, nonce layout, tag-chained AAD).
final class SaeadTests: XCTestCase {

    private static let vectors: Result<[String: Any], Error> =
        Result { try TestVectors.load("saead_kdf.json") }

    private var vectors: [String: Any] { try! Self.vectors.get() }

    private func hex(_ s: String) -> Data {
        var out = Data()
        var index = s.startIndex
        while index < s.endIndex {
            let next = s.index(index, offsetBy: 2)
            out.append(UInt8(s[index..<next], radix: 16)!)
            index = next
        }
        return out
    }

    private func caseObj(_ name: String) -> [String: Any] {
        let cases = vectors["cases"] as! [String: Any]
        return cases[name] as! [String: Any]
    }

    private func keys() throws -> (
        server: P256.KeyAgreement.PrivateKey,
        device: P256.KeyAgreement.PrivateKey,
        serverPub: P256.KeyAgreement.PublicKey,
        devicePub: P256.KeyAgreement.PublicKey
    ) {
        let server = try P256.KeyAgreement.PrivateKey(
            rawRepresentation: hex(vectors["server_private"] as! String))
        let device = try P256.KeyAgreement.PrivateKey(
            rawRepresentation: hex(vectors["device_private"] as! String))
        let serverPub = try P256.KeyAgreement.PublicKey(
            x963Representation: hex(vectors["server_public_uncompressed"] as! String))
        let devicePub = try P256.KeyAgreement.PublicKey(
            x963Representation: hex(vectors["device_public_uncompressed"] as! String))
        return (server, device, serverPub, devicePub)
    }

    func testFixedScalarsMatchPublicPoints() throws {
        let k = try keys()
        XCTAssertEqual(
            k.server.publicKey.x963Representation.map { $0 },
            k.serverPub.x963Representation.map { $0 }
        )
        XCTAssertEqual(
            k.device.publicKey.x963Representation.map { $0 },
            k.devicePub.x963Representation.map { $0 }
        )
    }

    func testKdfAndSealChainMatchVectors() throws {
        let k = try keys()
        let blockLog = vectors["block_log"] as! Int
        let pouchId = vectors["pouch_id"] as! Int

        for name in ["chacha_downlink", "aes_downlink", "chacha_uplink", "aes_uplink"] {
            let c = caseObj(name)
            let algorithm = c["algorithm"] as! Int
            let initiator = c["initiator"] as! Int
            let sessionId = hex(c["session_id"] as! String)

            XCTAssertEqual(
                c["info"] as! String,
                Saead.infoString(
                    initiator: initiator, sessionId: sessionId,
                    algorithm: algorithm, maxBlockSizeLog: blockLog
                ),
                name
            )

            let key = try Saead.deriveSessionKey(
                ourPrivate: k.server, peerPublic: k.devicePub, sessionId: sessionId,
                initiator: initiator, algorithm: algorithm, maxBlockSizeLog: blockLog
            )
            XCTAssertEqual(hex(c["key"] as! String), key, name)
            // Mirror derivation (the device's view) must agree.
            let mirror = try Saead.deriveSessionKey(
                ourPrivate: k.device, peerPublic: k.serverPub, sessionId: sessionId,
                initiator: initiator, algorithm: algorithm, maxBlockSizeLog: blockLog
            )
            XCTAssertEqual(key, mirror, name)

            var prevTag = Data()
            for block in c["blocks"] as! [[String: Any]] {
                let index = block["index"] as! Int
                let nonce = Saead.nonce(pouchId: pouchId, blockIndex: index, senderRole: initiator)
                XCTAssertEqual(hex(block["nonce"] as! String), nonce, name)
                let aad = index > 0 ? prevTag : Data()
                XCTAssertEqual(hex(block["aad"] as! String), aad, name)
                let sealed = try Saead.seal(
                    algorithm: algorithm, key: key, nonce: nonce,
                    plaintext: hex(block["plaintext"] as! String), aad: aad
                )
                XCTAssertEqual(hex(block["sealed"] as! String), sealed, name)
                prevTag = sealed.suffix(Saead.authTagLen)
            }
        }
    }

    func testDownlinkPouchRoundTripsThroughDeviceMirror() throws {
        let serverKey = P256.KeyAgreement.PrivateKey()
        let deviceKey = P256.KeyAgreement.PrivateKey()
        let session = SaeadSession(
            serverPrivate: serverKey, devicePublic: deviceKey.publicKey,
            serverCertRef: Data(repeating: 0xAA, count: 6)
        )

        let entries = [
            Entry(path: ".prov/ver", contentType: Pouch.contentTypeCbor, data: Messages.encodeVerReq()),
            Entry(path: ".prov/ctrl", contentType: Pouch.contentTypeCbor, data: Messages.encodeCtrl(.end)),
        ]
        let sessionId = Data((0..<16).map { UInt8($0) })
        let pouchBytes = try Saead.buildDownlinkPouch(
            session: session, sessionId: sessionId, entries: entries, blockSize: 24 // force 2 blocks
        )

        // Device side: adopt the downlink header, mirror-derive, decrypt.
        let (header, consumed) = try PouchHeader.decode(pouchBytes)
        XCTAssertEqual(Pouch.encryptionSaead, header.encryption)
        let info = try SessionInfo.fromCborObj(header.sessionInfo!)
        XCTAssertEqual(Pouch.roleServer, info.initiator)
        let key = try Saead.deriveSessionKey(
            ourPrivate: deviceKey, peerPublic: serverKey.publicKey, sessionId: info.sessionId,
            initiator: info.initiator, algorithm: info.algorithm, maxBlockSizeLog: info.maxBlockSizeLog
        )

        var payloads: [Data] = []
        var pos = consumed
        var index = 0
        var prevTag = Data()
        while pos < pouchBytes.count {
            let size = (Int(pouchBytes[pos]) << 8) | Int(pouchBytes[pos + 1])
            pos += 2
            let sealed = pouchBytes.subdata(in: pos..<(pos + size))
            pos += size
            let aad = index > 0 ? prevTag : Data()
            let plaintext = try Saead.open(
                algorithm: info.algorithm, key: key,
                nonce: Saead.nonce(pouchId: 0, blockIndex: index, senderRole: Pouch.roleServer),
                sealed: sealed, aad: aad
            )
            prevTag = sealed.suffix(Saead.authTagLen)
            index += 1
            payloads.append(plaintext.dropFirst())
        }
        XCTAssertEqual(2, index) // blockSize forced a 2-block chain
        XCTAssertEqual(entries, try Pouch.parseEntryBlocks(payloads))
    }

    func testUplinkPouchParsesAndTamperFails() throws {
        let serverKey = P256.KeyAgreement.PrivateKey()
        let deviceKey = P256.KeyAgreement.PrivateKey()
        let session = SaeadSession(
            serverPrivate: serverKey, devicePublic: deviceKey.publicKey, serverCertRef: Data(count: 6)
        )

        // Device side: build an uplink pouch (initiator = device).
        let sessionId = Data((0..<16).map { UInt8(0x10 + $0) })
        let algorithm = Pouch.algAesGcm
        let info = SessionInfo(
            sessionId: sessionId, initiator: Pouch.roleDevice, algorithm: algorithm,
            maxBlockSizeLog: 9, certRef: Data(count: 6)
        )
        let key = try Saead.deriveSessionKey(
            ourPrivate: deviceKey, peerPublic: serverKey.publicKey, sessionId: sessionId,
            initiator: Pouch.roleDevice, algorithm: algorithm, maxBlockSizeLog: 9
        )
        let entry = Entry(path: ".prov/ver", contentType: Pouch.contentTypeCbor, data: Data([0x42]))
        let blockPlaintext = Data([UInt8(Pouch.blockIdEntry | Pouch.blockFirst | Pouch.blockLast)]) + entry.encode()
        let sealed = try Saead.seal(
            algorithm: algorithm, key: key,
            nonce: Saead.nonce(pouchId: 0, blockIndex: 0, senderRole: Pouch.roleDevice),
            plaintext: blockPlaintext, aad: Data()
        )
        var pouchBytes = PouchHeader(
            encryption: Pouch.encryptionSaead, sessionInfo: info.toCborObj(), pouchId: 0
        ).encode()
        pouchBytes.append(UInt8((sealed.count >> 8) & 0xFF))
        pouchBytes.append(UInt8(sealed.count & 0xFF))
        pouchBytes.append(sealed)

        XCTAssertEqual([entry], try Saead.parseUplinkPouch(session: session, pouchBytes))

        // Tampering with the ciphertext must fail authentication.
        var tampered = pouchBytes
        tampered[tampered.count - 1] ^= 0x01
        XCTAssertThrowsError(try Saead.parseUplinkPouch(session: session, tampered)) { error in
            XCTAssertTrue(error is Saead.SaeadError, "\(error)")
        }
    }
}
