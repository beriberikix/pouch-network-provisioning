// Copyright (c) 2026 Jonathan Beri
// SPDX-License-Identifier: Apache-2.0

import Crypto
import Foundation

/// Proof-of-possession mutual authorization (.prov/auth).
///
/// Both proofs are HMAC-SHA256 keyed with the UTF-8 PoP secret:
///
///   dev_proof = HMAC(pop, "dev" + cli_nonce + dev_nonce)
///   cli_proof = HMAC(pop, "cli" + dev_nonce + cli_nonce)
///
/// The client verifies the device's proof before sending its own, so a device
/// that doesn't know the PoP learns nothing and receives no credentials.
/// Mirrors the Kotlin/Python `Auth`.
public enum Auth {
    public struct AuthException: Error, CustomStringConvertible {
        public let message: String

        public init(_ message: String) {
            self.message = message
        }

        public var description: String { message }
    }

    public static func deviceProof(pop: String, cliNonce: Data, devNonce: Data) -> Data {
        proof(pop: pop, tag: "dev", first: cliNonce, second: devNonce)
    }

    public static func clientProof(pop: String, devNonce: Data, cliNonce: Data) -> Data {
        proof(pop: pop, tag: "cli", first: devNonce, second: cliNonce)
    }

    private static func proof(pop: String, tag: String, first: Data, second: Data) -> Data {
        var hmac = HMAC<SHA256>(key: SymmetricKey(data: Data(pop.utf8)))
        hmac.update(data: Data(tag.utf8))
        hmac.update(data: first)
        hmac.update(data: second)
        return Data(hmac.finalize())
    }

    /// Run the mutual PoP handshake. Throws ``AuthException`` on mismatch.
    public static func authorize(session: ProvSession, pop: String, timeoutMs: Int64 = 15_000) async throws {
        let cliNonce = randomBytes(16)
        let (devNonce, devProof) = try Messages.decodeAuthChallengeRsp(
            try await session.request(
                path: Messages.pathAuth,
                message: Messages.encodeAuthChallenge(cliNonce: cliNonce),
                timeoutMs: timeoutMs
            )
        )
        let expected = deviceProof(pop: pop, cliNonce: cliNonce, devNonce: devNonce)
        guard constantTimeEquals(devProof, expected) else {
            throw AuthException("device proof mismatch — wrong PoP or impostor device")
        }
        let cliProof = clientProof(pop: pop, devNonce: devNonce, cliNonce: cliNonce)
        try Messages.decodeAuthProofRsp(
            try await session.request(
                path: Messages.pathAuth,
                message: Messages.encodeAuthProof(cliProof: cliProof),
                timeoutMs: timeoutMs
            )
        )
    }

    /// Cryptographically secure random bytes (SystemRandomNumberGenerator).
    static func randomBytes(_ count: Int) -> Data {
        var rng = SystemRandomNumberGenerator()
        return Data((0..<count).map { _ in UInt8.random(in: .min ... .max, using: &rng) })
    }

    /// Constant-time comparison to avoid leaking the proof via timing.
    private static func constantTimeEquals(_ a: Data, _ b: Data) -> Bool {
        guard a.count == b.count else { return false }
        let aBytes = [UInt8](a)
        let bBytes = [UInt8](b)
        var diff: UInt8 = 0
        for i in 0..<aBytes.count { diff |= aBytes[i] ^ bBytes[i] }
        return diff == 0
    }
}
