// Copyright (c) 2026 Jonathan Beri
// SPDX-License-Identifier: Apache-2.0

import Foundation

/// Certificate/key input helpers. The provisioning protocol carries credentials
/// as DER; callers may hold PEM. ``toDer(_:)`` normalizes either form to DER,
/// matching the CLI's acceptance of "PEM or DER".
public enum Pem {
    public struct PemError: Error, CustomStringConvertible {
        public let message: String

        public init(_ message: String) {
            self.message = message
        }

        public var description: String { message }
    }

    /// Return DER bytes for `input`, which may be PEM (base64 with headers) or already DER.
    public static func toDer(_ input: Data) throws -> Data {
        guard looksLikePem(input) else { return input }
        guard let text = String(data: input, encoding: .ascii) else {
            throw PemError("PEM input is not ASCII")
        }
        let base64 = text
            .split(whereSeparator: \.isNewline)
            .filter { !$0.hasPrefix("-----") }
            .joined()
            .filter { !$0.isWhitespace }
        guard let der = Data(base64Encoded: base64) else {
            throw PemError("bad base64 in PEM input")
        }
        return der
    }

    /// A DER SEQUENCE starts with 0x30; PEM starts with the ASCII "-----".
    private static func looksLikePem(_ input: Data) -> Bool {
        guard let first = input.first, first != 0x30 else { return false }
        let prefix = String(data: input.prefix(11), encoding: .ascii) ?? ""
        return prefix.hasPrefix("-----BEGIN")
    }
}
