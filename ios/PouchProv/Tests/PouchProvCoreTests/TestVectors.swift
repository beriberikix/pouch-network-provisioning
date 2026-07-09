// Copyright (c) 2026 Jonathan Beri
// SPDX-License-Identifier: Apache-2.0

import Foundation

struct TestVectorsError: Error, CustomStringConvertible {
    let message: String

    init(_ message: String) {
        self.message = message
    }

    var description: String { message }
}

/// Locates and loads the shared golden vectors in the repo-root `tests/vectors/`
/// — the same fixtures the Python CLI, the Kotlin SDK and the Zephyr device
/// codec are pinned to. The directory is found by walking up from this source
/// file's checkout location; `POUCHPROV_VECTORS_DIR` overrides (the analogue of
/// the Kotlin `pouchprov.vectors.dir` system property).
enum TestVectors {
    static func dir() throws -> URL {
        if let env = ProcessInfo.processInfo.environment["POUCHPROV_VECTORS_DIR"] {
            return URL(fileURLWithPath: env, isDirectory: true)
        }
        var url = URL(fileURLWithPath: #filePath)
        while url.path != "/" {
            url.deleteLastPathComponent()
            let candidate = url.appendingPathComponent("tests/vectors", isDirectory: true)
            if FileManager.default.fileExists(
                atPath: candidate.appendingPathComponent("prov_messages.json").path
            ) {
                return candidate
            }
        }
        throw TestVectorsError("tests/vectors not found above \(#filePath); set POUCHPROV_VECTORS_DIR")
    }

    static func load(_ fileName: String) throws -> [String: Any] {
        let data = try Data(contentsOf: dir().appendingPathComponent(fileName))
        guard let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw TestVectorsError("\(fileName) is not a JSON object")
        }
        return obj
    }

    static func hex(_ string: String) throws -> Data {
        let clean = string.trimmingCharacters(in: .whitespacesAndNewlines)
        guard clean.count % 2 == 0 else { throw TestVectorsError("odd-length hex string") }
        var data = Data(capacity: clean.count / 2)
        var index = clean.startIndex
        while index < clean.endIndex {
            let next = clean.index(index, offsetBy: 2)
            guard let byte = UInt8(clean[index..<next], radix: 16) else {
                throw TestVectorsError("bad hex string")
            }
            data.append(byte)
            index = next
        }
        return data
    }

    /// `count` bytes with values `start`, `start + 1`, ... (truncated to 8 bits).
    static func bytes(start: Int, count: Int) -> Data {
        Data((0..<count).map { UInt8(truncatingIfNeeded: start + $0) })
    }
}
