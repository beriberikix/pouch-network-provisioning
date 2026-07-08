// Copyright (c) 2026 Jonathan Beri
// SPDX-License-Identifier: Apache-2.0

import Foundation
import PouchProvCore

struct GoliothError: Error, CustomStringConvertible {
    let message: String

    init(_ message: String) {
        self.message = message
    }

    var description: String { message }
}

/// Mints Golioth-ready device credentials: generates a demo root CA, registers it
/// with the project (the same public-API flow the console's "temporary
/// certificate" button uses — see `docs/golioth-demo-certs.md`), then signs a
/// per-device certificate (CN = device ID) with that CA.
///
/// The CA is generated + registered once and reused for subsequent devices in this
/// provider instance. The project is discovered from the API key. A port of the
/// Android `GoliothCertProvider` on URLSession.
final class GoliothCertProvider {

    /// Device credentials plus the CA cert that signed them (for the optional CA slot).
    struct DeviceCredentials {
        let certificatePem: Data
        let privateKeyPem: Data
        let caCertificatePem: Data
    }

    private let apiKey: String
    private let baseUrl: String

    private var project: String?
    private var ca: DeviceCert.Credentials?
    private var caCertId: String?

    init(apiKey: String, baseUrl: String = "https://api.golioth.io") {
        self.apiKey = apiKey
        self.baseUrl = baseUrl
    }

    /// The project id the API key belongs to (discovered + cached).
    func projectId() async throws -> String {
        if let project { return project }
        let response = try await http("GET", "\(baseUrl)/v1/projects", body: nil)
        guard let id = Self.firstMatch(#""id"\s*:\s*"([^"]+)""#, in: response) else {
            throw GoliothError("no Golioth project found for this API key")
        }
        project = id
        return id
    }

    /// Mint (device cert, device key, CA cert) for `deviceId`, valid `validityDays`.
    /// Registers the demo CA on first call and reuses it after.
    func mintDeviceCredentials(deviceId: String, validityDays: Int) async throws -> DeviceCredentials {
        let pid = try await projectId()
        let root: DeviceCert.Credentials
        if let ca {
            root = ca
        } else {
            root = try DeviceCert.generateCa(commonName: "pouch-demo-CA")
            ca = root
            caCertId = try await registerCa(pid: pid, caCertPem: root.certificatePem)
        }
        let device = try DeviceCert.signDeviceCert(
            ca: root,
            deviceCommonName: deviceId,
            validityDays: validityDays
        )
        return DeviceCredentials(
            certificatePem: device.certificatePem,
            privateKeyPem: device.privateKeyPem,
            caCertificatePem: root.certificatePem
        )
    }

    /// POST the CA as a temporary (demo) root cert; returns its certificate id.
    private func registerCa(pid: String, caCertPem: Data) async throws -> String {
        let body = #"{"certType":"root","certFile":"\#(caCertPem.base64EncodedString())","demo":true}"#
        let response = try await http("POST", "\(baseUrl)/v1/projects/\(pid)/certificates", body: body)
        return Self.firstMatch(#""id"\s*:\s*"([^"]+)""#, in: response) ?? ""
    }

    /// List registered certificate ids (for cleanup).
    func listCertIds() async throws -> [String] {
        let response = try await http("GET", "\(baseUrl)/v1/projects/\(try await projectId())/certificates", body: nil)
        return Self.allMatches(#""id"\s*:\s*"([^"]+)""#, in: response)
    }

    /// Delete a registered certificate (e.g. to garbage-collect a demo CA).
    func deleteCert(certId: String) async throws {
        _ = try await http("DELETE", "\(baseUrl)/v1/projects/\(try await projectId())/certificates/\(certId)", body: nil)
    }

    private func http(_ method: String, _ url: String, body: String?) async throws -> String {
        guard let requestUrl = URL(string: url) else { throw GoliothError("bad URL \(url)") }
        var request = URLRequest(url: requestUrl, timeoutInterval: 15)
        request.httpMethod = method
        request.setValue(apiKey, forHTTPHeaderField: "x-api-key")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        if let body {
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.httpBody = Data(body.utf8)
        }
        let (data, response) = try await URLSession.shared.data(for: request)
        let text = String(decoding: data, as: UTF8.self)
        let code = (response as? HTTPURLResponse)?.statusCode ?? 0
        guard (200..<300).contains(code) else {
            throw GoliothError("Golioth API \(method) \(url) -> \(code): \(text)")
        }
        return text
    }

    private static func firstMatch(_ pattern: String, in text: String) -> String? {
        allMatches(pattern, in: text).first
    }

    private static func allMatches(_ pattern: String, in text: String) -> [String] {
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return [] }
        let range = NSRange(text.startIndex..., in: text)
        return regex.matches(in: text, range: range).compactMap { match in
            guard match.numberOfRanges > 1, let r = Range(match.range(at: 1), in: text) else { return nil }
            return String(text[r])
        }
    }
}
