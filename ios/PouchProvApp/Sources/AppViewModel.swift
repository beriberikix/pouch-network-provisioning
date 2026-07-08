// Copyright (c) 2026 Jonathan Beri
// SPDX-License-Identifier: Apache-2.0

import Combine
import Foundation
import PouchProvBLE
import PouchProvCore

/// Drives the reference provisioning flow: discover devices, connect + read the
/// device's capabilities, optionally scan Wi-Fi, then provision. Progress is
/// surfaced from the SDK's `PouchProvDevice.statePublisher`. A port of the
/// Android `ProvViewModel`.
@MainActor
final class AppViewModel: ObservableObject {

    static let defaultValidityDays = 7
    private static let keyApi = "golioth_api_key"
    private static let keyValidity = "cert_validity_days"

    private let manager = PouchProvManager()
    private let defaults = UserDefaults.standard

    // MARK: - settings (persisted)

    /// Golioth project API key — used by the (separate) CA-upload step.
    @Published private(set) var goliothApiKey: String

    /// Generated-certificate validity, in days from creation (default 7).
    @Published private(set) var certValidityDays: Int

    func setGoliothApiKey(_ value: String) {
        defaults.set(value, forKey: Self.keyApi)
        goliothApiKey = value
        golioth = nil // rebuild the provider (and re-register a CA) with the new key
    }

    func setCertValidityDays(_ days: Int) {
        let clamped = min(max(days, 1), 3650)
        defaults.set(clamped, forKey: Self.keyValidity)
        certValidityDays = clamped
    }

    // MARK: - discovery

    @Published private(set) var devices: [PouchProvDevice] = []
    @Published private(set) var scanning = false
    @Published private(set) var scanError: String?

    // MARK: - selected device

    @Published private(set) var selected: PouchProvDevice?
    @Published private(set) var connecting = false
    @Published private(set) var connectError: String?
    @Published private(set) var version: VersionInfo?

    // MARK: - Wi-Fi scan

    @Published private(set) var wifiScanning = false
    @Published private(set) var wifiNetworks: [ScanEntry]?
    @Published private(set) var wifiError: String?

    // MARK: - locally-generated device certificate

    @Published private(set) var generating = false

    /// Non-nil (the CN) once a certificate has been generated locally.
    @Published private(set) var generatedCn: String?

    /// Non-nil when local/Golioth cert generation failed.
    @Published private(set) var certError: String?

    private var generatedCert: Data?
    private var generatedKey: Data?
    private var golioth: GoliothCertProvider?

    // MARK: - provisioning progress

    @Published private(set) var provisionState: ProvisionState = .idle

    /// True once a provision run has been started (drives the progress UI).
    @Published private(set) var provisioning = false

    private var scanTask: Task<Void, Never>?
    private var stateSubscription: AnyCancellable?

    init() {
        goliothApiKey = defaults.string(forKey: Self.keyApi) ?? ""
        let storedDays = defaults.integer(forKey: Self.keyValidity)
        certValidityDays = storedDays == 0 ? Self.defaultValidityDays : storedDays
    }

    // MARK: - discovery

    func startScan() {
        scanTask?.cancel()
        devices = []
        scanError = nil
        scanning = true
        scanTask = Task {
            do {
                for try await device in manager.scan(timeoutMs: 12_000) {
                    if !devices.contains(where: { $0.identifier == device.identifier }) {
                        devices.append(device)
                    }
                }
            } catch {
                scanError = "\(error)"
            }
            scanning = false
        }
    }

    /// Select a device, connect, and read its version/capabilities.
    func select(_ device: PouchProvDevice) {
        scanTask?.cancel()
        scanning = false
        selected = device
        version = nil
        connectError = nil
        wifiNetworks = nil
        wifiError = nil
        provisionState = .idle
        clearGenerated()

        stateSubscription = device.statePublisher
            .receive(on: DispatchQueue.main)
            .sink { [weak self] state in self?.provisionState = state }

        connecting = true
        Task {
            do {
                try await device.connect()
                version = try await device.version()
            } catch {
                connectError = "\(error)"
            }
            connecting = false
        }
    }

    /// Authorize (if the device requires PoP) then scan for visible Wi-Fi networks.
    func scanWifi(pop: String) {
        guard let device = selected else { return }
        wifiError = nil
        wifiScanning = true
        Task {
            do {
                if version?.popRequired == true {
                    try await device.authorize(pop: pop)
                }
                wifiNetworks = try await device.scanWifi()
            } catch {
                wifiError = "\(error)"
            }
            wifiScanning = false
        }
    }

    // MARK: - certificates

    /// Generate a self-signed device cert/key locally (CN = device identifier).
    func generateCert(commonName: String) {
        generating = true
        certError = nil
        Task {
            do {
                let cn = commonName.isEmpty ? "pouch-device" : commonName
                let creds = try DeviceCert.generateSelfSigned(commonName: cn, validityDays: certValidityDays)
                generatedCert = creds.certificatePem
                generatedKey = creds.privateKeyPem
                generatedCn = cn
            } catch {
                certError = "\(error)"
            }
            generating = false
        }
    }

    /// Mint a Golioth-ready device cert: register a demo CA (once) and sign a device
    /// cert with it, using the API key from Settings. See `docs/golioth-demo-certs.md`.
    func mintGoliothCert(commonName: String) {
        let apiKey = goliothApiKey
        guard !apiKey.isEmpty else {
            certError = "Set a Golioth API key in Settings first"
            return
        }
        generating = true
        certError = nil
        Task {
            do {
                let cn = commonName.isEmpty ? "pouch-device" : commonName
                let provider: GoliothCertProvider
                if let golioth {
                    provider = golioth
                } else {
                    provider = GoliothCertProvider(apiKey: apiKey)
                    golioth = provider
                }
                let creds = try await provider.mintDeviceCredentials(deviceId: cn, validityDays: certValidityDays)
                generatedCert = creds.certificatePem
                generatedKey = creds.privateKeyPem
                generatedCn = "\(cn) (Golioth)"
            } catch {
                certError = "\(error)"
            }
            generating = false
        }
    }

    /// The locally-generated (cert, key) PEM pair, or nil if none generated.
    func generatedCredentials() -> (cert: Data, key: Data)? {
        guard let cert = generatedCert, let key = generatedKey else { return nil }
        return (cert, key)
    }

    private func clearGenerated() {
        generatedCert = nil
        generatedKey = nil
        generatedCn = nil
        certError = nil
    }

    // MARK: - provisioning

    func provision(pop: String?, ssid: String?, password: String?, cert: Data?, key: Data?, ca: Data?) {
        guard let device = selected else { return }
        provisioning = true
        Task {
            // Terminal state (done/failed) is published via device.statePublisher.
            _ = try? await device.provision(ProvisionRequest(
                pop: pop.flatMap { $0.isEmpty ? nil : $0 },
                ssid: ssid.flatMap { $0.isEmpty ? nil : $0 },
                password: password.flatMap { $0.isEmpty ? nil : $0 },
                certificate: cert,
                privateKey: key,
                caCertificate: ca
            ))
        }
    }

    /// Return to the editable form after a finished/failed run (keeps the connection).
    func resetProvision() {
        provisioning = false
        provisionState = .idle
    }

    func back() {
        stateSubscription = nil
        provisioning = false
        let device = selected
        selected = nil
        version = nil
        wifiNetworks = nil
        connectError = nil
        provisionState = .idle
        clearGenerated()
        Task { await device?.disconnect() }
    }
}
