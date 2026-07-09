// Copyright (c) 2026 Jonathan Beri
// SPDX-License-Identifier: Apache-2.0

#if canImport(CoreBluetooth)
import Combine
import CoreBluetooth
import Foundation
import PouchProvCore

/// A virtual handle to a physical pouch device — the pouch-branded analogue of
/// Espressif's `ESPDevice`. Wraps a ``BleTransport`` and a `ProvSession` and
/// exposes provisioning verbs that mirror the Python CLI (`discover`/`version`/
/// `wifi-scan`/`provision`) and the Kotlin `PouchProvDevice`.
///
/// Parity note vs Android: iOS identifies peripherals by a local `UUID` rather
/// than a MAC address, and offers no `forgetBond` API — to re-pair from scratch,
/// forget the device in Settings → Bluetooth.
public final class PouchProvDevice: Identifiable, @unchecked Sendable {

    public let peripheral: CBPeripheral
    public let name: String?
    public let rssi: Int

    /// CoreBluetooth's stable per-device identifier (no MAC address on iOS).
    public var identifier: UUID { peripheral.identifier }
    public var id: UUID { peripheral.identifier }

    private let transport: BleTransport
    private var session: ProvSession?

    /// Whether the mutual PoP handshake has already succeeded on this session.
    private var authorized = false

    private let stateSubject = CurrentValueSubject<ProvisionState, Never>(.idle)

    /// Live provisioning progress, primarily for driving a UI.
    public var state: ProvisionState { stateSubject.value }
    public var statePublisher: AnyPublisher<ProvisionState, Never> { stateSubject.eraseToAnyPublisher() }

    init(hub: CentralHub, peripheral: CBPeripheral, name: String?, rssi: Int) {
        self.peripheral = peripheral
        self.name = name
        self.rssi = rssi
        self.transport = BleTransport(gatt: GattClient(hub: hub, peripheral: peripheral))
    }

    private func requireSession() throws -> ProvSession {
        guard let session else { throw BleError("not connected — call connect() first") }
        return session
    }

    /// Connect, pair/encrypt, discover the pouch service, and open a session.
    public func connect() async throws {
        stateSubject.send(.connecting)
        try await transport.connect()
        session = ProvSession(transport: transport, maxlen: transport.maxlen)
        authorized = false
    }

    public func disconnect() async {
        await transport.disconnect()
        session = nil
        authorized = false
    }

    /// Query `.prov/ver`.
    public func version() async throws -> VersionInfo {
        try await Flows.getVersion(requireSession())
    }

    /// Run the mutual proof-of-possession handshake once per session (idempotent).
    public func authorize(pop: String) async throws {
        if authorized { return }
        try await Auth.authorize(session: requireSession(), pop: pop)
        authorized = true
    }

    /// Scan for Wi-Fi networks visible to the device (Wi-Fi devices only).
    public func scanWifi() async throws -> [ScanEntry] {
        try await Flows.scan(requireSession())
    }

    /// Set + apply Wi-Fi credentials and wait for the connection to settle.
    public func provisionWifi(ssid: String, password: String?) async throws -> WifiStatus {
        try await Flows.configureWifi(
            requireSession(),
            ssid: Data(ssid.utf8),
            password: password.map { Data($0.utf8) }
        )
    }

    /// Push device cert + key (+ optional CA) as DER (PEM inputs are accepted).
    public func provisionCredentials(cert: Data, key: Data, ca: Data? = nil) async throws {
        try await Flows.bootstrapCredentials(
            requireSession(),
            certDer: try Pem.toDer(cert),
            keyDer: try Pem.toDer(key),
            caDer: try ca.map { try Pem.toDer($0) }
        )
    }

    /// End the session; the device proceeds to normal operation.
    public func end() async throws {
        try await Flows.endSession(requireSession())
    }

    /// One-shot provisioning mirroring `pouchprov provision`: version -> authorize
    /// (if required) -> credentials (if present) -> Wi-Fi (if present and
    /// supported) -> end. Branches on advertised caps so BLE-only devices skip
    /// Wi-Fi. Progress is published to ``state``.
    public func provision(_ request: ProvisionRequest) async throws -> ProvisionResult {
        do {
            if session == nil { try await connect() }
            let session = try requireSession()

            stateSubject.send(.querying)
            let info = try await Flows.getVersion(session)

            stateSubject.send(.authorizing)
            if info.popRequired {
                guard let pop = request.pop, !pop.isEmpty else {
                    throw FlowError("device requires a proof-of-possession (pop)")
                }
                try await authorize(pop: pop) // guarded: no-op if already authorized
            }

            var credentialsStored = false
            if let certificate = request.certificate, let privateKey = request.privateKey {
                stateSubject.send(.pushingCredentials)
                try await provisionCredentials(cert: certificate, key: privateKey, ca: request.caCertificate)
                credentialsStored = true
            }

            var wifi: WifiStatus?
            if let ssid = request.ssid {
                guard info.hasCap("wifi") else {
                    throw FlowError("device does not support Wi-Fi provisioning")
                }
                stateSubject.send(.configuringWifi(nil))
                wifi = try await provisionWifi(ssid: ssid, password: request.password)
                stateSubject.send(.configuringWifi(wifi))
            }

            stateSubject.send(.finishing)
            try await Flows.endSession(session)

            let result = ProvisionResult(version: info, wifi: wifi, credentialsStored: credentialsStored)
            stateSubject.send(.done(result))
            return result
        } catch {
            stateSubject.send(.failed("\(error)"))
            throw error
        }
    }
}

/// A provisioning request mirroring the CLI's `provision` options. Provide
/// `ssid` and/or `certificate`+`privateKey`; certificates/keys may be PEM or DER.
public struct ProvisionRequest: Sendable {
    public let pop: String?
    public let ssid: String?
    public let password: String?
    public let certificate: Data?
    public let privateKey: Data?
    public let caCertificate: Data?

    public init(
        pop: String? = nil,
        ssid: String? = nil,
        password: String? = nil,
        certificate: Data? = nil,
        privateKey: Data? = nil,
        caCertificate: Data? = nil
    ) {
        self.pop = pop
        self.ssid = ssid
        self.password = password
        self.certificate = certificate
        self.privateKey = privateKey
        self.caCertificate = caCertificate
    }
}

public struct ProvisionResult: Equatable, Sendable {
    public let version: VersionInfo
    public let wifi: WifiStatus?
    public let credentialsStored: Bool

    public init(version: VersionInfo, wifi: WifiStatus?, credentialsStored: Bool) {
        self.version = version
        self.wifi = wifi
        self.credentialsStored = credentialsStored
    }
}

/// Provisioning progress, suitable for driving a UI via ``PouchProvDevice/state``.
/// The failure payload is the error's description (keeping the enum `Equatable`
/// for SwiftUI).
public enum ProvisionState: Equatable, Sendable {
    case idle
    case connecting
    case querying
    case authorizing
    case pushingCredentials
    case configuringWifi(WifiStatus?)
    case finishing
    case done(ProvisionResult)
    case failed(String)
}
#endif
