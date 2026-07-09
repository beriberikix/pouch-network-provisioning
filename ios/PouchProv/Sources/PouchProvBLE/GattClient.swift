// Copyright (c) 2026 Jonathan Beri
// SPDX-License-Identifier: Apache-2.0

#if canImport(CoreBluetooth)
import CoreBluetooth
import Foundation
import PouchProvCore

public struct BleError: Error, CustomStringConvertible {
    public let message: String

    public init(_ message: String) {
        self.message = message
    }

    public var description: String { message }
}

/// A one-shot completion slot with a per-wait timeout — the analogue of the
/// Kotlin `CompletableDeferred` + `withTimeout` pairs in `GattClient.kt`.
/// `complete` is safe to call from the CoreBluetooth queue; `value` returns nil
/// on timeout without breaking a later completion of a *different* slot.
final class OneShot<T>: @unchecked Sendable {
    private let lock = NSLock()
    private var result: T?
    private var completed = false
    private var timedOut = false
    private var waiter: CheckedContinuation<T?, Never>?

    func complete(_ value: T) {
        lock.lock()
        guard !completed && !timedOut else {
            lock.unlock()
            return
        }
        completed = true
        if let waiting = waiter {
            waiter = nil
            lock.unlock()
            waiting.resume(returning: value)
        } else {
            result = value
            lock.unlock()
        }
    }

    /// Wait up to `timeoutMs` for completion; nil on timeout.
    func value(timeoutMs: Int64) async -> T? {
        await withCheckedContinuation { continuation in
            lock.lock()
            if completed {
                let value = result
                lock.unlock()
                continuation.resume(returning: value)
                return
            }
            waiter = continuation
            lock.unlock()
            Task {
                try? await Task.sleep(nanoseconds: UInt64(max(timeoutMs, 0)) * 1_000_000)
                self.expire()
            }
        }
    }

    private func expire() {
        lock.lock()
        guard let waiting = waiter else {
            lock.unlock()
            return
        }
        waiter = nil
        timedOut = true
        lock.unlock()
        waiting.resume(returning: nil)
    }
}

/// Owns the single `CBCentralManager` (one per process is plenty) and
/// multiplexes its delegate callbacks: scan results to the active scan sink,
/// connect/disconnect completions to per-peripheral slots. A `CBPeripheral` can
/// only be connected through the central that discovered it, so `PouchProvManager`
/// and every `GattClient` share this hub — the analogue of the Android `context`
/// capture.
final class CentralHub: NSObject, CBCentralManagerDelegate, @unchecked Sendable {
    private var central: CBCentralManager!
    private let queue = DispatchQueue(label: "io.golioth.pouchprov.ble")

    private let lock = NSLock()
    private var scanSink: ((CBPeripheral, [String: Any], NSNumber) -> Void)?
    private var connectSlots: [UUID: OneShot<Result<Void, Error>>] = [:]

    override init() {
        super.init()
        central = CBCentralManager(delegate: self, queue: queue)
    }

    /// Wait for the central to leave `.unknown`/`.resetting`, then require
    /// `.poweredOn`. Keeps the Simulator (no BLE) and permission-denied cases
    /// from hanging or crashing.
    func waitPoweredOn(timeoutMs: Int64 = 10_000) async throws {
        let deadline = MonotonicClock.nowMs() + timeoutMs
        while true {
            switch central.state {
            case .poweredOn:
                return
            case .unsupported:
                throw BleError("Bluetooth LE is unavailable on this device")
            case .unauthorized:
                throw BleError("Bluetooth permission denied — allow Bluetooth in Settings")
            case .poweredOff:
                throw BleError("Bluetooth is off")
            case .unknown, .resetting:
                fallthrough
            @unknown default:
                guard MonotonicClock.nowMs() <= deadline else {
                    throw BleError("Bluetooth state undetermined")
                }
                try await Task.sleep(nanoseconds: 100 * 1_000_000)
            }
        }
    }

    func startScan(_ sink: @escaping (CBPeripheral, [String: Any], NSNumber) -> Void) {
        lock.lock()
        scanSink = sink
        lock.unlock()
        // Scan unfiltered and match on service data in the sink: the pouch
        // advertisement carries the 0xFC49 service *data* (not a service UUID
        // list), which a withServices: filter is not guaranteed to match.
        central.scanForPeripherals(withServices: nil, options: nil)
    }

    func stopScan() {
        lock.lock()
        scanSink = nil
        lock.unlock()
        if central.state == .poweredOn {
            central.stopScan()
        }
    }

    func connect(_ peripheral: CBPeripheral, timeoutMs: Int64) async throws {
        let slot = OneShot<Result<Void, Error>>()
        lock.lock()
        connectSlots[peripheral.identifier] = slot
        lock.unlock()
        central.connect(peripheral, options: nil)
        defer {
            lock.lock()
            connectSlots.removeValue(forKey: peripheral.identifier)
            lock.unlock()
        }
        guard let outcome = await slot.value(timeoutMs: timeoutMs) else {
            central.cancelPeripheralConnection(peripheral)
            throw BleError("connect timed out")
        }
        try outcome.get()
    }

    func disconnect(_ peripheral: CBPeripheral) {
        central.cancelPeripheralConnection(peripheral)
    }

    private func connectSlot(for id: UUID) -> OneShot<Result<Void, Error>>? {
        lock.lock()
        defer { lock.unlock() }
        return connectSlots[id]
    }

    // MARK: - CBCentralManagerDelegate

    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        // State is polled by waitPoweredOn.
    }

    func centralManager(
        _ central: CBCentralManager,
        didDiscover peripheral: CBPeripheral,
        advertisementData: [String: Any],
        rssi RSSI: NSNumber
    ) {
        lock.lock()
        let sink = scanSink
        lock.unlock()
        sink?(peripheral, advertisementData, RSSI)
    }

    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        connectSlot(for: peripheral.identifier)?.complete(.success(()))
    }

    func centralManager(_ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral, error: Error?) {
        connectSlot(for: peripheral.identifier)?
            .complete(.failure(error ?? BleError("failed to connect")))
    }

    func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral, error: Error?) {
        connectSlot(for: peripheral.identifier)?
            .complete(.failure(BleError("disconnected (\(error.map { "\($0)" } ?? "no error"))")))
    }
}

/// A thin async wrapper over the callback-based `CBPeripheral`. Only one GATT
/// operation is in flight at a time (serialized through an `AsyncMutex`, like
/// Android's single-outstanding-operation rule) and each is awaited via a
/// `OneShot` completed from the `CBPeripheralDelegate`.
///
/// It also handles the pouch link's mandatory encryption. iOS has no
/// `createBond`: pairing starts lazily when the first read/write/CCC hits an
/// insufficient-authentication/encryption error, and the system consent dialog
/// blocks that operation's callback — so the first CCC enable gets the long
/// pairing timeout, and writes retry through the transient
/// "Insufficient Encryption" window (mirrors `GattClient.kt` / `ble.py`).
final class GattClient: NSObject, CBPeripheralDelegate, @unchecked Sendable {

    private static let encryptionRetryMs: Int64 = 12_000
    // Pairing may surface a system consent dialog the user must accept.
    private static let pairingTimeoutMs: Int64 = 90_000

    private let hub: CentralHub
    let peripheral: CBPeripheral

    private let opLock = AsyncMutex()

    private let slotLock = NSLock()
    private var servicesSlot: OneShot<Result<Void, Error>>?
    private var charsSlot: OneShot<Result<Void, Error>>?
    private var writeSlot: OneShot<Result<Void, Error>>?
    private var notifySlot: OneShot<Result<Void, Error>>?
    private var readSlots: [CBUUID: OneShot<Result<Data, Error>>] = [:]

    /// Per-characteristic notification sinks.
    private var notifySinks: [CBUUID: @Sendable (Data) -> Void] = [:]

    /// Set once the first CCC enable (which is where iOS pairing blocks)
    /// has succeeded on this connection.
    private var pairingSettled = false

    init(hub: CentralHub, peripheral: CBPeripheral) {
        self.hub = hub
        self.peripheral = peripheral
        super.init()
    }

    // MARK: - lifecycle

    func connect(timeoutMs: Int64 = 20_000) async throws {
        try await hub.waitPoweredOn()
        try await hub.connect(peripheral, timeoutMs: timeoutMs)
        peripheral.delegate = self
        pairingSettled = false

        let services = OneShot<Result<Void, Error>>()
        setSlot { $0.servicesSlot = services }
        peripheral.discoverServices(nil)
        guard let servicesOutcome = await services.value(timeoutMs: timeoutMs) else {
            throw BleError("service discovery timed out")
        }
        try servicesOutcome.get()

        // The pouch peripheral declares its primary service with the 16-bit UUID
        // 0xFC49 (the 128-bit ...d272 is only used by pouch's central/broker
        // code), so discover characteristics on every service and look them up
        // across all of them rather than assuming a single service UUID.
        for service in peripheral.services ?? [] {
            let chars = OneShot<Result<Void, Error>>()
            setSlot { $0.charsSlot = chars }
            peripheral.discoverCharacteristics(nil, for: service)
            guard let charsOutcome = await chars.value(timeoutMs: timeoutMs) else {
                throw BleError("characteristic discovery timed out")
            }
            try charsOutcome.get()
        }
        // iOS negotiates the ATT MTU automatically (no requestMtu API); the
        // usable payload is read via maximumWriteValueLength — see maxWriteLength.
    }

    func disconnect() async {
        hub.disconnect(peripheral)
        slotLock.lock()
        notifySinks.removeAll()
        slotLock.unlock()
    }

    /// The single-ATT-write payload limit. `.withoutResponse` reports the real
    /// negotiated MTU minus the 3-byte ATT header (`.withResponse` would report
    /// the 512-byte prepared-write limit, which the pouch SAR endpoint does not
    /// speak). Valid after `connect()`.
    var maxWriteLength: Int {
        peripheral.maximumWriteValueLength(for: .withoutResponse)
    }

    // MARK: - operations

    private func characteristic(_ uuid: CBUUID) throws -> CBCharacteristic {
        for service in peripheral.services ?? [] {
            if let characteristic = service.characteristics?.first(where: { $0.uuid == uuid }) {
                return characteristic
            }
        }
        throw BleError("characteristic \(uuid) not found (service not discovered?)")
    }

    private func attCode(_ error: Error) -> CBATTError.Code? {
        let nsError = error as NSError
        guard nsError.domain == CBATTErrorDomain else { return nil }
        return CBATTError.Code(rawValue: nsError.code)
    }

    /// Write with response, retrying through the transient insufficient-encryption window.
    func write(_ uuid: CBUUID, data: Data, timeoutMs: Int64 = 10_000) async throws {
        try await opLock.withLock {
            let characteristic = try characteristic(uuid)
            let deadline = MonotonicClock.nowMs() + Self.encryptionRetryMs
            while true {
                let slot = OneShot<Result<Void, Error>>()
                setSlot { $0.writeSlot = slot }
                peripheral.writeValue(data, for: characteristic, type: .withResponse)
                guard let outcome = await slot.value(timeoutMs: timeoutMs) else {
                    throw BleError("write(\(uuid)) timed out")
                }
                switch outcome {
                case .success:
                    return
                case .failure(let error):
                    let code = attCode(error)
                    // "Unlikely Error" (0x0E) on a characteristic write is
                    // ambiguous but the write has, in practice, already been
                    // delivered to the pouch SAR endpoint. Do NOT re-send (a
                    // duplicate SAR fragment wedges the receiver with "Invalid
                    // state") and do NOT fail — treat it as sent and let the SAR
                    // ack/re-ack confirm delivery.
                    if code == .unlikelyError {
                        return
                    }
                    if code == .insufficientEncryption || code == .insufficientAuthentication,
                       MonotonicClock.nowMs() < deadline {
                        try await Task.sleep(nanoseconds: 300 * 1_000_000)
                        continue
                    }
                    throw BleError("write(\(uuid)) failed: \(error)")
                }
            }
        }
    }

    func read(_ uuid: CBUUID, timeoutMs: Int64 = 10_000) async throws -> Data {
        try await opLock.withLock {
            let characteristic = try characteristic(uuid)
            let slot = OneShot<Result<Data, Error>>()
            slotLock.lock()
            readSlots[uuid] = slot
            slotLock.unlock()
            peripheral.readValue(for: characteristic)
            guard let outcome = await slot.value(timeoutMs: timeoutMs) else {
                throw BleError("read(\(uuid)) timed out")
            }
            return try outcome.get()
        }
    }

    /// Enable or disable notifications (the CCC write happens inside CoreBluetooth).
    func setNotify(_ uuid: CBUUID, enable: Bool, onNotify: (@Sendable (Data) -> Void)?) async throws {
        try await opLock.withLock {
            let characteristic = try characteristic(uuid)

            if !enable {
                // Disabling notifications is per-transaction SAR cleanup: the pouch
                // device tears down its SAR endpoint on its own, and the disable
                // often errors (e.g. "Unlikely Error") as it does. Best-effort —
                // never fail the transaction on it.
                slotLock.lock()
                notifySinks.removeValue(forKey: uuid)
                slotLock.unlock()
                let slot = OneShot<Result<Void, Error>>()
                setSlot { $0.notifySlot = slot }
                peripheral.setNotifyValue(false, for: characteristic)
                _ = await slot.value(timeoutMs: 3_000)
                return
            }

            // Register the sink before enabling so the device's opening SAR ack
            // (sent as soon as its endpoint opens) cannot be missed.
            if let onNotify {
                slotLock.lock()
                notifySinks[uuid] = onNotify
                slotLock.unlock()
            }

            // The pouch characteristics require an encrypted link, and iOS pairs
            // lazily on the first protected access: the system pairing dialog
            // blocks this CCC enable, so give the first one the pairing timeout.
            // Transient insufficient-encryption results retry while the
            // peripheral-initiated encryption settles.
            let deadline = MonotonicClock.nowMs() + Self.encryptionRetryMs
            while true {
                let slot = OneShot<Result<Void, Error>>()
                setSlot { $0.notifySlot = slot }
                peripheral.setNotifyValue(true, for: characteristic)
                let waitMs: Int64 = pairingSettled ? 10_000 : Self.pairingTimeoutMs
                guard let outcome = await slot.value(timeoutMs: waitMs) else {
                    throw BleError("CCC enable on \(uuid) timed out")
                }
                switch outcome {
                case .success:
                    pairingSettled = true
                    return
                case .failure(let error):
                    let code = attCode(error)
                    let retryable = code == .insufficientEncryption
                        || code == .insufficientAuthentication
                        || code == .unlikelyError
                    if retryable, MonotonicClock.nowMs() < deadline {
                        try await Task.sleep(nanoseconds: 300 * 1_000_000)
                        continue
                    }
                    throw BleError("CCC enable on \(uuid) failed: \(error)")
                }
            }
        }
    }

    private func setSlot(_ assign: (GattClient) -> Void) {
        slotLock.lock()
        assign(self)
        slotLock.unlock()
    }

    private func takeSlot<T>(_ take: (GattClient) -> OneShot<T>?) -> OneShot<T>? {
        slotLock.lock()
        defer { slotLock.unlock() }
        return take(self)
    }

    // MARK: - CBPeripheralDelegate

    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        let slot = takeSlot { $0.servicesSlot }
        if let error {
            slot?.complete(.failure(error))
        } else {
            slot?.complete(.success(()))
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: Error?) {
        let slot = takeSlot { $0.charsSlot }
        if let error {
            slot?.complete(.failure(error))
        } else {
            slot?.complete(.success(()))
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didWriteValueFor characteristic: CBCharacteristic, error: Error?) {
        let slot = takeSlot { $0.writeSlot }
        if let error {
            slot?.complete(.failure(error))
        } else {
            slot?.complete(.success(()))
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateNotificationStateFor characteristic: CBCharacteristic, error: Error?) {
        let slot = takeSlot { $0.notifySlot }
        if let error {
            slot?.complete(.failure(error))
        } else {
            slot?.complete(.success(()))
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: Error?) {
        // Read responses and notifications share this callback; a pending read
        // slot for the characteristic wins (uplink/downlink are never read).
        slotLock.lock()
        let readSlot = readSlots.removeValue(forKey: characteristic.uuid)
        let sink = notifySinks[characteristic.uuid]
        slotLock.unlock()
        if let readSlot {
            if let error {
                readSlot.complete(.failure(error))
            } else {
                readSlot.complete(.success(characteristic.value ?? Data()))
            }
            return
        }
        guard error == nil, let value = characteristic.value else { return }
        sink?(value)
    }
}
#endif
