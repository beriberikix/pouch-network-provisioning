// Copyright (c) 2026 Jonathan Beri
// SPDX-License-Identifier: Apache-2.0

#if canImport(CoreBluetooth)
import CoreBluetooth
import Foundation
import PouchProvCore

/// Entry point for discovering and provisioning pouch devices over BLE — the
/// pouch-branded analogue of Espressif's `ESPProvisionManager`.
///
/// Creating the manager instantiates the process's `CBCentralManager`, which is
/// what triggers the system Bluetooth permission prompt (the app must declare
/// `NSBluetoothAlwaysUsageDescription`).
public final class PouchProvManager: @unchecked Sendable {

    private let hub = CentralHub()

    public init() {}

    /// Scan for devices advertising the pouch service with the provisioning flag
    /// set. Yields a ``PouchProvDevice`` the first time each device is seen. The
    /// stream runs until cancelled or `timeoutMs` elapses; it throws if Bluetooth
    /// is off, unauthorized or unavailable.
    ///
    /// With `includeAll`, pouch devices *not* in provisioning mode are yielded too
    /// (mirrors the CLI's `discover --all`); check ``PouchProvDevice/provisioning``
    /// before connecting.
    public func scan(
        timeoutMs: Int64 = 10_000,
        includeAll: Bool = false
    ) -> AsyncThrowingStream<PouchProvDevice, Error> {
        AsyncThrowingStream { continuation in
            let seen = SeenSet()
            let scanTask = Task { [hub] in
                do {
                    try await hub.waitPoweredOn()
                } catch {
                    continuation.finish(throwing: error)
                    return
                }
                hub.startScan { peripheral, advertisementData, rssi in
                    guard let serviceData =
                            advertisementData[CBAdvertisementDataServiceDataKey] as? [CBUUID: Data],
                          let data = serviceData[BleUuids.serviceUuid16],
                          data.count >= 2
                    else { return }
                    let bytes = [UInt8](data)
                    let version = Int(bytes[0])
                    let flags = bytes[1]
                    let provisioning = flags & BleUuids.advFlagProvisioning != 0
                    guard includeAll || provisioning else { return }
                    guard seen.insert(peripheral.identifier) else { return }
                    let name = (advertisementData[CBAdvertisementDataLocalNameKey] as? String)
                        ?? peripheral.name
                    continuation.yield(PouchProvDevice(
                        hub: hub,
                        peripheral: peripheral,
                        name: name,
                        rssi: rssi.intValue,
                        provisioning: provisioning,
                        pouchVersion: version >> 4,
                        gattVersion: version & 0x0F
                    ))
                }
                try? await Task.sleep(nanoseconds: UInt64(max(timeoutMs, 0)) * 1_000_000)
                hub.stopScan()
                continuation.finish()
            }
            continuation.onTermination = { [hub] _ in
                scanTask.cancel()
                hub.stopScan()
            }
        }
    }

    /// Wrap an already-known peripheral (e.g. retrieved by identifier).
    public func device(_ peripheral: CBPeripheral, name: String? = nil, rssi: Int = 0) -> PouchProvDevice {
        PouchProvDevice(hub: hub, peripheral: peripheral, name: name ?? peripheral.name, rssi: rssi)
    }
}

private final class SeenSet: @unchecked Sendable {
    private let lock = NSLock()
    private var values: Set<UUID> = []

    /// Returns true if the value was newly inserted.
    func insert(_ value: UUID) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return values.insert(value).inserted
    }
}
#endif
