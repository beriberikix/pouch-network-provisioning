// Copyright (c) 2026 Jonathan Beri
// SPDX-License-Identifier: Apache-2.0

#if canImport(CoreBluetooth)
import CoreBluetooth
import Foundation
import PouchProvCore

/// A pouch ``ProvTransport`` over CoreBluetooth GATT. Each pouch characteristic
/// (uplink, downlink) is exposed as a ``ProvChannel``: writes go to that
/// characteristic and a subscribe/unsubscribe cycle toggles its notifications —
/// one subscribe == one SAR transaction (pouch CCC semantics). Mirrors the
/// Android `BleTransport` / Python `transport.ble`.
public final class BleTransport: ProvTransport, @unchecked Sendable {

    private let gatt: GattClient
    private let downlinkChannel: BleChannel
    private let uplinkChannel: BleChannel

    // saead-only SAR endpoints, populated after connect (their presence is the
    // autodetection signal — saead is a compile-time firmware choice).
    public private(set) var info: (any ProvChannel)?
    public private(set) var serverCert: (any ProvChannel)?
    public private(set) var deviceCert: (any ProvChannel)?

    init(gatt: GattClient) {
        self.gatt = gatt
        self.downlinkChannel = BleChannel(gatt: gatt, uuid: BleUuids.downlink)
        self.uplinkChannel = BleChannel(gatt: gatt, uuid: BleUuids.uplink)
    }

    public var downlink: any ProvChannel { downlinkChannel }
    public var uplink: any ProvChannel { uplinkChannel }

    public func connect() async throws {
        try await gatt.connect()
        if gatt.hasCharacteristic(BleUuids.serverCert) {
            info = BleChannel(gatt: gatt, uuid: BleUuids.info)
            serverCert = BleChannel(gatt: gatt, uuid: BleUuids.serverCert)
            deviceCert = BleChannel(gatt: gatt, uuid: BleUuids.deviceCert)
        }
    }

    public func disconnect() async {
        await gatt.disconnect()
    }

    /// SAR packet size limit for this connection: the negotiated single-ATT-write
    /// payload, capped at the protocol default (ATT MTU 247 => 244).
    public var maxlen: Int {
        min(ProvSession.defaultMaxlen, gatt.maxWriteLength)
    }
}

private final class BleChannel: ProvChannel, @unchecked Sendable {
    private let gatt: GattClient
    private let uuid: CBUUID

    init(gatt: GattClient, uuid: CBUUID) {
        self.gatt = gatt
        self.uuid = uuid
    }

    func write(_ data: Data) async throws {
        try await gatt.write(uuid, data: data)
    }

    func subscribe(_ onNotify: @escaping @Sendable (Data) -> Void) async throws {
        try await gatt.setNotify(uuid, enable: true, onNotify: onNotify)
    }

    func unsubscribe() async {
        try? await gatt.setNotify(uuid, enable: false, onNotify: nil)
    }
}
#endif
