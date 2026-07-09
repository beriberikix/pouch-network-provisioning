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

    init(gatt: GattClient) {
        self.gatt = gatt
        self.downlinkChannel = BleChannel(gatt: gatt, uuid: BleUuids.downlink)
        self.uplinkChannel = BleChannel(gatt: gatt, uuid: BleUuids.uplink)
    }

    public var downlink: any ProvChannel { downlinkChannel }
    public var uplink: any ProvChannel { uplinkChannel }

    public func connect() async throws {
        try await gatt.connect()
    }

    public func disconnect() async {
        await gatt.disconnect()
    }

    /// SAR packet size limit for this connection: the negotiated single-ATT-write
    /// payload, capped at the protocol default (ATT MTU 247 => 244).
    public var maxlen: Int {
        min(ProvSession.defaultMaxlen, gatt.maxWriteLength)
    }

    /// Read the INFO characteristic ({flags, server_cert_snr}), for diagnostics
    /// and the future saead path.
    public func readInfo() async throws -> Data {
        try await gatt.read(BleUuids.info)
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
