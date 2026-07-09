// Copyright (c) 2026 Jonathan Beri
// SPDX-License-Identifier: Apache-2.0

#if canImport(CoreBluetooth)
import CoreBluetooth

/// Pouch BLE GATT identifiers and advertising flags (from the pouch GATT
/// transport and this project's `transport/ble.py`). The device is the GATT
/// server; the client is central.
public enum BleUuids {
    /// 16-bit service UUID used in advertising service data.
    public static let serviceUuid16 = CBUUID(string: "FC49")

    /// The peripheral's primary GATT service UUID. The pouch Zephyr peripheral
    /// declares it with the 16-bit `0xFC49` (expanded to the Bluetooth base UUID),
    /// so that — not the 128-bit form below — is what a central discovers.
    public static let service = serviceUuid16

    /// 128-bit pouch service UUID (used by pouch's central/broker code, not the peripheral).
    public static let service128 = CBUUID(string: "89A316AE-89B7-4EF6-B1D3-5C9A6E27D272")

    /// device -> client responses (notify).
    public static let uplink = CBUUID(string: "89A316AE-89B7-4EF6-B1D3-5C9A6E27D273")

    /// client -> device requests (write + notify).
    public static let downlink = CBUUID(string: "89A316AE-89B7-4EF6-B1D3-5C9A6E27D274")

    /// info SAR endpoint ({flags, server_cert_snr}; device-side sender).
    public static let info = CBUUID(string: "89A316AE-89B7-4EF6-B1D3-5C9A6E27D275")

    /// server-cert SAR endpoint (client pushes its cert; saead builds only).
    public static let serverCert = CBUUID(string: "89A316AE-89B7-4EF6-B1D3-5C9A6E27D276")

    /// device-cert SAR endpoint (device sends its identity cert; saead builds only).
    public static let deviceCert = CBUUID(string: "89A316AE-89B7-4EF6-B1D3-5C9A6E27D277")

    // Advertising flags byte (pouch service data): bit1 = provisioning available.
    public static let advFlagSyncRequest: UInt8 = 0x01
    public static let advFlagProvisioning: UInt8 = 0x02
}
#endif
