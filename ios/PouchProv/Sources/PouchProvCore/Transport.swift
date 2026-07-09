// Copyright (c) 2026 Jonathan Beri
// SPDX-License-Identifier: Apache-2.0

import Foundation

/// Transport abstraction.
///
/// A provisioning transport exposes the pouch uplink and downlink characteristics
/// as ``ProvChannel``s. A channel supports writing toward the device and a
/// subscribe/unsubscribe cycle delivering notifications; one subscribe == one SAR
/// transaction (pouch CCC semantics). Mirrors the Kotlin `Transport`/`Channel`.
public protocol ProvChannel: AnyObject {
    /// Write toward the device (Write With Response on real BLE).
    func write(_ data: Data) async throws

    /// Enable notifications; the device side opens its SAR endpoint.
    func subscribe(_ onNotify: @escaping @Sendable (Data) -> Void) async throws

    /// Disable notifications; the device side closes its SAR endpoint.
    func unsubscribe() async
}

public protocol ProvTransport: AnyObject {
    /// client -> device requests
    var downlink: any ProvChannel { get }

    /// device -> client responses
    var uplink: any ProvChannel { get }

    func connect() async throws

    func disconnect() async
}
