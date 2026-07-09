// Copyright (c) 2026 Jonathan Beri
// SPDX-License-Identifier: Apache-2.0

import Foundation
import XCTest
@testable import PouchProvCore

/// Wi-Fi security-type names. The integers are Zephyr's enum wifi_security_type,
/// carried verbatim in ScanEntry.auth; names must match the other clients.
final class SecurityNameTests: XCTestCase {

    func testKnownTypes() {
        let expected: [Int: String] = [
            0: "Open",
            1: "WPA2-PSK",
            2: "WPA2-PSK-SHA256",
            3: "WPA3-SAE",
            4: "WPA3-SAE-H2E",
            5: "WPA3-SAE-AUTO",
            6: "WAPI",
            7: "EAP-TLS",
            8: "WEP",
            9: "WPA-PSK",
            10: "WPA/WPA2-Auto",
            11: "DPP",
        ]
        for (auth, name) in expected {
            XCTAssertEqual(securityName(auth), name)
        }
    }

    func testUnknownTypes() {
        XCTAssertEqual(securityName(42), "unknown(42)")
        XCTAssertEqual(securityName(-1), "unknown(-1)")
    }

    func testScanEntryAuthName() {
        let entry = ScanEntry(ssid: Data("x".utf8), bssid: Data(), channel: 1, rssi: -40, auth: 3)
        XCTAssertEqual(entry.authName, "WPA3-SAE")
    }
}
