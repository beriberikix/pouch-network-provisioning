// swift-tools-version:6.0
// Copyright (c) 2026 Jonathan Beri
// SPDX-License-Identifier: Apache-2.0

import PackageDescription

// Swift 5 language mode for now: the CoreBluetooth delegate bridge is not yet
// audited for Swift 6 strict concurrency (tracked as a follow-up in ios/README.md).
let swiftSettings: [SwiftSetting] = [.swiftLanguageMode(.v5)]

let package = Package(
    name: "PouchProv",
    platforms: [
        .iOS(.v16),
        .macOS(.v13),
    ],
    products: [
        .library(name: "PouchProvCore", targets: ["PouchProvCore"]),
        .library(name: "PouchProvBLE", targets: ["PouchProvBLE"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", "3.0.0"..<"5.0.0"),
        .package(url: "https://github.com/apple/swift-certificates.git", from: "1.5.0"),
    ],
    targets: [
        // Platform-independent protocol logic (CBOR codec, pouch framing, SAR,
        // session, flows, certificates). Builds and tests on Linux and Apple
        // platforms alike — the analogue of the Android `pouchprov-core` module.
        .target(
            name: "PouchProvCore",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "X509", package: "swift-certificates"),
            ],
            swiftSettings: swiftSettings
        ),
        // CoreBluetooth transport + high-level device API — the analogue of the
        // Android `pouchprov-ble` module. Sources are guarded with
        // `#if canImport(CoreBluetooth)` so the target is empty on Linux.
        .target(
            name: "PouchProvBLE",
            dependencies: ["PouchProvCore"],
            swiftSettings: swiftSettings
        ),
        .testTarget(
            name: "PouchProvCoreTests",
            dependencies: ["PouchProvCore"],
            swiftSettings: swiftSettings
        ),
    ]
)
