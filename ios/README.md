<!-- Copyright (c) 2026 Jonathan Beri; SPDX-License-Identifier: Apache-2.0 -->
# Pouch provisioning — iOS

Native Swift SDK and a SwiftUI reference app for provisioning blank Zephyr
devices over BLE with the [pouch](https://github.com/golioth/pouch) protocol.
This is the iOS sibling of the Kotlin [`android/`](../android/) SDK and the
Python [`cli/`](../cli/); all three speak the same wire protocol (see
[`docs/clients.md`](../docs/clients.md)).

## Modules

| Module | Type | What |
|---|---|---|
| `PouchProv/Sources/PouchProvCore` | SPM library | Protocol: CBOR codec, pouch framing, SAR, PoP auth, lockstep session, flows, X.509 device certs. No CoreBluetooth — builds and tests on **Linux and macOS** against the shared golden vectors. |
| `PouchProv/Sources/PouchProvBLE` | SPM library | CoreBluetooth transport (scan, GATT, pairing, notifications) + the public API: `PouchProvManager`, `PouchProvDevice`. |
| `PouchProvApp` | iOS app | SwiftUI reference UI: scan → select → enter PoP / Wi-Fi / pick or mint certs → provision with live status. Project generated with XcodeGen. |

Dependencies: [swift-crypto](https://github.com/apple/swift-crypto) (HMAC, P-256)
and [swift-certificates](https://github.com/apple/swift-certificates) (X.509).
The CBOR codec is hand-rolled to stay byte-identical to the golden vectors
(insertion-ordered map keys, minimal-length heads).

## Prerequisites

- **Xcode 16+** (Swift 6 toolchain; the package builds in Swift 5 language mode).
- **[XcodeGen](https://github.com/yonaskolb/XcodeGen)** (`brew install xcodegen`)
  to generate the app's `.xcodeproj` — the project file is not committed.
- For SDK-only work, any **Swift 6.x toolchain** (macOS or Linux) is enough.
- For on-device testing: a **physical iPhone** (the Simulator has no Bluetooth),
  plus a device running the `samples/basic` target. An iPhone can complete the
  LE Secure-Connections pairing that **macOS cannot** — target iOS hardware,
  not Catalyst/macOS, for live end-to-end runs.

## Build & test

```console
$ cd ios/PouchProv
$ swift test                        # protocol conformance (no hardware)

$ cd ../PouchProvApp
$ xcodegen generate                 # emits PouchProvApp.xcodeproj
$ open PouchProvApp.xcodeproj       # build & run on an iPhone from Xcode
```

`swift test` reads the shared fixtures in `../../tests/vectors/` (found by
walking up from the checkout; override with `POUCHPROV_VECTORS_DIR`) and
verifies every request encoder / pouch frame byte-for-byte, plus SAR loopback,
full mock-transport Wi-Fi and cred-only flows, and certificate generation.

## Using the SDK

```swift
import PouchProvBLE

let manager = PouchProvManager()          // triggers the Bluetooth permission prompt
for try await device in manager.scan() {  // discover a provisioning device
    let result = try await device.provision(ProvisionRequest(
        pop: "abcd1234",
        ssid: "MyNet", password: "hunter22",       // omit for a BLE-only device
        certificate: certData, privateKey: keyData // PEM or DER
    ))
    break
}
// Observe device.statePublisher (Combine) to drive a UI with ProvisionState.
```

The app must declare `NSBluetoothAlwaysUsageDescription` in its Info.plist
(the reference app's `project.yml` shows this).

## On-device end-to-end

1. Build and flash a provisioning device following
   [`docs/hardware-testing.md`](../docs/hardware-testing.md). `samples/cred_only`
   gives a BLE-only **encrypted (saead)** device; `samples/basic` is plaintext.
   The client autodetects which.
2. Generate the project (`xcodegen generate`), open it in Xcode, set your
   signing team, and run on a connected iPhone (the Simulator has no Bluetooth).
   From the command line: `xcodebuild -project PouchProvApp.xcodeproj -scheme
   PouchProvApp -destination 'platform=iOS,id=<UDID>' -allowProvisioningUpdates
   DEVELOPMENT_TEAM=<TEAM> build`, then install with
   [`ios-deploy`](https://github.com/ios-control/ios-deploy) (`xcrun devicectl`
   does not support iOS 16).
3. In the app: Scan → Select the `PVN-…` device → accept the pairing prompt →
   enter the PoP (`abcd1234` for the samples) → for `cred_only`, pick a cert mode
   (Self-signed is simplest) and Generate → Provision. **Keep the screen awake**
   — a lock suspends BLE and stalls the final step.
4. The device card shows `encrypted (saead)` vs `plaintext session`; on success
   the device console reports `Session authorized` then `cloud device
   certificate stored`. The same board is provisionable by the CLI and the
   Android app, demonstrating cross-client interchangeability.

## Platform parity notes

- Devices are identified by CoreBluetooth's per-device `UUID`
  (`PouchProvDevice.identifier`) — iOS does not expose MAC addresses.
- There is no `forgetBond()`: iOS has no API to remove a bond. To re-pair from
  scratch, forget the device in **Settings → Bluetooth**.
- iOS pairs lazily on the first protected GATT operation (no `createBond`);
  the SDK gives the first notification-enable a long timeout so the system
  pairing dialog can be accepted.
- No MTU request API: the SAR packet size derives from
  `maximumWriteValueLength(for: .withoutResponse)`, capped at the protocol's
  244-byte default.

## Status

Feature parity with the CLI and the Android SDK. The SDK speaks both pouch
framings and autodetects per device: plaintext (`ENCRYPTION_NONE`) or the saead
encrypted session (TOFU cert exchange + ECDH/HKDF/per-block AEAD on
swift-crypto), surfaced as `PouchProvDevice.encrypted`. SDK verbs also cover
`credStatus()`, `reset()`, `reprovision()`, and scan-all discovery; the app adds
Golioth / self-signed / upload credential modes and device controls.

Remaining follow-ups:

- Swift 6 strict-concurrency language mode (the package builds in `.v5` mode
  today; the CoreBluetooth delegate bridge needs a Sendable audit first).
- An on-device XCUITest analogue of Android's `HardwareProvisioningTest`.
