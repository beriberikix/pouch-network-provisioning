<!-- Copyright (c) 2026 Jonathan Beri; SPDX-License-Identifier: Apache-2.0 -->
# Pouch provisioning — Android

Native Kotlin SDK and a Jetpack Compose reference app for provisioning blank
Zephyr devices over BLE with the [pouch](https://github.com/golioth/pouch)
protocol. This is the Android sibling of the Python [`cli/`](../cli/); both speak
the same wire protocol (see [`docs/clients.md`](../docs/clients.md)).

## Modules

| Module | Type | What |
|---|---|---|
| `pouchprov-core` | Kotlin/JVM | Protocol: CBOR codec, pouch framing, SAR, PoP auth, lockstep session, flows. No Android deps; JVM-tested against the shared golden vectors. |
| `pouchprov-ble` | Android library | BLE transport (scan, GATT, LESC pairing, notifications) + the public API: `PouchProvManager`, `PouchProvDevice`. |
| `app` | Android app | Compose reference UI: scan → select → enter PoP / Wi-Fi / pick cert files → provision with live status. |

Package namespace: `io.golioth.pouchprov`. Distribution: in-repo Gradle modules
for now (no Maven publishing yet).

## Prerequisites

- **JDK 17** (e.g. Temurin, or Homebrew `openjdk@17`).
- **Android Studio** (bundles the Android SDK, `adb`, emulator). Install **SDK
  Platform 35** (and 34), **Build-Tools 35**, **Platform-Tools**. Min SDK is 26.
- Point Gradle at the SDK: set `ANDROID_HOME` or create `android/local.properties`
  with `sdk.dir=/path/to/Android/sdk` (git-ignored).
- Gradle itself is provided by the committed wrapper (`./gradlew`, Gradle 8.9).
- For on-device testing: a **physical Android phone** with BLE + USB debugging
  (the emulator has no Bluetooth), plus a device running the `samples/basic`
  target. An Android phone can complete the LE Secure-Connections pairing that
  macOS cannot.

## Build & test

```console
$ cd android
$ ./gradlew :pouchprov-core:test                 # protocol conformance (no hardware)
$ ./gradlew :pouchprov-ble:assembleDebug          # build the SDK library
$ ./gradlew :app:installDebug                      # install the reference app on a phone
```

`:pouchprov-core:test` reads the shared fixtures in `../tests/vectors/` and
verifies every request encoder / pouch frame byte-for-byte, plus SAR loopback and
full mock-transport Wi-Fi and cred-only flows.

## Using the SDK

```kotlin
val manager = PouchProvManager(context)                 // hold BLE runtime permissions first
val device = manager.scan().first()                     // discover a provisioning device
device.provision(
    ProvisionRequest(
        pop = "abcd1234",
        ssid = "MyNet", password = "hunter22",           // omit for a BLE-only device
        certificate = certBytes, privateKey = keyBytes,  // PEM or DER
    ),
)
// Observe device.state (StateFlow<ProvisionState>) to drive a UI.
```

Runtime permissions the app must request: `BLUETOOTH_SCAN` + `BLUETOOTH_CONNECT`
(API 31+) or `ACCESS_FINE_LOCATION` (API ≤ 30). The reference `app` shows the flow.

## On-device end-to-end

1. Flash `samples/basic` (plaintext build) to an ESP32-S3 / nRF board.
2. `./gradlew :app:installDebug` on a connected phone (`adb devices` to confirm).
3. In the app: Scan → Select the `PVN-…` device → enter the PoP → Provision.
4. Confirm on the device console it received the `.prov/*` entries and reported
   `CONNECTED` / stored credentials. The same board is provisionable by
   `pouchprov` from Linux, demonstrating cross-client interchangeability.

## Status

Plaintext (`ENCRYPTION_NONE`) path, matching the CLI's live functional level. The
saead encrypted session is a follow-up behind the `SessionCrypto` seam in
`pouchprov-core`.
