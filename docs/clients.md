<!-- Copyright (c) 2026 Jonathan Beri; SPDX-License-Identifier: Apache-2.0 -->
# Provisioning clients

The provisioning protocol (`docs/protocol.md`, `cddl/prov.cddl`) is the contract;
every client speaks it identically and is pinned to the same golden vectors in
`tests/vectors/`. Three clients are maintained in this repo:

| Client | Language | Location | Status |
|---|---|---|---|
| CLI | Python | [`cli/`](../cli/) | Reference client |
| Android SDK + app | Kotlin | [`android/`](../android/) | Plaintext path; saead is a follow-up |
| iOS SDK + app | Swift | [`ios/`](../ios/) | Plaintext path; saead is a follow-up |

All three target the same functional level: discover a provisioning device,
read its version/capabilities, authorize with a proof-of-possession, push cloud
credentials and/or Wi-Fi, and end the session. Clients branch on the device's
advertised `caps`, so a BLE-only (credential-only) device is provisioned with
certificates alone.

## Capability parity

| Capability | Python CLI | Android (Kotlin) | iOS (Swift) |
|---|---|---|---|
| Discover devices | `pouchprov discover` | `PouchProvManager.scan()` | `PouchProvManager.scan()` |
| Read version/caps | `pouchprov version` | `PouchProvDevice.version()` | `PouchProvDevice.version()` |
| Scan Wi-Fi (device) | `pouchprov wifi-scan` | `PouchProvDevice.scanWifi()` | `PouchProvDevice.scanWifi()` |
| Authorize (PoP) | `--pop` on any command | `PouchProvDevice.authorize(pop)` | `PouchProvDevice.authorize(pop:)` |
| Provision Wi-Fi | `provision --ssid --password` | `PouchProvDevice.provisionWifi(ssid, password)` | `PouchProvDevice.provisionWifi(ssid:password:)` |
| Provision credentials | `provision --cert --key [--ca]` | `PouchProvDevice.provisionCredentials(cert, key, ca)` | `PouchProvDevice.provisionCredentials(cert:key:ca:)` |
| One-shot provision | `pouchprov provision …` | `PouchProvDevice.provision(ProvisionRequest(…))` | `PouchProvDevice.provision(ProvisionRequest(…))` |
| End session | (implicit at end of `provision`) | `PouchProvDevice.end()` | `PouchProvDevice.end()` |

iOS parity gaps (platform limitations, not protocol ones): devices are
identified by CoreBluetooth's per-device `UUID` rather than a MAC address,
and there is no `forgetBond()` — iOS offers no API to remove a bond, so
re-pairing from scratch means forgetting the device in Settings → Bluetooth.

### Equivalent one-shot invocations

Provision a Wi-Fi device with certificates + Wi-Fi in one shot:

```console
# Python
$ pouchprov provision --pop abcd1234 --ssid MyNet --password hunter22 \
      --cert device.crt.pem --key device.key.pem
```

```kotlin
// Android (Kotlin)
val device = manager.scan().first()          // discover
device.provision(
    ProvisionRequest(
        pop = "abcd1234",
        ssid = "MyNet",
        password = "hunter22",
        certificate = certPemBytes,           // PEM or DER
        privateKey = keyPemBytes,
    ),
)
```

Provision a BLE-only device with certificates alone — omit the SSID; the client
skips Wi-Fi because the device does not advertise the `wifi` cap:

```console
$ pouchprov provision --pop abcd1234 --cert device.crt.pem --key device.key.pem
```

```kotlin
device.provision(ProvisionRequest(pop = "abcd1234", certificate = cert, privateKey = key))
```

The Swift API is the same shape:

```swift
// iOS (Swift)
for try await device in manager.scan() {           // discover
    let result = try await device.provision(ProvisionRequest(
        pop: "abcd1234",
        ssid: "MyNet",                              // omit for a BLE-only device
        password: "hunter22",
        certificate: certPemData,                   // PEM or DER
        privateKey: keyPemData
    ))
    break
}
```

To mint temporary test credentials automatically (instead of supplying your own
`--cert`/`--key`), see [`docs/golioth-demo-certs.md`](golioth-demo-certs.md) —
the Golioth public-API flow the console's "temporary certificate" button uses,
with a per-client implementation plan.

## Shared conformance

Each client's protocol layer is validated byte-for-byte against
`tests/vectors/prov_messages.json` and `tests/vectors/pouch_frames.json`:

- **Python:** `cd cli && pytest`
- **Android:** `cd android && ./gradlew :pouchprov-core:test`
- **iOS:** `cd ios/PouchProv && swift test` (also runs on Linux)

Because all clients pin to the same fixtures, a message that encodes correctly in
one client encodes identically in the others and interoperates with the Zephyr
device codec generated from `cddl/prov.cddl`.

## Encryption note

Today the Android and iOS SDKs (like the CLI's live path) speak the **plaintext**
(`ENCRYPTION_NONE`) pouch framing, verifiable end-to-end against `samples/basic`.
Both session layers are built behind a `SessionCrypto` seam so the saead encrypted
path (ECDH + HKDF + per-block AEAD) can be added without reshaping the public API.
See `docs/protocol.md` for the saead details.
