<!-- Copyright (c) 2026 Jonathan Beri; SPDX-License-Identifier: Apache-2.0 -->
# Provisioning clients

The provisioning protocol (`docs/protocol.md`, `cddl/prov.cddl`) is the contract;
every client speaks it identically and is pinned to the same golden vectors in
`tests/vectors/`. Three clients are maintained in this repo:

| Client | Language | Location | Status |
|---|---|---|---|
| CLI | Python | [`cli/`](../cli/) | Reference client |
| Android SDK + app | Kotlin | [`android/`](../android/) | Feature parity with the CLI |
| iOS SDK + app | Swift | [`ios/`](../ios/) | Feature parity with the CLI |

All three speak both pouch framings: plaintext (`ENCRYPTION_NONE`) and encrypted
(saead), autodetected per device — see the Encryption section below.

All three target the same functional level: discover a provisioning device,
read its version/capabilities, authorize with a proof-of-possession, push cloud
credentials and/or Wi-Fi, and end the session. Clients branch on the device's
advertised `caps`, so a BLE-only (credential-only) device is provisioned with
certificates alone.

## Capability parity

| Capability | Python CLI | Android (Kotlin) | iOS (Swift) |
|---|---|---|---|
| Discover devices | `pouchprov discover [--all]` | `PouchProvManager.scan(includeAll)` | `PouchProvManager.scan(includeAll:)` |
| Read version/caps | `pouchprov version` | `PouchProvDevice.version()` | `PouchProvDevice.version()` |
| Scan Wi-Fi (device) | `pouchprov wifi-scan` (named security types) | `PouchProvDevice.scanWifi()` (`ScanEntry.authName`) | `PouchProvDevice.scanWifi()` (`ScanEntry.authName`) |
| Authorize (PoP) | `--pop` on any command | `PouchProvDevice.authorize(pop)` | `PouchProvDevice.authorize(pop:)` |
| Provision Wi-Fi | `provision --ssid --password` | `PouchProvDevice.provisionWifi(ssid, password)` | `PouchProvDevice.provisionWifi(ssid:password:)` |
| Provision credentials | `provision --cert --key [--ca]` | `PouchProvDevice.provisionCredentials(cert, key, ca)` | `PouchProvDevice.provisionCredentials(cert:key:ca:)` |
| Mint credentials (self-signed / demo CA / Golioth) | `pouchprov mint`, `provision --self-signed \| --golioth-api-key` | `DeviceCert` + `GoliothCertProvider` (app cert modes) | `DeviceCert` + `GoliothCertProvider` (app cert modes) |
| One-shot provision | `pouchprov provision …` | `PouchProvDevice.provision(ProvisionRequest(…))` | `PouchProvDevice.provision(ProvisionRequest(…))` |
| Credential status | `pouchprov cred-status` | `PouchProvDevice.credStatus()` | `PouchProvDevice.credStatus()` |
| Reset Wi-Fi state | `pouchprov reset` | `PouchProvDevice.reset()` | `PouchProvDevice.reset()` |
| Factory reset (reprovision) | `pouchprov reprovision` | `PouchProvDevice.reprovision()` | `PouchProvDevice.reprovision()` |
| Encrypted (saead) session | autodetected (`session: saead`) | autodetected (`device.encrypted`) | autodetected (`device.encrypted`) |
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

## Encryption

All three clients speak both pouch framings and **autodetect** which one the
device firmware was built with: the presence of the `server_cert` GATT
characteristic (saead builds only) selects the encrypted path; otherwise the
session runs plaintext (`ENCRYPTION_NONE`, `samples/basic`).

On a saead build the client first runs the **TOFU cert exchange** over the
dedicated SAR endpoints: read `info` (`{flags, server_cert_snr}`), push its
self-signed server certificate to `server_cert` when the stored serial
differs, then collect the device's identity certificate from `device_cert`.
The exchanged P-256 keys drive the ECDH + HKDF-SHA256 + per-block AEAD
session (`ChaCha20-Poly1305` or `AES-GCM`) described in `docs/protocol.md`.
The CLI persists its server identity in `~/.pouchprov/` so devices keep
trusting the same certificate; the mobile SDKs generate one per device
instance and re-push it (TOFU re-keys the device).

All three saead implementations are pinned to the shared deterministic
vectors in `tests/vectors/saead_kdf.json` (generated by
`scripts/gen_vectors.py` from the Python reference), so a KDF or framing
drift fails in unit tests on every platform.
