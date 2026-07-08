<!-- Copyright (c) 2026 Jonathan Beri; SPDX-License-Identifier: Apache-2.0 -->
# Provisioning clients

The provisioning protocol (`docs/protocol.md`, `cddl/prov.cddl`) is the contract;
every client speaks it identically and is pinned to the same golden vectors in
`tests/vectors/`. Three clients are maintained in this repo:

| Client | Language | Location | Status |
|---|---|---|---|
| CLI | Python | [`cli/`](../cli/) | Reference client |
| Android SDK + app | Kotlin | [`android/`](../android/) | Plaintext path; saead is a follow-up |
| iOS SDK + app | Swift | `ios/` | Planned |

All three target the same functional level: discover a provisioning device,
read its version/capabilities, authorize with a proof-of-possession, push cloud
credentials and/or Wi-Fi, and end the session. Clients branch on the device's
advertised `caps`, so a BLE-only (credential-only) device is provisioned with
certificates alone.

## Capability parity

| Capability | Python CLI | Android (Kotlin) | iOS (Swift) |
|---|---|---|---|
| Discover devices | `pouchprov discover` | `PouchProvManager.scan()` | _TBD_ |
| Read version/caps | `pouchprov version` | `PouchProvDevice.version()` | _TBD_ |
| Scan Wi-Fi (device) | `pouchprov wifi-scan` | `PouchProvDevice.scanWifi()` | _TBD_ |
| Authorize (PoP) | `--pop` on any command | `PouchProvDevice.authorize(pop)` | _TBD_ |
| Provision Wi-Fi | `provision --ssid --password` | `PouchProvDevice.provisionWifi(ssid, password)` | _TBD_ |
| Provision credentials | `provision --cert --key [--ca]` | `PouchProvDevice.provisionCredentials(cert, key, ca)` | _TBD_ |
| One-shot provision | `pouchprov provision …` | `PouchProvDevice.provision(ProvisionRequest(…))` | _TBD_ |
| End session | (implicit at end of `provision`) | `PouchProvDevice.end()` | _TBD_ |

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

To mint temporary test credentials automatically (instead of supplying your own
`--cert`/`--key`), see [`docs/golioth-demo-certs.md`](golioth-demo-certs.md) —
the Golioth public-API flow the console's "temporary certificate" button uses,
with a per-client implementation plan.

## Shared conformance

Each client's protocol layer is validated byte-for-byte against
`tests/vectors/prov_messages.json` and `tests/vectors/pouch_frames.json`:

- **Python:** `cd cli && pytest`
- **Android:** `cd android && ./gradlew :pouchprov-core:test`
- **iOS:** _planned_

Because all clients pin to the same fixtures, a message that encodes correctly in
one client encodes identically in the others and interoperates with the Zephyr
device codec generated from `cddl/prov.cddl`.

## Encryption note

Today the Android SDK (like the CLI's live path) speaks the **plaintext**
(`ENCRYPTION_NONE`) pouch framing, verifiable end-to-end against `samples/basic`.
The session layer is built behind a `SessionCrypto` seam so the saead encrypted
path (ECDH + HKDF + per-block AEAD) can be added without reshaping the public API.
See `docs/protocol.md` for the saead details.
