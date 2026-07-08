# Pouch Network Provisioning Protocol — v1

Status: v1, phase 1. This document is the normative contract for
provisioning clients (the Python CLI today; Android/iOS SDKs later).
Both reference implementations — the device library and the Python CLI —
are pinned to it byte-for-byte via the golden vectors in `tests/vectors/`.
Breaking changes may still land while the project is pre-1.0.

## Overview

This protocol provisions a **blank device** — no network credentials, no
cloud identity — over BLE, using the [pouch](https://github.com/golioth/pouch)
protocol end to end. The provisioning client (CLI/phone) acts in pouch's
**server role** and terminates the encrypted session locally; no cloud
connectivity is required on the device side at any point.

**Device classes.** Wi-Fi provisioning and cloud-credential bootstrap are
independent device features, each advertised as a capability in `.prov/ver`:

- **Wi-Fi (± BLE)** devices provision certificates *and* Wi-Fi credentials and
  advertise the `wifi`/`scan` caps.
- **BLE-only** devices provision certificates only and advertise no `wifi`
  cap; the client omits the Wi-Fi steps.

A client MUST branch on the advertised caps (e.g. skip `.prov/scan` and
`.prov/config` when `wifi` is absent). `.prov/ctrl` is available on every
device class.

A full provisioning session:

1. **Discovery** — device advertises the pouch GATT service with the
   provisioning flag set (§ Transport).
2. **Cert exchange** — stock pouch: client reads `info`, pushes its
   (self-signed) server certificate, collects the device certificate
   (trust-on-first-use; the device generates an ephemeral self-signed
   identity on first boot).
3. **Encrypted session** — stock pouch saead: ECDH + HKDF-SHA256 session
   keys, ChaCha20-Poly1305 or AES-256-GCM per-block AEAD.
4. **Authorization** — mutual proof-of-possession challenge-response on
   `.prov/auth` (§ Authorization). Gates all other endpoints.
5. **Credential bootstrap** — optional: client pushes a cloud device
   certificate + private key (+ CA) on `.prov/cred`.
6. **Wi-Fi provisioning** — scan (`.prov/scan`), configure and apply
   (`.prov/config`), poll connection status.
7. **End** — `.prov/ctrl` end; device proceeds to normal operation
   (e.g. connects to Golioth with the bootstrapped certificate and
   zero-touch enrolls).

## Transport

Provisioning messages are **pouch entries** on reserved `.prov/*` paths,
content type 60 (CBOR), carried over pouch's BLE GATT transport
(service `0xFC49`). Requests are downlink entries (client → device);
responses are uplink entries on the **same path**.

### Advertising

Service Data (UUID16 `0xFC49`): `{version, flags}` per pouch's GATT
transport. **Flags bit 1** (`0x02`) is set while provisioning is
available (vendor extension; bit 0 remains pouch's sync-request).
Device name: configurable prefix (default `PVN-`) + last 3 address
bytes in hex.

### RPC model

Pouch uplinks are device-initiated batches that auto-close after the
device's uplink handlers run; the device cannot stream responses into
an open pouch reactively. The RPC cycle is therefore client-driven, one
CCC-subscribe cycle per direction:

1. Client subscribes the **downlink** characteristic, sends one pouch
   (SAR-fragmented) containing 1..N request entries, ends the SAR
   transaction with **FIN|IDLE**, unsubscribes.
2. Device decrypts and dispatches entries **in order** on its pouch
   work queue; handlers enqueue responses.
3. Client subscribes the **uplink** characteristic; the device opens an
   uplink pouch and its provisioning uplink handler drains the response
   queue into it (waiting up to `CONFIG_POUCH_PROV_RESPONSE_WAIT_MS`,
   default 12 s). The client SAR-acks to receive.
4. An **empty pouch** (header, no entries) means "responses not ready —
   unsubscribe, back off, re-subscribe".

Clients MUST be lockstep per exchange: do not send request pouch N+1
before receiving response pouch N. Multiple entries within one request
pouch are answered by matching entries, in order, in one response pouch.

### SAR notes for client implementers

Formats per pouch `src/transport/sar/packet.h`:

- TX packet: 2-byte header — sequence (mod 256) + flags
  FIRST `0x?…` / LAST / FIN / IDLE — then fragment payload.
- ACK: 3 bytes — code, sequence, window (≤ 127).

Quirks a client MUST implement around (pouch reference behavior):

- The client's final FIN **must carry the IDLE flag**; the device treats
  a bare FIN as failure and drops the BLE connection.
- The device's own first FIN does *not* carry IDLE; treat any FIN
  received in the ended state as success.
- CCC re-subscribe is required per pouch in each direction (one SAR
  transaction per subscription).
- Re-sending an unchanged ACK is permitted and acts as a poll; the
  device re-pushes pending fragments.

### Sizing

An entry never spans pouch blocks. With the device's default block size
(512, advertised in `ver` as `"blk"`), clients SHOULD cap entry payloads
at **384 bytes** to leave room for entry/block/AEAD overhead.

## Messages

Encoding: CBOR (canonical, definite lengths). Every message is an array
`[op, ...]`. Full schema: [`cddl/prov.cddl`](../cddl/prov.cddl) — the
single source of truth; golden vectors in `tests/vectors/` pin both
reference implementations to it. Maps are extensible: decoders MUST
ignore unknown keys. Response arrays may gain trailing elements in
minor revisions: decoders MUST ignore extras.

Status codes: `0` ok, `1` invalid-proto, `2` invalid-argument,
`3` internal-error, `4` unauthorized, `5` invalid-state, `6` busy.

| Path | Purpose | Requests | Responses |
|---|---|---|---|
| `.prov/ver` | version/caps; never gated | `[0]` | `[0, status, {proto, caps, blk, lib, ?pop}]` |
| `.prov/auth` | PoP authorization | challenge `[0, nonce16]`, proof `[1, proof32]` | `[0, status, dev-nonce16, dev-proof32]`, `[1, status]` |
| `.prov/config` | Wi-Fi config | status `[0]`, set `[1, {ssid, ?pass, ?bssid, ?ch}]`, apply `[2]` | `[0, status, sta-state, ?detail]`, `[1, status]`, `[2, status]` |
| `.prov/scan` | Wi-Fi scan | start `[0, {?passive, ?period-ms}]`, status `[1]`, results `[2, start, count]` | `[0, status]`, `[1, status, finished, total]`, `[2, status, [*entry]]` |
| `.prov/cred` | credential bootstrap | write `[0, {kind, off, total, data}]`, finalize `[1]`, status `[2]` | `[0, status, received]`, `[1, status]`, `[2, status, {kind→len}]` |
| `.prov/ctrl` | control | reset `[0]`, reprovision `[1]`, end `[2]` | `[op, status]` |

Client flow: query `.prov/ver` first; verify `proto == 1`; run
`.prov/auth` if `pop` is true; then any of scan/config/cred; finish with
`.prov/ctrl` end. Wi-Fi apply is asynchronous — poll `.prov/config` `[0]`
until `sta-state` is connected (`0`) or failed (`3`, with a fail
reason: `0` auth error, `1` network not found).

`.prov/ctrl` ops: `end` (2) stops provisioning on every device class; `reset`
(0) and `reprovision` (1) act on the Wi-Fi state machine and are effective only
when the device has the Wi-Fi feature. `reprovision` additionally deletes any
stored cloud credentials so a device can be re-provisioned from scratch.

`.prov/cred` `kind`: `0` device certificate (DER), `1` private key
(DER), `2` CA certificate (DER). Chunks arrive in order per kind
(`off` strictly increasing); `finalize` validates (certificate must
parse) and persists atomically. Request op `3` is **reserved** for a
phase-2 CSR flow (device-generated key; private key never transits).

## Authorization (`.prov/auth`)

Proof-of-possession secret (PoP): a per-device secret printed on the
label/QR and known to the device firmware. Both proofs are HMAC-SHA256
keyed with the UTF-8 PoP bytes:

```
dev-proof = HMAC(PoP, "dev" || cli-nonce || dev-nonce)
cli-proof = HMAC(PoP, "cli" || dev-nonce || cli-nonce)
```

The client MUST verify `dev-proof` before sending `cli-proof` (a fake
device without the PoP must learn nothing and receive no credentials).
The device gates every endpoint except `.prov/ver` and `.prov/auth`
until the client proof verifies. Three consecutive failed proofs SHOULD
terminate the session.

## Threat model

Assets: the device's cloud credential (delivered on `.prov/cred`) and the
Wi-Fi passphrase (`.prov/config`). Adversary: a nearby BLE peer, optionally
an active relay in radio range during the provisioning window.

| Threat | Mitigation |
|---|---|
| Eavesdropping / tampering on the channel | pouch saead: per-block AEAD (ChaCha20-Poly1305 / AES-256-GCM), 12-byte per-block nonces, prior-block auth tag chained as AAD (reordering/truncation break decryption) |
| Client → device impersonation (a stranger provisions the device) | PoP client proof — the device rejects every gated endpoint until `HMAC(PoP, "cli" ‖ …)` verifies; 3 failed proofs end the session |
| Device → client impersonation (a fake device harvests the pushed credential) | PoP device proof, which the client verifies **before** sending its own proof or any credential |
| Replay of a captured session | random 16-byte session ids per pouch; the device also guards against same-power-cycle replay (`src/saead/downlink.c`) |
| Failed Wi-Fi attempt leaving stale/guessable creds | a failed connect deletes the just-stored credentials, so the device never boots "provisioned" without a working network |

**Residual risk (documented, accepted for phase 1).** An active relay MITM
present during the provisioning window can bridge two sessions: the PoP
challenge-response authenticates *possession of the secret* but is not
bound into pouch's key derivation, so it does not by itself authenticate
the *channel*. Closing this is tracked as
[upstream proposal #1](upstream-pouch.md#1-proposal-mix-a-pre-shared-secret-into-the-saead-hkdf-closes-mitm-gap)
(mix the PoP into the saead HKDF). Deployments that need MITM resistance
today should provision in a controlled RF environment.

**Trust in the client certificate.** The device accepts the client's
self-signed server certificate when built with
`CONFIG_POUCH_VALIDATE_SERVER_CERT=n` (the sample default, trust-on-first-
use). Closed fleets can instead ship a CA and pin
`CONFIG_POUCH_SERVER_CERT_CN` so only a known provisioning client is
accepted.

## Versioning

`proto` in the `ver` response is the protocol major version. Additive
changes (new caps, new map keys, new trailing response elements) do not
bump it; breaking changes do. Clients MUST refuse to proceed on an
unknown major version.
