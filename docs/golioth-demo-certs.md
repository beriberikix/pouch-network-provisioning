<!-- Copyright (c) 2026 Jonathan Beri; SPDX-License-Identifier: Apache-2.0 -->
# Golioth demo certificates (temporary test credentials)

The Golioth web console has a "generate temporary certificates" flow for quick
testing. It is backed by the **public** Golioth REST API, so we can replicate it
in our provisioning clients (Python CLI and mobile SDKs) and hand a freshly
provisioned device credentials that authenticate to Golioth with no manual
console steps.

This doc records exactly what the console does and how to implement the same in
each client.

## What the console actually does

Captured from `console.golioth.io.har`. Two things happen, and the important part
is that **the certificate is generated entirely on the client** — the API never
mints a key for you.

1. **Client-side (in the browser):** generate an ECDSA P-256 keypair and a
   self-signed **root CA** certificate. The console uses a random human-readable
   name (e.g. `CN=olive-agricultural-giraffe-CA`, `C=US`) and ~28-day validity.
2. **Upload the CA** to the project:

   ```http
   POST https://api.golioth.io/v1/projects/{projectId}/certificates
   Content-Type: application/json

   {
     "certType": "root",
     "certFile": "<base64 of the CA certificate PEM>",
     "demo": true
   }
   ```

   `"demo": true` is what makes it a *temporary test* CA: demo CAs enable
   certificate-based device auto-provisioning (a device presenting a client cert
   signed by this CA is created in the project on first connect, with no
   pre-registration).

That's the whole console flow. Note the console registers a **CA**, not a device
cert. Devices then present a **client cert signed by that CA**. For an end-to-end
"provision a blank device" experience our clients must do both halves:

```
                        ┌─ (A) once per project ──────────────────────┐
  generate root CA ──▶  upload CA (certType=root, demo=true)  ──▶ Golioth
                        └─────────────────────────────────────────────┘
                        ┌─ (B) once per device ───────────────────────┐
  generate device key ──▶ build CSR ──▶ sign with CA ──▶ device cert   │
                        └─────────────────────────────────────────────┘
  provision device over pouch with (device cert, device key [, CA cert])
```

Golioth identifies the device by the **client cert CN** — set the device cert
`CN` to the desired Golioth device ID/name.

## The public API (authoritative)

From `https://api.golioth.io/swagger.json`:

- **Endpoints**
  - `POST   /v1/projects/{projectId}/certificates` — register a CA
  - `GET    /v1/projects/{projectId}/certificates` — list
  - `GET    /v1/projects/{projectId}/certificates/{certificateId}` — fetch
  - `DELETE /v1/projects/{projectId}/certificates/{certificateId}` — clean up temp CAs
- **Auth** (`securityDefinitions`): send **one** of
  - `x-api-key: <PROJECT_API_KEY>`  (project API key — simplest for clients), or
  - `Authorization: Bearer <JWT>`   (what the console uses)
- **Request body** (`goliothCertificatesCreateBody`):

  | field      | type            | notes |
  |------------|-----------------|-------|
  | `certFile` | string (base64) | base64 of the CA cert **PEM** |
  | `certType` | string          | `"root"` for the console demo flow |
  | `demo`     | boolean         | `true` = temporary/test CA |

- **Response** (`goliothCreateCertificateResponse` → `goliothCertificate`):
  `{ data: { id, projectId, enabled, certType, certificateContent{…}, createdAt, demo } }`.
  Keep `data.id` — it is the `certificateId` for later `DELETE`.

> **camelCase vs snake_case:** the swagger schema uses `certFile`/`certType`; the
> live console call used `cert_file`/`cert_type`. Golioth's gRPC-gateway accepts
> both. Prefer the **swagger camelCase** form in our clients.

## Reference implementation (openssl + curl)

Use this to validate the flow by hand before wiring it into a client.

```bash
# (A) self-signed ECDSA P-256 root CA, 28-day validity
openssl ecparam -name prime256v1 -genkey -noout -out ca_key.pem
openssl req -x509 -new -key ca_key.pem -days 28 -out ca_cert.pem \
  -subj "/C=US/CN=pouch-demo-CA" \
  -addext "keyUsage=critical,keyCertSign" \
  -addext "basicConstraints=critical,CA:TRUE"

# register the CA as a demo cert
curl -s https://api.golioth.io/v1/projects/$PROJECT_ID/certificates \
  -H "x-api-key: $GOLIOTH_API_KEY" -H "Content-Type: application/json" \
  -d "{\"certType\":\"root\",\"certFile\":\"$(base64 -i ca_cert.pem)\",\"demo\":true}"

# (B) per-device key + cert signed by the CA (CN = Golioth device id)
DEVICE_ID=my-test-device
openssl ecparam -name prime256v1 -genkey -noout -out device_key.pem
openssl req -new -key device_key.pem -out device.csr -subj "/C=US/O=$PROJECT_ID/CN=$DEVICE_ID"
openssl x509 -req -in device.csr -CA ca_cert.pem -CAkey ca_key.pem \
  -CAcreateserial -days 28 -out device_cert.pem

# provision the blank device over pouch with the device credentials
pouchprov provision --pop $POP --cert device_cert.pem --key device_key.pem
```

`base64` flag note: macOS uses `base64 -i file`; GNU/Linux uses `base64 -w0 file`.

## Client implementation plan

Goal: a client subcommand/API that, given a Golioth API key + project (+ device
id), produces `(device_cert, device_key)` ready to feed the existing
`provision --cert --key` / `provisionCredentials(...)` path. The CA is reused
across devices, so cache it.

### Shared design

- **Inputs:** `apiKey`, `projectId`, `deviceId`, optional `caName`, `validityDays`
  (default 28), optional path to a cached CA keypair.
- **CA reuse:** if a cached demo CA keypair exists locally and its registration
  is still present in Golioth (`GET .../certificates`), reuse it; otherwise
  generate a new CA and `POST` it. Avoids creating a new demo CA per device.
- **Output:** device cert PEM + device key PEM (and the CA cert PEM for `--ca`).
- **Cleanup:** offer a "revoke/cleanup" action that `DELETE`s demo CAs by id.
- **Secrets:** never hardcode the API key; read from env
  (`GOLIOTH_API_KEY`, `GOLIOTH_PROJECT_ID`) or a config file. Do not log it.

### Python CLI (`cli/`) — implemented

- [`cli/src/pouchprov/golioth.py`](../cli/src/pouchprov/golioth.py):
  `GoliothCertProvider(api_key)` (stdlib `urllib`, header `x-api-key`) with
  `project_id()` (discovered from the key, cached), `mint_device_credentials
  (device_id, validity_days)`, `register_ca(ca_cert_pem)`, `list_cert_ids()`,
  and `delete_cert(cert_id)` — a line-for-line port of the mobile providers.
  The CA/device certs come from `pouchlink/cert.py` (`generate_ca`,
  `sign_device_cert`).
- The demo CA persists in `~/.pouchprov/golioth-demo-ca.{crt,key}.pem`
  (`--state-dir` to override) and is reused across devices.
- Mint-then-provision in one shot (CN = the session device id):
  ```
  pouchprov provision --pop … --golioth-api-key $GOLIOTH_API_KEY [--ssid …]
  pouchprov provision --pop … --self-signed          # no Golioth, local only
  ```
  or mint offline (and optionally register the demo CA):
  ```
  pouchprov mint my-device --out certs/ [--golioth-api-key $GOLIOTH_API_KEY]
  pouchprov provision --cert certs/my-device.crt.pem --key certs/my-device.key.pem
  ```
- `tests/test_golioth.py` fakes the HTTP layer (no live calls in CI).

### Mobile

**Android (Kotlin, `android/`)**
- Add to `pouchprov-core` (transport-agnostic): a `GoliothCertProvider` that
  builds the CA/device certs and calls the REST API. Use Bouncy Castle for
  X.509/CSR generation and `OkHttp` for the API (both common Android deps),
  or Conscrypt if already present.
- Public API mirroring the CLI:
  `GoliothCertProvider(apiKey, projectId).mintDeviceCredentials(deviceId): DeviceCredentials`
  returning `certificate`/`privateKey` bytes to pass straight into the existing
  `ProvisionRequest(certificate = …, privateKey = …)`.
- Keep the API key out of source; take it as a runtime parameter / secure store.

**iOS (Swift, `ios/`)** — implemented in the reference app
([`GoliothCertProvider.swift`](../ios/PouchProvApp/Sources/GoliothCertProvider.swift))
- Same shape as Android: `GoliothCertProvider(apiKey:).mintDeviceCredentials(deviceId:validityDays:)`
  on `URLSession`, with the P-256 CA + device certs generated by the SDK's
  `DeviceCert` (swift-crypto + swift-certificates — CA-sign rather than CSR,
  matching the Android implementation), feeding `provisionCredentials(cert:key:ca:)`.

## Caveats / open questions

- **Validity ~28 days** — demo/temp only; not for production fleets.
- **`certType` values** — the console/demo flow uses `"root"`; other values may
  exist but are undocumented in swagger (string type only). Stick to `"root"`.
- **Auto-provision semantics** — confirm a demo CA is sufficient for a device to
  self-register on first connect vs. needing an explicit device create; verify
  against a live project during implementation.
- **Rate/limits** — demo CAs may be capped per project; the `delete` path lets us
  garbage-collect between test runs.
- **CN convention** — verify Golioth maps client-cert CN → device id/name as
  assumed above before locking the CLI's `--golioth-device` semantics.

## References

- Console capture: `console.golioth.io.har` (repo root)
- API spec: <https://api.golioth.io/swagger.json>
- Client parity + provisioning entry points: `docs/clients.md`
