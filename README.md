# pouch-network-provisioning

Wi-Fi provisioning for blank Zephyr devices over BLE, built on the
[pouch](https://github.com/golioth/pouch) protocol — plus cloud credential
bootstrap for zero-touch [Golioth](https://golioth.io) enrollment.

A totally unprovisioned device (no Wi-Fi credentials, no cloud identity) is
provisioned in one CLI invocation:

```console
$ pouchprov provision --pop abcd1234 --ssid MyNet --password hunter22 \
      --cert device.crt.pem --key device.key.pem
cloud credentials stored
connected: MyNet (192.168.1.7)
```

The client terminates pouch's end-to-end encrypted session locally (pouch
*server* role), authorizes with a proof-of-possession challenge, pushes the
Golioth certificate and Wi-Fi credentials, and the device connects to
Golioth and enrolls via certificate auth. On the next boot the device reuses
the stored credentials and skips provisioning.

> **Status: early development.** The protocol is versioned and pinned by
> golden vectors, but breaking changes may land before 1.0.

## How it works

```
┌────────────┐   BLE GATT (pouch saead, E2E encrypted)   ┌──────────────┐
│  Provisioning │◀────────────────────────────────────────▶│   Device      │
│  client (CLI) │   .prov/{ver,auth,config,scan,cred,ctrl}  │ (pouch server │
│  = pouch      │                                           │  terminates   │
│  "server"     │                                           │  the session) │
└────────────┘                                           └──────┬───────┘
                                                                 │ cert auth
                                                                 ▼
                                                          ┌──────────────┐
                                                          │   Golioth     │
                                                          └──────────────┘
```

Provisioning messages are pouch entries on reserved `.prov/*` paths. The
device generates an ephemeral self-signed identity on first boot; the client
presents its own self-signed certificate; a mutual proof-of-possession
challenge inside the encrypted channel authorizes the session. See
[docs/protocol.md](docs/protocol.md) for the wire contract and
[cddl/prov.cddl](cddl/prov.cddl) for the schema.

## Layout

| Path | What |
|---|---|
| `cddl/`, `src/codec/` | Protocol schema and the zcbor-generated device codec (checked in) |
| `include/pouch_prov/`, `src/` | Device library: manager, dispatch, handlers, identity, cred store |
| `sim/wifi/` | Fake Wi-Fi driver for `native_sim` tests |
| `samples/basic/` | Minimal provisioning target (transport bring-up) |
| `samples/golioth_bootstrap/` | Full zero-touch onboarding sample |
| `cli/` | `pouch-prov` Python package (`pouchprov`) |
| `tests/` | Device `ztest` suites (run under twister/`native_sim`) |
| `docs/` | Protocol spec, upstream-pouch notes |

## Using the device library

Add this repo and pouch to your west manifest, then in your app:

```c
#include <pouch_prov/manager.h>

const struct pouch_prov_config cfg = {
    .pop = "abcd1234",              /* per-device secret (label/QR) */
    .device_id = "my-device",
    .wifi_conn_attempts = 3,
    .event_cb = my_event_handler,
};
pouch_prov_mgr_init(&cfg);
pouch_prov_mgr_start();
pouch_prov_mgr_wait(K_FOREVER);
/* creds are now in the settings store; feed them to your cloud client */
```

Build the encrypted configuration with `CONFIG_POUCH_ENCRYPTION_SAEAD=y`,
`CONFIG_POUCH_PROV=y` and the `POUCH_PROV_*` options you need
(`WIFI`, `CRED`, `IDENTITY`, `AUTH`). See
[`samples/golioth_bootstrap/prj.conf`](samples/golioth_bootstrap/prj.conf)
for a complete example, including the small `mbedtls_user_config.h` needed
for on-device certificate creation.

Wi-Fi (`POUCH_PROV_WIFI`) and cloud-credential bootstrap (`POUCH_PROV_CRED`)
are independent features, so the library serves all three device classes:

| Device | Provisions | Config |
|---|---|---|
| Wi-Fi (+ BLE) | certs + Wi-Fi | `POUCH_PROV_WIFI=y`, `POUCH_PROV_CRED=y` |
| BLE-only | certs only | `POUCH_PROV_WIFI=n`, `POUCH_PROV_CRED=y` |

A BLE-only device is provisioned with certificates alone — omit `--ssid`:

```console
$ pouchprov provision --pop abcd1234 --cert device.crt.pem --key device.key.pem
```

See [`samples/cred_only/`](samples/cred_only/) for a minimal BLE-only target.

## The CLI

```console
$ cd cli && uv pip install -e ".[dev]"
$ pouchprov discover                 # find provisioning-mode devices
$ pouchprov wifi-scan --pop abcd1234 # networks visible to the device
$ pouchprov provision --pop abcd1234 --ssid MyNet --password hunter22 \
      --cert device.crt.pem --key device.key.pem
```

Certificates/keys may be PEM or DER. The CLI is the reference client; the
same protocol is the contract for future Android/iOS SDKs.

## Development & testing

Device tests run under Zephyr's twister on `native_sim` (Linux/CI); the
Python CLI is tested with pytest.

```console
# CLI
cd cli && pytest && ruff check src tests

# Device (in a west workspace with zephyr + pouch)
west twister -T tests -p native_sim
```

CI ([.github/workflows/ci.yml](.github/workflows/ci.yml)) runs the twister
ztests, a sample build matrix, the CLI checks, and a generated-code
freshness check.

**Note:** the live encrypted BLE round-trip is validated from a phone or
Linux host — macOS CoreBluetooth cannot complete LE Secure-Connections
pairing with the ESP32-S3 (details in the protocol doc / dev notes).

## License

Apache-2.0. Portions of the device handlers and the fake-Wi-Fi driver are
adapted from
[network-provisioning-zephyr](https://github.com/beriberikix/network-provisioning-zephyr)
(Apache-2.0), itself derived from ESP-IDF's unified provisioning.
