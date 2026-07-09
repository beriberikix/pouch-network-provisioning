# pouch-prov

Network provisioning CLI for devices speaking the [pouch](https://github.com/golioth/pouch)
protocol. Provisions Wi-Fi credentials and/or bootstraps cloud (Golioth) device
certificates over BLE, terminating the encrypted pouch session locally.

## Install

```console
$ cd cli && uv pip install -e ".[dev]"     # or: pip install -e ".[dev]"
$ pytest && ruff check src tests            # unit tests, no hardware
```

Python ≥ 3.10; BLE is via [bleak](https://github.com/hbldh/bleak) (CoreBluetooth
on macOS, BlueZ on Linux). Runs on macOS or Linux — the macOS CLI pairs cleanly
with the nRF52840 DK.

## Usage

```
pouchprov discover [--all]          # scan (--all includes non-provisioning pouch devices)
pouchprov version                   # device protocol/caps
pouchprov wifi-scan --pop …         # device-side Wi-Fi scan (named security types)

# Wi-Fi device: certificates + Wi-Fi
pouchprov provision --pop abcd1234 --ssid MyNet --password hunter22 \
    --cert device.crt.pem --key device.key.pem

# BLE-only device: certificates only (omit --ssid)
pouchprov provision --pop abcd1234 --cert device.crt.pem --key device.key.pem

# Or mint credentials on the fly (CN = device id):
pouchprov provision --pop abcd1234 --self-signed [--ssid …]
pouchprov provision --pop abcd1234 --golioth-api-key $GOLIOTH_API_KEY

pouchprov mint my-device --out certs/   # offline minting (persistent demo CA)
pouchprov cred-status --pop …           # per-kind stored byte counts
pouchprov reset --pop …                 # reset the device's Wi-Fi state
pouchprov reprovision --pop …           # wipe ALL stored credentials
```

Every command autodetects the device's encryption mode: on a saead firmware
build it runs the TOFU cert exchange and the whole session is end-to-end
encrypted (`session: saead (ChaCha20-Poly1305)`); on a plaintext build it
prints `session: plaintext`. Client state (the TOFU server identity and the
demo CA used by `mint`) persists in `~/.pouchprov/` (`--state-dir` to
override).

## On-device end-to-end

Build and flash a provisioning device following
[`docs/hardware-testing.md`](../docs/hardware-testing.md), then, with it
advertising, run the commands above (`abcd1234` is the samples' default PoP).
`samples/cred_only` is a BLE-only saead device — omit `--ssid` and mint a cert:

```console
$ pouchprov provision --pop abcd1234 --self-signed
session: saead (ChaCha20-Poly1305)
minted self-signed credentials (CN=…, valid 28 days)
cloud credentials stored (DEVICE_CERT=293B, PRIVATE_KEY=138B)
```

The device console should report `Session authorized` then
`cloud device certificate stored`. If a reconnect fails with `CBError 14
"Peer removed pairing information"` (after re-flashing the device with
`--erase`), toggle macOS Bluetooth off/on to clear the stale bond — see the
hardware-testing guide.

Part of [pouch-network-provisioning](https://github.com/beriberikix/pouch-network-provisioning);
see `docs/protocol.md` in the repo root for the wire protocol and
`docs/clients.md` for the three-client parity matrix.
