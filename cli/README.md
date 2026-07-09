# pouch-prov

Network provisioning CLI for devices speaking the [pouch](https://github.com/golioth/pouch)
protocol. Provisions Wi-Fi credentials and/or bootstraps cloud (Golioth) device
certificates over BLE, terminating the encrypted pouch session locally.

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

Part of [pouch-network-provisioning](https://github.com/beriberikix/pouch-network-provisioning);
see `docs/protocol.md` in the repo root for the wire protocol and
`docs/clients.md` for the three-client parity matrix.
