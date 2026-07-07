# pouch-prov

Network provisioning CLI for devices speaking the [pouch](https://github.com/golioth/pouch)
protocol. Provisions Wi-Fi credentials and bootstraps cloud (Golioth) device
certificates over BLE, terminating the encrypted pouch session locally.

```
pouchprov discover
pouchprov provision --pop abcd1234 --ssid MyNet --password hunter22 \
    --cert device.crt.pem --key device.key.pem
```

Part of [pouch-network-provisioning](https://github.com/beriberikix/pouch-network-provisioning);
see `docs/protocol.md` in the repo root for the wire protocol.
