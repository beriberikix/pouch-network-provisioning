# pouch-network-provisioning

Wi-Fi provisioning for blank Zephyr devices over BLE, built on the
[pouch](https://github.com/golioth/pouch) protocol — plus cloud credential
bootstrap for zero-touch [Golioth](https://golioth.io) enrollment.

A totally unprovisioned device (no Wi-Fi credentials, no cloud identity) is
provisioned in one CLI invocation:

```
pouchprov provision --pop abcd1234 --ssid MyNet --password hunter22 \
    --cert device.crt.pem --key device.key.pem
```

The provisioning client terminates pouch's end-to-end encrypted session
locally (pouch server role), authorizes with a proof-of-possession
challenge, pushes the cloud certificate and Wi-Fi credentials, and the
device connects to Golioth and enrolls via certificate auth.

**Status: early development; breaking changes at any time.**

- Protocol: [docs/protocol.md](docs/protocol.md) · schema: [cddl/prov.cddl](cddl/prov.cddl)
- Device library: Zephyr module (this repo) on top of stock pouch
- Client: [cli/](cli/) Python package (`pouch-prov`)
- Design heritage: [network-provisioning-zephyr](https://github.com/beriberikix/network-provisioning-zephyr)
  / ESP-IDF unified provisioning, re-based onto pouch

## License

Apache-2.0
