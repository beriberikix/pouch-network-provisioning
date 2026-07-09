<!-- Copyright (c) 2026 Jonathan Beri; SPDX-License-Identifier: Apache-2.0 -->
# Hardware testing — building a device to provision

Every client's on-device end-to-end test needs a **provisioning device**: a
Zephyr board running one of the [`samples/`](../samples/) targets, advertising
for provisioning. This guide builds, flashes, and monitors one, then hands off
to the per-client instructions. Unit tests (`pytest` / `gradlew test` /
`swift test`) need no hardware — see each client's README.

The nRF52840 DK is the reference peer (its software Bluetooth controller
completes LE Secure-Connections pairing with every client, including macOS
CoreBluetooth). The ESP32-S3 also works except for bonded reconnect on the
pinned Zephyr — see the note in [`west.yml`](../west.yml).

## 1. West workspace

```console
$ west init -m https://github.com/beriberikix/pouch-network-provisioning pouch-ws
$ cd pouch-ws && west update
$ west zephyr-export
$ pip3 install -r zephyr/scripts/requirements.txt
$ pip3 install -r modules/lib/pouch/requirements.txt   # zcbor — required by the build
```

`zcbor` must be on `PATH` for the build (the device codec is generated from
`cddl/prov.cddl`); the second `pip install` provides it. Install a Zephyr
toolchain / SDK as per the [Zephyr getting-started
guide](https://docs.zephyrproject.org/latest/develop/getting_started/).

## 2. Build a sample

Which sample decides the device class and framing the client autodetects:

| Sample | Framing | Provisions | Use for |
|---|---|---|---|
| `samples/cred_only` | **saead (encrypted)** | credentials only | the default encrypted BLE-only demo — what the mobile apps drive |
| `samples/basic` | plaintext | transport bring-up | the simplest plaintext round-trip |
| `samples/basic` + `saead.conf` | saead | transport bring-up | encrypted `.prov/ver` without credentials |
| `samples/golioth_bootstrap` | saead | certs + Wi-Fi | full zero-touch onboarding |

For the encrypted credential flow on the nRF52840 DK:

```console
$ west build -p -b nrf52840dk/nrf52840 pouch-network-provisioning/samples/cred_only
```

Per-board tuning is applied automatically from
`samples/<sample>/boards/nrf52840dk_nrf52840.conf` (no `EXTRA_CONF_FILE`
needed) — for the nRF that bumps the heap and the Bluetooth RX-workqueue stack,
which the on-device software P-256 (LESC pairing **and** the saead session-key
ECDH) overflows at the defaults.

> **nRF + saead caveat (Zephyr v4.3.0).** The software controller computes the
> pairing DHKey on its RX-priority thread, whose stack
> (`CONFIG_BT_CTLR_RX_PRIO_STACK_SIZE`) is *promptless* upstream and cannot be
> raised from an overlay. On v4.3.0 it overflows during pairing. Until the
> Zephyr pin moves to v4.4.1 (tracked with the ESP32-S3 controller work in
> [`west.yml`](../west.yml)), raise its default in-tree:
> ```console
> $ sed -i.bak 's/default 448$/default 4096/' \
>       zephyr/subsys/bluetooth/controller/Kconfig.ll_sw_split
> ```
> Plaintext `samples/basic` does not need this (no on-device P-256).

The default PoP secret in the samples is `abcd1234` (`CONFIG_SAMPLE_POP`).

## 3. Flash & monitor

```console
$ west flash                              # nRF52840 DK uses the jlink runner
$ west flash --erase                      # also wipe stored creds + bonds (see below)
```

Read the device console on the board's USB-CDC serial port (the nRF DK exposes
it via the on-board J-Link) at **115200 8N1**:

```console
$ python3 -m serial.tools.miniterm /dev/tty.usbmodem<...> 115200
```

Use a real serial reader (`miniterm`/`screen`); piping `cat` over the CDC
garbles the stream. A successful run logs, on the device side:

```
pouch_prov_adv: Security: level 2 (err 0)      ← link paired + encrypted
pouch_prov_auth: Session authorized            ← PoP auth over the saead session
main: Provisioning complete
main: Provisioned: cloud device certificate stored (293 bytes)
```

## 4. Re-testing a device

A device that has stored credentials logs `credentials present` on boot and
**skips provisioning** (it no longer advertises). To return it to a blank,
advertising state, re-flash with `--erase` (this also clears its BLE bonds).

**After a device erase, forget/re-pair on the client too**, or the client's
stale bond desyncs from the now-bondless device:

- **macOS CLI:** connects fail with `CBError 14 "Peer removed pairing
  information"`. Toggle Bluetooth off/on (Control Center) to clear the stale
  key, or forget the device in **System Settings → Bluetooth**.
- **Android / iOS:** forget the device in the OS Bluetooth settings before the
  next connect.

## 5. Provision from a client

With the device advertising, drive any client — they interoperate against the
same board:

- **CLI:** [`cli/README.md`](../cli/README.md) — runs from macOS or Linux.
- **Android app:** [`android/README.md`](../android/README.md).
- **iOS app:** [`ios/README.md`](../ios/README.md).

> **Mobile apps: keep the screen awake during provisioning.** iOS and Android
> suspend BLE when the phone locks, which stalls the final session-end and
> surfaces as a timeout in the app even though the credential was already
> stored. Set Auto-Lock / screen timeout high for the test.
