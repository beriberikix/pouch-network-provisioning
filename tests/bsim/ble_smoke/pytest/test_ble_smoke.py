# Copyright (c) 2026 Jonathan Beri
# SPDX-License-Identifier: Apache-2.0

import re


def test_ble_provisioning_smoke(dut):
    # Log lines from all simulated devices (central + peripheral + phy)
    # interleave on one stream, and relative ordering between devices is
    # not guaranteed. Read until the central's final marker, then assert
    # the other stages over the collected output. The central's own
    # markers are internally ordered (single process), so PASS implies
    # found -> connected -> secured -> discovered -> subscribed.
    lines = dut.readlines_until(regex="PROV_BSIM: PASS", timeout=60)
    output = "\n".join(lines)

    # Peripheral advertised with the provisioning name prefix, and the
    # central validated the 0xFC49 service data + provisioning flag.
    assert re.search(r"Advertising as PVN-", output)
    assert re.search(r"PROV_BSIM: found PVN-", output)
    assert re.search(r"PROV_BSIM: connected", output)
    # Just Works LESC pairing on both sides (peripheral line is from
    # src/adv.c security_changed).
    assert re.search(r"PROV_BSIM: security L[24]", output)
    assert re.search(r"Security: level [24] \(err 0\)", output)
    # GATT service + characteristic discovery and uplink CCC subscribe.
    assert re.search(r"PROV_BSIM: service discovered", output)
    assert re.search(r"PROV_BSIM: subscribed", output)
