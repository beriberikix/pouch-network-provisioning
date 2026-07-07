# Copyright (c) 2026 Jonathan Beri
# SPDX-License-Identifier: Apache-2.0

# Log lines from all simulated devices interleave on one stream. Lines
# quoted below come from the central tester (PROV_BSIM markers) and the
# peripheral (src/adv.c logs); ordering between the two devices is only
# asserted where the protocol guarantees it.


def test_ble_provisioning_smoke(dut):
    # Peripheral advertises with the provisioning name prefix.
    dut.readlines_until(regex="Advertising as PVN-", timeout=60)
    # Central validated the service data (0xFC49 + provisioning flag) and
    # the name prefix, then connected.
    dut.readlines_until(regex="PROV_BSIM: connected", timeout=60)
    # Just Works LESC pairing completed (central side...)
    dut.readlines_until(regex="PROV_BSIM: security L[24]", timeout=60)
    # ...and peripheral side (src/adv.c security_changed).
    dut.readlines_until(regex="Security: level [24]", timeout=60)
    # Service + characteristic discovery and uplink CCC subscribe passed.
    dut.readlines_until(regex="PROV_BSIM: PASS", timeout=60)
