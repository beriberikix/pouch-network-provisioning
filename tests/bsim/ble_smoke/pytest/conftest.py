# Copyright (c) 2026 Jonathan Beri
# SPDX-License-Identifier: Apache-2.0
#
# Override twister_harness's dut fixture to launch the simulation with
# `west flash -d <build_dir>`: pouch's bsim runners start every sysbuild
# domain (central + peripheral + bs_2G4_phy) with all output interleaved
# on the flash process's stdout, which twister_harness captures.
# (Pattern from pouch examples/zephyr/gateway/pytest/conftest.py, minus
# the Golioth cloud fixtures.)

import pytest
from twister_harness.device.device_adapter import DeviceAdapter


def determine_scope(fixture_name, config):
    if dut_scope := config.getoption("--dut-scope", None):
        return dut_scope
    return "function"


@pytest.fixture(scope=determine_scope)
def dut(request, device_object: DeviceAdapter):
    """Launched simulation (all BabbleSim domains)."""
    device_object.initialize_log_files(request.node.name)
    try:
        device_object.command = [
            device_object.west,
            "flash",
            "-d",
            str(device_object.device_config.build_dir),
        ]
        device_object.process_kwargs["cwd"] = str(device_object.device_config.build_dir)
        device_object.launch()
        yield device_object
    finally:
        device_object.close()
