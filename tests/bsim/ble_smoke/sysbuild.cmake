# Copyright (c) 2026 Jonathan Beri
# SPDX-License-Identifier: Apache-2.0
#
# BabbleSim topology (pattern from pouch examples/zephyr/gateway):
# the default image is the central tester; add the 2G4 phy and the
# provisioning peripheral as extra sysbuild images. `west flash` on the
# sysbuild dir launches every domain via pouch's bsim runners, with the
# central last (foreground) so the flash process blocks on it.

if(BOARD MATCHES "bsim")
  set_config_string(${DEFAULT_IMAGE} CONFIG_BOOT_BANNER_STRING "Booting ${DEFAULT_IMAGE}")

  ExternalZephyrProject_Add(
    APPLICATION bsim_2G4_phy
    SOURCE_DIR ${ZEPHYR_POUCH_MODULE_DIR}/bsim_bin
    BOARD bsim_2G4_phy
  )
  sysbuild_add_dependencies(FLASH ${DEFAULT_IMAGE} bsim_2G4_phy)

  ExternalZephyrProject_Add(
    APPLICATION peripheral
    SOURCE_DIR ${APP_DIR}/../peripheral
  )
  set_config_string(peripheral CONFIG_BOOT_BANNER_STRING "Booting peripheral")
  sysbuild_add_dependencies(FLASH ${DEFAULT_IMAGE} peripheral)
endif()
