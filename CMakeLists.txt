# Copyright (c) 2026 Jonathan Beri
# SPDX-License-Identifier: Apache-2.0

if(CONFIG_POUCH_PROV)

zephyr_library_named(pouch_prov)

zephyr_include_directories(include)

zephyr_library_sources(
  src/codec/prov_encode.c
  src/codec/prov_decode.c
)
zephyr_library_include_directories(src/codec/include)

# Core sources land in M2+:
zephyr_library_sources_ifdef(CONFIG_POUCH_PROV_WIFI
  # src/handlers/wifi_config.c src/handlers/wifi_scan.c src/handlers/ctrl.c
)

endif()
