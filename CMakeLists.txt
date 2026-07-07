# Copyright (c) 2026 Jonathan Beri
# SPDX-License-Identifier: Apache-2.0

if(CONFIG_POUCH_PROV)

zephyr_library_named(pouch_prov)

zephyr_include_directories(include)

zephyr_library_sources(
  src/codec/prov_encode.c
  src/codec/prov_decode.c
  src/manager.c
  src/adv.c
  src/dispatch.c
  src/rpc.c
  src/handlers/version.c
)
zephyr_library_include_directories(src src/codec/include)

# M3+: src/identity.c src/handlers/auth.c
# M4:  src/handlers/wifi_config.c src/handlers/wifi_scan.c src/handlers/ctrl.c
# M5:  src/cred_store.c src/handlers/cred.c

endif()
