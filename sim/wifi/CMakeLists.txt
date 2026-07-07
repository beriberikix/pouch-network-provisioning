# Copyright (c) 2026 Jonathan Beri
# SPDX-License-Identifier: Apache-2.0
if(CONFIG_POUCH_PROV_FAKE_WIFI)
  zephyr_library_named(pouch_prov_fake_wifi)
  zephyr_library_sources(fake_wifi.c)
  zephyr_include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../include)
endif()
