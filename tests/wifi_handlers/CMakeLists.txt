# Copyright (c) 2026 Jonathan Beri
# SPDX-License-Identifier: Apache-2.0
cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(pouch_prov_wifi_handlers_test)

set(ROOT ${CMAKE_CURRENT_SOURCE_DIR}/../..)

target_sources(app PRIVATE
  src/main.c
  ${ROOT}/src/handlers/wifi_config.c
  ${ROOT}/src/handlers/wifi_scan.c
  ${ROOT}/src/handlers/ctrl.c
  ${ROOT}/src/codec/prov_encode.c
  ${ROOT}/src/codec/prov_decode.c
)
target_include_directories(app PRIVATE
  ${ROOT}/src ${ROOT}/src/codec/include ${ROOT}/include
)
# The handlers reference these POUCH_PROV Kconfig symbols; the full module
# (and its BLE dependency) is not enabled for this focused unit test, so
# provide them directly.
target_compile_definitions(app PRIVATE
  CONFIG_POUCH_PROV_LOG_LEVEL=3
  CONFIG_POUCH_PROV_SCAN_CACHE=16
  CONFIG_POUCH_PROV_WIFI=1
)
