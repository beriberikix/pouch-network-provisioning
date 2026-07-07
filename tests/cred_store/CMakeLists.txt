# Copyright (c) 2026 Jonathan Beri
# SPDX-License-Identifier: Apache-2.0
cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(pouch_prov_cred_store_test)

set(ROOT ${CMAKE_CURRENT_SOURCE_DIR}/../..)

target_sources(app PRIVATE src/main.c ${ROOT}/src/cred_store.c)
target_include_directories(app PRIVATE
  ${ROOT}/src ${ROOT}/src/codec/include ${ROOT}/include ${CMAKE_CURRENT_SOURCE_DIR}
)
target_compile_definitions(app PRIVATE
  CONFIG_POUCH_PROV_LOG_LEVEL=3
  CONFIG_POUCH_PROV_CRED=1
)
