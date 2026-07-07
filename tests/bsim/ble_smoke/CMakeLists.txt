# Copyright (c) 2026 Jonathan Beri
# SPDX-License-Identifier: Apache-2.0
cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(pouch_prov_bsim_ble_smoke)

target_sources(app PRIVATE src/main.c)

# Golden vectors (frame_single_entry et al.), generated from
# tests/vectors/*.json and kept fresh by the codegen CI job.
target_include_directories(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../codec/src)
