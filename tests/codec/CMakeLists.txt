# Copyright (c) 2026 Jonathan Beri
# SPDX-License-Identifier: Apache-2.0
cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(prov_codec_test)

# Build the generated codec directly (no CONFIG_POUCH_PROV dependency chain
# so this test runs standalone on native_sim with just ZCBOR).
target_sources(app PRIVATE
  src/main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../src/codec/prov_encode.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../src/codec/prov_decode.c
)
target_include_directories(app PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../../src/codec/include
)
