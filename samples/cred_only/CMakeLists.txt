# Copyright (c) 2026 Jonathan Beri
# SPDX-License-Identifier: Apache-2.0
cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(cred_only)

target_sources(app PRIVATE src/main.c)

# mbedtls_user_config.h enables the x509 create/parse + base64 that pouch's
# saead build needs (see samples/basic for the rationale).
zephyr_include_directories(${CMAKE_CURRENT_SOURCE_DIR})
