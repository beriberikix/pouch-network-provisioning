# Copyright (c) 2026 Jonathan Beri
# SPDX-License-Identifier: Apache-2.0
cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(pouch_prov_basic)

target_sources(app PRIVATE src/main.c)

# Expose mbedtls_user_config.h (CONFIG_MBEDTLS_USER_CONFIG_FILE) on the
# include path for the saead build overlay.
zephyr_include_directories(${CMAKE_CURRENT_SOURCE_DIR})
