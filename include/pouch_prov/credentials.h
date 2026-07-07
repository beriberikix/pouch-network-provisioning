/*
 * Copyright (c) 2026 Jonathan Beri
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>

/**
 * @file credentials.h
 * @brief Access to cloud credentials bootstrapped over provisioning.
 *
 * After a successful provisioning session the application reads the stored
 * DER credentials and hands them to its cloud client (e.g. the Golioth
 * Firmware SDK's PKI credential). The returned buffers are backed by the
 * settings subsystem and remain valid until overwritten or deleted.
 */

enum pouch_prov_cred_kind {
	POUCH_PROV_CRED_DEVICE_CERT = 0,
	POUCH_PROV_CRED_PRIVATE_KEY = 1,
	POUCH_PROV_CRED_CA_CERT = 2,
};

/** True if a credential of this kind is stored. */
bool pouch_prov_cred_present(enum pouch_prov_cred_kind kind);

/**
 * Get a pointer to a stored DER credential.
 *
 * @param kind    Which credential.
 * @param out_len Set to the DER length on success.
 * @return Pointer to the DER bytes (valid until overwritten/deleted), or
 *         NULL if not present.
 */
const uint8_t *pouch_prov_cred_get(enum pouch_prov_cred_kind kind, size_t *out_len);

/** Delete all stored cloud credentials. */
int pouch_prov_cred_delete_all(void);
