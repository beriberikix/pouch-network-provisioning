/*
 * Copyright (c) 2026 Jonathan Beri
 * SPDX-License-Identifier: Apache-2.0
 *
 * Cloud credential store: DER blobs (device cert, private key, CA cert)
 * staged during chunked writes and persisted atomically on finalize via
 * the settings subsystem. The persisted blobs are loaded into static
 * buffers on boot and handed to the application for its cloud client.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/settings/settings.h>

#include <mbedtls/x509_crt.h>

#include <pouch_prov/credentials.h>

#include "pouch_prov_internal.h"

LOG_MODULE_REGISTER(pouch_prov_cred_store, CONFIG_POUCH_PROV_LOG_LEVEL);

#define DEVICE_CERT_MAX 2048
#define PRIVATE_KEY_MAX 512
#define CA_CERT_MAX     2048

struct blob {
	uint8_t *buf;
	size_t cap;
	size_t len;      /* persisted length */
	size_t staged;   /* bytes accumulated during the current write */
	size_t expected; /* total announced by the client */
};

static uint8_t device_cert[DEVICE_CERT_MAX];
static uint8_t private_key[PRIVATE_KEY_MAX];
static uint8_t ca_cert[CA_CERT_MAX];

static struct blob blobs[] = {
	[POUCH_PROV_CRED_DEVICE_CERT] = { .buf = device_cert, .cap = sizeof(device_cert) },
	[POUCH_PROV_CRED_PRIVATE_KEY] = { .buf = private_key, .cap = sizeof(private_key) },
	[POUCH_PROV_CRED_CA_CERT] = { .buf = ca_cert, .cap = sizeof(ca_cert) },
};

static const char *const setting_key[] = {
	[POUCH_PROV_CRED_DEVICE_CERT] = "pnp/cred/cert",
	[POUCH_PROV_CRED_PRIVATE_KEY] = "pnp/cred/key",
	[POUCH_PROV_CRED_CA_CERT] = "pnp/cred/ca",
};

static bool kind_valid(int kind)
{
	return kind >= 0 && kind < (int)ARRAY_SIZE(blobs);
}

/* --- settings glue -------------------------------------------------------- */

static int cred_set(const char *name, size_t len, settings_read_cb read_cb, void *cb_arg)
{
	for (int k = 0; k < (int)ARRAY_SIZE(blobs); k++) {
		const char *leaf = setting_key[k] + strlen("pnp/cred/");

		if (strcmp(name, leaf) != 0) {
			continue;
		}
		if (len > blobs[k].cap) {
			return -EINVAL;
		}
		ssize_t rc = read_cb(cb_arg, blobs[k].buf, blobs[k].cap);

		if (rc < 0) {
			return rc;
		}
		blobs[k].len = rc;
		return 0;
	}
	return -ENOENT;
}

SETTINGS_STATIC_HANDLER_DEFINE(pouch_prov_cred, "pnp/cred", NULL, cred_set, NULL, NULL);

/* --- write / finalize (called by the cred handler) ------------------------ */

int pouch_prov_cred_stage(int kind, uint32_t offset, uint32_t total, const uint8_t *data,
			  size_t data_len)
{
	if (!kind_valid(kind)) {
		return -EINVAL;
	}
	struct blob *b = &blobs[kind];

	if (total > b->cap) {
		return -EMSGSIZE;
	}
	if (offset == 0) {
		b->staged = 0;
		b->expected = total;
	}
	/* Chunks must arrive in order and not exceed the announced total. */
	if (offset != b->staged || b->staged + data_len > b->expected) {
		return -EINVAL;
	}
	memcpy(b->buf + b->staged, data, data_len);
	b->staged += data_len;
	return (int)b->staged;
}

int pouch_prov_cred_finalize(void)
{
	struct blob *cert = &blobs[POUCH_PROV_CRED_DEVICE_CERT];
	struct blob *key = &blobs[POUCH_PROV_CRED_PRIVATE_KEY];

	/* A usable bootstrap needs at least a device certificate and key,
	 * each fully received. */
	if (cert->staged == 0 || cert->staged != cert->expected || key->staged == 0 ||
	    key->staged != key->expected) {
		return -EINVAL;
	}

	/* Validate the device certificate parses as X.509. */
	mbedtls_x509_crt parsed;

	mbedtls_x509_crt_init(&parsed);
	int ret = mbedtls_x509_crt_parse(&parsed, cert->buf, cert->staged);

	mbedtls_x509_crt_free(&parsed);
	if (ret != 0) {
		LOG_ERR("Device certificate does not parse (-0x%x)", -ret);
		return -EBADMSG;
	}

	/* Persist all staged blobs. */
	for (int k = 0; k < (int)ARRAY_SIZE(blobs); k++) {
		struct blob *b = &blobs[k];

		if (b->staged == 0 || b->staged != b->expected) {
			continue; /* not (fully) provided this session */
		}
		int err = settings_save_one(setting_key[k], b->buf, b->staged);

		if (err != 0) {
			LOG_ERR("Failed to persist %s (%d)", setting_key[k], err);
			return -EIO;
		}
		b->len = b->staged;
	}

	pouch_prov_emit(POUCH_PROV_EVENT_CLOUD_CRED_STORED, NULL);
	return 0;
}

size_t pouch_prov_cred_received(int kind)
{
	return kind_valid(kind) ? blobs[kind].staged : 0;
}

/* --- public API ----------------------------------------------------------- */

bool pouch_prov_cred_present(enum pouch_prov_cred_kind kind)
{
	return kind_valid(kind) && blobs[kind].len > 0;
}

const uint8_t *pouch_prov_cred_get(enum pouch_prov_cred_kind kind, size_t *out_len)
{
	if (!pouch_prov_cred_present(kind)) {
		return NULL;
	}
	if (out_len != NULL) {
		*out_len = blobs[kind].len;
	}
	return blobs[kind].buf;
}

int pouch_prov_cred_delete_all(void)
{
	for (int k = 0; k < (int)ARRAY_SIZE(blobs); k++) {
		(void)settings_delete(setting_key[k]);
		blobs[k].len = 0;
		blobs[k].staged = 0;
		blobs[k].expected = 0;
	}
	return 0;
}
