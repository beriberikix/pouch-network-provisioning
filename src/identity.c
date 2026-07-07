/*
 * Copyright (c) 2026 Jonathan Beri
 * SPDX-License-Identifier: Apache-2.0
 *
 * Device pouch identity: on first boot, generate a P-256 key pair and a
 * self-signed X.509 certificate to serve as the device's pouch credential.
 * Both the raw private key and the certificate are persisted via the
 * settings subsystem and reloaded into a volatile PSA key on each boot.
 * (This avoids a dependency on a configured PSA persistent-key storage
 * backend; the bootstrap identity is not the cloud credential.)
 *
 * The certificate is self-signed and consumed trust-on-first-use by the
 * local provisioning client, which only needs the embedded public key for
 * ECDH — it is not validated against a CA in local provisioning.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/settings/settings.h>

#include <mbedtls/pk.h>
#include <mbedtls/psa_util.h>
#include <mbedtls/x509_crt.h>
#include <psa/crypto.h>

#include <pouch/types.h>

#include "pouch_prov_internal.h"

LOG_MODULE_REGISTER(pouch_prov_identity, CONFIG_POUCH_PROV_LOG_LEVEL);

#define CERT_SETTINGS_KEY "pnp/id/cert"
#define KEY_SETTINGS_KEY  "pnp/id/key"
#define IDENTITY_CERT_MAX 640
#define P256_PRIV_LEN     32

static uint8_t cert_der[IDENTITY_CERT_MAX];
static size_t cert_der_len;
static uint8_t priv_raw[P256_PRIV_LEN];
static size_t priv_raw_len;
static psa_key_id_t identity_key = PSA_KEY_ID_NULL;

/* --- settings glue -------------------------------------------------------- */

static int id_set(const char *name, size_t len, settings_read_cb read_cb, void *cb_arg)
{
	const char *next;

	if (settings_name_steq(name, "cert", &next) && !next) {
		if (len > sizeof(cert_der)) {
			return -EINVAL;
		}
		ssize_t rc = read_cb(cb_arg, cert_der, sizeof(cert_der));

		if (rc < 0) {
			return rc;
		}
		cert_der_len = rc;
		return 0;
	}
	if (settings_name_steq(name, "key", &next) && !next) {
		if (len > sizeof(priv_raw)) {
			return -EINVAL;
		}
		ssize_t rc = read_cb(cb_arg, priv_raw, sizeof(priv_raw));

		if (rc < 0) {
			return rc;
		}
		priv_raw_len = rc;
		return 0;
	}
	return -ENOENT;
}

SETTINGS_STATIC_HANDLER_DEFINE(pouch_prov_id, "pnp/id", NULL, id_set, NULL, NULL);

/* --- key + certificate ---------------------------------------------------- */

/* Import the raw P-256 private scalar into a volatile PSA key usable for
 * both ECDH (pouch session) and ECDSA (self-signing the certificate). */
static psa_key_id_t import_key(const uint8_t *raw, size_t len)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t id = PSA_KEY_ID_NULL;

	psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&attr, 256);
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_SIGN_HASH |
					       PSA_KEY_USAGE_SIGN_MESSAGE);
	psa_set_key_algorithm(&attr, PSA_ALG_ECDH);
	psa_set_key_enrollment_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));

	if (psa_import_key(&attr, raw, len, &id) != PSA_SUCCESS) {
		id = PSA_KEY_ID_NULL;
	}
	psa_reset_key_attributes(&attr);
	return id;
}

/* Generate a fresh key, export the raw private scalar, persist it, and
 * return a volatile PSA key id. */
static int generate_key(void)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t tmp = PSA_KEY_ID_NULL;
	int ret = -EIO;

	psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&attr, 256);
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_DERIVE |
					       PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_SIGN_MESSAGE);
	psa_set_key_algorithm(&attr, PSA_ALG_ECDH);
	psa_set_key_enrollment_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));

	if (psa_generate_key(&attr, &tmp) != PSA_SUCCESS) {
		goto out;
	}
	if (psa_export_key(tmp, priv_raw, sizeof(priv_raw), &priv_raw_len) != PSA_SUCCESS) {
		goto out;
	}
	if (settings_save_one(KEY_SETTINGS_KEY, priv_raw, priv_raw_len) != 0) {
		goto out;
	}
	ret = 0;

out:
	psa_reset_key_attributes(&attr);
	if (tmp != PSA_KEY_ID_NULL) {
		psa_destroy_key(tmp); /* re-import volatile without EXPORT usage */
	}
	if (ret == 0) {
		identity_key = import_key(priv_raw, priv_raw_len);
		if (identity_key == PSA_KEY_ID_NULL) {
			ret = -EIO;
		}
	}
	return ret;
}

static int build_self_signed_cert(void)
{
	mbedtls_pk_context pk;
	mbedtls_x509write_cert crt;
	mbedtls_mpi serial;
	uint8_t buf[IDENTITY_CERT_MAX];
	int ret;

	mbedtls_pk_init(&pk);
	mbedtls_x509write_crt_init(&crt);
	mbedtls_mpi_init(&serial);

	ret = mbedtls_pk_setup_opaque(&pk, identity_key);
	if (ret != 0) {
		LOG_ERR("pk_setup_opaque: -0x%x", -ret);
		goto out;
	}

	mbedtls_x509write_crt_set_subject_key(&crt, &pk);
	mbedtls_x509write_crt_set_issuer_key(&crt, &pk);
	mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA256);
	mbedtls_x509write_crt_set_version(&crt, MBEDTLS_X509_CRT_VERSION_3);

	ret = mbedtls_x509write_crt_set_subject_name(&crt, "CN=pouch-prov-device");
	if (ret == 0) {
		ret = mbedtls_x509write_crt_set_issuer_name(&crt, "CN=pouch-prov-device");
	}
	if (ret == 0) {
		ret = mbedtls_mpi_lset(&serial, 1);
	}
	if (ret == 0) {
		ret = mbedtls_x509write_crt_set_serial(&crt, &serial);
	}
	if (ret == 0) {
		ret = mbedtls_x509write_crt_set_validity(&crt, "20260101000000",
							 "20360101000000");
	}
	if (ret != 0) {
		LOG_ERR("x509write setup: -0x%x", -ret);
		goto out;
	}

	/* Write DER at the end of buf; returns length, data is right-aligned. */
	ret = mbedtls_x509write_crt_der(&crt, buf, sizeof(buf), mbedtls_psa_get_random,
					MBEDTLS_PSA_RANDOM_STATE);
	if (ret < 0) {
		LOG_ERR("x509write_crt_der: -0x%x", -ret);
		goto out;
	}

	cert_der_len = ret;
	memcpy(cert_der, buf + sizeof(buf) - ret, ret);

	ret = settings_save_one(CERT_SETTINGS_KEY, cert_der, cert_der_len);
	if (ret != 0) {
		LOG_ERR("Failed to persist certificate (%d)", ret);
	}

out:
	mbedtls_mpi_free(&serial);
	mbedtls_x509write_crt_free(&crt);
	mbedtls_pk_free(&pk);
	return ret < 0 ? -EIO : 0;
}

int pouch_prov_identity_ensure(struct pouch_cert *cert_out, psa_key_id_t *key_out)
{
	psa_status_t status = psa_crypto_init();

	if (status != PSA_SUCCESS) {
		return -EIO;
	}

	if (priv_raw_len > 0) {
		/* Restored from settings: re-import the stored key. */
		identity_key = import_key(priv_raw, priv_raw_len);
		if (identity_key == PSA_KEY_ID_NULL) {
			LOG_ERR("Failed to import stored identity key");
			return -EIO;
		}
	} else {
		LOG_INF("Generating device identity");
		int err = generate_key();

		if (err != 0) {
			LOG_ERR("Key generation failed (%d)", err);
			return err;
		}
		cert_der_len = 0; /* force cert regeneration */
	}

	if (cert_der_len == 0) {
		int err = build_self_signed_cert();

		if (err != 0) {
			return err;
		}
	}

	cert_out->buffer = cert_der;
	cert_out->size = cert_der_len;
	*key_out = identity_key;
	return 0;
}
