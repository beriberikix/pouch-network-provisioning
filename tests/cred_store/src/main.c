/*
 * Copyright (c) 2026 Jonathan Beri
 * SPDX-License-Identifier: Apache-2.0
 *
 * Exercises the credential store: chunked staging, ordered-write
 * enforcement, finalize validation (cert must parse; cert+key required),
 * persistence + reload, and delete.
 */

#include <zephyr/ztest.h>
#include <zephyr/settings/settings.h>

#include <pouch_prov/credentials.h>

#include "pouch_prov_internal.h"
#include "test_cert.inc"

/* Stub the manager event sink used by cred_finalize. */
static bool stored_event;
void pouch_prov_emit(enum pouch_prov_event event, const void *data)
{
	ARG_UNUSED(data);
	if (event == POUCH_PROV_EVENT_CLOUD_CRED_STORED) {
		stored_event = true;
	}
}

static const uint8_t fake_key[120] = {1, 2, 3, 4, 5};

static void before(void *unused)
{
	ARG_UNUSED(unused);
	stored_event = false;
	(void)pouch_prov_cred_delete_all();
}

ZTEST_SUITE(cred_store, NULL, NULL, before, NULL, NULL);

/* Stage a blob in chunks of `chunk` bytes. */
static void stage_chunked(int kind, const uint8_t *der, size_t len, size_t chunk)
{
	size_t off = 0;

	while (off < len) {
		size_t n = MIN(chunk, len - off);
		int rc = pouch_prov_cred_stage(kind, off, len, der + off, n);

		zassert_true(rc >= 0, "stage failed at off %zu (%d)", off, rc);
		off += n;
		zassert_equal((size_t)rc, off);
	}
}

ZTEST(cred_store, test_stage_finalize_persist)
{
	stage_chunked(POUCH_PROV_CRED_DEVICE_CERT, test_cert_der, sizeof(test_cert_der), 64);
	stage_chunked(POUCH_PROV_CRED_PRIVATE_KEY, fake_key, sizeof(fake_key), 64);

	zassert_ok(pouch_prov_cred_finalize());
	zassert_true(stored_event);

	zassert_true(pouch_prov_cred_present(POUCH_PROV_CRED_DEVICE_CERT));
	zassert_true(pouch_prov_cred_present(POUCH_PROV_CRED_PRIVATE_KEY));

	size_t len;
	const uint8_t *cert = pouch_prov_cred_get(POUCH_PROV_CRED_DEVICE_CERT, &len);

	zassert_equal(len, sizeof(test_cert_der));
	zassert_mem_equal(cert, test_cert_der, len);
}

ZTEST(cred_store, test_reload_after_settings_load)
{
	stage_chunked(POUCH_PROV_CRED_DEVICE_CERT, test_cert_der, sizeof(test_cert_der), 128);
	stage_chunked(POUCH_PROV_CRED_PRIVATE_KEY, fake_key, sizeof(fake_key), 128);
	zassert_ok(pouch_prov_cred_finalize());

	/* Simulate a reboot: reload from persistent storage. */
	zassert_ok(settings_load_subtree("pnp/cred"));
	zassert_true(pouch_prov_cred_present(POUCH_PROV_CRED_DEVICE_CERT));
}

ZTEST(cred_store, test_out_of_order_rejected)
{
	zassert_true(pouch_prov_cred_stage(POUCH_PROV_CRED_DEVICE_CERT, 0, 100, test_cert_der, 50) >= 0);
	/* Wrong offset (gap) must be rejected. */
	zassert_true(pouch_prov_cred_stage(POUCH_PROV_CRED_DEVICE_CERT, 60, 100,
					   test_cert_der + 60, 40) < 0);
}

ZTEST(cred_store, test_finalize_requires_cert_and_key)
{
	/* Only a cert, no key. */
	stage_chunked(POUCH_PROV_CRED_DEVICE_CERT, test_cert_der, sizeof(test_cert_der), 64);
	zassert_not_equal(pouch_prov_cred_finalize(), 0);
	zassert_false(pouch_prov_cred_present(POUCH_PROV_CRED_DEVICE_CERT));
}

ZTEST(cred_store, test_finalize_rejects_bad_cert)
{
	static const uint8_t garbage[64] = {0xff, 0x00, 0xff};

	stage_chunked(POUCH_PROV_CRED_DEVICE_CERT, garbage, sizeof(garbage), 32);
	stage_chunked(POUCH_PROV_CRED_PRIVATE_KEY, fake_key, sizeof(fake_key), 32);
	zassert_equal(pouch_prov_cred_finalize(), -EBADMSG);
}
