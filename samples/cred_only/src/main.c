/*
 * Copyright (c) 2026 Jonathan Beri
 * SPDX-License-Identifier: Apache-2.0
 *
 * BLE-only credential bootstrap: a blank device with no Wi-Fi radio advertises
 * for provisioning, the client bootstraps a cloud device certificate + key
 * over the encrypted pouch session, and the device stores them for its cloud
 * client. On a subsequent boot the stored credentials are reused and
 * provisioning is skipped.
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include <pouch_prov/manager.h>
#include <pouch_prov/credentials.h>

LOG_MODULE_REGISTER(main);

static void prov_event(enum pouch_prov_event event, const void *data, void *user_data)
{
	ARG_UNUSED(data);
	ARG_UNUSED(user_data);
	LOG_INF("Provisioning event %d", event);
}

static bool credentials_ready(void)
{
	return pouch_prov_cred_present(POUCH_PROV_CRED_DEVICE_CERT) &&
	       pouch_prov_cred_present(POUCH_PROV_CRED_PRIVATE_KEY);
}

int main(void)
{
	const struct pouch_prov_config config = {
		.pop = CONFIG_SAMPLE_POP,
		.device_id = "cred-only",
		.event_cb = prov_event,
	};
	int err;

	err = pouch_prov_mgr_init(&config);
	if (err != 0) {
		LOG_ERR("init failed (%d)", err);
		return err;
	}

	if (!credentials_ready()) {
		LOG_INF("Blank device — starting provisioning");
		err = pouch_prov_mgr_start();
		if (err != 0) {
			LOG_ERR("start failed (%d)", err);
			return err;
		}
		/* Wait until the client finishes (ctrl end or autostop). */
		(void)pouch_prov_mgr_wait(K_FOREVER);
		LOG_INF("Provisioning complete");
	}

	if (pouch_prov_mgr_is_provisioned()) {
		size_t cert_len = 0;

		(void)pouch_prov_cred_get(POUCH_PROV_CRED_DEVICE_CERT, &cert_len);
		LOG_INF("Provisioned: cloud device certificate stored (%zu bytes)", cert_len);
		/* An application would hand these credentials to its cloud client. */
	} else {
		LOG_WRN("No credentials available");
	}

	return 0;
}
