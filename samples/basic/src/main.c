/*
 * Copyright (c) 2026 Jonathan Beri
 * SPDX-License-Identifier: Apache-2.0
 *
 * Minimal provisioning target: starts the provisioning service and
 * waits. Used for transport bring-up with the pouchprov CLI.
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include <pouch_prov/manager.h>

LOG_MODULE_REGISTER(main);

static void prov_event(enum pouch_prov_event event, const void *data, void *user_data)
{
	LOG_INF("Provisioning event: %d", event);
}

int main(void)
{
	const struct pouch_prov_config config = {
		.pop = CONFIG_SAMPLE_POP[0] != '\0' ? CONFIG_SAMPLE_POP : NULL,
		.device_id = "pouch-prov-basic",
		.event_cb = prov_event,
	};
	int err;

	err = pouch_prov_mgr_init(&config);
	if (err != 0) {
		LOG_ERR("init failed (%d)", err);
		return err;
	}

	err = pouch_prov_mgr_start();
	if (err != 0) {
		LOG_ERR("start failed (%d)", err);
		return err;
	}

	LOG_INF("Provisioning service running");
	(void)pouch_prov_mgr_wait(K_FOREVER);
	LOG_INF("Provisioning ended");

	return 0;
}
