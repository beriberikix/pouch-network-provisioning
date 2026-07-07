/*
 * Copyright (c) 2026 Jonathan Beri
 * SPDX-License-Identifier: Apache-2.0
 *
 * Provisioning manager: lifecycle, pouch init, event fan-out.
 * Structure mirrors network-provisioning-zephyr's network_prov_mgr.c.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/settings/settings.h>

#include <pouch/events.h>
#include <pouch/pouch.h>

#include <pouch_prov/manager.h>

#include "pouch_prov_internal.h"

LOG_MODULE_REGISTER(pouch_prov_mgr, CONFIG_POUCH_PROV_LOG_LEVEL);

static struct pouch_prov_config config;
static bool initialized;
static bool running;
static K_EVENT_DEFINE(mgr_events);

#define MGR_EVENT_ENDED BIT(0)

const struct pouch_prov_config *pouch_prov_config_get(void)
{
	return &config;
}

void pouch_prov_emit(enum pouch_prov_event event, const void *data)
{
	if (config.event_cb != NULL) {
		config.event_cb(event, data, config.user_data);
	}
}

/* Reset per-session state whenever a pouch session cycle starts. Pouch
 * sessions are per-CCC-subscribe (many per provisioning session); the
 * provisioning session itself (auth state) resets on BLE disconnect via
 * pouch_prov_mgr_session_ended(). */
static void pouch_event_handler(enum pouch_event event, void *ctx)
{
	ARG_UNUSED(ctx);

	if (event == POUCH_EVENT_SESSION_END) {
		LOG_DBG("Pouch cycle ended");
	}
}

POUCH_EVENT_HANDLER(pouch_event_handler, NULL);

void pouch_prov_mgr_session_ended(void)
{
	/* BLE link dropped: clear authorization and any queued responses. */
	pouch_prov_dispatch_reset();
	pouch_prov_rpc_reset();
}

int pouch_prov_mgr_init(const struct pouch_prov_config *cfg)
{
	int err;

	if (initialized) {
		return -EALREADY;
	}
	if (cfg == NULL || cfg->device_id == NULL) {
		return -EINVAL;
	}

	config = *cfg;

#if defined(CONFIG_POUCH_ENCRYPTION_NONE)
	struct pouch_config pouch_cfg = {
		.device_id = config.device_id,
	};
#else
	/* SAEAD identity (ephemeral self-signed cert) lands in M3. */
	struct pouch_config pouch_cfg = { 0 };
#error "POUCH_PROV currently requires CONFIG_POUCH_ENCRYPTION_NONE (saead lands in M3)"
#endif

	err = pouch_init(&pouch_cfg);
	if (err != 0) {
		LOG_ERR("pouch_init failed (%d)", err);
		return err;
	}

	initialized = true;

	return 0;
}

int pouch_prov_mgr_start(void)
{
	int err;

	if (!initialized) {
		return -EINVAL;
	}
	if (running) {
		return -EALREADY;
	}

	if (!bt_is_ready()) {
		err = bt_enable(NULL);
		if (err != 0 && err != -EALREADY) {
			LOG_ERR("bt_enable failed (%d)", err);
			return err;
		}
	}

	/* Restore identity and bonds. Required by CONFIG_BT_SETTINGS, and lets
	 * bonds survive reboots so a central's cached key stays valid. */
	if (IS_ENABLED(CONFIG_SETTINGS)) {
		err = settings_load();
		if (err != 0) {
			LOG_WRN("settings_load failed (%d)", err);
		}
	}

	pouch_prov_dispatch_reset();
	pouch_prov_rpc_reset();
	k_event_clear(&mgr_events, MGR_EVENT_ENDED);

	err = pouch_prov_adv_start();
	if (err != 0) {
		return err;
	}

	running = true;
	pouch_prov_emit(POUCH_PROV_EVENT_STARTED, NULL);

	return 0;
}

int pouch_prov_mgr_stop(void)
{
	if (!running) {
		return -EALREADY;
	}

	running = false;
	(void)pouch_prov_adv_stop();
	pouch_prov_dispatch_reset();
	pouch_prov_rpc_reset();

	k_event_post(&mgr_events, MGR_EVENT_ENDED);
	pouch_prov_emit(POUCH_PROV_EVENT_ENDED, NULL);

	return 0;
}

bool pouch_prov_mgr_is_provisioned(void)
{
	/* Wi-Fi credential presence check lands with the M4 handlers. */
	return false;
}

int pouch_prov_mgr_wait(k_timeout_t timeout)
{
	uint32_t events = k_event_wait(&mgr_events, MGR_EVENT_ENDED, false, timeout);

	return (events & MGR_EVENT_ENDED) != 0 ? 0 : -EAGAIN;
}

int pouch_prov_mgr_reset(void)
{
	/* Credential wipe lands with the M4/M5 handlers. */
	pouch_prov_dispatch_reset();
	pouch_prov_rpc_reset();

	return 0;
}
