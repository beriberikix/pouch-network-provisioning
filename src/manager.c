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

#include <pouch_prov/credentials.h>
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

	struct pouch_config pouch_cfg;

#if defined(CONFIG_POUCH_ENCRYPTION_NONE)
	pouch_cfg.device_id = config.device_id;
#elif defined(CONFIG_POUCH_PROV_IDENTITY)
	/* Generate/restore the device's pouch identity (persistent key + cert)
	 * and hand it to pouch. The settings backend must be loaded first so a
	 * previously generated certificate is restored. */
	if (IS_ENABLED(CONFIG_SETTINGS)) {
		(void)settings_subsys_init();
		(void)settings_load_subtree("pnp"); /* identity + bootstrapped creds */
	}
	err = pouch_prov_identity_ensure(&pouch_cfg.certificate, &pouch_cfg.private_key);
	if (err != 0) {
		LOG_ERR("identity setup failed (%d)", err);
		return err;
	}
#else
#error "POUCH_PROV needs CONFIG_POUCH_ENCRYPTION_NONE or CONFIG_POUCH_PROV_IDENTITY"
#endif

	err = pouch_init(&pouch_cfg);
	if (err != 0) {
		LOG_ERR("pouch_init failed (%d)", err);
		return err;
	}

#if defined(CONFIG_POUCH_PROV_WIFI)
	(void)pouch_prov_wifi_config_init(config.wifi_conn_attempts);
	(void)pouch_prov_wifi_scan_init();
#endif

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
#if defined(CONFIG_POUCH_PROV_WIFI)
	return pouch_prov_wifi_is_provisioned();
#elif defined(CONFIG_POUCH_PROV_CRED)
	/* A cred-only (BLE-only) device is provisioned once it holds a cloud
	 * device certificate to operate with. */
	return pouch_prov_cred_present(POUCH_PROV_CRED_DEVICE_CERT);
#else
	return false;
#endif
}

void pouch_prov_ctrl_end_requested(void)
{
	(void)pouch_prov_mgr_stop();
}

int pouch_prov_mgr_wait(k_timeout_t timeout)
{
	uint32_t events = k_event_wait(&mgr_events, MGR_EVENT_ENDED, false, timeout);

	return (events & MGR_EVENT_ENDED) != 0 ? 0 : -EAGAIN;
}

int pouch_prov_mgr_reset(void)
{
#if defined(CONFIG_POUCH_PROV_WIFI)
	pouch_prov_wifi_reprovision();
#endif
#if defined(CONFIG_POUCH_PROV_CRED)
	(void)pouch_prov_cred_delete_all();
#endif
	pouch_prov_dispatch_reset();
	pouch_prov_rpc_reset();

	return 0;
}
