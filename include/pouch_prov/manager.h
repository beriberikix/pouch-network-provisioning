/*
 * Copyright (c) 2026 Jonathan Beri
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include <zephyr/kernel.h>

#include <pouch_prov/events.h>

/**
 * @file manager.h
 * @brief Pouch network provisioning manager
 */

struct pouch_prov_config {
	/**
	 * Proof-of-possession secret (UTF-8), or NULL to disable the
	 * .prov/auth authorization gate (development only).
	 */
	const char *pop;

	/**
	 * Device ID passed to pouch. Must remain valid while provisioning
	 * is in use.
	 */
	const char *device_id;

	/** Wi-Fi connection retry budget (0 = default). */
	uint32_t wifi_conn_attempts;

	/** Application event callback (optional). */
	pouch_prov_event_cb_t event_cb;
	void *user_data;
};

/**
 * Initialize the provisioning manager and the pouch stack.
 *
 * Under CONFIG_POUCH_ENCRYPTION_SAEAD this also ensures the device has a
 * pouch identity (generating an ephemeral self-signed certificate on
 * first boot when CONFIG_POUCH_PROV_IDENTITY is enabled).
 */
int pouch_prov_mgr_init(const struct pouch_prov_config *config);

/** Start the provisioning service (advertising). */
int pouch_prov_mgr_start(void);

/** Stop the provisioning service. */
int pouch_prov_mgr_stop(void);

/**
 * True when the device holds the credentials it needs to operate: Wi-Fi
 * credentials when Wi-Fi provisioning is enabled, otherwise a stored cloud
 * device certificate (cred-only / BLE-only builds).
 */
bool pouch_prov_mgr_is_provisioned(void);

/**
 * Block until provisioning ends (ctrl end from the client, stop, or
 * autostop timeout).
 */
int pouch_prov_mgr_wait(k_timeout_t timeout);

/**
 * Wipe stored credentials (Wi-Fi when enabled, and cloud credentials when the
 * cred bootstrap endpoint is enabled) and reset the state machine.
 */
int pouch_prov_mgr_reset(void);
