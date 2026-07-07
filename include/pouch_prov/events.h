/*
 * Copyright (c) 2026 Jonathan Beri
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

/**
 * @file events.h
 * @brief Application-facing provisioning events
 */

enum pouch_prov_event {
	/** Provisioning service started (advertising). */
	POUCH_PROV_EVENT_STARTED,
	/** Encrypted session authorized (PoP verified, or auth disabled). */
	POUCH_PROV_EVENT_SESSION_AUTHORIZED,
	/** Wi-Fi credentials received and staged. */
	POUCH_PROV_EVENT_WIFI_CRED_RECV,
	/** Wi-Fi station connected. */
	POUCH_PROV_EVENT_WIFI_CONNECTED,
	/** Wi-Fi connection failed (data: const enum pouch_prov_fail_reason *). */
	POUCH_PROV_EVENT_WIFI_FAIL,
	/** Cloud credentials stored (data: none). */
	POUCH_PROV_EVENT_CLOUD_CRED_STORED,
	/** Provisioning ended (ctrl end, stop, or autostop). */
	POUCH_PROV_EVENT_ENDED,
};

enum pouch_prov_fail_reason {
	POUCH_PROV_FAIL_AUTH_ERROR = 0,
	POUCH_PROV_FAIL_NETWORK_NOT_FOUND = 1,
};

typedef void (*pouch_prov_event_cb_t)(enum pouch_prov_event event, const void *data,
				      void *user_data);
