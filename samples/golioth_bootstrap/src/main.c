/*
 * Copyright (c) 2026 Jonathan Beri
 * SPDX-License-Identifier: Apache-2.0
 *
 * Zero-touch onboarding: a blank device advertises for provisioning, the
 * client bootstraps a Golioth device certificate + Wi-Fi credentials over
 * the encrypted pouch session, then this app connects to Golioth with the
 * provisioned certificate. On a subsequent boot the stored credentials are
 * reused and provisioning is skipped.
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/net_mgmt.h>
#include <zephyr/net/net_event.h>
#include <zephyr/net/wifi_mgmt.h>

#include <golioth/client.h>

#include <pouch_prov/manager.h>
#include <pouch_prov/credentials.h>

LOG_MODULE_REGISTER(main);

static K_SEM_DEFINE(wifi_up, 0, 1);
static struct net_mgmt_event_callback wifi_cb;

static void net_event(struct net_mgmt_event_callback *cb, uint64_t event, struct net_if *iface)
{
	ARG_UNUSED(cb);
	ARG_UNUSED(iface);
	if (event == NET_EVENT_L4_CONNECTED) {
		k_sem_give(&wifi_up);
	}
}

static void prov_event(enum pouch_prov_event event, const void *data, void *user_data)
{
	ARG_UNUSED(data);
	ARG_UNUSED(user_data);
	LOG_INF("Provisioning event %d", event);
}

static bool credentials_ready(void)
{
	return pouch_prov_mgr_is_provisioned() &&
	       pouch_prov_cred_present(POUCH_PROV_CRED_DEVICE_CERT) &&
	       pouch_prov_cred_present(POUCH_PROV_CRED_PRIVATE_KEY);
}

static int connect_to_golioth(void)
{
	size_t cert_len, key_len, ca_len = 0;
	const uint8_t *cert = pouch_prov_cred_get(POUCH_PROV_CRED_DEVICE_CERT, &cert_len);
	const uint8_t *key = pouch_prov_cred_get(POUCH_PROV_CRED_PRIVATE_KEY, &key_len);
	const uint8_t *ca = pouch_prov_cred_get(POUCH_PROV_CRED_CA_CERT, &ca_len);

	struct golioth_client_config config = {
		.credentials = {
			.auth_type = GOLIOTH_TLS_AUTH_TYPE_PKI,
			.pki = {
				.public_cert = cert,
				.public_cert_len = cert_len,
				.private_key = key,
				.private_key_len = key_len,
				.ca_cert = ca,
				.ca_cert_len = ca_len,
			},
		},
	};

	struct golioth_client *client = golioth_client_create(&config);

	if (client == NULL) {
		return -ENOMEM;
	}

	LOG_INF("Connecting to Golioth with the provisioned certificate...");
	if (!golioth_client_wait_for_connect(client, 30000)) {
		LOG_ERR("Golioth connection timed out");
		return -ETIMEDOUT;
	}

	LOG_INF("Zero-touch enrolled: connected to Golioth");
	return 0;
}

int main(void)
{
	const struct pouch_prov_config config = {
		.pop = CONFIG_SAMPLE_POP,
		.device_id = "golioth-bootstrap",
		.wifi_conn_attempts = 3,
		.event_cb = prov_event,
	};
	int err;

	net_mgmt_init_event_callback(&wifi_cb, net_event, NET_EVENT_L4_CONNECTED);
	net_mgmt_add_event_callback(&wifi_cb);

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
		/* Wait until the client finishes (ctrl end / autostop). */
		(void)pouch_prov_mgr_wait(K_FOREVER);
		LOG_INF("Provisioning complete");
	} else {
		LOG_INF("Already provisioned — connecting Wi-Fi from stored credentials");
		struct net_if *iface = net_if_get_first_wifi();

		if (iface != NULL) {
			(void)net_mgmt(NET_REQUEST_WIFI_CONNECT_STORED, iface, NULL, 0);
		}
	}

	/* Wait for L4 (IP) connectivity, then bring up Golioth. */
	if (k_sem_take(&wifi_up, K_SECONDS(60)) != 0) {
		LOG_ERR("Wi-Fi did not come up");
		return -ETIMEDOUT;
	}

	return connect_to_golioth();
}
