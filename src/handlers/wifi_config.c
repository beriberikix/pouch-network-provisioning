/*
 * Copyright (c) 2026 Jonathan Beri
 * SPDX-License-Identifier: Apache-2.0
 *
 * .prov/config — Wi-Fi station configuration: stage (set), persist + connect
 * (apply), poll (status). Connect runs asynchronously; the client polls
 * status until connected or failed. Retry/failure/credential-cleanup logic
 * adapted from network-provisioning-zephyr's wifi_config_handler.c.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/net/wifi_credentials.h>
#include <zephyr/net/wifi_mgmt.h>

#include <prov_decode.h>
#include <prov_encode.h>

#include "pouch_prov_internal.h"

LOG_MODULE_REGISTER(pouch_prov_wifi_config, CONFIG_POUCH_PROV_LOG_LEVEL);

#define SSID_MAX 32
#define PASS_MAX 63

static struct {
	uint8_t ssid[SSID_MAX + 1];
	size_t ssid_len;
	uint8_t pass[PASS_MAX + 1];
	size_t pass_len;
	uint8_t bssid[WIFI_MAC_ADDR_LEN];
	bool has_bssid;
	uint8_t channel;

	/* Snapshot of the in-flight attempt (see n-p-z rationale): connect
	 * params may be rewritten or cleared before the async result arrives. */
	uint8_t inflight_ssid[SSID_MAX + 1];
	size_t inflight_ssid_len;
	uint8_t inflight_pass[PASS_MAX + 1];
	size_t inflight_pass_len;
	uint8_t inflight_bssid[WIFI_MAC_ADDR_LEN];
	bool inflight_has_bssid;
	uint8_t inflight_channel;

	uint32_t attempts_max;
	uint32_t attempts_completed;
	int last_conn_status;
	struct k_work_delayable retry_work;

	uint32_t sta_state; /* sta_state_* choice value */
	uint32_t fail_reason;

	struct net_mgmt_event_callback mgmt_cb;
	bool cb_registered;
} wc;

static struct net_if *wifi_iface(void)
{
	struct net_if *iface = net_if_get_wifi_sta();

	return iface != NULL ? iface : net_if_get_first_wifi();
}

static void clear_inflight(void)
{
	memset(wc.inflight_ssid, 0, sizeof(wc.inflight_ssid));
	wc.inflight_ssid_len = 0;
	memset(wc.inflight_pass, 0, sizeof(wc.inflight_pass));
	wc.inflight_pass_len = 0;
	wc.inflight_has_bssid = false;
	wc.inflight_channel = 0;
}

static int connect_from_inflight(void)
{
	struct net_if *iface = wifi_iface();

	if (iface == NULL) {
		return -ENODEV;
	}

	struct wifi_connect_req_params params = {0};

	params.ssid = wc.inflight_ssid;
	params.ssid_length = wc.inflight_ssid_len;
	params.psk = (wc.inflight_pass_len > 0) ? wc.inflight_pass : NULL;
	params.psk_length = wc.inflight_pass_len;
	params.security = (wc.inflight_pass_len > 0) ? WIFI_SECURITY_TYPE_PSK
						     : WIFI_SECURITY_TYPE_NONE;
	params.channel = (wc.inflight_channel > 0) ? wc.inflight_channel : WIFI_CHANNEL_ANY;
	params.band = WIFI_FREQ_BAND_UNKNOWN;
	params.mfp = WIFI_MFP_OPTIONAL;
	params.timeout = SYS_FOREVER_MS;
	if (wc.inflight_has_bssid) {
		memcpy(params.bssid, wc.inflight_bssid, WIFI_MAC_ADDR_LEN);
	}

	return net_mgmt(NET_REQUEST_WIFI_CONNECT, iface, &params, sizeof(params));
}

static void final_failure(void)
{
	wc.sta_state = sta_state_sta_failed_m_c;

	enum pouch_prov_fail_reason reason;

	if (wc.last_conn_status == WIFI_STATUS_CONN_AP_NOT_FOUND) {
		wc.fail_reason = fail_reason_fail_network_not_found_m_c;
		reason = POUCH_PROV_FAIL_NETWORK_NOT_FOUND;
	} else {
		wc.fail_reason = fail_reason_fail_auth_error_m_c;
		reason = POUCH_PROV_FAIL_AUTH_ERROR;
	}

	/* A failed connect must not leave the device "provisioned". */
	(void)wifi_credentials_delete_by_ssid((const char *)wc.inflight_ssid,
					      wc.inflight_ssid_len);
	clear_inflight();
	pouch_prov_emit(POUCH_PROV_EVENT_WIFI_FAIL, &reason);
}

static void retry_work_handler(struct k_work *work)
{
	ARG_UNUSED(work);
	if (wc.inflight_ssid_len == 0) {
		return;
	}
	if (connect_from_inflight() != 0) {
		final_failure();
	}
}

static void on_connect_result(struct net_mgmt_event_callback *cb)
{
	const struct wifi_status *status = (const struct wifi_status *)cb->info;

	if (wc.inflight_ssid_len == 0) {
		return; /* stale result after a reset */
	}

	if (status->status == 0) {
		wc.sta_state = sta_state_sta_connected_m_c;
		clear_inflight();
		pouch_prov_emit(POUCH_PROV_EVENT_WIFI_CONNECTED, NULL);
		return;
	}

	wc.last_conn_status = status->conn_status;

	if (wc.attempts_max > 0) {
		wc.attempts_completed++;
		if (wc.attempts_completed < wc.attempts_max) {
			wc.sta_state = sta_state_sta_connecting_m_c;
			k_work_schedule(&wc.retry_work, K_SECONDS(1));
			return;
		}
	}
	final_failure();
}

static void mgmt_event(struct net_mgmt_event_callback *cb, uint64_t event, struct net_if *iface)
{
	ARG_UNUSED(iface);
	if (event == NET_EVENT_WIFI_CONNECT_RESULT) {
		on_connect_result(cb);
	}
}

int pouch_prov_wifi_config_init(uint32_t conn_attempts)
{
	wc.sta_state = sta_state_sta_disconnected_m_c;
	wc.attempts_max = conn_attempts;
	wc.attempts_completed = 0;
	k_work_init_delayable(&wc.retry_work, retry_work_handler);
	if (!wc.cb_registered) {
		net_mgmt_init_event_callback(&wc.mgmt_cb, mgmt_event,
					     NET_EVENT_WIFI_CONNECT_RESULT);
		net_mgmt_add_event_callback(&wc.mgmt_cb);
		wc.cb_registered = true;
	}
	return 0;
}

void pouch_prov_wifi_config_reset(void)
{
	clear_inflight();
	(void)k_work_cancel_delayable(&wc.retry_work);
	memset(wc.ssid, 0, sizeof(wc.ssid));
	wc.ssid_len = 0;
	memset(wc.pass, 0, sizeof(wc.pass));
	wc.pass_len = 0;
	wc.has_bssid = false;
	wc.channel = 0;
	wc.attempts_completed = 0;
	wc.sta_state = sta_state_sta_disconnected_m_c;
	wc.fail_reason = fail_reason_fail_auth_error_m_c;
}

bool pouch_prov_wifi_is_provisioned(void)
{
	return !wifi_credentials_is_empty();
}

void pouch_prov_wifi_reset_state(void)
{
	pouch_prov_wifi_config_reset();
}

void pouch_prov_wifi_reprovision(void)
{
	/* Wipe every stored network, then reset the state machine. */
	(void)wifi_credentials_delete_all();
	pouch_prov_wifi_config_reset();
}

static uint32_t do_set(const struct wifi_config *cfg)
{
	if (cfg->wifi_config_ssid.len == 0 || cfg->wifi_config_ssid.len > SSID_MAX) {
		return prov_status_status_invalid_argument_m_c;
	}
	if (cfg->wifi_config_pass_present && cfg->wifi_config_pass.wifi_config_pass.len > PASS_MAX) {
		return prov_status_status_invalid_argument_m_c;
	}

	memset(wc.ssid, 0, sizeof(wc.ssid));
	wc.ssid_len = cfg->wifi_config_ssid.len;
	memcpy(wc.ssid, cfg->wifi_config_ssid.value, wc.ssid_len);

	memset(wc.pass, 0, sizeof(wc.pass));
	if (cfg->wifi_config_pass_present) {
		wc.pass_len = cfg->wifi_config_pass.wifi_config_pass.len;
		memcpy(wc.pass, cfg->wifi_config_pass.wifi_config_pass.value, wc.pass_len);
	} else {
		wc.pass_len = 0;
	}

	wc.has_bssid = cfg->wifi_config_bssid_present &&
		       cfg->wifi_config_bssid.wifi_config_bssid.len == WIFI_MAC_ADDR_LEN;
	if (wc.has_bssid) {
		memcpy(wc.bssid, cfg->wifi_config_bssid.wifi_config_bssid.value, WIFI_MAC_ADDR_LEN);
	}
	wc.channel = cfg->wifi_config_ch_present ? (uint8_t)cfg->wifi_config_ch.wifi_config_ch : 0;

	return prov_status_status_ok_m_c;
}

static uint32_t do_apply(void)
{
	struct net_if *iface = wifi_iface();

	if (iface == NULL || wc.ssid_len == 0) {
		return prov_status_status_invalid_state_m_c;
	}

	uint32_t flags = 0;
	const uint8_t *bssid = NULL;
	size_t bssid_len = 0;

	if (wc.has_bssid) {
		flags |= WIFI_CREDENTIALS_FLAG_BSSID;
		bssid = wc.bssid;
		bssid_len = WIFI_MAC_ADDR_LEN;
	}

	(void)wifi_credentials_delete_by_ssid((const char *)wc.ssid, wc.ssid_len);

	enum wifi_security_type sec =
		(wc.pass_len > 0) ? WIFI_SECURITY_TYPE_PSK : WIFI_SECURITY_TYPE_NONE;
	int ret = wifi_credentials_set_personal((const char *)wc.ssid, wc.ssid_len, sec, bssid,
						bssid_len, (const char *)wc.pass, wc.pass_len,
						flags, wc.channel, 0);
	if (ret != 0) {
		return prov_status_status_internal_error_m_c;
	}

	pouch_prov_emit(POUCH_PROV_EVENT_WIFI_CRED_RECV, NULL);
	wc.sta_state = sta_state_sta_connecting_m_c;

	(void)k_work_cancel_delayable(&wc.retry_work);
	memcpy(wc.inflight_ssid, wc.ssid, sizeof(wc.inflight_ssid));
	wc.inflight_ssid_len = wc.ssid_len;
	memcpy(wc.inflight_pass, wc.pass, sizeof(wc.inflight_pass));
	wc.inflight_pass_len = wc.pass_len;
	wc.inflight_has_bssid = wc.has_bssid;
	if (wc.has_bssid) {
		memcpy(wc.inflight_bssid, wc.bssid, WIFI_MAC_ADDR_LEN);
	}
	wc.inflight_channel = wc.channel;
	wc.attempts_completed = 0;

	if (connect_from_inflight() != 0) {
		/* Rejected synchronously — surface as an async-style failure. */
		wc.last_conn_status = WIFI_STATUS_CONN_WRONG_PASSWORD;
		final_failure();
	}
	return prov_status_status_ok_m_c;
}

static void fill_connected(struct connected_info *out)
{
	struct net_if *iface = wifi_iface();
	struct wifi_iface_status status = {0};
	static uint8_t ip4[4];

	if (iface != NULL &&
	    net_mgmt(NET_REQUEST_WIFI_IFACE_STATUS, iface, &status, sizeof(status)) == 0) {
		out->connected_info_ssid.value = status.ssid;
		out->connected_info_ssid.len = status.ssid_len;
		out->connected_info_rssi.connected_info_rssi = status.rssi;
		out->connected_info_rssi_present = true;
	} else {
		out->connected_info_ssid.value = wc.ssid;
		out->connected_info_ssid.len = wc.ssid_len;
	}

	if (iface != NULL) {
		struct in_addr *addr = net_if_ipv4_get_global_addr(iface, NET_ADDR_PREFERRED);

		if (addr != NULL) {
			memcpy(ip4, addr->s4_addr, 4);
		}
	}
	out->connected_info_ip4.value = ip4;
	out->connected_info_ip4.len = 4;
}

static int encode_status(uint8_t *rsp, size_t rsp_size, size_t *rsp_len)
{
	struct config_rsp_r out = {
		.config_rsp_choice = config_rsp_config_status_rsp_m_c,
		.config_rsp_config_status_rsp_m = {
			.config_status_rsp_prov_status_m.prov_status_choice =
				prov_status_status_ok_m_c,
			.config_status_rsp_sta_state_m.sta_state_choice = wc.sta_state,
		},
	};
	struct config_status_rsp *s = &out.config_rsp_config_status_rsp_m;

	if (wc.sta_state == sta_state_sta_connected_m_c) {
		s->config_status_rsp_config_detail_m_present = true;
		s->config_status_rsp_config_detail_m.config_detail_choice =
			config_detail_connected_info_m_c;
		fill_connected(&s->config_status_rsp_config_detail_m.config_detail_connected_info_m);
	} else if (wc.sta_state == sta_state_sta_failed_m_c) {
		s->config_status_rsp_config_detail_m_present = true;
		s->config_status_rsp_config_detail_m.config_detail_choice =
			config_detail_fail_reason_m_c;
		s->config_status_rsp_config_detail_m.config_detail_fail_reason_m.fail_reason_choice =
			wc.fail_reason;
	}

	return cbor_encode_config_rsp(rsp, rsp_size, &out, rsp_len) == 0 ? 0 : -ENOMEM;
}

static int encode_ack(uint32_t op, uint32_t status, uint8_t *rsp, size_t rsp_size, size_t *rsp_len)
{
	struct config_rsp_r out;

	if (op == OP_CONFIG_SET) {
		out.config_rsp_choice = config_rsp_config_set_rsp_m_c;
		out.config_rsp_config_set_rsp_m.config_set_rsp_prov_status_m.prov_status_choice =
			status;
	} else {
		out.config_rsp_choice = config_rsp_config_apply_rsp_m_c;
		out.config_rsp_config_apply_rsp_m.config_apply_rsp_prov_status_m.prov_status_choice =
			status;
	}
	return cbor_encode_config_rsp(rsp, rsp_size, &out, rsp_len) == 0 ? 0 : -ENOMEM;
}

int pouch_prov_handle_config(const uint8_t *req, size_t req_len, uint8_t *rsp, size_t rsp_size,
			     size_t *rsp_len)
{
	struct config_req_r in;
	size_t consumed;

	if (cbor_decode_config_req(req, req_len, &in, &consumed) != 0) {
		return -EBADMSG;
	}

	switch (in.config_req_choice) {
	case config_req_config_get_status_m_c:
		return encode_status(rsp, rsp_size, rsp_len);
	case config_req_config_set_m_c: {
		uint32_t status = do_set(&in.config_req_config_set_m.config_set_wifi_config_m);

		return encode_ack(OP_CONFIG_SET, status, rsp, rsp_size, rsp_len);
	}
	case config_req_config_apply_m_c:
		return encode_ack(OP_CONFIG_APPLY, do_apply(), rsp, rsp_size, rsp_len);
	default:
		return -EBADMSG;
	}
}
