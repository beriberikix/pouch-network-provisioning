/*
 * Copyright (c) 2026 Jonathan Beri
 * SPDX-License-Identifier: Apache-2.0
 *
 * .prov/scan — Wi-Fi AP scan. Start kicks a scan and returns immediately;
 * the client polls status until finished, then fetches results in pages.
 * Scan collection adapted from network-provisioning-zephyr.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/wifi_mgmt.h>

#include <prov_decode.h>
#include <prov_encode.h>

#include "pouch_prov_internal.h"

LOG_MODULE_REGISTER(pouch_prov_wifi_scan, CONFIG_POUCH_PROV_LOG_LEVEL);

#define SCAN_MAX CONFIG_POUCH_PROV_SCAN_CACHE
/* Entries per results page — a conservative bound that keeps the encoded
 * page within POUCH_PROV_MSG_MAX. */
#define PAGE_MAX 6

struct ap_entry {
	uint8_t ssid[WIFI_SSID_MAX_LEN];
	uint8_t ssid_len;
	uint8_t bssid[WIFI_MAC_ADDR_LEN];
	uint8_t channel;
	int8_t rssi;
	uint32_t auth;
};

static struct {
	struct ap_entry entries[SCAN_MAX];
	size_t count;
	bool finished;
	struct net_mgmt_event_callback cb;
	bool cb_registered;
} sc;

static void on_result(struct net_mgmt_event_callback *cb)
{
	const struct wifi_scan_result *r = (const struct wifi_scan_result *)cb->info;

	if (sc.count >= SCAN_MAX) {
		return;
	}
	struct ap_entry *e = &sc.entries[sc.count++];

	e->ssid_len = MIN(r->ssid_length, sizeof(e->ssid));
	memcpy(e->ssid, r->ssid, e->ssid_len);
	memcpy(e->bssid, r->mac, WIFI_MAC_ADDR_LEN);
	e->channel = r->channel;
	e->rssi = r->rssi;
	e->auth = r->security;
}

static void mgmt_event(struct net_mgmt_event_callback *cb, uint64_t event, struct net_if *iface)
{
	ARG_UNUSED(iface);
	switch (event) {
	case NET_EVENT_WIFI_SCAN_RESULT:
		on_result(cb);
		break;
	case NET_EVENT_WIFI_SCAN_DONE:
		sc.finished = true;
		break;
	default:
		break;
	}
}

int pouch_prov_wifi_scan_init(void)
{
	if (!sc.cb_registered) {
		net_mgmt_init_event_callback(&sc.cb, mgmt_event,
					     NET_EVENT_WIFI_SCAN_RESULT | NET_EVENT_WIFI_SCAN_DONE);
		net_mgmt_add_event_callback(&sc.cb);
		sc.cb_registered = true;
	}
	return 0;
}

static uint32_t do_start(void)
{
	struct net_if *iface = net_if_get_wifi_sta();

	if (iface == NULL) {
		iface = net_if_get_first_wifi();
	}
	if (iface == NULL) {
		return prov_status_status_internal_error_m_c;
	}

	sc.count = 0;
	sc.finished = false;

	if (net_mgmt(NET_REQUEST_WIFI_SCAN, iface, NULL, 0) != 0) {
		sc.finished = true;
		return prov_status_status_internal_error_m_c;
	}
	return prov_status_status_ok_m_c;
}

static int encode_results(uint32_t start, uint32_t want, uint8_t *rsp, size_t rsp_size,
			  size_t *rsp_len)
{
	struct scan_rsp_r out = {
		.scan_rsp_choice = scan_rsp_scan_results_rsp_m_c,
		.scan_rsp_scan_results_rsp_m.scan_results_rsp_prov_status_m.prov_status_choice =
			prov_status_status_ok_m_c,
	};
	struct scan_results_rsp *r = &out.scan_rsp_scan_results_rsp_m;
	size_t n = 0;

	for (uint32_t i = start; i < sc.count && n < want && n < PAGE_MAX; i++, n++) {
		struct ap_entry *e = &sc.entries[i];
		struct scan_entry *dst = &r->scan_results_rsp_scan_entry_m_l_scan_entry_m[n];

		dst->scan_entry_ssid.value = e->ssid;
		dst->scan_entry_ssid.len = e->ssid_len;
		dst->scan_entry_bssid.value = e->bssid;
		dst->scan_entry_bssid.len = WIFI_MAC_ADDR_LEN;
		dst->scan_entry_ch = e->channel;
		dst->scan_entry_rssi = e->rssi;
		dst->scan_entry_auth = e->auth;
	}
	r->scan_results_rsp_scan_entry_m_l_scan_entry_m_count = n;

	return cbor_encode_scan_rsp(rsp, rsp_size, &out, rsp_len) == 0 ? 0 : -ENOMEM;
}

int pouch_prov_handle_scan(const uint8_t *req, size_t req_len, uint8_t *rsp, size_t rsp_size,
			   size_t *rsp_len)
{
	struct scan_req_r in;
	size_t consumed;

	if (cbor_decode_scan_req(req, req_len, &in, &consumed) != 0) {
		return -EBADMSG;
	}

	switch (in.scan_req_choice) {
	case scan_req_scan_start_m_c: {
		struct scan_rsp_r out = {
			.scan_rsp_choice = scan_rsp_scan_start_rsp_m_c,
			.scan_rsp_scan_start_rsp_m.scan_start_rsp_prov_status_m.prov_status_choice =
				do_start(),
		};

		return cbor_encode_scan_rsp(rsp, rsp_size, &out, rsp_len) == 0 ? 0 : -ENOMEM;
	}
	case scan_req_scan_get_status_m_c: {
		struct scan_rsp_r out = {
			.scan_rsp_choice = scan_rsp_scan_status_rsp_m_c,
			.scan_rsp_scan_status_rsp_m = {
				.scan_status_rsp_prov_status_m.prov_status_choice =
					prov_status_status_ok_m_c,
				.scan_status_rsp_finished = sc.finished,
				.scan_status_rsp_total = sc.count,
			},
		};

		return cbor_encode_scan_rsp(rsp, rsp_size, &out, rsp_len) == 0 ? 0 : -ENOMEM;
	}
	case scan_req_scan_get_results_m_c:
		return encode_results(in.scan_req_scan_get_results_m.scan_get_results_start,
				      in.scan_req_scan_get_results_m.scan_get_results_count, rsp,
				      rsp_size, rsp_len);
	default:
		return -EBADMSG;
	}
}
