/*
 * Copyright (c) 2026 Jonathan Beri
 * SPDX-License-Identifier: Apache-2.0
 *
 * Drives the .prov/config, .prov/scan and .prov/ctrl handlers against the
 * fake Wi-Fi backend: connect success/auth-fail/not-found, credential
 * cleanup on failure, scan pagination.
 */

#include <zephyr/ztest.h>
#include <zephyr/kernel.h>
#include <zephyr/net/wifi_credentials.h>

#include <prov_decode.h>
#include <prov_encode.h>

#include "pouch_prov_internal.h"
#include "pouch_prov/test/fake_wifi.h"

/* Stub the manager event sink; the handlers only emit through this. */
static enum pouch_prov_event last_event = (enum pouch_prov_event)-1;
static enum pouch_prov_fail_reason last_fail;

void pouch_prov_emit(enum pouch_prov_event event, const void *data)
{
	last_event = event;
	if (event == POUCH_PROV_EVENT_WIFI_FAIL && data != NULL) {
		last_fail = *(const enum pouch_prov_fail_reason *)data;
	}
}

/* ctrl.c calls this on an end request; not exercised here. */
void pouch_prov_ctrl_end_requested(void)
{
}

static const struct fake_wifi_ap AP = {
	.ssid = "testnet", .ssid_len = 7, .bssid = {1, 2, 3, 4, 5, 6},
	.channel = 6, .rssi = -50, .security = WIFI_SECURITY_TYPE_PSK,
};

static void reset_all(void *unused)
{
	ARG_UNUSED(unused);
	fake_wifi_reset();
	(void)wifi_credentials_delete_all();
	pouch_prov_wifi_config_reset();
}

ZTEST_SUITE(wifi_handlers, NULL, NULL, reset_all, NULL, NULL);

/* Encode a config set + apply, run them, and pump the connect work. */
static uint32_t apply_creds(const char *ssid, const char *pass)
{
	uint8_t buf[128], rsp[128];
	size_t len, rlen;
	struct config_req_r req = {
		.config_req_choice = config_req_config_set_m_c,
		.config_req_config_set_m.config_set_wifi_config_m = {
			.wifi_config_ssid = { .value = ssid, .len = strlen(ssid) },
			.wifi_config_pass_present = pass != NULL,
		},
	};
	if (pass != NULL) {
		req.config_req_config_set_m.config_set_wifi_config_m.wifi_config_pass
			.wifi_config_pass = (struct zcbor_string){ .value = pass,
								   .len = strlen(pass) };
	}
	zassert_ok(cbor_encode_config_req(buf, sizeof(buf), &req, &len));
	zassert_ok(pouch_prov_handle_config(buf, len, rsp, sizeof(rsp), &rlen));

	struct config_req_r apply = { .config_req_choice = config_req_config_apply_m_c };

	zassert_ok(cbor_encode_config_req(buf, sizeof(buf), &apply, &len));
	zassert_ok(pouch_prov_handle_config(buf, len, rsp, sizeof(rsp), &rlen));

	k_sleep(K_MSEC(200)); /* let the fake connect work + net_mgmt event run */

	/* Poll status. */
	struct config_req_r status = { .config_req_choice = config_req_config_get_status_m_c };

	zassert_ok(cbor_encode_config_req(buf, sizeof(buf), &status, &len));
	zassert_ok(pouch_prov_handle_config(buf, len, rsp, sizeof(rsp), &rlen));

	struct config_rsp_r out;
	size_t consumed;

	zassert_ok(cbor_decode_config_rsp(rsp, rlen, &out, &consumed));
	zassert_equal(out.config_rsp_choice, config_rsp_config_status_rsp_m_c);
	return out.config_rsp_config_status_rsp_m.config_status_rsp_sta_state_m.sta_state_choice;
}

ZTEST(wifi_handlers, test_connect_success)
{
	fake_wifi_set_scan_aps(&AP, 1);
	fake_wifi_set_expected_credentials("testnet", "hunter22");

	uint32_t state = apply_creds("testnet", "hunter22");

	zassert_equal(state, sta_state_sta_connected_m_c);
	zassert_equal(last_event, POUCH_PROV_EVENT_WIFI_CONNECTED);
	zassert_false(wifi_credentials_is_empty(), "creds should be stored");
}

ZTEST(wifi_handlers, test_wrong_password_deletes_creds)
{
	fake_wifi_set_scan_aps(&AP, 1);
	fake_wifi_set_expected_credentials("testnet", "correct-pass");

	uint32_t state = apply_creds("testnet", "wrong-pass");

	zassert_equal(state, sta_state_sta_failed_m_c);
	zassert_equal(last_event, POUCH_PROV_EVENT_WIFI_FAIL);
	zassert_equal(last_fail, POUCH_PROV_FAIL_AUTH_ERROR);
	zassert_true(wifi_credentials_is_empty(), "failed creds must be deleted");
}

ZTEST(wifi_handlers, test_network_not_found)
{
	/* No AP programmed -> creds_outcome returns AP_NOT_FOUND. */
	fake_wifi_set_expected_credentials("ghost", "whatever1");

	uint32_t state = apply_creds("ghost", "whatever1");

	zassert_equal(state, sta_state_sta_failed_m_c);
	zassert_equal(last_fail, POUCH_PROV_FAIL_NETWORK_NOT_FOUND);
}

ZTEST(wifi_handlers, test_scan_and_paginate)
{
	struct fake_wifi_ap aps[3] = {AP, AP, AP};

	memcpy(aps[1].ssid, "netB", 4); aps[1].ssid_len = 4;
	memcpy(aps[2].ssid, "netC", 4); aps[2].ssid_len = 4;
	fake_wifi_set_scan_aps(aps, 3);

	uint8_t buf[64], rsp[256];
	size_t len, rlen, consumed;

	/* Start. */
	struct scan_req_r start = { .scan_req_choice = scan_req_scan_start_m_c };

	zassert_ok(cbor_encode_scan_req(buf, sizeof(buf), &start, &len));
	zassert_ok(pouch_prov_handle_scan(buf, len, rsp, sizeof(rsp), &rlen));

	k_sleep(K_MSEC(200));

	/* Status: finished, 3 results. */
	struct scan_req_r st = { .scan_req_choice = scan_req_scan_get_status_m_c };

	zassert_ok(cbor_encode_scan_req(buf, sizeof(buf), &st, &len));
	zassert_ok(pouch_prov_handle_scan(buf, len, rsp, sizeof(rsp), &rlen));

	struct scan_rsp_r sr;

	zassert_ok(cbor_decode_scan_rsp(rsp, rlen, &sr, &consumed));
	zassert_true(sr.scan_rsp_scan_status_rsp_m.scan_status_rsp_finished);
	zassert_equal(sr.scan_rsp_scan_status_rsp_m.scan_status_rsp_total, 3);

	/* Fetch page of 2 from index 1. */
	struct scan_req_r res = {
		.scan_req_choice = scan_req_scan_get_results_m_c,
		.scan_req_scan_get_results_m = { .scan_get_results_start = 1,
						 .scan_get_results_count = 2 },
	};

	zassert_ok(cbor_encode_scan_req(buf, sizeof(buf), &res, &len));
	zassert_ok(pouch_prov_handle_scan(buf, len, rsp, sizeof(rsp), &rlen));
	zassert_ok(cbor_decode_scan_rsp(rsp, rlen, &sr, &consumed));
	zassert_equal(sr.scan_rsp_choice, scan_rsp_scan_results_rsp_m_c);
	zassert_equal(sr.scan_rsp_scan_results_rsp_m.scan_results_rsp_scan_entry_m_l_scan_entry_m_count,
		      2);
}

ZTEST(wifi_handlers, test_ctrl_reprovision_wipes)
{
	fake_wifi_set_scan_aps(&AP, 1);
	fake_wifi_set_expected_credentials("testnet", "hunter22");
	(void)apply_creds("testnet", "hunter22");
	zassert_false(wifi_credentials_is_empty());

	uint8_t buf[16], rsp[16];
	size_t len, rlen;
	struct ctrl_req_r ctrl = { .ctrl_req_choice = ctrl_req_ctrl_reprovision_m_c };

	zassert_ok(cbor_encode_ctrl_req(buf, sizeof(buf), &ctrl, &len));
	zassert_ok(pouch_prov_handle_ctrl(buf, len, rsp, sizeof(rsp), &rlen));
	zassert_true(wifi_credentials_is_empty(), "reprovision must wipe creds");
}
