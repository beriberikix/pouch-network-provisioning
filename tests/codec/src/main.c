/*
 * Copyright (c) 2026 Jonathan Beri
 * SPDX-License-Identifier: Apache-2.0
 *
 * Pins the zcbor-generated device codec to the shared golden vectors
 * (tests/vectors/*.json), the same bytes the Python CLI is tested
 * against. Decode tests consume CLI-encoded requests; encode tests must
 * produce byte-identical responses to what the CLI decodes.
 */

#include <zephyr/ztest.h>

#include <prov_decode.h>
#include <prov_encode.h>

#include "vectors.inc"

ZTEST_SUITE(prov_codec, NULL, NULL, NULL, NULL, NULL);

/* ---- Request decoding (CLI -> device) ---------------------------------- */

ZTEST(prov_codec, test_decode_ver_req)
{
	size_t consumed;

	zassert_ok(cbor_decode_ver_req(vec_ver_req, sizeof(vec_ver_req), NULL, &consumed));
	zassert_equal(consumed, sizeof(vec_ver_req));
}

ZTEST(prov_codec, test_decode_config_set_full)
{
	struct config_req_r req;
	size_t consumed;

	zassert_ok(cbor_decode_config_req(vec_config_set_full, sizeof(vec_config_set_full), &req,
					  &consumed));
	zassert_equal(req.config_req_choice, config_req_config_set_m_c);

	const struct wifi_config *cfg =
		&req.config_req_config_set_m.config_set_wifi_config_m;
	zassert_equal(cfg->wifi_config_ssid.len, 6);
	zassert_mem_equal(cfg->wifi_config_ssid.value, "myssid", 6);
	zassert_true(cfg->wifi_config_pass_present);
	zassert_mem_equal(cfg->wifi_config_pass.wifi_config_pass.value, "hunter22", 8);
	zassert_true(cfg->wifi_config_bssid_present);
	zassert_equal(cfg->wifi_config_bssid.wifi_config_bssid.len, 6);
	zassert_true(cfg->wifi_config_ch_present);
	zassert_equal(cfg->wifi_config_ch.wifi_config_ch, 11);
}

ZTEST(prov_codec, test_decode_config_set_minimal)
{
	struct config_req_r req;
	size_t consumed;

	zassert_ok(cbor_decode_config_req(vec_config_set_minimal, sizeof(vec_config_set_minimal),
					  &req, &consumed));
	zassert_equal(req.config_req_choice, config_req_config_set_m_c);

	const struct wifi_config *cfg =
		&req.config_req_config_set_m.config_set_wifi_config_m;
	zassert_mem_equal(cfg->wifi_config_ssid.value, "open-net", 8);
	zassert_false(cfg->wifi_config_pass_present);
	zassert_false(cfg->wifi_config_bssid_present);
	zassert_false(cfg->wifi_config_ch_present);
}

ZTEST(prov_codec, test_decode_config_ops)
{
	struct config_req_r req;
	size_t consumed;

	zassert_ok(cbor_decode_config_req(vec_config_get_status, sizeof(vec_config_get_status),
					  &req, &consumed));
	zassert_equal(req.config_req_choice, config_req_config_get_status_m_c);

	zassert_ok(cbor_decode_config_req(vec_config_apply, sizeof(vec_config_apply), &req,
					  &consumed));
	zassert_equal(req.config_req_choice, config_req_config_apply_m_c);
}

ZTEST(prov_codec, test_decode_auth_reqs)
{
	struct auth_req_r req;
	size_t consumed;

	zassert_ok(cbor_decode_auth_req(vec_auth_challenge, sizeof(vec_auth_challenge), &req,
					&consumed));
	zassert_equal(req.auth_req_choice, auth_req_auth_challenge_m_c);
	zassert_equal(req.auth_req_auth_challenge_m.auth_challenge_cli_nonce.len, 16);

	zassert_ok(cbor_decode_auth_req(vec_auth_proof, sizeof(vec_auth_proof), &req, &consumed));
	zassert_equal(req.auth_req_choice, auth_req_auth_proof_m_c);
	zassert_equal(req.auth_req_auth_proof_m.auth_proof_cli_proof.len, 32);
}

ZTEST(prov_codec, test_decode_scan_reqs)
{
	struct scan_req_r req;
	size_t consumed;

	zassert_ok(cbor_decode_scan_req(vec_scan_start_defaults, sizeof(vec_scan_start_defaults),
					&req, &consumed));
	zassert_equal(req.scan_req_choice, scan_req_scan_start_m_c);

	zassert_ok(cbor_decode_scan_req(vec_scan_start_passive, sizeof(vec_scan_start_passive),
					&req, &consumed));
	const struct scan_params *params =
		&req.scan_req_scan_start_m.scan_start_scan_params_m;
	zassert_true(params->scan_params_passive_present);
	zassert_true(params->scan_params_passive.scan_params_passive);
	zassert_true(params->scan_params_period_ms_present);
	zassert_equal(params->scan_params_period_ms.scan_params_period_ms, 120);

	zassert_ok(cbor_decode_scan_req(vec_scan_get_results, sizeof(vec_scan_get_results), &req,
					&consumed));
	zassert_equal(req.scan_req_choice, scan_req_scan_get_results_m_c);
	zassert_equal(req.scan_req_scan_get_results_m.scan_get_results_start, 4);
	zassert_equal(req.scan_req_scan_get_results_m.scan_get_results_count, 6);
}

ZTEST(prov_codec, test_decode_cred_write)
{
	struct cred_req_r req;
	size_t consumed;

	zassert_ok(cbor_decode_cred_req(vec_cred_write, sizeof(vec_cred_write), &req, &consumed));
	zassert_equal(req.cred_req_choice, cred_req_cred_write_m_c);

	const struct cred_chunk *chunk = &req.cred_req_cred_write_m.cred_write_cred_chunk_m;
	zassert_equal(chunk->cred_chunk_kind.cred_kind_choice, cred_kind_cred_device_cert_m_c);
	zassert_equal(chunk->cred_chunk_off, 0);
	zassert_equal(chunk->cred_chunk_total, 6);
	zassert_equal(chunk->cred_chunk_data.len, 6);
	zassert_equal(chunk->cred_chunk_data.value[0], 0x30);
}

ZTEST(prov_codec, test_decode_ctrl_reqs)
{
	struct ctrl_req_r req;
	size_t consumed;

	zassert_ok(cbor_decode_ctrl_req(vec_ctrl_reset, sizeof(vec_ctrl_reset), &req, &consumed));
	zassert_equal(req.ctrl_req_choice, ctrl_req_ctrl_reset_m_c);
	zassert_ok(cbor_decode_ctrl_req(vec_ctrl_end, sizeof(vec_ctrl_end), &req, &consumed));
	zassert_equal(req.ctrl_req_choice, ctrl_req_ctrl_end_m_c);
}

/* ---- Response encoding (device -> CLI) ---------------------------------- */

ZTEST(prov_codec, test_encode_ver_rsp)
{
	uint8_t buf[128];
	size_t len;
	struct ver_rsp rsp = {
		.ver_rsp_prov_status_m.prov_status_choice = prov_status_status_ok_m_c,
		.ver_rsp_ver_info_m = {
			.ver_info_proto = 1,
			.ver_info_caps_tstr = {
				{ .value = "wifi", .len = 4 },
				{ .value = "scan", .len = 4 },
				{ .value = "cred", .len = 4 },
				{ .value = "auth", .len = 4 },
			},
			.ver_info_caps_tstr_count = 4,
			.ver_info_blk = 512,
			.ver_info_lib = { .value = "0.1.0", .len = 5 },
			.ver_info_pop = { .ver_info_pop = true },
			.ver_info_pop_present = true,
		},
	};

	zassert_ok(cbor_encode_ver_rsp(buf, sizeof(buf), &rsp, &len));
	zassert_equal(len, sizeof(vec_ver_rsp), "len %zu != %zu", len, sizeof(vec_ver_rsp));
	zassert_mem_equal(buf, vec_ver_rsp, len);
}

ZTEST(prov_codec, test_encode_config_status_connected)
{
	uint8_t buf[128];
	size_t len;
	static const uint8_t ip4[] = { 192, 168, 1, 7 };
	struct config_rsp_r rsp = {
		.config_rsp_choice = config_rsp_config_status_rsp_m_c,
		.config_rsp_config_status_rsp_m = {
			.config_status_rsp_prov_status_m.prov_status_choice =
				prov_status_status_ok_m_c,
			.config_status_rsp_sta_state_m.sta_state_choice =
				sta_state_sta_connected_m_c,
			.config_status_rsp_config_detail_m_present = true,
			.config_status_rsp_config_detail_m = {
				.config_detail_choice = config_detail_connected_info_m_c,
				.config_detail_connected_info_m = {
					.connected_info_ip4 = { .value = ip4, .len = 4 },
					.connected_info_ssid = { .value = "myssid", .len = 6 },
					.connected_info_rssi_present = true,
					.connected_info_rssi = { .connected_info_rssi = -41 },
				},
			},
		},
	};

	zassert_ok(cbor_encode_config_rsp(buf, sizeof(buf), &rsp, &len));
	zassert_equal(len, sizeof(vec_config_status_connected));
	zassert_mem_equal(buf, vec_config_status_connected, len);
}

ZTEST(prov_codec, test_encode_config_status_failed_auth)
{
	uint8_t buf[64];
	size_t len;
	struct config_rsp_r rsp = {
		.config_rsp_choice = config_rsp_config_status_rsp_m_c,
		.config_rsp_config_status_rsp_m = {
			.config_status_rsp_prov_status_m.prov_status_choice =
				prov_status_status_ok_m_c,
			.config_status_rsp_sta_state_m.sta_state_choice =
				sta_state_sta_failed_m_c,
			.config_status_rsp_config_detail_m_present = true,
			.config_status_rsp_config_detail_m = {
				.config_detail_choice = config_detail_fail_reason_m_c,
				.config_detail_fail_reason_m.fail_reason_choice =
					fail_reason_fail_auth_error_m_c,
			},
		},
	};

	zassert_ok(cbor_encode_config_rsp(buf, sizeof(buf), &rsp, &len));
	zassert_equal(len, sizeof(vec_config_status_failed_auth));
	zassert_mem_equal(buf, vec_config_status_failed_auth, len);
}

ZTEST(prov_codec, test_encode_auth_challenge_rsp)
{
	uint8_t buf[128];
	size_t len;
	uint8_t nonce[16], proof[32];

	for (int i = 0; i < 16; i++) {
		nonce[i] = 16 + i;
	}
	for (int i = 0; i < 32; i++) {
		proof[i] = 32 + i;
	}

	struct auth_rsp_r rsp = {
		.auth_rsp_choice = auth_rsp_auth_challenge_rsp_m_c,
		.auth_rsp_auth_challenge_rsp_m = {
			.auth_challenge_rsp_prov_status_m.prov_status_choice =
				prov_status_status_ok_m_c,
			.auth_challenge_rsp_dev_nonce = { .value = nonce, .len = 16 },
			.auth_challenge_rsp_dev_proof = { .value = proof, .len = 32 },
		},
	};

	zassert_ok(cbor_encode_auth_rsp(buf, sizeof(buf), &rsp, &len));
	zassert_equal(len, sizeof(vec_auth_challenge_rsp));
	zassert_mem_equal(buf, vec_auth_challenge_rsp, len);
}

ZTEST(prov_codec, test_encode_scan_results_rsp)
{
	uint8_t buf[256];
	size_t len;
	static const uint8_t bssid0[] = { 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6 };
	static const uint8_t bssid1[] = { 0x06, 0x11, 0x22, 0x33, 0x44, 0xff };
	struct scan_rsp_r rsp = {
		.scan_rsp_choice = scan_rsp_scan_results_rsp_m_c,
		.scan_rsp_scan_results_rsp_m = {
			.scan_results_rsp_prov_status_m.prov_status_choice =
				prov_status_status_ok_m_c,
			.scan_results_rsp_scan_entry_m_l_scan_entry_m = {
				{
					.scan_entry_ssid = { .value = "myssid", .len = 6 },
					.scan_entry_bssid = { .value = bssid0, .len = 6 },
					.scan_entry_ch = 11,
					.scan_entry_rssi = -41,
					.scan_entry_auth = 1,
				},
				{
					.scan_entry_ssid = { .value = "guest", .len = 5 },
					.scan_entry_bssid = { .value = bssid1, .len = 6 },
					.scan_entry_ch = 1,
					.scan_entry_rssi = -73,
					.scan_entry_auth = 0,
				},
			},
			.scan_results_rsp_scan_entry_m_l_scan_entry_m_count = 2,
		},
	};

	zassert_ok(cbor_encode_scan_rsp(buf, sizeof(buf), &rsp, &len));
	zassert_equal(len, sizeof(vec_scan_results_rsp));
	zassert_mem_equal(buf, vec_scan_results_rsp, len);
}

ZTEST(prov_codec, test_encode_cred_status_rsp)
{
	uint8_t buf[64];
	size_t len;
	struct cred_rsp_r rsp = {
		.cred_rsp_choice = cred_rsp_cred_status_rsp_m_c,
		.cred_rsp_cred_status_rsp_m = {
			.cred_status_rsp_prov_status_m.prov_status_choice =
				prov_status_status_ok_m_c,
			.map_tstruint = {
				{
					.cred_status_rsp_map_tstruint_key = { .value = "0",
									      .len = 1 },
					.map_tstruint = 1042,
				},
				{
					.cred_status_rsp_map_tstruint_key = { .value = "1",
									      .len = 1 },
					.map_tstruint = 121,
				},
			},
			.map_tstruint_count = 2,
		},
	};

	zassert_ok(cbor_encode_cred_rsp(buf, sizeof(buf), &rsp, &len));
	zassert_equal(len, sizeof(vec_cred_status_rsp));
	zassert_mem_equal(buf, vec_cred_status_rsp, len);
}

ZTEST(prov_codec, test_encode_ctrl_rsp)
{
	uint8_t buf[16];
	size_t len;
	struct ctrl_rsp rsp = {
		.ctrl_rsp_ctrl_op_m = 2,
		.ctrl_rsp_prov_status_m.prov_status_choice = prov_status_status_ok_m_c,
	};

	zassert_ok(cbor_encode_ctrl_rsp(buf, sizeof(buf), &rsp, &len));
	zassert_equal(len, sizeof(vec_ctrl_end_rsp));
	zassert_mem_equal(buf, vec_ctrl_end_rsp, len);
}

/* ---- Robustness ---------------------------------------------------------- */

ZTEST(prov_codec, test_decode_rejects_garbage)
{
	struct config_req_r req;
	size_t consumed;
	static const uint8_t garbage[] = { 0xff, 0x00, 0x12, 0x34 };

	zassert_not_equal(cbor_decode_config_req(garbage, sizeof(garbage), &req, &consumed), 0);
	/* response bytes are not a valid request */
	zassert_not_equal(cbor_decode_auth_req(vec_ver_rsp, sizeof(vec_ver_rsp), NULL, &consumed),
			  0);
}
