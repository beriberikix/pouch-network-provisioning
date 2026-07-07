/*
 * Copyright (c) 2026 Jonathan Beri
 * SPDX-License-Identifier: Apache-2.0
 *
 * .prov/ver — protocol version and capability discovery. Never gated.
 */

#include <errno.h>

#include <zephyr/kernel.h>

#include <prov_decode.h>
#include <prov_encode.h>

#include "pouch_prov_internal.h"

#define LIB_VERSION "0.1.0"
#define PROTO_VERSION 1

#define CAP(_s) { .value = (_s), .len = sizeof(_s) - 1 }

int pouch_prov_handle_ver(const uint8_t *req, size_t req_len, uint8_t *rsp, size_t rsp_size,
			  size_t *rsp_len)
{
	size_t consumed;

	if (cbor_decode_ver_req(req, req_len, NULL, &consumed) != 0) {
		return -EBADMSG;
	}

	struct ver_rsp out = {
		.ver_rsp_prov_status_m.prov_status_choice = prov_status_status_ok_m_c,
		.ver_rsp_ver_info_m = {
			.ver_info_proto = PROTO_VERSION,
			.ver_info_blk = CONFIG_POUCH_BLOCK_SIZE,
			.ver_info_lib = CAP(LIB_VERSION),
			.ver_info_pop = { .ver_info_pop = true },
			.ver_info_pop_present = true,
		},
	};

	size_t ncaps = 0;

	if (IS_ENABLED(CONFIG_POUCH_PROV_WIFI)) {
		out.ver_rsp_ver_info_m.ver_info_caps_tstr[ncaps++] =
			(struct zcbor_string)CAP("wifi");
		out.ver_rsp_ver_info_m.ver_info_caps_tstr[ncaps++] =
			(struct zcbor_string)CAP("scan");
	}
	if (IS_ENABLED(CONFIG_POUCH_PROV_CRED)) {
		out.ver_rsp_ver_info_m.ver_info_caps_tstr[ncaps++] =
			(struct zcbor_string)CAP("cred");
	}
	if (IS_ENABLED(CONFIG_POUCH_PROV_AUTH) && pouch_prov_config_get()->pop != NULL) {
		out.ver_rsp_ver_info_m.ver_info_caps_tstr[ncaps++] =
			(struct zcbor_string)CAP("auth");
	} else {
		out.ver_rsp_ver_info_m.ver_info_pop.ver_info_pop = false;
	}
	out.ver_rsp_ver_info_m.ver_info_caps_tstr_count = ncaps;

	return cbor_encode_ver_rsp(rsp, rsp_size, &out, rsp_len) == 0 ? 0 : -ENOMEM;
}
