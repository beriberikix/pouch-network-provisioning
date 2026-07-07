/*
 * Copyright (c) 2026 Jonathan Beri
 * SPDX-License-Identifier: Apache-2.0
 *
 * .prov/cred — cloud credential bootstrap. The client writes DER blobs
 * (device cert, private key, CA cert) in ordered chunks, then finalizes to
 * validate and persist them. The application later reads them for its cloud
 * client (see include/pouch_prov/credentials.h).
 */

#include <errno.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include <prov_decode.h>
#include <prov_encode.h>

#include <pouch_prov/credentials.h>

#include "pouch_prov_internal.h"

LOG_MODULE_REGISTER(pouch_prov_cred, CONFIG_POUCH_PROV_LOG_LEVEL);

static int status_map(int rc)
{
	switch (rc) {
	case 0:
		return prov_status_status_ok_m_c;
	case -EINVAL:
	case -EMSGSIZE:
	case -EBADMSG:
		return prov_status_status_invalid_argument_m_c;
	default:
		return prov_status_status_internal_error_m_c;
	}
}

int pouch_prov_handle_cred(const uint8_t *req, size_t req_len, uint8_t *rsp, size_t rsp_size,
			   size_t *rsp_len)
{
	struct cred_req_r in;
	size_t consumed;

	if (cbor_decode_cred_req(req, req_len, &in, &consumed) != 0) {
		return -EBADMSG;
	}

	switch (in.cred_req_choice) {
	case cred_req_cred_write_m_c: {
		const struct cred_chunk *c = &in.cred_req_cred_write_m.cred_write_cred_chunk_m;
		int rc = pouch_prov_cred_stage(c->cred_chunk_kind.cred_kind_choice, c->cred_chunk_off,
					       c->cred_chunk_total, c->cred_chunk_data.value,
					       c->cred_chunk_data.len);

		struct cred_rsp_r out = {
			.cred_rsp_choice = cred_rsp_cred_write_rsp_m_c,
			.cred_rsp_cred_write_rsp_m = {
				.cred_write_rsp_prov_status_m.prov_status_choice =
					status_map(rc < 0 ? rc : 0),
				.cred_write_rsp_received = rc < 0 ? 0 : (uint32_t)rc,
			},
		};

		return cbor_encode_cred_rsp(rsp, rsp_size, &out, rsp_len) == 0 ? 0 : -ENOMEM;
	}
	case cred_req_cred_finalize_m_c: {
		int rc = pouch_prov_cred_finalize();
		struct cred_rsp_r out = {
			.cred_rsp_choice = cred_rsp_cred_finalize_rsp_m_c,
			.cred_rsp_cred_finalize_rsp_m.cred_finalize_rsp_prov_status_m.prov_status_choice =
				status_map(rc),
		};

		return cbor_encode_cred_rsp(rsp, rsp_size, &out, rsp_len) == 0 ? 0 : -ENOMEM;
	}
	case cred_req_cred_get_status_m_c: {
		static const char *const key_name[] = {"0", "1", "2"};
		struct cred_rsp_r out = {
			.cred_rsp_choice = cred_rsp_cred_status_rsp_m_c,
			.cred_rsp_cred_status_rsp_m.cred_status_rsp_prov_status_m.prov_status_choice =
				prov_status_status_ok_m_c,
		};
		struct cred_status_rsp *s = &out.cred_rsp_cred_status_rsp_m;
		size_t n = 0;

		for (int k = 0; k < 3; k++) {
			size_t got = pouch_prov_cred_received(k);

			if (got == 0) {
				continue;
			}
			s->map_tstruint[n].cred_status_rsp_map_tstruint_key =
				(struct zcbor_string){ .value = key_name[k], .len = 1 };
			s->map_tstruint[n].map_tstruint = got;
			n++;
		}
		s->map_tstruint_count = n;

		return cbor_encode_cred_rsp(rsp, rsp_size, &out, rsp_len) == 0 ? 0 : -ENOMEM;
	}
	default:
		return -EBADMSG;
	}
}
