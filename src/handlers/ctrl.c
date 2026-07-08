/*
 * Copyright (c) 2026 Jonathan Beri
 * SPDX-License-Identifier: Apache-2.0
 *
 * .prov/ctrl — provisioning state-machine control: reset, re-provision,
 * end. End signals the manager that the client is done.
 */

#include <errno.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include <prov_decode.h>
#include <prov_encode.h>

#include <pouch_prov/credentials.h>

#include "pouch_prov_internal.h"

LOG_MODULE_REGISTER(pouch_prov_ctrl, CONFIG_POUCH_PROV_LOG_LEVEL);

int pouch_prov_handle_ctrl(const uint8_t *req, size_t req_len, uint8_t *rsp, size_t rsp_size,
			   size_t *rsp_len)
{
	struct ctrl_req_r in;
	size_t consumed;
	uint32_t op;

	if (cbor_decode_ctrl_req(req, req_len, &in, &consumed) != 0) {
		return -EBADMSG;
	}

	switch (in.ctrl_req_choice) {
	case ctrl_req_ctrl_reset_m_c:
		op = OP_CTRL_RESET;
#if defined(CONFIG_POUCH_PROV_WIFI)
		/* Reset the Wi-Fi state machine without wiping stored creds.
		 * A no-op on cred-only builds (nothing staged to reset). */
		pouch_prov_wifi_reset_state();
#endif
		break;
	case ctrl_req_ctrl_reprovision_m_c:
		op = OP_CTRL_REPROV;
		/* Wipe every credential the device might have been provisioned
		 * with so it can be re-provisioned from scratch. */
#if defined(CONFIG_POUCH_PROV_WIFI)
		pouch_prov_wifi_reprovision();
#endif
#if defined(CONFIG_POUCH_PROV_CRED)
		(void)pouch_prov_cred_delete_all();
#endif
		break;
	case ctrl_req_ctrl_end_m_c:
		op = OP_CTRL_END;
		break;
	default:
		return -EBADMSG;
	}

	struct ctrl_rsp out = {
		.ctrl_rsp_ctrl_op_m = op,
		.ctrl_rsp_prov_status_m.prov_status_choice = prov_status_status_ok_m_c,
	};
	int err = cbor_encode_ctrl_rsp(rsp, rsp_size, &out, rsp_len);

	/* The end request is the last exchange: let the manager stop after the
	 * response has been queued. */
	if (op == OP_CTRL_END && err == 0) {
		pouch_prov_ctrl_end_requested();
	}
	return err == 0 ? 0 : -ENOMEM;
}
