/*
 * Copyright (c) 2026 Jonathan Beri
 * SPDX-License-Identifier: Apache-2.0
 *
 * Downlink entry dispatcher.
 *
 * Registers the single POUCH_DOWNLINK_HANDLER for the library and routes
 * .prov entries to endpoint handlers by exact path match. Entries on
 * other paths are ignored (they belong to other pouch services). Runs on
 * the pouch work-queue thread; requests are processed strictly in entry
 * order, which the RPC lockstep contract relies on.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include <pouch/downlink.h>
#include <pouch/types.h>

#include <prov_encode.h>

#include "pouch_prov_internal.h"

LOG_MODULE_REGISTER(pouch_prov_dispatch, CONFIG_POUCH_PROV_LOG_LEVEL);

static const struct pouch_prov_endpoint endpoints[] = {
	{ .path = POUCH_PROV_PATH_VER, .handler = pouch_prov_handle_ver, .require_auth = false },
#if defined(CONFIG_POUCH_PROV_AUTH)
	{ .path = POUCH_PROV_PATH_AUTH, .handler = pouch_prov_handle_auth, .require_auth = false },
#endif
	/* Available in every build: the `end` op stops provisioning regardless of
	 * device class (reset/reprovision are gated inside the handler). */
	{ .path = POUCH_PROV_PATH_CTRL, .handler = pouch_prov_handle_ctrl, .require_auth = true },
#if defined(CONFIG_POUCH_PROV_WIFI)
	{ .path = POUCH_PROV_PATH_CONFIG, .handler = pouch_prov_handle_config,
	  .require_auth = true },
	{ .path = POUCH_PROV_PATH_SCAN, .handler = pouch_prov_handle_scan, .require_auth = true },
#endif
#if defined(CONFIG_POUCH_PROV_CRED)
	{ .path = POUCH_PROV_PATH_CRED, .handler = pouch_prov_handle_cred, .require_auth = true },
#endif
};

static struct {
	const struct pouch_prov_endpoint *endpoint;
	size_t len;
	bool overflow;
	uint8_t buf[POUCH_PROV_MSG_MAX];
} active;

static bool authorized;

bool pouch_prov_session_authorized(void)
{
	return authorized || pouch_prov_config_get()->pop == NULL;
}

void pouch_prov_session_set_authorized(bool state)
{
	authorized = state;
}

void pouch_prov_dispatch_reset(void)
{
	active.endpoint = NULL;
	authorized = false;
#if defined(CONFIG_POUCH_PROV_AUTH)
	pouch_prov_auth_reset();
#endif
}

/**
 * Encode a bare [op, status] response. All response message families
 * share this shape for error reporting (ctrl-rsp in the schema).
 */
static void respond_status(const char *path, uint32_t op, uint32_t status)
{
	struct ctrl_rsp rsp = {
		.ctrl_rsp_ctrl_op_m = op,
		.ctrl_rsp_prov_status_m.prov_status_choice = status,
	};
	uint8_t buf[16];
	size_t len;

	if (cbor_encode_ctrl_rsp(buf, sizeof(buf), &rsp, &len) == 0) {
		(void)pouch_prov_rpc_enqueue(path, buf, len);
	}
}

/** Best-effort extraction of the op code (first uint) for error replies. */
static uint32_t peek_op(const uint8_t *msg, size_t len)
{
	/* Canonical CBOR: array header then a small uint (0..6 in v1). */
	if (len >= 2 && msg[0] >= 0x81 && msg[0] <= 0x84 && msg[1] <= 0x17) {
		return msg[1];
	}
	return 0;
}

static void downlink_start(unsigned int stream_id, const char *path, uint16_t content_type)
{
	active.endpoint = NULL;
	active.len = 0;
	active.overflow = false;

	if (stream_id != 0 || strncmp(path, ".prov/", 6) != 0) {
		return;
	}

	if (content_type != POUCH_CONTENT_TYPE_CBOR) {
		LOG_WRN("Ignoring %s with content type %u", path, content_type);
		return;
	}

	for (size_t i = 0; i < ARRAY_SIZE(endpoints); i++) {
		if (strcmp(endpoints[i].path, path) == 0) {
			active.endpoint = &endpoints[i];
			return;
		}
	}

	LOG_WRN("No provisioning endpoint for %s", path);
}

static void downlink_data(unsigned int stream_id, const void *data, size_t len, bool is_last)
{
	const struct pouch_prov_endpoint *ep = active.endpoint;

	if (ep == NULL || stream_id != 0) {
		return;
	}

	if (active.len + len > sizeof(active.buf)) {
		active.overflow = true;
	} else {
		memcpy(&active.buf[active.len], data, len);
		active.len += len;
	}

	if (!is_last) {
		return;
	}

	active.endpoint = NULL;

	if (active.overflow) {
		LOG_WRN("%s request exceeds %d bytes", ep->path, POUCH_PROV_MSG_MAX);
		respond_status(ep->path, 0, prov_status_status_invalid_argument_m_c);
		return;
	}

	if (ep->require_auth && !pouch_prov_session_authorized()) {
		respond_status(ep->path, peek_op(active.buf, active.len),
			       prov_status_status_unauthorized_m_c);
		return;
	}

	uint8_t rsp[POUCH_PROV_MSG_MAX];
	size_t rsp_len;
	int err = ep->handler(active.buf, active.len, rsp, sizeof(rsp), &rsp_len);

	if (err == -EBADMSG) {
		respond_status(ep->path, peek_op(active.buf, active.len),
			       prov_status_status_invalid_argument_m_c);
		return;
	}
	if (err != 0) {
		LOG_ERR("%s handler failed (%d)", ep->path, err);
		respond_status(ep->path, peek_op(active.buf, active.len),
			       prov_status_status_internal_error_m_c);
		return;
	}

	if (rsp_len > 0) {
		err = pouch_prov_rpc_enqueue(ep->path, rsp, rsp_len);
		if (err != 0) {
			LOG_ERR("Failed to queue %s response (%d)", ep->path, err);
		}
	}
}

POUCH_DOWNLINK_HANDLER(downlink_start, downlink_data);
