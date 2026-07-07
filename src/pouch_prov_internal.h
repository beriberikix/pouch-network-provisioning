/*
 * Copyright (c) 2026 Jonathan Beri
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <pouch_prov/events.h>
#include <pouch_prov/manager.h>

/** Reserved provisioning entry paths (docs/protocol.md). */
#define POUCH_PROV_PATH_VER    ".prov/ver"
#define POUCH_PROV_PATH_AUTH   ".prov/auth"
#define POUCH_PROV_PATH_CONFIG ".prov/config"
#define POUCH_PROV_PATH_SCAN   ".prov/scan"
#define POUCH_PROV_PATH_CRED   ".prov/cred"
#define POUCH_PROV_PATH_CTRL   ".prov/ctrl"

/** Response payload ceiling: fits one pouch entry in a 512-byte block. */
#define POUCH_PROV_MSG_MAX 384

/* Operation codes (cddl/prov.cddl). zcbor does not emit these as constants. */
#define OP_CONFIG_STATUS 0
#define OP_CONFIG_SET    1
#define OP_CONFIG_APPLY  2
#define OP_SCAN_START    0
#define OP_SCAN_STATUS   1
#define OP_SCAN_RESULTS  2
#define OP_CRED_WRITE    0
#define OP_CRED_FINALIZE 1
#define OP_CRED_STATUS   2
#define OP_CTRL_RESET    0
#define OP_CTRL_REPROV   1
#define OP_CTRL_END      2

/**
 * Endpoint request handler.
 *
 * Decodes @p req, writes the response message into @p rsp.
 * Runs on the pouch work-queue thread.
 *
 * @return 0 on success (rsp/rsp_len filled), negative errno to drop the
 *         request (no response entry is queued).
 */
typedef int (*pouch_prov_handler_t)(const uint8_t *req, size_t req_len, uint8_t *rsp,
				    size_t rsp_size, size_t *rsp_len);

struct pouch_prov_endpoint {
	const char *path;
	pouch_prov_handler_t handler;
	/** Reject with status unauthorized until the session is authorized. */
	bool require_auth;
};

/* dispatch.c */
void pouch_prov_dispatch_reset(void);
bool pouch_prov_session_authorized(void);
void pouch_prov_session_set_authorized(bool authorized);

/* rpc.c */
int pouch_prov_rpc_enqueue(const char *path, const uint8_t *msg, size_t len);
void pouch_prov_rpc_reset(void);

/* manager.c */
void pouch_prov_emit(enum pouch_prov_event event, const void *data);
const struct pouch_prov_config *pouch_prov_config_get(void);
void pouch_prov_mgr_session_ended(void);

/* adv.c */
int pouch_prov_adv_start(void);
int pouch_prov_adv_stop(void);

/* identity.c */
#if defined(CONFIG_POUCH_PROV_IDENTITY)
#include <pouch/types.h>
#include <psa/crypto.h>
int pouch_prov_identity_ensure(struct pouch_cert *cert_out, psa_key_id_t *key_out);
#endif

/* handlers */
int pouch_prov_handle_ver(const uint8_t *req, size_t req_len, uint8_t *rsp, size_t rsp_size,
			  size_t *rsp_len);
int pouch_prov_handle_auth(const uint8_t *req, size_t req_len, uint8_t *rsp, size_t rsp_size,
			   size_t *rsp_len);
/* Reset per-connection auth state (called on disconnect). */
void pouch_prov_auth_reset(void);

#if defined(CONFIG_POUCH_PROV_WIFI)
int pouch_prov_handle_config(const uint8_t *req, size_t req_len, uint8_t *rsp, size_t rsp_size,
			     size_t *rsp_len);
int pouch_prov_handle_scan(const uint8_t *req, size_t req_len, uint8_t *rsp, size_t rsp_size,
			   size_t *rsp_len);
int pouch_prov_handle_ctrl(const uint8_t *req, size_t req_len, uint8_t *rsp, size_t rsp_size,
			   size_t *rsp_len);

int pouch_prov_wifi_config_init(uint32_t conn_attempts);
int pouch_prov_wifi_scan_init(void);
void pouch_prov_wifi_config_reset(void);
bool pouch_prov_wifi_is_provisioned(void);

/* ctrl helpers */
void pouch_prov_wifi_reset_state(void);  /* reset SM without wiping creds */
void pouch_prov_wifi_reprovision(void);  /* wipe stored Wi-Fi credentials + reset */
void pouch_prov_ctrl_end_requested(void); /* manager: client is done */
#endif
