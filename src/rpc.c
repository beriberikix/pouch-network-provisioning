/*
 * Copyright (c) 2026 Jonathan Beri
 * SPDX-License-Identifier: Apache-2.0
 *
 * Response queue and uplink flushing.
 *
 * Pouch uplinks are device-initiated batches: when the client subscribes
 * the uplink characteristic, pouch starts an uplink pouch, runs every
 * POUCH_UPLINK_HANDLER on its work queue, then auto-closes the pouch.
 * Our handler drains the response queue into the open pouch, waiting up
 * to CONFIG_POUCH_PROV_RESPONSE_WAIT_MS for the first response so a
 * request that is still being processed isn't answered with an empty
 * pouch (the client treats an empty pouch as "retry later").
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include <pouch/types.h>
#include <pouch/uplink.h>

#include "pouch_prov_internal.h"

LOG_MODULE_REGISTER(pouch_prov_rpc, CONFIG_POUCH_PROV_LOG_LEVEL);

struct rpc_rsp {
	void *fifo_reserved;
	const char *path; /* one of the static POUCH_PROV_PATH_* strings */
	size_t len;
	uint8_t msg[];
};

static K_FIFO_DEFINE(rsp_fifo);
static K_SEM_DEFINE(rsp_ready, 0, 1);

int pouch_prov_rpc_enqueue(const char *path, const uint8_t *msg, size_t len)
{
	struct rpc_rsp *rsp;

	if (len > POUCH_PROV_MSG_MAX) {
		return -EMSGSIZE;
	}

	rsp = k_malloc(sizeof(*rsp) + len);
	if (rsp == NULL) {
		return -ENOMEM;
	}

	rsp->path = path;
	rsp->len = len;
	memcpy(rsp->msg, msg, len);

	k_fifo_put(&rsp_fifo, rsp);
	k_sem_give(&rsp_ready);

	return 0;
}

void pouch_prov_rpc_reset(void)
{
	struct rpc_rsp *rsp;

	while ((rsp = k_fifo_get(&rsp_fifo, K_NO_WAIT)) != NULL) {
		k_free(rsp);
	}
	k_sem_reset(&rsp_ready);
}

static void rpc_uplink_flush(void)
{
	struct rpc_rsp *rsp;
	int err;

	/* Wait for the first response if none is pending yet. */
	if (k_fifo_is_empty(&rsp_fifo)) {
		(void)k_sem_take(&rsp_ready, K_MSEC(CONFIG_POUCH_PROV_RESPONSE_WAIT_MS));
	}

	while ((rsp = k_fifo_get(&rsp_fifo, K_NO_WAIT)) != NULL) {
		err = pouch_uplink_entry_write(rsp->path, POUCH_CONTENT_TYPE_CBOR, rsp->msg,
					       rsp->len, K_MSEC(500));
		if (err != 0) {
			LOG_ERR("Uplink write failed (%d), dropping response for %s", err,
				rsp->path);
		}
		k_free(rsp);
	}
}

POUCH_UPLINK_HANDLER(rpc_uplink_flush);
