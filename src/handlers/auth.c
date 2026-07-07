/*
 * Copyright (c) 2026 Jonathan Beri
 * SPDX-License-Identifier: Apache-2.0
 *
 * .prov/auth — mutual proof-of-possession authorization.
 *
 *   dev_proof = HMAC-SHA256(pop, "dev" || cli_nonce || dev_nonce)
 *   cli_proof = HMAC-SHA256(pop, "cli" || dev_nonce || cli_nonce)
 *
 * The client verifies dev_proof before sending cli_proof, so an impostor
 * device without the PoP reveals nothing. The device gates all other
 * endpoints until cli_proof verifies (see dispatch.c).
 */

#include <errno.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/random/random.h>

#include <psa/crypto.h>

#include <prov_decode.h>
#include <prov_encode.h>

#include "pouch_prov_internal.h"

LOG_MODULE_REGISTER(pouch_prov_auth, CONFIG_POUCH_PROV_LOG_LEVEL);

#define NONCE_LEN 16
#define PROOF_LEN 32
#define MAX_ATTEMPTS 3

static struct {
	uint8_t cli_nonce[NONCE_LEN];
	uint8_t dev_nonce[NONCE_LEN];
	bool challenged;
	uint8_t attempts;
} state;

void pouch_prov_auth_reset(void)
{
	memset(&state, 0, sizeof(state));
}

static int hmac_proof(const char *tag, const uint8_t *first, const uint8_t *second,
		      uint8_t out[PROOF_LEN])
{
	const struct pouch_prov_config *cfg = pouch_prov_config_get();
	psa_mac_operation_t op = PSA_MAC_OPERATION_INIT;
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key;
	size_t out_len;
	int ret = -EIO;

	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_MESSAGE);
	psa_set_key_algorithm(&attr, PSA_ALG_HMAC(PSA_ALG_SHA_256));
	psa_set_key_type(&attr, PSA_KEY_TYPE_HMAC);

	if (psa_import_key(&attr, (const uint8_t *)cfg->pop, strlen(cfg->pop), &key) !=
	    PSA_SUCCESS) {
		return -EIO;
	}

	if (psa_mac_sign_setup(&op, key, PSA_ALG_HMAC(PSA_ALG_SHA_256)) != PSA_SUCCESS) {
		goto out;
	}
	if (psa_mac_update(&op, (const uint8_t *)tag, 3) != PSA_SUCCESS ||
	    psa_mac_update(&op, first, NONCE_LEN) != PSA_SUCCESS ||
	    psa_mac_update(&op, second, NONCE_LEN) != PSA_SUCCESS) {
		psa_mac_abort(&op);
		goto out;
	}
	if (psa_mac_sign_finish(&op, out, PROOF_LEN, &out_len) == PSA_SUCCESS &&
	    out_len == PROOF_LEN) {
		ret = 0;
	}

out:
	psa_destroy_key(key);
	return ret;
}

static int respond_status(uint32_t op, uint32_t status, uint8_t *rsp, size_t rsp_size,
			  size_t *rsp_len)
{
	struct auth_rsp_r out = {
		.auth_rsp_choice = auth_rsp_auth_proof_rsp_m_c,
		.auth_rsp_auth_proof_rsp_m.auth_proof_rsp_prov_status_m.prov_status_choice = status,
	};

	return cbor_encode_auth_rsp(rsp, rsp_size, &out, rsp_len) == 0 ? 0 : -ENOMEM;
}

int pouch_prov_handle_auth(const uint8_t *req, size_t req_len, uint8_t *rsp, size_t rsp_size,
			   size_t *rsp_len)
{
	struct auth_req_r in;
	size_t consumed;

	if (cbor_decode_auth_req(req, req_len, &in, &consumed) != 0) {
		return -EBADMSG;
	}

	if (in.auth_req_choice == auth_req_auth_challenge_m_c) {
		const struct zcbor_string *nonce =
			&in.auth_req_auth_challenge_m.auth_challenge_cli_nonce;

		if (nonce->len != NONCE_LEN) {
			return -EBADMSG;
		}
		memcpy(state.cli_nonce, nonce->value, NONCE_LEN);
		sys_rand_get(state.dev_nonce, NONCE_LEN);
		state.challenged = true;

		uint8_t proof[PROOF_LEN];

		if (hmac_proof("dev", state.cli_nonce, state.dev_nonce, proof) != 0) {
			return -EIO;
		}

		struct auth_rsp_r out = {
			.auth_rsp_choice = auth_rsp_auth_challenge_rsp_m_c,
			.auth_rsp_auth_challenge_rsp_m = {
				.auth_challenge_rsp_prov_status_m.prov_status_choice =
					prov_status_status_ok_m_c,
				.auth_challenge_rsp_dev_nonce = { .value = state.dev_nonce,
								  .len = NONCE_LEN },
				.auth_challenge_rsp_dev_proof = { .value = proof,
								  .len = PROOF_LEN },
			},
		};

		return cbor_encode_auth_rsp(rsp, rsp_size, &out, rsp_len) == 0 ? 0 : -ENOMEM;
	}

	/* proof */
	const struct zcbor_string *proof = &in.auth_req_auth_proof_m.auth_proof_cli_proof;

	if (!state.challenged || proof->len != PROOF_LEN) {
		return respond_status(1, prov_status_status_invalid_state_m_c, rsp, rsp_size,
				      rsp_len);
	}

	if (++state.attempts > MAX_ATTEMPTS) {
		return respond_status(1, prov_status_status_unauthorized_m_c, rsp, rsp_size,
				      rsp_len);
	}

	uint8_t expected[PROOF_LEN];

	if (hmac_proof("cli", state.dev_nonce, state.cli_nonce, expected) != 0) {
		return -EIO;
	}

	/* Constant-time compare. */
	uint8_t diff = 0;

	for (size_t i = 0; i < PROOF_LEN; i++) {
		diff |= expected[i] ^ proof->value[i];
	}

	if (diff != 0) {
		LOG_WRN("Client proof mismatch (attempt %u)", state.attempts);
		return respond_status(1, prov_status_status_unauthorized_m_c, rsp, rsp_size,
				      rsp_len);
	}

	pouch_prov_session_set_authorized(true);
	LOG_INF("Session authorized");
	return respond_status(1, prov_status_status_ok_m_c, rsp, rsp_size, rsp_len);
}
