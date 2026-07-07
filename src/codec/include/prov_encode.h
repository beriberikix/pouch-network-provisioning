/*
 * Generated using zcbor version 0.9.1
 * https://github.com/NordicSemiconductor/zcbor
 * Generated with a --default-max-qty of 8
 */

#ifndef PROV_ENCODE_H__
#define PROV_ENCODE_H__

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "prov_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#if DEFAULT_MAX_QTY != 8
#error "The type file was generated with a different default_max_qty than this file"
#endif


int cbor_encode_ver_req(
		uint8_t *payload, size_t payload_len,
		const void *input,
		size_t *payload_len_out);


int cbor_encode_ver_rsp(
		uint8_t *payload, size_t payload_len,
		const struct ver_rsp *input,
		size_t *payload_len_out);


int cbor_encode_auth_req(
		uint8_t *payload, size_t payload_len,
		const struct auth_req_r *input,
		size_t *payload_len_out);


int cbor_encode_auth_rsp(
		uint8_t *payload, size_t payload_len,
		const struct auth_rsp_r *input,
		size_t *payload_len_out);


int cbor_encode_config_req(
		uint8_t *payload, size_t payload_len,
		const struct config_req_r *input,
		size_t *payload_len_out);


int cbor_encode_config_rsp(
		uint8_t *payload, size_t payload_len,
		const struct config_rsp_r *input,
		size_t *payload_len_out);


int cbor_encode_scan_req(
		uint8_t *payload, size_t payload_len,
		const struct scan_req_r *input,
		size_t *payload_len_out);


int cbor_encode_scan_rsp(
		uint8_t *payload, size_t payload_len,
		const struct scan_rsp_r *input,
		size_t *payload_len_out);


int cbor_encode_cred_req(
		uint8_t *payload, size_t payload_len,
		const struct cred_req_r *input,
		size_t *payload_len_out);


int cbor_encode_cred_rsp(
		uint8_t *payload, size_t payload_len,
		const struct cred_rsp_r *input,
		size_t *payload_len_out);


int cbor_encode_ctrl_req(
		uint8_t *payload, size_t payload_len,
		const struct ctrl_req_r *input,
		size_t *payload_len_out);


int cbor_encode_ctrl_rsp(
		uint8_t *payload, size_t payload_len,
		const struct ctrl_rsp *input,
		size_t *payload_len_out);


#ifdef __cplusplus
}
#endif

#endif /* PROV_ENCODE_H__ */
