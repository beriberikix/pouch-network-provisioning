/*
 * Generated using zcbor version 0.9.1
 * https://github.com/NordicSemiconductor/zcbor
 * Generated with a --default-max-qty of 8
 */

#ifndef PROV_DECODE_H__
#define PROV_DECODE_H__

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


int cbor_decode_ver_req(
		const uint8_t *payload, size_t payload_len,
		void *result,
		size_t *payload_len_out);


int cbor_decode_ver_rsp(
		const uint8_t *payload, size_t payload_len,
		struct ver_rsp *result,
		size_t *payload_len_out);


int cbor_decode_auth_req(
		const uint8_t *payload, size_t payload_len,
		struct auth_req_r *result,
		size_t *payload_len_out);


int cbor_decode_auth_rsp(
		const uint8_t *payload, size_t payload_len,
		struct auth_rsp_r *result,
		size_t *payload_len_out);


int cbor_decode_config_req(
		const uint8_t *payload, size_t payload_len,
		struct config_req_r *result,
		size_t *payload_len_out);


int cbor_decode_config_rsp(
		const uint8_t *payload, size_t payload_len,
		struct config_rsp_r *result,
		size_t *payload_len_out);


int cbor_decode_scan_req(
		const uint8_t *payload, size_t payload_len,
		struct scan_req_r *result,
		size_t *payload_len_out);


int cbor_decode_scan_rsp(
		const uint8_t *payload, size_t payload_len,
		struct scan_rsp_r *result,
		size_t *payload_len_out);


int cbor_decode_cred_req(
		const uint8_t *payload, size_t payload_len,
		struct cred_req_r *result,
		size_t *payload_len_out);


int cbor_decode_cred_rsp(
		const uint8_t *payload, size_t payload_len,
		struct cred_rsp_r *result,
		size_t *payload_len_out);


int cbor_decode_ctrl_req(
		const uint8_t *payload, size_t payload_len,
		struct ctrl_req_r *result,
		size_t *payload_len_out);


int cbor_decode_ctrl_rsp(
		const uint8_t *payload, size_t payload_len,
		struct ctrl_rsp *result,
		size_t *payload_len_out);


#ifdef __cplusplus
}
#endif

#endif /* PROV_DECODE_H__ */
