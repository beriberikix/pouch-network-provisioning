/*
 * Generated using zcbor version 0.9.1
 * https://github.com/NordicSemiconductor/zcbor
 * Generated with a --default-max-qty of 8
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "zcbor_encode.h"
#include "prov_encode.h"
#include "zcbor_print.h"

#if DEFAULT_MAX_QTY != 8
#error "The type file was generated with a different default_max_qty than this file"
#endif

#define log_result(state, result, func) do { \
	if (!result) { \
		zcbor_trace_file(state); \
		zcbor_log("%s error: %s\r\n", func, zcbor_error_str(zcbor_peek_error(state))); \
	} else { \
		zcbor_log("%s success\r\n", func); \
	} \
} while(0)

static bool encode_prov_status(zcbor_state_t *state, const struct prov_status_r *input);
static bool encode_repeated_ver_info_pop(zcbor_state_t *state, const struct ver_info_pop *input);
static bool encode_ver_info(zcbor_state_t *state, const struct ver_info *input);
static bool encode_auth_challenge(zcbor_state_t *state, const struct auth_challenge *input);
static bool encode_auth_proof(zcbor_state_t *state, const struct auth_proof *input);
static bool encode_config_get_status(zcbor_state_t *state, const void *input);
static bool encode_repeated_wifi_config_pass(zcbor_state_t *state, const struct wifi_config_pass *input);
static bool encode_repeated_wifi_config_bssid(zcbor_state_t *state, const struct wifi_config_bssid *input);
static bool encode_repeated_wifi_config_ch(zcbor_state_t *state, const struct wifi_config_ch *input);
static bool encode_wifi_config(zcbor_state_t *state, const struct wifi_config *input);
static bool encode_config_set(zcbor_state_t *state, const struct config_set *input);
static bool encode_config_apply(zcbor_state_t *state, const void *input);
static bool encode_repeated_scan_params_passive(zcbor_state_t *state, const struct scan_params_passive *input);
static bool encode_repeated_scan_params_period_ms(zcbor_state_t *state, const struct scan_params_period_ms *input);
static bool encode_scan_params(zcbor_state_t *state, const struct scan_params *input);
static bool encode_scan_start(zcbor_state_t *state, const struct scan_start *input);
static bool encode_scan_get_status(zcbor_state_t *state, const void *input);
static bool encode_scan_get_results(zcbor_state_t *state, const struct scan_get_results *input);
static bool encode_ctrl_reset(zcbor_state_t *state, const void *input);
static bool encode_ctrl_reprovision(zcbor_state_t *state, const void *input);
static bool encode_ctrl_end(zcbor_state_t *state, const void *input);
static bool encode_auth_challenge_rsp(zcbor_state_t *state, const struct auth_challenge_rsp *input);
static bool encode_auth_proof_rsp(zcbor_state_t *state, const struct auth_proof_rsp *input);
static bool encode_scan_start_rsp(zcbor_state_t *state, const struct scan_start_rsp *input);
static bool encode_scan_status_rsp(zcbor_state_t *state, const struct scan_status_rsp *input);
static bool encode_scan_entry(zcbor_state_t *state, const struct scan_entry *input);
static bool encode_scan_results_rsp(zcbor_state_t *state, const struct scan_results_rsp *input);
static bool encode_cred_write_rsp(zcbor_state_t *state, const struct cred_write_rsp *input);
static bool encode_cred_finalize_rsp(zcbor_state_t *state, const struct cred_finalize_rsp *input);
static bool encode_repeated_map_tstruint(zcbor_state_t *state, const struct map_tstruint *input);
static bool encode_cred_status_rsp(zcbor_state_t *state, const struct cred_status_rsp *input);
static bool encode_sta_state(zcbor_state_t *state, const struct sta_state_r *input);
static bool encode_fail_reason(zcbor_state_t *state, const struct fail_reason_r *input);
static bool encode_repeated_connected_info_rssi(zcbor_state_t *state, const struct connected_info_rssi *input);
static bool encode_connected_info(zcbor_state_t *state, const struct connected_info *input);
static bool encode_config_detail(zcbor_state_t *state, const struct config_detail_r *input);
static bool encode_config_status_rsp(zcbor_state_t *state, const struct config_status_rsp *input);
static bool encode_config_set_rsp(zcbor_state_t *state, const struct config_set_rsp *input);
static bool encode_config_apply_rsp(zcbor_state_t *state, const struct config_apply_rsp *input);
static bool encode_cred_kind(zcbor_state_t *state, const struct cred_kind_r *input);
static bool encode_cred_chunk(zcbor_state_t *state, const struct cred_chunk *input);
static bool encode_cred_write(zcbor_state_t *state, const struct cred_write *input);
static bool encode_cred_finalize(zcbor_state_t *state, const void *input);
static bool encode_cred_get_status(zcbor_state_t *state, const void *input);
static bool encode_ctrl_rsp(zcbor_state_t *state, const struct ctrl_rsp *input);
static bool encode_ctrl_req(zcbor_state_t *state, const struct ctrl_req_r *input);
static bool encode_cred_rsp(zcbor_state_t *state, const struct cred_rsp_r *input);
static bool encode_cred_req(zcbor_state_t *state, const struct cred_req_r *input);
static bool encode_scan_rsp(zcbor_state_t *state, const struct scan_rsp_r *input);
static bool encode_scan_req(zcbor_state_t *state, const struct scan_req_r *input);
static bool encode_config_rsp(zcbor_state_t *state, const struct config_rsp_r *input);
static bool encode_config_req(zcbor_state_t *state, const struct config_req_r *input);
static bool encode_auth_rsp(zcbor_state_t *state, const struct auth_rsp_r *input);
static bool encode_auth_req(zcbor_state_t *state, const struct auth_req_r *input);
static bool encode_ver_rsp(zcbor_state_t *state, const struct ver_rsp *input);
static bool encode_ver_req(zcbor_state_t *state, const void *input);


static bool encode_prov_status(
		zcbor_state_t *state, const struct prov_status_r *input)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((((*input).prov_status_choice == prov_status_status_ok_m_c) ? ((zcbor_uint32_put(state, (0))))
	: (((*input).prov_status_choice == prov_status_status_invalid_proto_m_c) ? ((zcbor_uint32_put(state, (1))))
	: (((*input).prov_status_choice == prov_status_status_invalid_argument_m_c) ? ((zcbor_uint32_put(state, (2))))
	: (((*input).prov_status_choice == prov_status_status_internal_error_m_c) ? ((zcbor_uint32_put(state, (3))))
	: (((*input).prov_status_choice == prov_status_status_unauthorized_m_c) ? ((zcbor_uint32_put(state, (4))))
	: (((*input).prov_status_choice == prov_status_status_invalid_state_m_c) ? ((zcbor_uint32_put(state, (5))))
	: (((*input).prov_status_choice == prov_status_status_busy_m_c) ? ((zcbor_uint32_put(state, (6))))
	: false)))))))));

	log_result(state, res, __func__);
	return res;
}

static bool encode_repeated_ver_info_pop(
		zcbor_state_t *state, const struct ver_info_pop *input)
{
	zcbor_log("%s\r\n", __func__);
	struct zcbor_string tmp_str;

	bool res = ((((zcbor_tstr_encode(state, ((tmp_str.value = (uint8_t *)"pop", tmp_str.len = sizeof("pop") - 1, &tmp_str)))))
	&& (zcbor_bool_encode(state, (&(*input).ver_info_pop)))));

	log_result(state, res, __func__);
	return res;
}

static bool encode_ver_info(
		zcbor_state_t *state, const struct ver_info *input)
{
	zcbor_log("%s\r\n", __func__);
	struct zcbor_string tmp_str;

	bool res = (((zcbor_map_start_encode(state, 5) && (((((zcbor_tstr_encode(state, ((tmp_str.value = (uint8_t *)"proto", tmp_str.len = sizeof("proto") - 1, &tmp_str)))))
	&& (zcbor_uint32_encode(state, (&(*input).ver_info_proto))))
	&& (((zcbor_tstr_encode(state, ((tmp_str.value = (uint8_t *)"caps", tmp_str.len = sizeof("caps") - 1, &tmp_str)))))
	&& (zcbor_list_start_encode(state, 8) && ((zcbor_multi_encode_minmax(0, 8, &(*input).ver_info_caps_tstr_count, (zcbor_encoder_t *)zcbor_tstr_encode, state, (*&(*input).ver_info_caps_tstr), sizeof(struct zcbor_string))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_list_end_encode(state, 8)))
	&& (((zcbor_tstr_encode(state, ((tmp_str.value = (uint8_t *)"blk", tmp_str.len = sizeof("blk") - 1, &tmp_str)))))
	&& (zcbor_uint32_encode(state, (&(*input).ver_info_blk))))
	&& (((zcbor_tstr_encode(state, ((tmp_str.value = (uint8_t *)"lib", tmp_str.len = sizeof("lib") - 1, &tmp_str)))))
	&& (zcbor_tstr_encode(state, (&(*input).ver_info_lib))))
	&& (!(*input).ver_info_pop_present || encode_repeated_ver_info_pop(state, (&(*input).ver_info_pop)))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_map_end_encode(state, 5))));

	log_result(state, res, __func__);
	return res;
}

static bool encode_auth_challenge(
		zcbor_state_t *state, const struct auth_challenge *input)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_list_start_encode(state, 2) && ((((zcbor_uint32_put(state, (0))))
	&& (((((*input).auth_challenge_cli_nonce.len == 16)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))
	&& (zcbor_bstr_encode(state, (&(*input).auth_challenge_cli_nonce))))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_list_end_encode(state, 2))));

	log_result(state, res, __func__);
	return res;
}

static bool encode_auth_proof(
		zcbor_state_t *state, const struct auth_proof *input)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_list_start_encode(state, 2) && ((((zcbor_uint32_put(state, (1))))
	&& (((((*input).auth_proof_cli_proof.len == 32)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))
	&& (zcbor_bstr_encode(state, (&(*input).auth_proof_cli_proof))))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_list_end_encode(state, 2))));

	log_result(state, res, __func__);
	return res;
}

static bool encode_config_get_status(
		zcbor_state_t *state, const void *input)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_list_start_encode(state, 1) && ((((zcbor_uint32_put(state, (0))))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_list_end_encode(state, 1))));

	log_result(state, res, __func__);
	return res;
}

static bool encode_repeated_wifi_config_pass(
		zcbor_state_t *state, const struct wifi_config_pass *input)
{
	zcbor_log("%s\r\n", __func__);
	struct zcbor_string tmp_str;

	bool res = ((((zcbor_tstr_encode(state, ((tmp_str.value = (uint8_t *)"pass", tmp_str.len = sizeof("pass") - 1, &tmp_str)))))
	&& ((((*input).wifi_config_pass.len >= 0)
	&& ((*input).wifi_config_pass.len <= 64)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))
	&& (zcbor_bstr_encode(state, (&(*input).wifi_config_pass)))));

	log_result(state, res, __func__);
	return res;
}

static bool encode_repeated_wifi_config_bssid(
		zcbor_state_t *state, const struct wifi_config_bssid *input)
{
	zcbor_log("%s\r\n", __func__);
	struct zcbor_string tmp_str;

	bool res = ((((zcbor_tstr_encode(state, ((tmp_str.value = (uint8_t *)"bssid", tmp_str.len = sizeof("bssid") - 1, &tmp_str)))))
	&& ((((*input).wifi_config_bssid.len == 6)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))
	&& (zcbor_bstr_encode(state, (&(*input).wifi_config_bssid)))));

	log_result(state, res, __func__);
	return res;
}

static bool encode_repeated_wifi_config_ch(
		zcbor_state_t *state, const struct wifi_config_ch *input)
{
	zcbor_log("%s\r\n", __func__);
	struct zcbor_string tmp_str;

	bool res = ((((zcbor_tstr_encode(state, ((tmp_str.value = (uint8_t *)"ch", tmp_str.len = sizeof("ch") - 1, &tmp_str)))))
	&& (zcbor_uint32_encode(state, (&(*input).wifi_config_ch)))));

	log_result(state, res, __func__);
	return res;
}

static bool encode_wifi_config(
		zcbor_state_t *state, const struct wifi_config *input)
{
	zcbor_log("%s\r\n", __func__);
	struct zcbor_string tmp_str;

	bool res = (((zcbor_map_start_encode(state, 4) && (((((zcbor_tstr_encode(state, ((tmp_str.value = (uint8_t *)"ssid", tmp_str.len = sizeof("ssid") - 1, &tmp_str)))))
	&& ((((*input).wifi_config_ssid.len >= 1)
	&& ((*input).wifi_config_ssid.len <= 32)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))
	&& (zcbor_bstr_encode(state, (&(*input).wifi_config_ssid))))
	&& (!(*input).wifi_config_pass_present || encode_repeated_wifi_config_pass(state, (&(*input).wifi_config_pass)))
	&& (!(*input).wifi_config_bssid_present || encode_repeated_wifi_config_bssid(state, (&(*input).wifi_config_bssid)))
	&& (!(*input).wifi_config_ch_present || encode_repeated_wifi_config_ch(state, (&(*input).wifi_config_ch)))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_map_end_encode(state, 4))));

	log_result(state, res, __func__);
	return res;
}

static bool encode_config_set(
		zcbor_state_t *state, const struct config_set *input)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_list_start_encode(state, 2) && ((((zcbor_uint32_put(state, (1))))
	&& ((encode_wifi_config(state, (&(*input).config_set_wifi_config_m))))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_list_end_encode(state, 2))));

	log_result(state, res, __func__);
	return res;
}

static bool encode_config_apply(
		zcbor_state_t *state, const void *input)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_list_start_encode(state, 1) && ((((zcbor_uint32_put(state, (2))))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_list_end_encode(state, 1))));

	log_result(state, res, __func__);
	return res;
}

static bool encode_repeated_scan_params_passive(
		zcbor_state_t *state, const struct scan_params_passive *input)
{
	zcbor_log("%s\r\n", __func__);
	struct zcbor_string tmp_str;

	bool res = ((((zcbor_tstr_encode(state, ((tmp_str.value = (uint8_t *)"passive", tmp_str.len = sizeof("passive") - 1, &tmp_str)))))
	&& (zcbor_bool_encode(state, (&(*input).scan_params_passive)))));

	log_result(state, res, __func__);
	return res;
}

static bool encode_repeated_scan_params_period_ms(
		zcbor_state_t *state, const struct scan_params_period_ms *input)
{
	zcbor_log("%s\r\n", __func__);
	struct zcbor_string tmp_str;

	bool res = ((((zcbor_tstr_encode(state, ((tmp_str.value = (uint8_t *)"period-ms", tmp_str.len = sizeof("period-ms") - 1, &tmp_str)))))
	&& (zcbor_uint32_encode(state, (&(*input).scan_params_period_ms)))));

	log_result(state, res, __func__);
	return res;
}

static bool encode_scan_params(
		zcbor_state_t *state, const struct scan_params *input)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_map_start_encode(state, 2) && (((!(*input).scan_params_passive_present || encode_repeated_scan_params_passive(state, (&(*input).scan_params_passive)))
	&& (!(*input).scan_params_period_ms_present || encode_repeated_scan_params_period_ms(state, (&(*input).scan_params_period_ms)))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_map_end_encode(state, 2))));

	log_result(state, res, __func__);
	return res;
}

static bool encode_scan_start(
		zcbor_state_t *state, const struct scan_start *input)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_list_start_encode(state, 2) && ((((zcbor_uint32_put(state, (0))))
	&& ((encode_scan_params(state, (&(*input).scan_start_scan_params_m))))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_list_end_encode(state, 2))));

	log_result(state, res, __func__);
	return res;
}

static bool encode_scan_get_status(
		zcbor_state_t *state, const void *input)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_list_start_encode(state, 1) && ((((zcbor_uint32_put(state, (1))))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_list_end_encode(state, 1))));

	log_result(state, res, __func__);
	return res;
}

static bool encode_scan_get_results(
		zcbor_state_t *state, const struct scan_get_results *input)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_list_start_encode(state, 3) && ((((zcbor_uint32_put(state, (2))))
	&& ((zcbor_uint32_encode(state, (&(*input).scan_get_results_start))))
	&& ((zcbor_uint32_encode(state, (&(*input).scan_get_results_count))))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_list_end_encode(state, 3))));

	log_result(state, res, __func__);
	return res;
}

static bool encode_ctrl_reset(
		zcbor_state_t *state, const void *input)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_list_start_encode(state, 1) && ((((zcbor_uint32_put(state, (0))))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_list_end_encode(state, 1))));

	log_result(state, res, __func__);
	return res;
}

static bool encode_ctrl_reprovision(
		zcbor_state_t *state, const void *input)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_list_start_encode(state, 1) && ((((zcbor_uint32_put(state, (1))))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_list_end_encode(state, 1))));

	log_result(state, res, __func__);
	return res;
}

static bool encode_ctrl_end(
		zcbor_state_t *state, const void *input)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_list_start_encode(state, 1) && ((((zcbor_uint32_put(state, (2))))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_list_end_encode(state, 1))));

	log_result(state, res, __func__);
	return res;
}

static bool encode_auth_challenge_rsp(
		zcbor_state_t *state, const struct auth_challenge_rsp *input)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_list_start_encode(state, 4) && ((((zcbor_uint32_put(state, (0))))
	&& ((encode_prov_status(state, (&(*input).auth_challenge_rsp_prov_status_m))))
	&& (((((*input).auth_challenge_rsp_dev_nonce.len == 16)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))
	&& (zcbor_bstr_encode(state, (&(*input).auth_challenge_rsp_dev_nonce))))
	&& (((((*input).auth_challenge_rsp_dev_proof.len == 32)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))
	&& (zcbor_bstr_encode(state, (&(*input).auth_challenge_rsp_dev_proof))))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_list_end_encode(state, 4))));

	log_result(state, res, __func__);
	return res;
}

static bool encode_auth_proof_rsp(
		zcbor_state_t *state, const struct auth_proof_rsp *input)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_list_start_encode(state, 2) && ((((zcbor_uint32_put(state, (1))))
	&& ((encode_prov_status(state, (&(*input).auth_proof_rsp_prov_status_m))))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_list_end_encode(state, 2))));

	log_result(state, res, __func__);
	return res;
}

static bool encode_scan_start_rsp(
		zcbor_state_t *state, const struct scan_start_rsp *input)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_list_start_encode(state, 2) && ((((zcbor_uint32_put(state, (0))))
	&& ((encode_prov_status(state, (&(*input).scan_start_rsp_prov_status_m))))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_list_end_encode(state, 2))));

	log_result(state, res, __func__);
	return res;
}

static bool encode_scan_status_rsp(
		zcbor_state_t *state, const struct scan_status_rsp *input)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_list_start_encode(state, 4) && ((((zcbor_uint32_put(state, (1))))
	&& ((encode_prov_status(state, (&(*input).scan_status_rsp_prov_status_m))))
	&& ((zcbor_bool_encode(state, (&(*input).scan_status_rsp_finished))))
	&& ((zcbor_uint32_encode(state, (&(*input).scan_status_rsp_total))))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_list_end_encode(state, 4))));

	log_result(state, res, __func__);
	return res;
}

static bool encode_scan_entry(
		zcbor_state_t *state, const struct scan_entry *input)
{
	zcbor_log("%s\r\n", __func__);
	struct zcbor_string tmp_str;

	bool res = (((zcbor_map_start_encode(state, 5) && (((((zcbor_tstr_encode(state, ((tmp_str.value = (uint8_t *)"ssid", tmp_str.len = sizeof("ssid") - 1, &tmp_str)))))
	&& ((((*input).scan_entry_ssid.len >= 0)
	&& ((*input).scan_entry_ssid.len <= 32)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))
	&& (zcbor_bstr_encode(state, (&(*input).scan_entry_ssid))))
	&& (((zcbor_tstr_encode(state, ((tmp_str.value = (uint8_t *)"bssid", tmp_str.len = sizeof("bssid") - 1, &tmp_str)))))
	&& ((((*input).scan_entry_bssid.len == 6)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))
	&& (zcbor_bstr_encode(state, (&(*input).scan_entry_bssid))))
	&& (((zcbor_tstr_encode(state, ((tmp_str.value = (uint8_t *)"ch", tmp_str.len = sizeof("ch") - 1, &tmp_str)))))
	&& (zcbor_uint32_encode(state, (&(*input).scan_entry_ch))))
	&& (((zcbor_tstr_encode(state, ((tmp_str.value = (uint8_t *)"rssi", tmp_str.len = sizeof("rssi") - 1, &tmp_str)))))
	&& (zcbor_int32_encode(state, (&(*input).scan_entry_rssi))))
	&& (((zcbor_tstr_encode(state, ((tmp_str.value = (uint8_t *)"auth", tmp_str.len = sizeof("auth") - 1, &tmp_str)))))
	&& (zcbor_uint32_encode(state, (&(*input).scan_entry_auth))))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_map_end_encode(state, 5))));

	log_result(state, res, __func__);
	return res;
}

static bool encode_scan_results_rsp(
		zcbor_state_t *state, const struct scan_results_rsp *input)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_list_start_encode(state, 3) && ((((zcbor_uint32_put(state, (2))))
	&& ((encode_prov_status(state, (&(*input).scan_results_rsp_prov_status_m))))
	&& ((zcbor_list_start_encode(state, 8) && ((zcbor_multi_encode_minmax(0, 8, &(*input).scan_results_rsp_scan_entry_m_l_scan_entry_m_count, (zcbor_encoder_t *)encode_scan_entry, state, (*&(*input).scan_results_rsp_scan_entry_m_l_scan_entry_m), sizeof(struct scan_entry))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_list_end_encode(state, 8)))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_list_end_encode(state, 3))));

	log_result(state, res, __func__);
	return res;
}

static bool encode_cred_write_rsp(
		zcbor_state_t *state, const struct cred_write_rsp *input)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_list_start_encode(state, 3) && ((((zcbor_uint32_put(state, (0))))
	&& ((encode_prov_status(state, (&(*input).cred_write_rsp_prov_status_m))))
	&& ((zcbor_uint32_encode(state, (&(*input).cred_write_rsp_received))))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_list_end_encode(state, 3))));

	log_result(state, res, __func__);
	return res;
}

static bool encode_cred_finalize_rsp(
		zcbor_state_t *state, const struct cred_finalize_rsp *input)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_list_start_encode(state, 2) && ((((zcbor_uint32_put(state, (1))))
	&& ((encode_prov_status(state, (&(*input).cred_finalize_rsp_prov_status_m))))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_list_end_encode(state, 2))));

	log_result(state, res, __func__);
	return res;
}

static bool encode_repeated_map_tstruint(
		zcbor_state_t *state, const struct map_tstruint *input)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((((zcbor_tstr_encode(state, (&(*input).cred_status_rsp_map_tstruint_key))))
	&& (zcbor_uint32_encode(state, (&(*input).map_tstruint)))));

	log_result(state, res, __func__);
	return res;
}

static bool encode_cred_status_rsp(
		zcbor_state_t *state, const struct cred_status_rsp *input)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_list_start_encode(state, 3) && ((((zcbor_uint32_put(state, (2))))
	&& ((encode_prov_status(state, (&(*input).cred_status_rsp_prov_status_m))))
	&& ((zcbor_map_start_encode(state, 8) && ((zcbor_multi_encode_minmax(0, 8, &(*input).map_tstruint_count, (zcbor_encoder_t *)encode_repeated_map_tstruint, state, (*&(*input).map_tstruint), sizeof(struct map_tstruint))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_map_end_encode(state, 8)))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_list_end_encode(state, 3))));

	log_result(state, res, __func__);
	return res;
}

static bool encode_sta_state(
		zcbor_state_t *state, const struct sta_state_r *input)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((((*input).sta_state_choice == sta_state_sta_connected_m_c) ? ((zcbor_uint32_put(state, (0))))
	: (((*input).sta_state_choice == sta_state_sta_connecting_m_c) ? ((zcbor_uint32_put(state, (1))))
	: (((*input).sta_state_choice == sta_state_sta_disconnected_m_c) ? ((zcbor_uint32_put(state, (2))))
	: (((*input).sta_state_choice == sta_state_sta_failed_m_c) ? ((zcbor_uint32_put(state, (3))))
	: false))))));

	log_result(state, res, __func__);
	return res;
}

static bool encode_fail_reason(
		zcbor_state_t *state, const struct fail_reason_r *input)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((((*input).fail_reason_choice == fail_reason_fail_auth_error_m_c) ? ((zcbor_uint32_put(state, (0))))
	: (((*input).fail_reason_choice == fail_reason_fail_network_not_found_m_c) ? ((zcbor_uint32_put(state, (1))))
	: false))));

	log_result(state, res, __func__);
	return res;
}

static bool encode_repeated_connected_info_rssi(
		zcbor_state_t *state, const struct connected_info_rssi *input)
{
	zcbor_log("%s\r\n", __func__);
	struct zcbor_string tmp_str;

	bool res = ((((zcbor_tstr_encode(state, ((tmp_str.value = (uint8_t *)"rssi", tmp_str.len = sizeof("rssi") - 1, &tmp_str)))))
	&& (zcbor_int32_encode(state, (&(*input).connected_info_rssi)))));

	log_result(state, res, __func__);
	return res;
}

static bool encode_connected_info(
		zcbor_state_t *state, const struct connected_info *input)
{
	zcbor_log("%s\r\n", __func__);
	struct zcbor_string tmp_str;

	bool res = (((zcbor_map_start_encode(state, 3) && (((((zcbor_tstr_encode(state, ((tmp_str.value = (uint8_t *)"ip4", tmp_str.len = sizeof("ip4") - 1, &tmp_str)))))
	&& ((((*input).connected_info_ip4.len == 4)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))
	&& (zcbor_bstr_encode(state, (&(*input).connected_info_ip4))))
	&& (((zcbor_tstr_encode(state, ((tmp_str.value = (uint8_t *)"ssid", tmp_str.len = sizeof("ssid") - 1, &tmp_str)))))
	&& ((((*input).connected_info_ssid.len >= 1)
	&& ((*input).connected_info_ssid.len <= 32)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))
	&& (zcbor_bstr_encode(state, (&(*input).connected_info_ssid))))
	&& (!(*input).connected_info_rssi_present || encode_repeated_connected_info_rssi(state, (&(*input).connected_info_rssi)))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_map_end_encode(state, 3))));

	log_result(state, res, __func__);
	return res;
}

static bool encode_config_detail(
		zcbor_state_t *state, const struct config_detail_r *input)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((((*input).config_detail_choice == config_detail_fail_reason_m_c) ? ((encode_fail_reason(state, (&(*input).config_detail_fail_reason_m))))
	: (((*input).config_detail_choice == config_detail_connected_info_m_c) ? ((encode_connected_info(state, (&(*input).config_detail_connected_info_m))))
	: false))));

	log_result(state, res, __func__);
	return res;
}

static bool encode_config_status_rsp(
		zcbor_state_t *state, const struct config_status_rsp *input)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_list_start_encode(state, 4) && ((((zcbor_uint32_put(state, (0))))
	&& ((encode_prov_status(state, (&(*input).config_status_rsp_prov_status_m))))
	&& ((encode_sta_state(state, (&(*input).config_status_rsp_sta_state_m))))
	&& (!(*input).config_status_rsp_config_detail_m_present || encode_config_detail(state, (&(*input).config_status_rsp_config_detail_m)))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_list_end_encode(state, 4))));

	log_result(state, res, __func__);
	return res;
}

static bool encode_config_set_rsp(
		zcbor_state_t *state, const struct config_set_rsp *input)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_list_start_encode(state, 2) && ((((zcbor_uint32_put(state, (1))))
	&& ((encode_prov_status(state, (&(*input).config_set_rsp_prov_status_m))))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_list_end_encode(state, 2))));

	log_result(state, res, __func__);
	return res;
}

static bool encode_config_apply_rsp(
		zcbor_state_t *state, const struct config_apply_rsp *input)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_list_start_encode(state, 2) && ((((zcbor_uint32_put(state, (2))))
	&& ((encode_prov_status(state, (&(*input).config_apply_rsp_prov_status_m))))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_list_end_encode(state, 2))));

	log_result(state, res, __func__);
	return res;
}

static bool encode_cred_kind(
		zcbor_state_t *state, const struct cred_kind_r *input)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((((*input).cred_kind_choice == cred_kind_cred_device_cert_m_c) ? ((zcbor_uint32_put(state, (0))))
	: (((*input).cred_kind_choice == cred_kind_cred_private_key_m_c) ? ((zcbor_uint32_put(state, (1))))
	: (((*input).cred_kind_choice == cred_kind_cred_ca_cert_m_c) ? ((zcbor_uint32_put(state, (2))))
	: false)))));

	log_result(state, res, __func__);
	return res;
}

static bool encode_cred_chunk(
		zcbor_state_t *state, const struct cred_chunk *input)
{
	zcbor_log("%s\r\n", __func__);
	struct zcbor_string tmp_str;

	bool res = (((zcbor_map_start_encode(state, 4) && (((((zcbor_tstr_encode(state, ((tmp_str.value = (uint8_t *)"kind", tmp_str.len = sizeof("kind") - 1, &tmp_str)))))
	&& (encode_cred_kind(state, (&(*input).cred_chunk_kind))))
	&& (((zcbor_tstr_encode(state, ((tmp_str.value = (uint8_t *)"off", tmp_str.len = sizeof("off") - 1, &tmp_str)))))
	&& (zcbor_uint32_encode(state, (&(*input).cred_chunk_off))))
	&& (((zcbor_tstr_encode(state, ((tmp_str.value = (uint8_t *)"total", tmp_str.len = sizeof("total") - 1, &tmp_str)))))
	&& (zcbor_uint32_encode(state, (&(*input).cred_chunk_total))))
	&& (((zcbor_tstr_encode(state, ((tmp_str.value = (uint8_t *)"data", tmp_str.len = sizeof("data") - 1, &tmp_str)))))
	&& (zcbor_bstr_encode(state, (&(*input).cred_chunk_data))))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_map_end_encode(state, 4))));

	log_result(state, res, __func__);
	return res;
}

static bool encode_cred_write(
		zcbor_state_t *state, const struct cred_write *input)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_list_start_encode(state, 2) && ((((zcbor_uint32_put(state, (0))))
	&& ((encode_cred_chunk(state, (&(*input).cred_write_cred_chunk_m))))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_list_end_encode(state, 2))));

	log_result(state, res, __func__);
	return res;
}

static bool encode_cred_finalize(
		zcbor_state_t *state, const void *input)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_list_start_encode(state, 1) && ((((zcbor_uint32_put(state, (1))))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_list_end_encode(state, 1))));

	log_result(state, res, __func__);
	return res;
}

static bool encode_cred_get_status(
		zcbor_state_t *state, const void *input)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_list_start_encode(state, 1) && ((((zcbor_uint32_put(state, (2))))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_list_end_encode(state, 1))));

	log_result(state, res, __func__);
	return res;
}

static bool encode_ctrl_rsp(
		zcbor_state_t *state, const struct ctrl_rsp *input)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_list_start_encode(state, 2) && (((((((((*input).ctrl_rsp_ctrl_op_m <= 2)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))
	&& (zcbor_uint32_encode(state, (&(*input).ctrl_rsp_ctrl_op_m))))
	&& ((encode_prov_status(state, (&(*input).ctrl_rsp_prov_status_m))))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_list_end_encode(state, 2))));

	log_result(state, res, __func__);
	return res;
}

static bool encode_ctrl_req(
		zcbor_state_t *state, const struct ctrl_req_r *input)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((((*input).ctrl_req_choice == ctrl_req_ctrl_reset_m_c) ? ((encode_ctrl_reset(state, NULL)))
	: (((*input).ctrl_req_choice == ctrl_req_ctrl_reprovision_m_c) ? ((encode_ctrl_reprovision(state, NULL)))
	: (((*input).ctrl_req_choice == ctrl_req_ctrl_end_m_c) ? ((encode_ctrl_end(state, NULL)))
	: false)))));

	log_result(state, res, __func__);
	return res;
}

static bool encode_cred_rsp(
		zcbor_state_t *state, const struct cred_rsp_r *input)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((((*input).cred_rsp_choice == cred_rsp_cred_write_rsp_m_c) ? ((encode_cred_write_rsp(state, (&(*input).cred_rsp_cred_write_rsp_m))))
	: (((*input).cred_rsp_choice == cred_rsp_cred_finalize_rsp_m_c) ? ((encode_cred_finalize_rsp(state, (&(*input).cred_rsp_cred_finalize_rsp_m))))
	: (((*input).cred_rsp_choice == cred_rsp_cred_status_rsp_m_c) ? ((encode_cred_status_rsp(state, (&(*input).cred_rsp_cred_status_rsp_m))))
	: false)))));

	log_result(state, res, __func__);
	return res;
}

static bool encode_cred_req(
		zcbor_state_t *state, const struct cred_req_r *input)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((((*input).cred_req_choice == cred_req_cred_write_m_c) ? ((encode_cred_write(state, (&(*input).cred_req_cred_write_m))))
	: (((*input).cred_req_choice == cred_req_cred_finalize_m_c) ? ((encode_cred_finalize(state, NULL)))
	: (((*input).cred_req_choice == cred_req_cred_get_status_m_c) ? ((encode_cred_get_status(state, NULL)))
	: false)))));

	log_result(state, res, __func__);
	return res;
}

static bool encode_scan_rsp(
		zcbor_state_t *state, const struct scan_rsp_r *input)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((((*input).scan_rsp_choice == scan_rsp_scan_start_rsp_m_c) ? ((encode_scan_start_rsp(state, (&(*input).scan_rsp_scan_start_rsp_m))))
	: (((*input).scan_rsp_choice == scan_rsp_scan_status_rsp_m_c) ? ((encode_scan_status_rsp(state, (&(*input).scan_rsp_scan_status_rsp_m))))
	: (((*input).scan_rsp_choice == scan_rsp_scan_results_rsp_m_c) ? ((encode_scan_results_rsp(state, (&(*input).scan_rsp_scan_results_rsp_m))))
	: false)))));

	log_result(state, res, __func__);
	return res;
}

static bool encode_scan_req(
		zcbor_state_t *state, const struct scan_req_r *input)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((((*input).scan_req_choice == scan_req_scan_start_m_c) ? ((encode_scan_start(state, (&(*input).scan_req_scan_start_m))))
	: (((*input).scan_req_choice == scan_req_scan_get_status_m_c) ? ((encode_scan_get_status(state, NULL)))
	: (((*input).scan_req_choice == scan_req_scan_get_results_m_c) ? ((encode_scan_get_results(state, (&(*input).scan_req_scan_get_results_m))))
	: false)))));

	log_result(state, res, __func__);
	return res;
}

static bool encode_config_rsp(
		zcbor_state_t *state, const struct config_rsp_r *input)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((((*input).config_rsp_choice == config_rsp_config_status_rsp_m_c) ? ((encode_config_status_rsp(state, (&(*input).config_rsp_config_status_rsp_m))))
	: (((*input).config_rsp_choice == config_rsp_config_set_rsp_m_c) ? ((encode_config_set_rsp(state, (&(*input).config_rsp_config_set_rsp_m))))
	: (((*input).config_rsp_choice == config_rsp_config_apply_rsp_m_c) ? ((encode_config_apply_rsp(state, (&(*input).config_rsp_config_apply_rsp_m))))
	: false)))));

	log_result(state, res, __func__);
	return res;
}

static bool encode_config_req(
		zcbor_state_t *state, const struct config_req_r *input)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((((*input).config_req_choice == config_req_config_get_status_m_c) ? ((encode_config_get_status(state, NULL)))
	: (((*input).config_req_choice == config_req_config_set_m_c) ? ((encode_config_set(state, (&(*input).config_req_config_set_m))))
	: (((*input).config_req_choice == config_req_config_apply_m_c) ? ((encode_config_apply(state, NULL)))
	: false)))));

	log_result(state, res, __func__);
	return res;
}

static bool encode_auth_rsp(
		zcbor_state_t *state, const struct auth_rsp_r *input)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((((*input).auth_rsp_choice == auth_rsp_auth_challenge_rsp_m_c) ? ((encode_auth_challenge_rsp(state, (&(*input).auth_rsp_auth_challenge_rsp_m))))
	: (((*input).auth_rsp_choice == auth_rsp_auth_proof_rsp_m_c) ? ((encode_auth_proof_rsp(state, (&(*input).auth_rsp_auth_proof_rsp_m))))
	: false))));

	log_result(state, res, __func__);
	return res;
}

static bool encode_auth_req(
		zcbor_state_t *state, const struct auth_req_r *input)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((((*input).auth_req_choice == auth_req_auth_challenge_m_c) ? ((encode_auth_challenge(state, (&(*input).auth_req_auth_challenge_m))))
	: (((*input).auth_req_choice == auth_req_auth_proof_m_c) ? ((encode_auth_proof(state, (&(*input).auth_req_auth_proof_m))))
	: false))));

	log_result(state, res, __func__);
	return res;
}

static bool encode_ver_rsp(
		zcbor_state_t *state, const struct ver_rsp *input)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_list_start_encode(state, 3) && ((((zcbor_uint32_put(state, (0))))
	&& ((encode_prov_status(state, (&(*input).ver_rsp_prov_status_m))))
	&& ((encode_ver_info(state, (&(*input).ver_rsp_ver_info_m))))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_list_end_encode(state, 3))));

	log_result(state, res, __func__);
	return res;
}

static bool encode_ver_req(
		zcbor_state_t *state, const void *input)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_list_start_encode(state, 1) && ((((zcbor_uint32_put(state, (0))))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_list_end_encode(state, 1))));

	log_result(state, res, __func__);
	return res;
}



int cbor_encode_ver_req(
		uint8_t *payload, size_t payload_len,
		const void *input,
		size_t *payload_len_out)
{
	zcbor_state_t states[3];

	return zcbor_entry_function(payload, payload_len, (void *)input, payload_len_out, states,
		(zcbor_decoder_t *)encode_ver_req, sizeof(states) / sizeof(zcbor_state_t), 1);
}


int cbor_encode_ver_rsp(
		uint8_t *payload, size_t payload_len,
		const struct ver_rsp *input,
		size_t *payload_len_out)
{
	zcbor_state_t states[5];

	return zcbor_entry_function(payload, payload_len, (void *)input, payload_len_out, states,
		(zcbor_decoder_t *)encode_ver_rsp, sizeof(states) / sizeof(zcbor_state_t), 1);
}


int cbor_encode_auth_req(
		uint8_t *payload, size_t payload_len,
		const struct auth_req_r *input,
		size_t *payload_len_out)
{
	zcbor_state_t states[4];

	return zcbor_entry_function(payload, payload_len, (void *)input, payload_len_out, states,
		(zcbor_decoder_t *)encode_auth_req, sizeof(states) / sizeof(zcbor_state_t), 1);
}


int cbor_encode_auth_rsp(
		uint8_t *payload, size_t payload_len,
		const struct auth_rsp_r *input,
		size_t *payload_len_out)
{
	zcbor_state_t states[5];

	return zcbor_entry_function(payload, payload_len, (void *)input, payload_len_out, states,
		(zcbor_decoder_t *)encode_auth_rsp, sizeof(states) / sizeof(zcbor_state_t), 1);
}


int cbor_encode_config_req(
		uint8_t *payload, size_t payload_len,
		const struct config_req_r *input,
		size_t *payload_len_out)
{
	zcbor_state_t states[5];

	return zcbor_entry_function(payload, payload_len, (void *)input, payload_len_out, states,
		(zcbor_decoder_t *)encode_config_req, sizeof(states) / sizeof(zcbor_state_t), 1);
}


int cbor_encode_config_rsp(
		uint8_t *payload, size_t payload_len,
		const struct config_rsp_r *input,
		size_t *payload_len_out)
{
	zcbor_state_t states[6];

	return zcbor_entry_function(payload, payload_len, (void *)input, payload_len_out, states,
		(zcbor_decoder_t *)encode_config_rsp, sizeof(states) / sizeof(zcbor_state_t), 1);
}


int cbor_encode_scan_req(
		uint8_t *payload, size_t payload_len,
		const struct scan_req_r *input,
		size_t *payload_len_out)
{
	zcbor_state_t states[5];

	return zcbor_entry_function(payload, payload_len, (void *)input, payload_len_out, states,
		(zcbor_decoder_t *)encode_scan_req, sizeof(states) / sizeof(zcbor_state_t), 1);
}


int cbor_encode_scan_rsp(
		uint8_t *payload, size_t payload_len,
		const struct scan_rsp_r *input,
		size_t *payload_len_out)
{
	zcbor_state_t states[6];

	return zcbor_entry_function(payload, payload_len, (void *)input, payload_len_out, states,
		(zcbor_decoder_t *)encode_scan_rsp, sizeof(states) / sizeof(zcbor_state_t), 1);
}


int cbor_encode_cred_req(
		uint8_t *payload, size_t payload_len,
		const struct cred_req_r *input,
		size_t *payload_len_out)
{
	zcbor_state_t states[6];

	return zcbor_entry_function(payload, payload_len, (void *)input, payload_len_out, states,
		(zcbor_decoder_t *)encode_cred_req, sizeof(states) / sizeof(zcbor_state_t), 1);
}


int cbor_encode_cred_rsp(
		uint8_t *payload, size_t payload_len,
		const struct cred_rsp_r *input,
		size_t *payload_len_out)
{
	zcbor_state_t states[5];

	return zcbor_entry_function(payload, payload_len, (void *)input, payload_len_out, states,
		(zcbor_decoder_t *)encode_cred_rsp, sizeof(states) / sizeof(zcbor_state_t), 1);
}


int cbor_encode_ctrl_req(
		uint8_t *payload, size_t payload_len,
		const struct ctrl_req_r *input,
		size_t *payload_len_out)
{
	zcbor_state_t states[4];

	return zcbor_entry_function(payload, payload_len, (void *)input, payload_len_out, states,
		(zcbor_decoder_t *)encode_ctrl_req, sizeof(states) / sizeof(zcbor_state_t), 1);
}


int cbor_encode_ctrl_rsp(
		uint8_t *payload, size_t payload_len,
		const struct ctrl_rsp *input,
		size_t *payload_len_out)
{
	zcbor_state_t states[4];

	return zcbor_entry_function(payload, payload_len, (void *)input, payload_len_out, states,
		(zcbor_decoder_t *)encode_ctrl_rsp, sizeof(states) / sizeof(zcbor_state_t), 1);
}
