/*
 * Generated using zcbor version 0.9.1
 * https://github.com/NordicSemiconductor/zcbor
 * Generated with a --default-max-qty of 8
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "zcbor_decode.h"
#include "prov_decode.h"
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

static bool decode_prov_status(zcbor_state_t *state, struct prov_status_r *result);
static bool decode_repeated_ver_info_pop(zcbor_state_t *state, struct ver_info_pop *result);
static bool decode_ver_info(zcbor_state_t *state, struct ver_info *result);
static bool decode_auth_challenge(zcbor_state_t *state, struct auth_challenge *result);
static bool decode_auth_proof(zcbor_state_t *state, struct auth_proof *result);
static bool decode_config_get_status(zcbor_state_t *state, void *result);
static bool decode_repeated_wifi_config_pass(zcbor_state_t *state, struct wifi_config_pass *result);
static bool decode_repeated_wifi_config_bssid(zcbor_state_t *state, struct wifi_config_bssid *result);
static bool decode_repeated_wifi_config_ch(zcbor_state_t *state, struct wifi_config_ch *result);
static bool decode_wifi_config(zcbor_state_t *state, struct wifi_config *result);
static bool decode_config_set(zcbor_state_t *state, struct config_set *result);
static bool decode_config_apply(zcbor_state_t *state, void *result);
static bool decode_repeated_scan_params_passive(zcbor_state_t *state, struct scan_params_passive *result);
static bool decode_repeated_scan_params_period_ms(zcbor_state_t *state, struct scan_params_period_ms *result);
static bool decode_scan_params(zcbor_state_t *state, struct scan_params *result);
static bool decode_scan_start(zcbor_state_t *state, struct scan_start *result);
static bool decode_scan_get_status(zcbor_state_t *state, void *result);
static bool decode_scan_get_results(zcbor_state_t *state, struct scan_get_results *result);
static bool decode_ctrl_reset(zcbor_state_t *state, void *result);
static bool decode_ctrl_reprovision(zcbor_state_t *state, void *result);
static bool decode_ctrl_end(zcbor_state_t *state, void *result);
static bool decode_auth_challenge_rsp(zcbor_state_t *state, struct auth_challenge_rsp *result);
static bool decode_auth_proof_rsp(zcbor_state_t *state, struct auth_proof_rsp *result);
static bool decode_scan_start_rsp(zcbor_state_t *state, struct scan_start_rsp *result);
static bool decode_scan_status_rsp(zcbor_state_t *state, struct scan_status_rsp *result);
static bool decode_scan_entry(zcbor_state_t *state, struct scan_entry *result);
static bool decode_scan_results_rsp(zcbor_state_t *state, struct scan_results_rsp *result);
static bool decode_cred_write_rsp(zcbor_state_t *state, struct cred_write_rsp *result);
static bool decode_cred_finalize_rsp(zcbor_state_t *state, struct cred_finalize_rsp *result);
static bool decode_repeated_map_tstruint(zcbor_state_t *state, struct map_tstruint *result);
static bool decode_cred_status_rsp(zcbor_state_t *state, struct cred_status_rsp *result);
static bool decode_sta_state(zcbor_state_t *state, struct sta_state_r *result);
static bool decode_fail_reason(zcbor_state_t *state, struct fail_reason_r *result);
static bool decode_repeated_connected_info_rssi(zcbor_state_t *state, struct connected_info_rssi *result);
static bool decode_connected_info(zcbor_state_t *state, struct connected_info *result);
static bool decode_config_detail(zcbor_state_t *state, struct config_detail_r *result);
static bool decode_config_status_rsp(zcbor_state_t *state, struct config_status_rsp *result);
static bool decode_config_set_rsp(zcbor_state_t *state, struct config_set_rsp *result);
static bool decode_config_apply_rsp(zcbor_state_t *state, struct config_apply_rsp *result);
static bool decode_cred_kind(zcbor_state_t *state, struct cred_kind_r *result);
static bool decode_cred_chunk(zcbor_state_t *state, struct cred_chunk *result);
static bool decode_cred_write(zcbor_state_t *state, struct cred_write *result);
static bool decode_cred_finalize(zcbor_state_t *state, void *result);
static bool decode_cred_get_status(zcbor_state_t *state, void *result);
static bool decode_ctrl_rsp(zcbor_state_t *state, struct ctrl_rsp *result);
static bool decode_ctrl_req(zcbor_state_t *state, struct ctrl_req_r *result);
static bool decode_cred_rsp(zcbor_state_t *state, struct cred_rsp_r *result);
static bool decode_cred_req(zcbor_state_t *state, struct cred_req_r *result);
static bool decode_scan_rsp(zcbor_state_t *state, struct scan_rsp_r *result);
static bool decode_scan_req(zcbor_state_t *state, struct scan_req_r *result);
static bool decode_config_rsp(zcbor_state_t *state, struct config_rsp_r *result);
static bool decode_config_req(zcbor_state_t *state, struct config_req_r *result);
static bool decode_auth_rsp(zcbor_state_t *state, struct auth_rsp_r *result);
static bool decode_auth_req(zcbor_state_t *state, struct auth_req_r *result);
static bool decode_ver_rsp(zcbor_state_t *state, struct ver_rsp *result);
static bool decode_ver_req(zcbor_state_t *state, void *result);


static bool decode_prov_status(
		zcbor_state_t *state, struct prov_status_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((((zcbor_uint_decode(state, &(*result).prov_status_choice, sizeof((*result).prov_status_choice)))) && ((((((*result).prov_status_choice == prov_status_status_ok_m_c) && ((1)))
	|| (((*result).prov_status_choice == prov_status_status_invalid_proto_m_c) && ((1)))
	|| (((*result).prov_status_choice == prov_status_status_invalid_argument_m_c) && ((1)))
	|| (((*result).prov_status_choice == prov_status_status_internal_error_m_c) && ((1)))
	|| (((*result).prov_status_choice == prov_status_status_unauthorized_m_c) && ((1)))
	|| (((*result).prov_status_choice == prov_status_status_invalid_state_m_c) && ((1)))
	|| (((*result).prov_status_choice == prov_status_status_busy_m_c) && ((1)))) || (zcbor_error(state, ZCBOR_ERR_WRONG_VALUE), false))))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_ver_info_pop(
		zcbor_state_t *state, struct ver_info_pop *result)
{
	zcbor_log("%s\r\n", __func__);
	struct zcbor_string tmp_str;

	bool res = ((((zcbor_tstr_expect(state, ((tmp_str.value = (uint8_t *)"pop", tmp_str.len = sizeof("pop") - 1, &tmp_str)))))
	&& (zcbor_bool_decode(state, (&(*result).ver_info_pop)))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_ver_info(
		zcbor_state_t *state, struct ver_info *result)
{
	zcbor_log("%s\r\n", __func__);
	struct zcbor_string tmp_str;

	bool res = (((zcbor_map_start_decode(state) && (((((zcbor_tstr_expect(state, ((tmp_str.value = (uint8_t *)"proto", tmp_str.len = sizeof("proto") - 1, &tmp_str)))))
	&& (zcbor_uint32_decode(state, (&(*result).ver_info_proto))))
	&& (((zcbor_tstr_expect(state, ((tmp_str.value = (uint8_t *)"caps", tmp_str.len = sizeof("caps") - 1, &tmp_str)))))
	&& (zcbor_list_start_decode(state) && ((zcbor_multi_decode(0, 8, &(*result).ver_info_caps_tstr_count, (zcbor_decoder_t *)zcbor_tstr_decode, state, (*&(*result).ver_info_caps_tstr), sizeof(struct zcbor_string))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state)))
	&& (((zcbor_tstr_expect(state, ((tmp_str.value = (uint8_t *)"blk", tmp_str.len = sizeof("blk") - 1, &tmp_str)))))
	&& (zcbor_uint32_decode(state, (&(*result).ver_info_blk))))
	&& (((zcbor_tstr_expect(state, ((tmp_str.value = (uint8_t *)"lib", tmp_str.len = sizeof("lib") - 1, &tmp_str)))))
	&& (zcbor_tstr_decode(state, (&(*result).ver_info_lib))))
	&& zcbor_present_decode(&((*result).ver_info_pop_present), (zcbor_decoder_t *)decode_repeated_ver_info_pop, state, (&(*result).ver_info_pop))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_map_end_decode(state))));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		zcbor_tstr_decode(state, (*&(*result).ver_info_caps_tstr));
		decode_repeated_ver_info_pop(state, (&(*result).ver_info_pop));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_auth_challenge(
		zcbor_state_t *state, struct auth_challenge *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_list_start_decode(state) && ((((zcbor_uint32_expect(state, (0))))
	&& ((zcbor_bstr_decode(state, (&(*result).auth_challenge_cli_nonce)))
	&& ((((*result).auth_challenge_cli_nonce.len == 16)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false)))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_auth_proof(
		zcbor_state_t *state, struct auth_proof *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_list_start_decode(state) && ((((zcbor_uint32_expect(state, (1))))
	&& ((zcbor_bstr_decode(state, (&(*result).auth_proof_cli_proof)))
	&& ((((*result).auth_proof_cli_proof.len == 32)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false)))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_config_get_status(
		zcbor_state_t *state, void *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_list_start_decode(state) && ((((zcbor_uint32_expect(state, (0))))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_wifi_config_pass(
		zcbor_state_t *state, struct wifi_config_pass *result)
{
	zcbor_log("%s\r\n", __func__);
	struct zcbor_string tmp_str;

	bool res = ((((zcbor_tstr_expect(state, ((tmp_str.value = (uint8_t *)"pass", tmp_str.len = sizeof("pass") - 1, &tmp_str)))))
	&& (zcbor_bstr_decode(state, (&(*result).wifi_config_pass)))
	&& ((((*result).wifi_config_pass.len >= 0)
	&& ((*result).wifi_config_pass.len <= 64)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_wifi_config_bssid(
		zcbor_state_t *state, struct wifi_config_bssid *result)
{
	zcbor_log("%s\r\n", __func__);
	struct zcbor_string tmp_str;

	bool res = ((((zcbor_tstr_expect(state, ((tmp_str.value = (uint8_t *)"bssid", tmp_str.len = sizeof("bssid") - 1, &tmp_str)))))
	&& (zcbor_bstr_decode(state, (&(*result).wifi_config_bssid)))
	&& ((((*result).wifi_config_bssid.len == 6)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_wifi_config_ch(
		zcbor_state_t *state, struct wifi_config_ch *result)
{
	zcbor_log("%s\r\n", __func__);
	struct zcbor_string tmp_str;

	bool res = ((((zcbor_tstr_expect(state, ((tmp_str.value = (uint8_t *)"ch", tmp_str.len = sizeof("ch") - 1, &tmp_str)))))
	&& (zcbor_uint32_decode(state, (&(*result).wifi_config_ch)))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_wifi_config(
		zcbor_state_t *state, struct wifi_config *result)
{
	zcbor_log("%s\r\n", __func__);
	struct zcbor_string tmp_str;

	bool res = (((zcbor_map_start_decode(state) && (((((zcbor_tstr_expect(state, ((tmp_str.value = (uint8_t *)"ssid", tmp_str.len = sizeof("ssid") - 1, &tmp_str)))))
	&& (zcbor_bstr_decode(state, (&(*result).wifi_config_ssid)))
	&& ((((*result).wifi_config_ssid.len >= 1)
	&& ((*result).wifi_config_ssid.len <= 32)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false)))
	&& zcbor_present_decode(&((*result).wifi_config_pass_present), (zcbor_decoder_t *)decode_repeated_wifi_config_pass, state, (&(*result).wifi_config_pass))
	&& zcbor_present_decode(&((*result).wifi_config_bssid_present), (zcbor_decoder_t *)decode_repeated_wifi_config_bssid, state, (&(*result).wifi_config_bssid))
	&& zcbor_present_decode(&((*result).wifi_config_ch_present), (zcbor_decoder_t *)decode_repeated_wifi_config_ch, state, (&(*result).wifi_config_ch))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_map_end_decode(state))));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		decode_repeated_wifi_config_pass(state, (&(*result).wifi_config_pass));
		decode_repeated_wifi_config_bssid(state, (&(*result).wifi_config_bssid));
		decode_repeated_wifi_config_ch(state, (&(*result).wifi_config_ch));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_config_set(
		zcbor_state_t *state, struct config_set *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_list_start_decode(state) && ((((zcbor_uint32_expect(state, (1))))
	&& ((decode_wifi_config(state, (&(*result).config_set_wifi_config_m))))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_config_apply(
		zcbor_state_t *state, void *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_list_start_decode(state) && ((((zcbor_uint32_expect(state, (2))))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_scan_params_passive(
		zcbor_state_t *state, struct scan_params_passive *result)
{
	zcbor_log("%s\r\n", __func__);
	struct zcbor_string tmp_str;

	bool res = ((((zcbor_tstr_expect(state, ((tmp_str.value = (uint8_t *)"passive", tmp_str.len = sizeof("passive") - 1, &tmp_str)))))
	&& (zcbor_bool_decode(state, (&(*result).scan_params_passive)))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_scan_params_period_ms(
		zcbor_state_t *state, struct scan_params_period_ms *result)
{
	zcbor_log("%s\r\n", __func__);
	struct zcbor_string tmp_str;

	bool res = ((((zcbor_tstr_expect(state, ((tmp_str.value = (uint8_t *)"period-ms", tmp_str.len = sizeof("period-ms") - 1, &tmp_str)))))
	&& (zcbor_uint32_decode(state, (&(*result).scan_params_period_ms)))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_scan_params(
		zcbor_state_t *state, struct scan_params *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_map_start_decode(state) && ((zcbor_present_decode(&((*result).scan_params_passive_present), (zcbor_decoder_t *)decode_repeated_scan_params_passive, state, (&(*result).scan_params_passive))
	&& zcbor_present_decode(&((*result).scan_params_period_ms_present), (zcbor_decoder_t *)decode_repeated_scan_params_period_ms, state, (&(*result).scan_params_period_ms))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_map_end_decode(state))));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		decode_repeated_scan_params_passive(state, (&(*result).scan_params_passive));
		decode_repeated_scan_params_period_ms(state, (&(*result).scan_params_period_ms));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_scan_start(
		zcbor_state_t *state, struct scan_start *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_list_start_decode(state) && ((((zcbor_uint32_expect(state, (0))))
	&& ((decode_scan_params(state, (&(*result).scan_start_scan_params_m))))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_scan_get_status(
		zcbor_state_t *state, void *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_list_start_decode(state) && ((((zcbor_uint32_expect(state, (1))))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_scan_get_results(
		zcbor_state_t *state, struct scan_get_results *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_list_start_decode(state) && ((((zcbor_uint32_expect(state, (2))))
	&& ((zcbor_uint32_decode(state, (&(*result).scan_get_results_start))))
	&& ((zcbor_uint32_decode(state, (&(*result).scan_get_results_count))))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_ctrl_reset(
		zcbor_state_t *state, void *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_list_start_decode(state) && ((((zcbor_uint32_expect(state, (0))))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_ctrl_reprovision(
		zcbor_state_t *state, void *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_list_start_decode(state) && ((((zcbor_uint32_expect(state, (1))))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_ctrl_end(
		zcbor_state_t *state, void *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_list_start_decode(state) && ((((zcbor_uint32_expect(state, (2))))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_auth_challenge_rsp(
		zcbor_state_t *state, struct auth_challenge_rsp *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_list_start_decode(state) && ((((zcbor_uint32_expect(state, (0))))
	&& ((decode_prov_status(state, (&(*result).auth_challenge_rsp_prov_status_m))))
	&& ((zcbor_bstr_decode(state, (&(*result).auth_challenge_rsp_dev_nonce)))
	&& ((((*result).auth_challenge_rsp_dev_nonce.len == 16)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false)))
	&& ((zcbor_bstr_decode(state, (&(*result).auth_challenge_rsp_dev_proof)))
	&& ((((*result).auth_challenge_rsp_dev_proof.len == 32)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false)))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_auth_proof_rsp(
		zcbor_state_t *state, struct auth_proof_rsp *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_list_start_decode(state) && ((((zcbor_uint32_expect(state, (1))))
	&& ((decode_prov_status(state, (&(*result).auth_proof_rsp_prov_status_m))))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_scan_start_rsp(
		zcbor_state_t *state, struct scan_start_rsp *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_list_start_decode(state) && ((((zcbor_uint32_expect(state, (0))))
	&& ((decode_prov_status(state, (&(*result).scan_start_rsp_prov_status_m))))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_scan_status_rsp(
		zcbor_state_t *state, struct scan_status_rsp *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_list_start_decode(state) && ((((zcbor_uint32_expect(state, (1))))
	&& ((decode_prov_status(state, (&(*result).scan_status_rsp_prov_status_m))))
	&& ((zcbor_bool_decode(state, (&(*result).scan_status_rsp_finished))))
	&& ((zcbor_uint32_decode(state, (&(*result).scan_status_rsp_total))))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_scan_entry(
		zcbor_state_t *state, struct scan_entry *result)
{
	zcbor_log("%s\r\n", __func__);
	struct zcbor_string tmp_str;

	bool res = (((zcbor_map_start_decode(state) && (((((zcbor_tstr_expect(state, ((tmp_str.value = (uint8_t *)"ssid", tmp_str.len = sizeof("ssid") - 1, &tmp_str)))))
	&& (zcbor_bstr_decode(state, (&(*result).scan_entry_ssid)))
	&& ((((*result).scan_entry_ssid.len >= 0)
	&& ((*result).scan_entry_ssid.len <= 32)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false)))
	&& (((zcbor_tstr_expect(state, ((tmp_str.value = (uint8_t *)"bssid", tmp_str.len = sizeof("bssid") - 1, &tmp_str)))))
	&& (zcbor_bstr_decode(state, (&(*result).scan_entry_bssid)))
	&& ((((*result).scan_entry_bssid.len == 6)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false)))
	&& (((zcbor_tstr_expect(state, ((tmp_str.value = (uint8_t *)"ch", tmp_str.len = sizeof("ch") - 1, &tmp_str)))))
	&& (zcbor_uint32_decode(state, (&(*result).scan_entry_ch))))
	&& (((zcbor_tstr_expect(state, ((tmp_str.value = (uint8_t *)"rssi", tmp_str.len = sizeof("rssi") - 1, &tmp_str)))))
	&& (zcbor_int32_decode(state, (&(*result).scan_entry_rssi))))
	&& (((zcbor_tstr_expect(state, ((tmp_str.value = (uint8_t *)"auth", tmp_str.len = sizeof("auth") - 1, &tmp_str)))))
	&& (zcbor_uint32_decode(state, (&(*result).scan_entry_auth))))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_map_end_decode(state))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_scan_results_rsp(
		zcbor_state_t *state, struct scan_results_rsp *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_list_start_decode(state) && ((((zcbor_uint32_expect(state, (2))))
	&& ((decode_prov_status(state, (&(*result).scan_results_rsp_prov_status_m))))
	&& ((zcbor_list_start_decode(state) && ((zcbor_multi_decode(0, 8, &(*result).scan_results_rsp_scan_entry_m_l_scan_entry_m_count, (zcbor_decoder_t *)decode_scan_entry, state, (*&(*result).scan_results_rsp_scan_entry_m_l_scan_entry_m), sizeof(struct scan_entry))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state)))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state))));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		decode_scan_entry(state, (*&(*result).scan_results_rsp_scan_entry_m_l_scan_entry_m));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_cred_write_rsp(
		zcbor_state_t *state, struct cred_write_rsp *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_list_start_decode(state) && ((((zcbor_uint32_expect(state, (0))))
	&& ((decode_prov_status(state, (&(*result).cred_write_rsp_prov_status_m))))
	&& ((zcbor_uint32_decode(state, (&(*result).cred_write_rsp_received))))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_cred_finalize_rsp(
		zcbor_state_t *state, struct cred_finalize_rsp *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_list_start_decode(state) && ((((zcbor_uint32_expect(state, (1))))
	&& ((decode_prov_status(state, (&(*result).cred_finalize_rsp_prov_status_m))))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_map_tstruint(
		zcbor_state_t *state, struct map_tstruint *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((((zcbor_tstr_decode(state, (&(*result).cred_status_rsp_map_tstruint_key))))
	&& (zcbor_uint32_decode(state, (&(*result).map_tstruint)))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_cred_status_rsp(
		zcbor_state_t *state, struct cred_status_rsp *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_list_start_decode(state) && ((((zcbor_uint32_expect(state, (2))))
	&& ((decode_prov_status(state, (&(*result).cred_status_rsp_prov_status_m))))
	&& ((zcbor_map_start_decode(state) && ((zcbor_multi_decode(0, 8, &(*result).map_tstruint_count, (zcbor_decoder_t *)decode_repeated_map_tstruint, state, (*&(*result).map_tstruint), sizeof(struct map_tstruint))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_map_end_decode(state)))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state))));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		decode_repeated_map_tstruint(state, (*&(*result).map_tstruint));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_sta_state(
		zcbor_state_t *state, struct sta_state_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((((zcbor_uint_decode(state, &(*result).sta_state_choice, sizeof((*result).sta_state_choice)))) && ((((((*result).sta_state_choice == sta_state_sta_connected_m_c) && ((1)))
	|| (((*result).sta_state_choice == sta_state_sta_connecting_m_c) && ((1)))
	|| (((*result).sta_state_choice == sta_state_sta_disconnected_m_c) && ((1)))
	|| (((*result).sta_state_choice == sta_state_sta_failed_m_c) && ((1)))) || (zcbor_error(state, ZCBOR_ERR_WRONG_VALUE), false))))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_fail_reason(
		zcbor_state_t *state, struct fail_reason_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((((zcbor_uint_decode(state, &(*result).fail_reason_choice, sizeof((*result).fail_reason_choice)))) && ((((((*result).fail_reason_choice == fail_reason_fail_auth_error_m_c) && ((1)))
	|| (((*result).fail_reason_choice == fail_reason_fail_network_not_found_m_c) && ((1)))) || (zcbor_error(state, ZCBOR_ERR_WRONG_VALUE), false))))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_connected_info_rssi(
		zcbor_state_t *state, struct connected_info_rssi *result)
{
	zcbor_log("%s\r\n", __func__);
	struct zcbor_string tmp_str;

	bool res = ((((zcbor_tstr_expect(state, ((tmp_str.value = (uint8_t *)"rssi", tmp_str.len = sizeof("rssi") - 1, &tmp_str)))))
	&& (zcbor_int32_decode(state, (&(*result).connected_info_rssi)))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_connected_info(
		zcbor_state_t *state, struct connected_info *result)
{
	zcbor_log("%s\r\n", __func__);
	struct zcbor_string tmp_str;

	bool res = (((zcbor_map_start_decode(state) && (((((zcbor_tstr_expect(state, ((tmp_str.value = (uint8_t *)"ip4", tmp_str.len = sizeof("ip4") - 1, &tmp_str)))))
	&& (zcbor_bstr_decode(state, (&(*result).connected_info_ip4)))
	&& ((((*result).connected_info_ip4.len == 4)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false)))
	&& (((zcbor_tstr_expect(state, ((tmp_str.value = (uint8_t *)"ssid", tmp_str.len = sizeof("ssid") - 1, &tmp_str)))))
	&& (zcbor_bstr_decode(state, (&(*result).connected_info_ssid)))
	&& ((((*result).connected_info_ssid.len >= 1)
	&& ((*result).connected_info_ssid.len <= 32)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false)))
	&& zcbor_present_decode(&((*result).connected_info_rssi_present), (zcbor_decoder_t *)decode_repeated_connected_info_rssi, state, (&(*result).connected_info_rssi))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_map_end_decode(state))));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		decode_repeated_connected_info_rssi(state, (&(*result).connected_info_rssi));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_config_detail(
		zcbor_state_t *state, struct config_detail_r *result)
{
	zcbor_log("%s\r\n", __func__);
	bool int_res;

	bool res = (((zcbor_union_start_code(state) && (int_res = ((((decode_fail_reason(state, (&(*result).config_detail_fail_reason_m)))) && (((*result).config_detail_choice = config_detail_fail_reason_m_c), true))
	|| (zcbor_union_elem_code(state) && (((decode_connected_info(state, (&(*result).config_detail_connected_info_m)))) && (((*result).config_detail_choice = config_detail_connected_info_m_c), true)))), zcbor_union_end_code(state), int_res))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_config_status_rsp(
		zcbor_state_t *state, struct config_status_rsp *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_list_start_decode(state) && ((((zcbor_uint32_expect(state, (0))))
	&& ((decode_prov_status(state, (&(*result).config_status_rsp_prov_status_m))))
	&& ((decode_sta_state(state, (&(*result).config_status_rsp_sta_state_m))))
	&& ((*result).config_status_rsp_config_detail_m_present = ((decode_config_detail(state, (&(*result).config_status_rsp_config_detail_m)))), 1)) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_config_set_rsp(
		zcbor_state_t *state, struct config_set_rsp *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_list_start_decode(state) && ((((zcbor_uint32_expect(state, (1))))
	&& ((decode_prov_status(state, (&(*result).config_set_rsp_prov_status_m))))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_config_apply_rsp(
		zcbor_state_t *state, struct config_apply_rsp *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_list_start_decode(state) && ((((zcbor_uint32_expect(state, (2))))
	&& ((decode_prov_status(state, (&(*result).config_apply_rsp_prov_status_m))))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_cred_kind(
		zcbor_state_t *state, struct cred_kind_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((((zcbor_uint_decode(state, &(*result).cred_kind_choice, sizeof((*result).cred_kind_choice)))) && ((((((*result).cred_kind_choice == cred_kind_cred_device_cert_m_c) && ((1)))
	|| (((*result).cred_kind_choice == cred_kind_cred_private_key_m_c) && ((1)))
	|| (((*result).cred_kind_choice == cred_kind_cred_ca_cert_m_c) && ((1)))) || (zcbor_error(state, ZCBOR_ERR_WRONG_VALUE), false))))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_cred_chunk(
		zcbor_state_t *state, struct cred_chunk *result)
{
	zcbor_log("%s\r\n", __func__);
	struct zcbor_string tmp_str;

	bool res = (((zcbor_map_start_decode(state) && (((((zcbor_tstr_expect(state, ((tmp_str.value = (uint8_t *)"kind", tmp_str.len = sizeof("kind") - 1, &tmp_str)))))
	&& (decode_cred_kind(state, (&(*result).cred_chunk_kind))))
	&& (((zcbor_tstr_expect(state, ((tmp_str.value = (uint8_t *)"off", tmp_str.len = sizeof("off") - 1, &tmp_str)))))
	&& (zcbor_uint32_decode(state, (&(*result).cred_chunk_off))))
	&& (((zcbor_tstr_expect(state, ((tmp_str.value = (uint8_t *)"total", tmp_str.len = sizeof("total") - 1, &tmp_str)))))
	&& (zcbor_uint32_decode(state, (&(*result).cred_chunk_total))))
	&& (((zcbor_tstr_expect(state, ((tmp_str.value = (uint8_t *)"data", tmp_str.len = sizeof("data") - 1, &tmp_str)))))
	&& (zcbor_bstr_decode(state, (&(*result).cred_chunk_data))))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_map_end_decode(state))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_cred_write(
		zcbor_state_t *state, struct cred_write *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_list_start_decode(state) && ((((zcbor_uint32_expect(state, (0))))
	&& ((decode_cred_chunk(state, (&(*result).cred_write_cred_chunk_m))))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_cred_finalize(
		zcbor_state_t *state, void *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_list_start_decode(state) && ((((zcbor_uint32_expect(state, (1))))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_cred_get_status(
		zcbor_state_t *state, void *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_list_start_decode(state) && ((((zcbor_uint32_expect(state, (2))))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_ctrl_rsp(
		zcbor_state_t *state, struct ctrl_rsp *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_list_start_decode(state) && ((((zcbor_uint32_decode(state, (&(*result).ctrl_rsp_ctrl_op_m)))
	&& ((((((*result).ctrl_rsp_ctrl_op_m <= 2)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false)))
	&& ((decode_prov_status(state, (&(*result).ctrl_rsp_prov_status_m))))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_ctrl_req(
		zcbor_state_t *state, struct ctrl_req_r *result)
{
	zcbor_log("%s\r\n", __func__);
	bool int_res;

	bool res = (((zcbor_union_start_code(state) && (int_res = ((((decode_ctrl_reset(state, NULL))) && (((*result).ctrl_req_choice = ctrl_req_ctrl_reset_m_c), true))
	|| (zcbor_union_elem_code(state) && (((decode_ctrl_reprovision(state, NULL))) && (((*result).ctrl_req_choice = ctrl_req_ctrl_reprovision_m_c), true)))
	|| (zcbor_union_elem_code(state) && (((decode_ctrl_end(state, NULL))) && (((*result).ctrl_req_choice = ctrl_req_ctrl_end_m_c), true)))), zcbor_union_end_code(state), int_res))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_cred_rsp(
		zcbor_state_t *state, struct cred_rsp_r *result)
{
	zcbor_log("%s\r\n", __func__);
	bool int_res;

	bool res = (((zcbor_union_start_code(state) && (int_res = ((((decode_cred_write_rsp(state, (&(*result).cred_rsp_cred_write_rsp_m)))) && (((*result).cred_rsp_choice = cred_rsp_cred_write_rsp_m_c), true))
	|| (zcbor_union_elem_code(state) && (((decode_cred_finalize_rsp(state, (&(*result).cred_rsp_cred_finalize_rsp_m)))) && (((*result).cred_rsp_choice = cred_rsp_cred_finalize_rsp_m_c), true)))
	|| (zcbor_union_elem_code(state) && (((decode_cred_status_rsp(state, (&(*result).cred_rsp_cred_status_rsp_m)))) && (((*result).cred_rsp_choice = cred_rsp_cred_status_rsp_m_c), true)))), zcbor_union_end_code(state), int_res))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_cred_req(
		zcbor_state_t *state, struct cred_req_r *result)
{
	zcbor_log("%s\r\n", __func__);
	bool int_res;

	bool res = (((zcbor_union_start_code(state) && (int_res = ((((decode_cred_write(state, (&(*result).cred_req_cred_write_m)))) && (((*result).cred_req_choice = cred_req_cred_write_m_c), true))
	|| (zcbor_union_elem_code(state) && (((decode_cred_finalize(state, NULL))) && (((*result).cred_req_choice = cred_req_cred_finalize_m_c), true)))
	|| (zcbor_union_elem_code(state) && (((decode_cred_get_status(state, NULL))) && (((*result).cred_req_choice = cred_req_cred_get_status_m_c), true)))), zcbor_union_end_code(state), int_res))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_scan_rsp(
		zcbor_state_t *state, struct scan_rsp_r *result)
{
	zcbor_log("%s\r\n", __func__);
	bool int_res;

	bool res = (((zcbor_union_start_code(state) && (int_res = ((((decode_scan_start_rsp(state, (&(*result).scan_rsp_scan_start_rsp_m)))) && (((*result).scan_rsp_choice = scan_rsp_scan_start_rsp_m_c), true))
	|| (zcbor_union_elem_code(state) && (((decode_scan_status_rsp(state, (&(*result).scan_rsp_scan_status_rsp_m)))) && (((*result).scan_rsp_choice = scan_rsp_scan_status_rsp_m_c), true)))
	|| (zcbor_union_elem_code(state) && (((decode_scan_results_rsp(state, (&(*result).scan_rsp_scan_results_rsp_m)))) && (((*result).scan_rsp_choice = scan_rsp_scan_results_rsp_m_c), true)))), zcbor_union_end_code(state), int_res))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_scan_req(
		zcbor_state_t *state, struct scan_req_r *result)
{
	zcbor_log("%s\r\n", __func__);
	bool int_res;

	bool res = (((zcbor_union_start_code(state) && (int_res = ((((decode_scan_start(state, (&(*result).scan_req_scan_start_m)))) && (((*result).scan_req_choice = scan_req_scan_start_m_c), true))
	|| (zcbor_union_elem_code(state) && (((decode_scan_get_status(state, NULL))) && (((*result).scan_req_choice = scan_req_scan_get_status_m_c), true)))
	|| (zcbor_union_elem_code(state) && (((decode_scan_get_results(state, (&(*result).scan_req_scan_get_results_m)))) && (((*result).scan_req_choice = scan_req_scan_get_results_m_c), true)))), zcbor_union_end_code(state), int_res))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_config_rsp(
		zcbor_state_t *state, struct config_rsp_r *result)
{
	zcbor_log("%s\r\n", __func__);
	bool int_res;

	bool res = (((zcbor_union_start_code(state) && (int_res = ((((decode_config_status_rsp(state, (&(*result).config_rsp_config_status_rsp_m)))) && (((*result).config_rsp_choice = config_rsp_config_status_rsp_m_c), true))
	|| (zcbor_union_elem_code(state) && (((decode_config_set_rsp(state, (&(*result).config_rsp_config_set_rsp_m)))) && (((*result).config_rsp_choice = config_rsp_config_set_rsp_m_c), true)))
	|| (zcbor_union_elem_code(state) && (((decode_config_apply_rsp(state, (&(*result).config_rsp_config_apply_rsp_m)))) && (((*result).config_rsp_choice = config_rsp_config_apply_rsp_m_c), true)))), zcbor_union_end_code(state), int_res))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_config_req(
		zcbor_state_t *state, struct config_req_r *result)
{
	zcbor_log("%s\r\n", __func__);
	bool int_res;

	bool res = (((zcbor_union_start_code(state) && (int_res = ((((decode_config_get_status(state, NULL))) && (((*result).config_req_choice = config_req_config_get_status_m_c), true))
	|| (zcbor_union_elem_code(state) && (((decode_config_set(state, (&(*result).config_req_config_set_m)))) && (((*result).config_req_choice = config_req_config_set_m_c), true)))
	|| (zcbor_union_elem_code(state) && (((decode_config_apply(state, NULL))) && (((*result).config_req_choice = config_req_config_apply_m_c), true)))), zcbor_union_end_code(state), int_res))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_auth_rsp(
		zcbor_state_t *state, struct auth_rsp_r *result)
{
	zcbor_log("%s\r\n", __func__);
	bool int_res;

	bool res = (((zcbor_union_start_code(state) && (int_res = ((((decode_auth_challenge_rsp(state, (&(*result).auth_rsp_auth_challenge_rsp_m)))) && (((*result).auth_rsp_choice = auth_rsp_auth_challenge_rsp_m_c), true))
	|| (zcbor_union_elem_code(state) && (((decode_auth_proof_rsp(state, (&(*result).auth_rsp_auth_proof_rsp_m)))) && (((*result).auth_rsp_choice = auth_rsp_auth_proof_rsp_m_c), true)))), zcbor_union_end_code(state), int_res))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_auth_req(
		zcbor_state_t *state, struct auth_req_r *result)
{
	zcbor_log("%s\r\n", __func__);
	bool int_res;

	bool res = (((zcbor_union_start_code(state) && (int_res = ((((decode_auth_challenge(state, (&(*result).auth_req_auth_challenge_m)))) && (((*result).auth_req_choice = auth_req_auth_challenge_m_c), true))
	|| (zcbor_union_elem_code(state) && (((decode_auth_proof(state, (&(*result).auth_req_auth_proof_m)))) && (((*result).auth_req_choice = auth_req_auth_proof_m_c), true)))), zcbor_union_end_code(state), int_res))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_ver_rsp(
		zcbor_state_t *state, struct ver_rsp *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_list_start_decode(state) && ((((zcbor_uint32_expect(state, (0))))
	&& ((decode_prov_status(state, (&(*result).ver_rsp_prov_status_m))))
	&& ((decode_ver_info(state, (&(*result).ver_rsp_ver_info_m))))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_ver_req(
		zcbor_state_t *state, void *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_list_start_decode(state) && ((((zcbor_uint32_expect(state, (0))))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state))));

	log_result(state, res, __func__);
	return res;
}



int cbor_decode_ver_req(
		const uint8_t *payload, size_t payload_len,
		void *result,
		size_t *payload_len_out)
{
	zcbor_state_t states[3];

	return zcbor_entry_function(payload, payload_len, (void *)result, payload_len_out, states,
		(zcbor_decoder_t *)decode_ver_req, sizeof(states) / sizeof(zcbor_state_t), 1);
}


int cbor_decode_ver_rsp(
		const uint8_t *payload, size_t payload_len,
		struct ver_rsp *result,
		size_t *payload_len_out)
{
	zcbor_state_t states[5];

	return zcbor_entry_function(payload, payload_len, (void *)result, payload_len_out, states,
		(zcbor_decoder_t *)decode_ver_rsp, sizeof(states) / sizeof(zcbor_state_t), 1);
}


int cbor_decode_auth_req(
		const uint8_t *payload, size_t payload_len,
		struct auth_req_r *result,
		size_t *payload_len_out)
{
	zcbor_state_t states[4];

	return zcbor_entry_function(payload, payload_len, (void *)result, payload_len_out, states,
		(zcbor_decoder_t *)decode_auth_req, sizeof(states) / sizeof(zcbor_state_t), 1);
}


int cbor_decode_auth_rsp(
		const uint8_t *payload, size_t payload_len,
		struct auth_rsp_r *result,
		size_t *payload_len_out)
{
	zcbor_state_t states[5];

	return zcbor_entry_function(payload, payload_len, (void *)result, payload_len_out, states,
		(zcbor_decoder_t *)decode_auth_rsp, sizeof(states) / sizeof(zcbor_state_t), 1);
}


int cbor_decode_config_req(
		const uint8_t *payload, size_t payload_len,
		struct config_req_r *result,
		size_t *payload_len_out)
{
	zcbor_state_t states[5];

	return zcbor_entry_function(payload, payload_len, (void *)result, payload_len_out, states,
		(zcbor_decoder_t *)decode_config_req, sizeof(states) / sizeof(zcbor_state_t), 1);
}


int cbor_decode_config_rsp(
		const uint8_t *payload, size_t payload_len,
		struct config_rsp_r *result,
		size_t *payload_len_out)
{
	zcbor_state_t states[6];

	return zcbor_entry_function(payload, payload_len, (void *)result, payload_len_out, states,
		(zcbor_decoder_t *)decode_config_rsp, sizeof(states) / sizeof(zcbor_state_t), 1);
}


int cbor_decode_scan_req(
		const uint8_t *payload, size_t payload_len,
		struct scan_req_r *result,
		size_t *payload_len_out)
{
	zcbor_state_t states[5];

	return zcbor_entry_function(payload, payload_len, (void *)result, payload_len_out, states,
		(zcbor_decoder_t *)decode_scan_req, sizeof(states) / sizeof(zcbor_state_t), 1);
}


int cbor_decode_scan_rsp(
		const uint8_t *payload, size_t payload_len,
		struct scan_rsp_r *result,
		size_t *payload_len_out)
{
	zcbor_state_t states[6];

	return zcbor_entry_function(payload, payload_len, (void *)result, payload_len_out, states,
		(zcbor_decoder_t *)decode_scan_rsp, sizeof(states) / sizeof(zcbor_state_t), 1);
}


int cbor_decode_cred_req(
		const uint8_t *payload, size_t payload_len,
		struct cred_req_r *result,
		size_t *payload_len_out)
{
	zcbor_state_t states[6];

	return zcbor_entry_function(payload, payload_len, (void *)result, payload_len_out, states,
		(zcbor_decoder_t *)decode_cred_req, sizeof(states) / sizeof(zcbor_state_t), 1);
}


int cbor_decode_cred_rsp(
		const uint8_t *payload, size_t payload_len,
		struct cred_rsp_r *result,
		size_t *payload_len_out)
{
	zcbor_state_t states[5];

	return zcbor_entry_function(payload, payload_len, (void *)result, payload_len_out, states,
		(zcbor_decoder_t *)decode_cred_rsp, sizeof(states) / sizeof(zcbor_state_t), 1);
}


int cbor_decode_ctrl_req(
		const uint8_t *payload, size_t payload_len,
		struct ctrl_req_r *result,
		size_t *payload_len_out)
{
	zcbor_state_t states[4];

	return zcbor_entry_function(payload, payload_len, (void *)result, payload_len_out, states,
		(zcbor_decoder_t *)decode_ctrl_req, sizeof(states) / sizeof(zcbor_state_t), 1);
}


int cbor_decode_ctrl_rsp(
		const uint8_t *payload, size_t payload_len,
		struct ctrl_rsp *result,
		size_t *payload_len_out)
{
	zcbor_state_t states[4];

	return zcbor_entry_function(payload, payload_len, (void *)result, payload_len_out, states,
		(zcbor_decoder_t *)decode_ctrl_rsp, sizeof(states) / sizeof(zcbor_state_t), 1);
}
