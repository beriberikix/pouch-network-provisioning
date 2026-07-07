/*
 * Generated using zcbor version 0.9.1
 * https://github.com/NordicSemiconductor/zcbor
 * Generated with a --default-max-qty of 8
 */

#ifndef PROV_TYPES_H__
#define PROV_TYPES_H__

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <zcbor_common.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Which value for --default-max-qty this file was created with.
 *
 *  The define is used in the other generated file to do a build-time
 *  compatibility check.
 *
 *  See `zcbor --help` for more information about --default-max-qty
 */
#define DEFAULT_MAX_QTY 8

struct prov_status_r {
	enum {
		prov_status_status_ok_m_c = 0,
		prov_status_status_invalid_proto_m_c = 1,
		prov_status_status_invalid_argument_m_c = 2,
		prov_status_status_internal_error_m_c = 3,
		prov_status_status_unauthorized_m_c = 4,
		prov_status_status_invalid_state_m_c = 5,
		prov_status_status_busy_m_c = 6,
	} prov_status_choice;
};

struct ver_info_pop {
	bool ver_info_pop;
};

struct ver_info {
	uint32_t ver_info_proto;
	struct zcbor_string ver_info_caps_tstr[8];
	size_t ver_info_caps_tstr_count;
	uint32_t ver_info_blk;
	struct zcbor_string ver_info_lib;
	struct ver_info_pop ver_info_pop;
	bool ver_info_pop_present;
};

struct ver_rsp {
	struct prov_status_r ver_rsp_prov_status_m;
	struct ver_info ver_rsp_ver_info_m;
};

struct auth_challenge {
	struct zcbor_string auth_challenge_cli_nonce;
};

struct auth_proof {
	struct zcbor_string auth_proof_cli_proof;
};

struct auth_req_r {
	union {
		struct auth_challenge auth_req_auth_challenge_m;
		struct auth_proof auth_req_auth_proof_m;
	};
	enum {
		auth_req_auth_challenge_m_c,
		auth_req_auth_proof_m_c,
	} auth_req_choice;
};

struct wifi_config_pass {
	struct zcbor_string wifi_config_pass;
};

struct wifi_config_bssid {
	struct zcbor_string wifi_config_bssid;
};

struct wifi_config_ch {
	uint32_t wifi_config_ch;
};

struct wifi_config {
	struct zcbor_string wifi_config_ssid;
	struct wifi_config_pass wifi_config_pass;
	bool wifi_config_pass_present;
	struct wifi_config_bssid wifi_config_bssid;
	bool wifi_config_bssid_present;
	struct wifi_config_ch wifi_config_ch;
	bool wifi_config_ch_present;
};

struct config_set {
	struct wifi_config config_set_wifi_config_m;
};

struct config_req_r {
	union {
		struct config_set config_req_config_set_m;
	};
	enum {
		config_req_config_get_status_m_c,
		config_req_config_set_m_c,
		config_req_config_apply_m_c,
	} config_req_choice;
};

struct scan_params_passive {
	bool scan_params_passive;
};

struct scan_params_period_ms {
	uint32_t scan_params_period_ms;
};

struct scan_params {
	struct scan_params_passive scan_params_passive;
	bool scan_params_passive_present;
	struct scan_params_period_ms scan_params_period_ms;
	bool scan_params_period_ms_present;
};

struct scan_start {
	struct scan_params scan_start_scan_params_m;
};

struct scan_get_results {
	uint32_t scan_get_results_start;
	uint32_t scan_get_results_count;
};

struct scan_req_r {
	union {
		struct scan_start scan_req_scan_start_m;
		struct scan_get_results scan_req_scan_get_results_m;
	};
	enum {
		scan_req_scan_start_m_c,
		scan_req_scan_get_status_m_c,
		scan_req_scan_get_results_m_c,
	} scan_req_choice;
};

struct ctrl_req_r {
	enum {
		ctrl_req_ctrl_reset_m_c,
		ctrl_req_ctrl_reprovision_m_c,
		ctrl_req_ctrl_end_m_c,
	} ctrl_req_choice;
};

struct ctrl_rsp {
	uint32_t ctrl_rsp_ctrl_op_m;
	struct prov_status_r ctrl_rsp_prov_status_m;
};

struct auth_challenge_rsp {
	struct prov_status_r auth_challenge_rsp_prov_status_m;
	struct zcbor_string auth_challenge_rsp_dev_nonce;
	struct zcbor_string auth_challenge_rsp_dev_proof;
};

struct auth_proof_rsp {
	struct prov_status_r auth_proof_rsp_prov_status_m;
};

struct auth_rsp_r {
	union {
		struct auth_challenge_rsp auth_rsp_auth_challenge_rsp_m;
		struct auth_proof_rsp auth_rsp_auth_proof_rsp_m;
	};
	enum {
		auth_rsp_auth_challenge_rsp_m_c,
		auth_rsp_auth_proof_rsp_m_c,
	} auth_rsp_choice;
};

struct scan_start_rsp {
	struct prov_status_r scan_start_rsp_prov_status_m;
};

struct scan_status_rsp {
	struct prov_status_r scan_status_rsp_prov_status_m;
	bool scan_status_rsp_finished;
	uint32_t scan_status_rsp_total;
};

struct scan_entry {
	struct zcbor_string scan_entry_ssid;
	struct zcbor_string scan_entry_bssid;
	uint32_t scan_entry_ch;
	int32_t scan_entry_rssi;
	uint32_t scan_entry_auth;
};

struct scan_results_rsp {
	struct prov_status_r scan_results_rsp_prov_status_m;
	struct scan_entry scan_results_rsp_scan_entry_m_l_scan_entry_m[8];
	size_t scan_results_rsp_scan_entry_m_l_scan_entry_m_count;
};

struct scan_rsp_r {
	union {
		struct scan_start_rsp scan_rsp_scan_start_rsp_m;
		struct scan_status_rsp scan_rsp_scan_status_rsp_m;
		struct scan_results_rsp scan_rsp_scan_results_rsp_m;
	};
	enum {
		scan_rsp_scan_start_rsp_m_c,
		scan_rsp_scan_status_rsp_m_c,
		scan_rsp_scan_results_rsp_m_c,
	} scan_rsp_choice;
};

struct cred_write_rsp {
	struct prov_status_r cred_write_rsp_prov_status_m;
	uint32_t cred_write_rsp_received;
};

struct cred_finalize_rsp {
	struct prov_status_r cred_finalize_rsp_prov_status_m;
};

struct map_tstruint {
	struct zcbor_string cred_status_rsp_map_tstruint_key;
	uint32_t map_tstruint;
};

struct cred_status_rsp {
	struct prov_status_r cred_status_rsp_prov_status_m;
	struct map_tstruint map_tstruint[8];
	size_t map_tstruint_count;
};

struct cred_rsp_r {
	union {
		struct cred_write_rsp cred_rsp_cred_write_rsp_m;
		struct cred_finalize_rsp cred_rsp_cred_finalize_rsp_m;
		struct cred_status_rsp cred_rsp_cred_status_rsp_m;
	};
	enum {
		cred_rsp_cred_write_rsp_m_c,
		cred_rsp_cred_finalize_rsp_m_c,
		cred_rsp_cred_status_rsp_m_c,
	} cred_rsp_choice;
};

struct sta_state_r {
	enum {
		sta_state_sta_connected_m_c = 0,
		sta_state_sta_connecting_m_c = 1,
		sta_state_sta_disconnected_m_c = 2,
		sta_state_sta_failed_m_c = 3,
	} sta_state_choice;
};

struct fail_reason_r {
	enum {
		fail_reason_fail_auth_error_m_c = 0,
		fail_reason_fail_network_not_found_m_c = 1,
	} fail_reason_choice;
};

struct connected_info_rssi {
	int32_t connected_info_rssi;
};

struct connected_info {
	struct zcbor_string connected_info_ip4;
	struct zcbor_string connected_info_ssid;
	struct connected_info_rssi connected_info_rssi;
	bool connected_info_rssi_present;
};

struct config_detail_r {
	union {
		struct fail_reason_r config_detail_fail_reason_m;
		struct connected_info config_detail_connected_info_m;
	};
	enum {
		config_detail_fail_reason_m_c,
		config_detail_connected_info_m_c,
	} config_detail_choice;
};

struct config_status_rsp {
	struct prov_status_r config_status_rsp_prov_status_m;
	struct sta_state_r config_status_rsp_sta_state_m;
	struct config_detail_r config_status_rsp_config_detail_m;
	bool config_status_rsp_config_detail_m_present;
};

struct config_set_rsp {
	struct prov_status_r config_set_rsp_prov_status_m;
};

struct config_apply_rsp {
	struct prov_status_r config_apply_rsp_prov_status_m;
};

struct config_rsp_r {
	union {
		struct config_status_rsp config_rsp_config_status_rsp_m;
		struct config_set_rsp config_rsp_config_set_rsp_m;
		struct config_apply_rsp config_rsp_config_apply_rsp_m;
	};
	enum {
		config_rsp_config_status_rsp_m_c,
		config_rsp_config_set_rsp_m_c,
		config_rsp_config_apply_rsp_m_c,
	} config_rsp_choice;
};

struct cred_kind_r {
	enum {
		cred_kind_cred_device_cert_m_c = 0,
		cred_kind_cred_private_key_m_c = 1,
		cred_kind_cred_ca_cert_m_c = 2,
	} cred_kind_choice;
};

struct cred_chunk {
	struct cred_kind_r cred_chunk_kind;
	uint32_t cred_chunk_off;
	uint32_t cred_chunk_total;
	struct zcbor_string cred_chunk_data;
};

struct cred_write {
	struct cred_chunk cred_write_cred_chunk_m;
};

struct cred_req_r {
	union {
		struct cred_write cred_req_cred_write_m;
	};
	enum {
		cred_req_cred_write_m_c,
		cred_req_cred_finalize_m_c,
		cred_req_cred_get_status_m_c,
	} cred_req_choice;
};

#ifdef __cplusplus
}
#endif

#endif /* PROV_TYPES_H__ */
