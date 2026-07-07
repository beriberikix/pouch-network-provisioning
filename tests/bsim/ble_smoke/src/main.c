/*
 * Copyright (c) 2026 Jonathan Beri
 * SPDX-License-Identifier: Apache-2.0
 *
 * BabbleSim central tester: scans for the provisioning advertisement,
 * connects, pairs (Just Works LESC — the peripheral sends the Security
 * Request per src/adv.c), discovers the pouch GATT service, and then
 * performs a .prov/ver RPC round trip over the pouch SAR transport:
 * request pouch written to the downlink characteristic, response pouch
 * received via uplink notifications. Each stage prints a "PROV_BSIM:"
 * marker that pytest/test_ble_smoke.py asserts; failures print
 * "PROV_BSIM: FAIL <stage>" so they are diagnosable from the log.
 *
 * Wire-format constants are intentionally redefined here (rather than
 * pulled from pouch headers) so the test pins the format the pouchprov
 * CLI and future mobile SDKs rely on. The SAR client below mirrors
 * cli/src/pouchprov/pouchlink/sar.py; the request frame bytes are the
 * golden vector shared with the CLI tests (tests/codec/src/vectors.inc,
 * generated from tests/vectors/pouch_frames.json).
 */

#include <string.h>

#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/conn.h>
#include <zephyr/bluetooth/gap.h>
#include <zephyr/bluetooth/gatt.h>
#include <zephyr/bluetooth/uuid.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/sys/printk.h>

#include "vectors.inc" /* frame_single_entry: pouch frame with a .prov/ver request */

/* Pouch GATT service (16-bit) and characteristic (128-bit) UUIDs, from
 * pouch port/zephyr/transport/gatt/common.h.
 */
#define POUCH_SVC_UUID_VAL 0xFC49

static const struct bt_uuid_16 svc_uuid = BT_UUID_INIT_16(POUCH_SVC_UUID_VAL);
static const struct bt_uuid_128 uplink_uuid =
	BT_UUID_INIT_128(BT_UUID_128_ENCODE(0x89a316ae, 0x89b7, 0x4ef6, 0xb1d3, 0x5c9a6e27d273));
static const struct bt_uuid_128 downlink_uuid =
	BT_UUID_INIT_128(BT_UUID_128_ENCODE(0x89a316ae, 0x89b7, 0x4ef6, 0xb1d3, 0x5c9a6e27d274));
static const struct bt_uuid_128 info_uuid =
	BT_UUID_INIT_128(BT_UUID_128_ENCODE(0x89a316ae, 0x89b7, 0x4ef6, 0xb1d3, 0x5c9a6e27d275));

/* Service data payload: le16 UUID + version byte + flags byte. */
#define ADV_SVC_DATA_LEN      4
#define ADV_FLAG_PROVISIONING (1 << 1)

#define DEVICE_NAME_PREFIX "PVN-"

/* Pouch SAR wire format (pouch src/transport/sar/packet.{h,c}).
 * TX packet: [flags, seq] + fragment; FIN packet: [FLAG_FIN, code].
 * ACK packet: [code, last in-order seq (0xFF before any), window].
 */
#define SAR_FLAG_FIRST 0x01
#define SAR_FLAG_LAST  0x02
#define SAR_FLAG_FIN   0x04
#define SAR_CODE_ACK   0x00
#define SAR_ACK_LEN    3
#define SAR_SEQ_NONE   0xFF
#define SAR_WINDOW     8

static K_SEM_DEFINE(sem_found, 0, 1);
static K_SEM_DEFINE(sem_connected, 0, 1);
static K_SEM_DEFINE(sem_secured, 0, 1);
static K_SEM_DEFINE(sem_discovered, 0, 1);
static K_SEM_DEFINE(sem_subscribed, 0, 1);

static struct bt_conn *default_conn;

/* Incoming downlink notifications (SAR ACKs from the device's receiver). */
K_MSGQ_DEFINE(dl_ack_q, SAR_ACK_LEN, 4, 1);

/* Incoming uplink notifications (SAR TX packets from the device's sender). */
struct ul_pkt {
	uint16_t len;
	uint8_t data[251];
};
K_MSGQ_DEFINE(ul_pkt_q, sizeof(struct ul_pkt), 8, 1);

struct adv_result {
	bool svc_data_ok;
	bool name_ok;
	char name[32];
};

static bool adv_parse_cb(struct bt_data *data, void *user_data)
{
	struct adv_result *res = user_data;

	switch (data->type) {
	case BT_DATA_SVC_DATA16:
		if (data->data_len == ADV_SVC_DATA_LEN &&
		    sys_get_le16(data->data) == POUCH_SVC_UUID_VAL &&
		    (data->data[3] & ADV_FLAG_PROVISIONING) != 0) {
			res->svc_data_ok = true;
		}
		break;
	case BT_DATA_NAME_COMPLETE:
		if (data->data_len < sizeof(res->name)) {
			memcpy(res->name, data->data, data->data_len);
			res->name[data->data_len] = '\0';
			res->name_ok = strncmp(res->name, DEVICE_NAME_PREFIX,
					       strlen(DEVICE_NAME_PREFIX)) == 0;
		}
		break;
	default:
		break;
	}

	return true;
}

static void device_found(const bt_addr_le_t *addr, int8_t rssi, uint8_t type,
			 struct net_buf_simple *ad)
{
	struct adv_result res = {0};
	int err;

	if (type != BT_GAP_ADV_TYPE_ADV_IND) {
		return;
	}

	bt_data_parse(ad, adv_parse_cb, &res);

	if (!res.svc_data_ok || !res.name_ok) {
		return;
	}

	printk("PROV_BSIM: found %s\n", res.name);

	err = bt_le_scan_stop();
	if (err != 0) {
		printk("PROV_BSIM: FAIL scan_stop (%d)\n", err);
		return;
	}

	err = bt_conn_le_create(addr, BT_CONN_LE_CREATE_CONN, BT_LE_CONN_PARAM_DEFAULT,
				&default_conn);
	if (err != 0) {
		printk("PROV_BSIM: FAIL conn_create (%d)\n", err);
		return;
	}

	k_sem_give(&sem_found);
}

static void connected(struct bt_conn *conn, uint8_t err)
{
	if (err != 0) {
		printk("PROV_BSIM: FAIL connect (0x%02x)\n", err);
		return;
	}

	printk("PROV_BSIM: connected\n");
	k_sem_give(&sem_connected);
}

static void disconnected(struct bt_conn *conn, uint8_t reason)
{
	printk("PROV_BSIM: disconnected (0x%02x)\n", reason);
}

static void security_changed(struct bt_conn *conn, bt_security_t level, enum bt_security_err err)
{
	if (err != BT_SECURITY_ERR_SUCCESS || level < BT_SECURITY_L2) {
		printk("PROV_BSIM: FAIL security (level %d err %d)\n", level, err);
		return;
	}

	printk("PROV_BSIM: security L%d\n", level);
	k_sem_give(&sem_secured);
}

BT_CONN_CB_DEFINE(conn_callbacks) = {
	.connected = connected,
	.disconnected = disconnected,
	.security_changed = security_changed,
};

/* GATT discovery: primary service by 16-bit UUID, then all characteristics
 * in its handle range, requiring uplink + downlink + info to be present.
 */
static struct bt_gatt_discover_params disc_params;
static uint16_t svc_end_handle;
static uint16_t uplink_value_handle;
static uint16_t downlink_value_handle;
static bool found_uplink, found_downlink, found_info;

static uint8_t discover_cb(struct bt_conn *conn, const struct bt_gatt_attr *attr,
			   struct bt_gatt_discover_params *params)
{
	if (params->type == BT_GATT_DISCOVER_PRIMARY) {
		if (attr == NULL) {
			printk("PROV_BSIM: FAIL service_not_found\n");
			return BT_GATT_ITER_STOP;
		}

		const struct bt_gatt_service_val *svc = attr->user_data;

		svc_end_handle = svc->end_handle;
		printk("PROV_BSIM: service 0x%04x-0x%04x\n", attr->handle, svc->end_handle);

		disc_params.uuid = NULL;
		disc_params.type = BT_GATT_DISCOVER_CHARACTERISTIC;
		disc_params.start_handle = attr->handle + 1;
		disc_params.end_handle = svc->end_handle;

		int err = bt_gatt_discover(conn, &disc_params);

		if (err != 0) {
			printk("PROV_BSIM: FAIL chrc_discover (%d)\n", err);
		}

		return BT_GATT_ITER_STOP;
	}

	/* BT_GATT_DISCOVER_CHARACTERISTIC */
	if (attr == NULL) {
		if (found_uplink && found_downlink && found_info) {
			k_sem_give(&sem_discovered);
		} else {
			printk("PROV_BSIM: FAIL missing_chrc (uplink=%d downlink=%d info=%d)\n",
			       found_uplink, found_downlink, found_info);
		}
		return BT_GATT_ITER_STOP;
	}

	const struct bt_gatt_chrc *chrc = attr->user_data;

	if (bt_uuid_cmp(chrc->uuid, &uplink_uuid.uuid) == 0) {
		found_uplink = true;
		uplink_value_handle = chrc->value_handle;
	} else if (bt_uuid_cmp(chrc->uuid, &downlink_uuid.uuid) == 0) {
		found_downlink = true;
		downlink_value_handle = chrc->value_handle;
	} else if (bt_uuid_cmp(chrc->uuid, &info_uuid.uuid) == 0) {
		found_info = true;
	}

	return BT_GATT_ITER_CONTINUE;
}

static uint8_t downlink_notify_cb(struct bt_conn *conn, struct bt_gatt_subscribe_params *params,
				  const void *data, uint16_t length)
{
	if (data != NULL && length == SAR_ACK_LEN) {
		(void)k_msgq_put(&dl_ack_q, data, K_NO_WAIT);
	}

	return BT_GATT_ITER_CONTINUE;
}

static uint8_t uplink_notify_cb(struct bt_conn *conn, struct bt_gatt_subscribe_params *params,
				const void *data, uint16_t length)
{
	struct ul_pkt pkt;

	if (data == NULL || length > sizeof(pkt.data)) {
		return BT_GATT_ITER_CONTINUE;
	}

	pkt.len = length;
	memcpy(pkt.data, data, length);
	(void)k_msgq_put(&ul_pkt_q, &pkt, K_NO_WAIT);

	return BT_GATT_ITER_CONTINUE;
}

static void subscribe_cb(struct bt_conn *conn, uint8_t err,
			 struct bt_gatt_subscribe_params *params)
{
	if (err != 0) {
		printk("PROV_BSIM: FAIL subscribe (0x%02x)\n", err);
		return;
	}

	k_sem_give(&sem_subscribed);
}

static struct bt_gatt_subscribe_params dl_sub_params;
static struct bt_gatt_discover_params dl_ccc_disc_params;
static struct bt_gatt_subscribe_params ul_sub_params;
static struct bt_gatt_discover_params ul_ccc_disc_params;

static int wait_stage(struct k_sem *sem, const char *stage)
{
	if (k_sem_take(sem, K_SECONDS(30)) != 0) {
		printk("PROV_BSIM: FAIL timeout_%s\n", stage);
		return -ETIMEDOUT;
	}

	return 0;
}

static int subscribe(struct bt_gatt_subscribe_params *params,
		     struct bt_gatt_discover_params *ccc_disc, uint16_t value_handle,
		     bt_gatt_notify_func_t notify, const char *stage)
{
	memset(params, 0, sizeof(*params));
	params->notify = notify;
	params->subscribe = subscribe_cb;
	params->value = BT_GATT_CCC_NOTIFY;
	params->value_handle = value_handle;
	params->ccc_handle = 0; /* auto-discover via disc_params */
	params->disc_params = ccc_disc;
	params->end_handle = svc_end_handle;

	int err = bt_gatt_subscribe(default_conn, params);

	if (err != 0) {
		printk("PROV_BSIM: FAIL %s_subscribe_req (%d)\n", stage, err);
		return err;
	}

	return wait_stage(&sem_subscribed, stage);
}

/* The pouch GATT transport is designed for ATT Write Commands: its write
 * handler consumes the data but returns 0, which the ATT server rejects
 * for Write Requests after the data was already accepted (flow control
 * lives in the SAR ACKs instead).
 */
static int gatt_write_sync(uint16_t handle, const void *data, uint16_t len)
{
	return bt_gatt_write_without_response(default_conn, handle, data, len, false);
}

/* Send the request pouch as one SAR transaction on the downlink
 * characteristic: wait for the receiver's open ACK, send the single
 * FIRST|LAST fragment, wait for its ACK, then send FIN (code 0).
 */
static int send_request(const uint8_t *frame, size_t frame_len)
{
	uint8_t ack[SAR_ACK_LEN];
	uint8_t pkt[2 + sizeof(frame_single_entry)];
	int err;

	if (k_msgq_get(&dl_ack_q, ack, K_SECONDS(30)) != 0) {
		printk("PROV_BSIM: FAIL timeout_open_ack\n");
		return -ETIMEDOUT;
	}
	if (ack[0] != SAR_CODE_ACK || ack[1] != SAR_SEQ_NONE) {
		printk("PROV_BSIM: FAIL open_ack (%02x %02x %02x)\n", ack[0], ack[1], ack[2]);
		return -EIO;
	}

	pkt[0] = SAR_FLAG_FIRST | SAR_FLAG_LAST;
	pkt[1] = 0; /* seq */
	memcpy(&pkt[2], frame, frame_len);

	err = gatt_write_sync(downlink_value_handle, pkt, 2 + frame_len);
	if (err != 0) {
		printk("PROV_BSIM: FAIL request_write (%d)\n", err);
		return err;
	}

	if (k_msgq_get(&dl_ack_q, ack, K_SECONDS(30)) != 0) {
		printk("PROV_BSIM: FAIL timeout_request_ack\n");
		return -ETIMEDOUT;
	}
	if (ack[0] != SAR_CODE_ACK || ack[1] != 0) {
		printk("PROV_BSIM: FAIL request_ack (%02x %02x %02x)\n", ack[0], ack[1], ack[2]);
		return -EIO;
	}

	const uint8_t fin[] = {SAR_FLAG_FIN, SAR_CODE_ACK};

	err = gatt_write_sync(downlink_value_handle, fin, sizeof(fin));
	if (err != 0) {
		printk("PROV_BSIM: FAIL fin_write (%d)\n", err);
		return err;
	}

	return 0;
}

/* Receive the response pouch as one SAR transaction on the uplink
 * characteristic: send the initial ACK, collect and ack in-order
 * fragments until LAST, then expect FIN. The ACK is re-sent as a poll
 * while waiting (mirroring the CLI's SarReceiver): the device's sender
 * opens asynchronously after the CCC subscribe and drops ACKs that
 * arrive before that, then waits for one before pushing fragments.
 */
static int recv_response(uint8_t *buf, size_t buf_size, size_t *out_len)
{
	uint8_t ack[SAR_ACK_LEN] = {SAR_CODE_ACK, SAR_SEQ_NONE, SAR_WINDOW};
	struct ul_pkt pkt;
	size_t len = 0;
	uint8_t expected = 0;
	bool ended = false;
	int err;

	err = gatt_write_sync(uplink_value_handle, ack, sizeof(ack));
	if (err != 0) {
		printk("PROV_BSIM: FAIL initial_ack_write (%d)\n", err);
		return err;
	}

	int polls_left = 60;

	while (true) {
		if (k_msgq_get(&ul_pkt_q, &pkt, K_MSEC(500)) != 0) {
			if (--polls_left <= 0) {
				printk("PROV_BSIM: FAIL timeout_response\n");
				return -ETIMEDOUT;
			}

			err = gatt_write_sync(uplink_value_handle, ack, sizeof(ack));
			if (err != 0) {
				printk("PROV_BSIM: FAIL poll_ack_write (%d)\n", err);
				return err;
			}
			continue;
		}
		if (pkt.len < 2) {
			printk("PROV_BSIM: FAIL short_packet (%u)\n", pkt.len);
			return -EIO;
		}

		uint8_t flags = pkt.data[0];

		if (flags & SAR_FLAG_FIN) {
			if (!ended) {
				printk("PROV_BSIM: FAIL fin_before_last\n");
				return -EIO;
			}
			/* Any FIN after LAST ends the transfer (code is
			 * informational; the device's first FIN is code 0).
			 */
			*out_len = len;
			return 0;
		}

		uint8_t seq = pkt.data[1];

		if (ended || seq != expected) {
			printk("PROV_BSIM: FAIL unexpected_seq (%u, expected %u)\n", seq,
			       expected);
			return -EIO;
		}
		if (len + pkt.len - 2 > buf_size) {
			printk("PROV_BSIM: FAIL response_overflow\n");
			return -ENOMEM;
		}

		memcpy(&buf[len], &pkt.data[2], pkt.len - 2);
		len += pkt.len - 2;
		expected = (seq + 1) & 0xFF;
		if (flags & SAR_FLAG_LAST) {
			ended = true;
		}

		ack[1] = seq;
		err = gatt_write_sync(uplink_value_handle, ack, sizeof(ack));
		if (err != 0) {
			printk("PROV_BSIM: FAIL frag_ack_write (%d)\n", err);
			return err;
		}
	}
}

/* Check the response pouch contains a .prov/ver entry whose payload is a
 * ver-rsp with op 0 and status 0 (ok). The CBOR array head may grow
 * trailing elements in minor revisions (0x83..0x85 accepted).
 */
static bool response_has_ver_ok(const uint8_t *buf, size_t len)
{
	static const uint8_t path[] = ".prov/ver";
	const size_t path_len = sizeof(path) - 1;

	for (size_t i = 0; i + path_len + 3 <= len; i++) {
		if (memcmp(&buf[i], path, path_len) != 0) {
			continue;
		}

		const uint8_t *rsp = &buf[i + path_len];

		if (rsp[0] >= 0x83 && rsp[0] <= 0x85 && rsp[1] == 0x00 && rsp[2] == 0x00) {
			return true;
		}
	}

	return false;
}

int main(void)
{
	static uint8_t response[512];
	size_t response_len = 0;
	int err;

	err = bt_enable(NULL);
	if (err != 0) {
		printk("PROV_BSIM: FAIL bt_enable (%d)\n", err);
		return err;
	}

	err = bt_le_scan_start(BT_LE_SCAN_ACTIVE, device_found);
	if (err != 0) {
		printk("PROV_BSIM: FAIL scan_start (%d)\n", err);
		return err;
	}

	printk("PROV_BSIM: scanning\n");

	if (wait_stage(&sem_found, "scan") != 0 || wait_stage(&sem_connected, "connect") != 0) {
		return -ETIMEDOUT;
	}

	/* The peripheral sends an SMP Security Request on connect; requesting
	 * from this side as well is harmless and covers both trigger paths.
	 */
	err = bt_conn_set_security(default_conn, BT_SECURITY_L2);
	if (err != 0 && err != -EBUSY) {
		printk("PROV_BSIM: set_security returned %d\n", err);
	}

	if (wait_stage(&sem_secured, "security") != 0) {
		return -ETIMEDOUT;
	}

	disc_params.uuid = &svc_uuid.uuid;
	disc_params.func = discover_cb;
	disc_params.type = BT_GATT_DISCOVER_PRIMARY;
	disc_params.start_handle = BT_ATT_FIRST_ATTRIBUTE_HANDLE;
	disc_params.end_handle = BT_ATT_LAST_ATTRIBUTE_HANDLE;

	err = bt_gatt_discover(default_conn, &disc_params);
	if (err != 0) {
		printk("PROV_BSIM: FAIL discover (%d)\n", err);
		return err;
	}

	if (wait_stage(&sem_discovered, "discovery") != 0) {
		return -ETIMEDOUT;
	}

	printk("PROV_BSIM: service discovered\n");

	/* Request cycle: one SAR transaction per downlink subscription. The
	 * CCC write opens the device's SAR receiver, which acks immediately.
	 */
	err = subscribe(&dl_sub_params, &dl_ccc_disc_params, downlink_value_handle,
			downlink_notify_cb, "downlink");
	if (err != 0) {
		return err;
	}

	err = send_request(frame_single_entry, sizeof(frame_single_entry));
	if (err != 0) {
		return err;
	}

	printk("PROV_BSIM: request sent\n");

	err = bt_gatt_unsubscribe(default_conn, &dl_sub_params);
	if (err != 0) {
		printk("PROV_BSIM: FAIL downlink_unsubscribe (%d)\n", err);
		return err;
	}

	/* Response cycle: the uplink CCC write opens the device's uplink
	 * pouch; its provisioning uplink handler drains the response queue
	 * into it (waiting for the first response), and the device's SAR
	 * sender pushes fragments once we ack.
	 */
	err = subscribe(&ul_sub_params, &ul_ccc_disc_params, uplink_value_handle,
			uplink_notify_cb, "uplink");
	if (err != 0) {
		return err;
	}

	printk("PROV_BSIM: subscribed\n");

	err = recv_response(response, sizeof(response), &response_len);
	if (err != 0) {
		return err;
	}

	printk("PROV_BSIM: response (%u bytes):", (unsigned int)response_len);
	for (size_t i = 0; i < response_len; i++) {
		printk(" %02x", response[i]);
	}
	printk("\n");

	if (!response_has_ver_ok(response, response_len)) {
		printk("PROV_BSIM: FAIL ver_response_check\n");
		return -EINVAL;
	}

	printk("PROV_BSIM: ver response OK\n");
	printk("PROV_BSIM: PASS\n");

	k_sleep(K_FOREVER);

	return 0;
}
