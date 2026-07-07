/*
 * Copyright (c) 2026 Jonathan Beri
 * SPDX-License-Identifier: Apache-2.0
 *
 * BabbleSim central tester: scans for the provisioning advertisement,
 * connects, pairs (Just Works LESC — the peripheral sends the Security
 * Request per src/adv.c), discovers the pouch GATT service, and
 * subscribes to the uplink characteristic. Each stage prints a
 * "PROV_BSIM:" marker that pytest/test_ble_smoke.py asserts in order;
 * a timeout prints "PROV_BSIM: FAIL <stage>" so failures are diagnosable
 * from the simulation log.
 *
 * Wire-format constants are intentionally redefined here (rather than
 * pulled from pouch headers) so the test pins the advertised format the
 * pouchprov CLI and future mobile SDKs rely on.
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

static K_SEM_DEFINE(sem_found, 0, 1);
static K_SEM_DEFINE(sem_connected, 0, 1);
static K_SEM_DEFINE(sem_secured, 0, 1);
static K_SEM_DEFINE(sem_discovered, 0, 1);
static K_SEM_DEFINE(sem_subscribed, 0, 1);

static struct bt_conn *default_conn;

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
	} else if (bt_uuid_cmp(chrc->uuid, &info_uuid.uuid) == 0) {
		found_info = true;
	}

	return BT_GATT_ITER_CONTINUE;
}

static struct bt_gatt_subscribe_params sub_params;
static struct bt_gatt_discover_params ccc_disc_params;

static uint8_t uplink_notify_cb(struct bt_conn *conn, struct bt_gatt_subscribe_params *params,
				const void *data, uint16_t length)
{
	if (data != NULL) {
		printk("PROV_BSIM: uplink notification (%u bytes)\n", length);
	}

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

static int wait_stage(struct k_sem *sem, const char *stage)
{
	if (k_sem_take(sem, K_SECONDS(30)) != 0) {
		printk("PROV_BSIM: FAIL timeout_%s\n", stage);
		return -ETIMEDOUT;
	}

	return 0;
}

int main(void)
{
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

	sub_params.notify = uplink_notify_cb;
	sub_params.subscribe = subscribe_cb;
	sub_params.value = BT_GATT_CCC_NOTIFY;
	sub_params.value_handle = uplink_value_handle;
	sub_params.ccc_handle = 0; /* auto-discover via disc_params */
	sub_params.disc_params = &ccc_disc_params;
	sub_params.end_handle = svc_end_handle;

	err = bt_gatt_subscribe(default_conn, &sub_params);
	if (err != 0) {
		printk("PROV_BSIM: FAIL subscribe_req (%d)\n", err);
		return err;
	}

	if (wait_stage(&sem_subscribed, "subscribe") != 0) {
		return -ETIMEDOUT;
	}

	printk("PROV_BSIM: subscribed\n");
	printk("PROV_BSIM: PASS\n");

	k_sleep(K_FOREVER);

	return 0;
}
