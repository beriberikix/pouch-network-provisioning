/*
 * Copyright (c) 2026 Jonathan Beri
 * SPDX-License-Identifier: Apache-2.0
 *
 * BLE advertising for provisioning. Pouch-standard service data
 * (UUID16 0xFC49, version + flags) with flags bit 1 set as the
 * "provisioning available" vendor extension (bit 0 remains pouch's
 * sync-request flag). Advertising restarts on disconnect.
 *
 * Adapted from pouch examples/zephyr/ble_gatt/src/ble_peripheral.c.
 */

#include <stdio.h>

#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/conn.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include <pouch/transport/bluetooth/gatt.h>

#include "pouch_prov_internal.h"

LOG_MODULE_REGISTER(pouch_prov_adv, CONFIG_POUCH_PROV_LOG_LEVEL);

#define ADV_FLAG_PROVISIONING (1 << 1)

static struct pouch_gatt_adv service_data = POUCH_GATT_ADV_DATA_INIT;
static char device_name[sizeof(CONFIG_POUCH_PROV_DEVICE_NAME_PREFIX) + 6];
static bool adv_enabled;

static struct bt_data ad[] = {
	BT_DATA_BYTES(BT_DATA_FLAGS, (BT_LE_AD_GENERAL | BT_LE_AD_NO_BREDR)),
	BT_DATA(BT_DATA_SVC_DATA16, &service_data, sizeof(service_data)),
	BT_DATA(BT_DATA_NAME_COMPLETE, device_name, 0 /* set at start */),
};

static void set_device_name(void)
{
	bt_addr_le_t addrs[CONFIG_BT_ID_MAX];
	size_t count = ARRAY_SIZE(addrs);

	bt_id_get(addrs, &count);

	const uint8_t *a = addrs[0].a.val;

	snprintf(device_name, sizeof(device_name), "%s%02x%02x%02x",
		 CONFIG_POUCH_PROV_DEVICE_NAME_PREFIX, a[2], a[1], a[0]);
	ad[2].data_len = strlen(device_name);
}

static void connected(struct bt_conn *conn, uint8_t err)
{
	if (err != 0) {
		return;
	}

	/* pouch's characteristics require an encrypted LESC link for writes.
	 * Central stacks (macOS/iOS in particular) do not reliably initiate
	 * pairing on ATT security errors, so request security from our side:
	 * the SMP Security Request makes the central pair (Just Works) and
	 * encrypt the link.
	 */
	int sec_err = bt_conn_set_security(conn, BT_SECURITY_L2);

	if (sec_err != 0) {
		LOG_WRN("Security request failed (%d)", sec_err);
	}
}

static void security_changed(struct bt_conn *conn, bt_security_t level, enum bt_security_err err)
{
	LOG_INF("Security: level %d (err %d)", level, err);
}

static void disconnected(struct bt_conn *conn, uint8_t reason)
{
	LOG_DBG("Disconnected (0x%02x)", reason);
	pouch_prov_mgr_session_ended();
}

static void recycled(void)
{
	if (adv_enabled) {
		int err = bt_le_adv_start(BT_LE_ADV_CONN_FAST_2, ad, ARRAY_SIZE(ad), NULL, 0);

		if (err != 0 && err != -EALREADY) {
			LOG_ERR("Failed to resume advertising (%d)", err);
		}
	}
}

BT_CONN_CB_DEFINE(prov_conn_callbacks) = {
	.connected = connected,
	.disconnected = disconnected,
	.security_changed = security_changed,
	.recycled = recycled,
};

int pouch_prov_adv_start(void)
{
	int err;

	service_data.payload.flags |= ADV_FLAG_PROVISIONING;
	set_device_name();

	err = bt_le_adv_start(BT_LE_ADV_CONN_FAST_2, ad, ARRAY_SIZE(ad), NULL, 0);
	if (err == -EALREADY) {
		err = 0;
	}
	if (err == 0) {
		adv_enabled = true;
		LOG_INF("Advertising as %s", device_name);
	}

	return err;
}

int pouch_prov_adv_stop(void)
{
	adv_enabled = false;
	service_data.payload.flags &= ~ADV_FLAG_PROVISIONING;

	int err = bt_le_adv_stop();

	return err == -EALREADY ? 0 : err;
}
