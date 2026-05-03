#ifdef WINDOWS

#include "selftest_local.h"

/* Forward-declare the reconnect counters rather than pulling in the
 * full new_mqtt.h (which drags in lwip headers not present in the sim). */
extern int mqtt_reconnect;

/*
 * Tests for orchestrator-support commands added in the power-management /
 * orchestrator session:
 *
 *   MqttPort    – set MQTT port via script; validates range 1-65535
 *   SSID2       – set fallback WiFi SSID via script
 *   Password2   – set fallback WiFi password via script
 *   MQTTReconnect – force MQTT reconnect; sets mqtt_reconnect = 5
 *   WiFiReconnect – schedule WiFi disconnect+reconnect; sets g_reconnectWiFi = 3
 *   PowerSave   – smoke test: command is registered and returns OK on all builds;
 *                 the actual RF-sleep protection is PLATFORM_BEKEN-specific and
 *                 is not exercisable in the Windows simulator.
 */

static void Test_MqttPort() {
	SIM_ClearOBK(0);

	/* default after SIM_ClearOBK is 1883 */
	SELFTEST_ASSERT_INTEGER(CFG_GetMQTTPort(), 1883);

	/* set a different port and read it back */
	SELFTEST_ASSERT(CMD_ExecuteCommand("MqttPort 8883", 0) == CMD_RES_OK);
	SELFTEST_ASSERT_INTEGER(CFG_GetMQTTPort(), 8883);

	/* restore standard port */
	SELFTEST_ASSERT(CMD_ExecuteCommand("MqttPort 1883", 0) == CMD_RES_OK);
	SELFTEST_ASSERT_INTEGER(CFG_GetMQTTPort(), 1883);

	/* boundary values */
	SELFTEST_ASSERT(CMD_ExecuteCommand("MqttPort 1", 0) == CMD_RES_OK);
	SELFTEST_ASSERT_INTEGER(CFG_GetMQTTPort(), 1);

	SELFTEST_ASSERT(CMD_ExecuteCommand("MqttPort 65535", 0) == CMD_RES_OK);
	SELFTEST_ASSERT_INTEGER(CFG_GetMQTTPort(), 65535);

	/* port 0 must be rejected; stored value must stay unchanged */
	SELFTEST_ASSERT(CMD_ExecuteCommand("MqttPort 0", 0) == CMD_RES_BAD_ARGUMENT);
	SELFTEST_ASSERT_INTEGER(CFG_GetMQTTPort(), 65535);

	/* port 65536 must be rejected */
	SELFTEST_ASSERT(CMD_ExecuteCommand("MqttPort 65536", 0) == CMD_RES_BAD_ARGUMENT);
	SELFTEST_ASSERT_INTEGER(CFG_GetMQTTPort(), 65535);

	/* missing argument */
	SELFTEST_ASSERT(CMD_ExecuteCommand("MqttPort", 0) == CMD_RES_NOT_ENOUGH_ARGUMENTS);
	SELFTEST_ASSERT_INTEGER(CFG_GetMQTTPort(), 65535);
}

static void Test_SSID2() {
	SIM_ClearOBK(0);

	SELFTEST_ASSERT(CMD_ExecuteCommand("SSID2 HomeNetwork", 0) == CMD_RES_OK);
	SELFTEST_ASSERT_STRING(CFG_GetWiFiSSID2(), "HomeNetwork");

	/* overwrite with a different value */
	SELFTEST_ASSERT(CMD_ExecuteCommand("SSID2 BackupAP", 0) == CMD_RES_OK);
	SELFTEST_ASSERT_STRING(CFG_GetWiFiSSID2(), "BackupAP");

	/* quoted SSID with embedded space */
	SELFTEST_ASSERT(CMD_ExecuteCommand("SSID2 \"My Network\"", 0) == CMD_RES_OK);
	SELFTEST_ASSERT_STRING(CFG_GetWiFiSSID2(), "My Network");

	/* missing argument */
	SELFTEST_ASSERT(CMD_ExecuteCommand("SSID2", 0) == CMD_RES_NOT_ENOUGH_ARGUMENTS);
}

static void Test_Password2() {
	SIM_ClearOBK(0);

	SELFTEST_ASSERT(CMD_ExecuteCommand("Password2 s3cr3t", 0) == CMD_RES_OK);
	SELFTEST_ASSERT_STRING(CFG_GetWiFiPass2(), "s3cr3t");

	/* overwrite */
	SELFTEST_ASSERT(CMD_ExecuteCommand("Password2 hunter2", 0) == CMD_RES_OK);
	SELFTEST_ASSERT_STRING(CFG_GetWiFiPass2(), "hunter2");

	/* quoted passphrase with embedded space */
	SELFTEST_ASSERT(CMD_ExecuteCommand("Password2 \"my passphrase\"", 0) == CMD_RES_OK);
	SELFTEST_ASSERT_STRING(CFG_GetWiFiPass2(), "my passphrase");

	/* missing argument */
	SELFTEST_ASSERT(CMD_ExecuteCommand("Password2", 0) == CMD_RES_NOT_ENOUGH_ARGUMENTS);
}

static void Test_MQTTReconnect() {
	SIM_ClearOBK(0);

	/* ensure a clean baseline */
	mqtt_reconnect = 0;

	/* MQTTReconnect must succeed and schedule a reconnect countdown */
	SELFTEST_ASSERT(CMD_ExecuteCommand("MQTTReconnect", 0) == CMD_RES_OK);
	SELFTEST_ASSERT_INTEGER(mqtt_reconnect, 5);
}

static void Test_WiFiReconnect() {
	SIM_ClearOBK(0);

	/* ensure a clean baseline */
	g_reconnectWiFi = 0;

	/* WiFiReconnect must succeed and arm the 3-second countdown */
	SELFTEST_ASSERT(CMD_ExecuteCommand("WiFiReconnect", 0) == CMD_RES_OK);
	SELFTEST_ASSERT_INTEGER(g_reconnectWiFi, 3);

	/* calling again resets the countdown */
	g_reconnectWiFi = 0;
	SELFTEST_ASSERT(CMD_ExecuteCommand("WiFiReconnect", 0) == CMD_RES_OK);
	SELFTEST_ASSERT_INTEGER(g_reconnectWiFi, 3);
}

static void Test_PowerSave_Smoke() {
	/*
	 * The RF-sleep protection fix lives in the PLATFORM_BEKEN code path and
	 * cannot be exercised in the Windows simulator (which takes the "#else"
	 * stub).  This test verifies that the command is registered and returns
	 * CMD_RES_OK in all configurations, and that configuring BL0937 pins
	 * before calling PowerSave 1 does not cause a crash in any build.
	 */
	SIM_ClearOBK(0);

	SELFTEST_ASSERT(CMD_ExecuteCommand("PowerSave 1", 0) == CMD_RES_OK);
	SELFTEST_ASSERT(CMD_ExecuteCommand("PowerSave 0", 0) == CMD_RES_OK);

	/* With a BL0937 CF pin configured: on PLATFORM_BEKEN the fix prevents
	 * RF sleep being enabled; in the simulator the stub path must not crash. */
	PIN_SetPinRoleForPinIndex(7, IOR_BL0937_CF);
	PIN_SetPinChannelForPinIndex(7, 1);
	SELFTEST_ASSERT(CMD_ExecuteCommand("PowerSave 1", 0) == CMD_RES_OK);
	SELFTEST_ASSERT(CMD_ExecuteCommand("PowerSave 0", 0) == CMD_RES_OK);
}

void Test_OrchestratorCmds() {
	Test_MqttPort();
	Test_SSID2();
	Test_Password2();
	Test_MQTTReconnect();
	Test_WiFiReconnect();
	Test_PowerSave_Smoke();
}

#endif
