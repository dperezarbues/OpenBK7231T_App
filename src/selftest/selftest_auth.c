#ifdef WINDOWS

#include "selftest_local.h"

/*
 * Tests for auth-related additions:
 *   - OBK_FLAG_MQTT_BLOCK_OTA (flag 52): ota_http must be rejected when
 *     the command arrives via MQTT and the flag is set, but must still work
 *     from the console / HTTP interface.
 *   - $Version tokenizer expansion: must produce a non-empty string.
 */

void Test_Auth() {
	char buffer[128];
	commandResult_t result;

	/* ── OBK_FLAG_MQTT_BLOCK_OTA ───────────────────────────────────── */

	SIM_ClearOBK(0);

	/* flag off by default — ota_http via MQTT should proceed normally */
	SELFTEST_ASSERT_FLAG(OBK_FLAG_MQTT_BLOCK_OTA, false);
	result = CMD_ExecuteCommandArgs("ota_http", "http://test.local/fw.rbl",
									COMMAND_FLAG_SOURCE_MQTT);
	SELFTEST_ASSERT(result != CMD_RES_ERROR);

	/* enable the block */
	CMD_ExecuteCommand("SetFlag 52 1", 0);
	SELFTEST_ASSERT_FLAG(OBK_FLAG_MQTT_BLOCK_OTA, true);

	/* ota_http via MQTT must now be rejected */
	result = CMD_ExecuteCommandArgs("ota_http", "http://test.local/fw.rbl",
									COMMAND_FLAG_SOURCE_MQTT);
	SELFTEST_ASSERT(result == CMD_RES_ERROR);

	/* ota_http from console must still work regardless of the flag */
	result = CMD_ExecuteCommandArgs("ota_http", "http://test.local/fw.rbl",
									COMMAND_FLAG_SOURCE_CONSOLE);
	SELFTEST_ASSERT(result != CMD_RES_ERROR);

	/* ota_http from HTTP must still work regardless of the flag */
	result = CMD_ExecuteCommandArgs("ota_http", "http://test.local/fw.rbl",
									COMMAND_FLAG_SOURCE_HTTP);
	SELFTEST_ASSERT(result != CMD_RES_ERROR);

	/* clearing the flag must re-allow MQTT OTA */
	CMD_ExecuteCommand("SetFlag 52 0", 0);
	SELFTEST_ASSERT_FLAG(OBK_FLAG_MQTT_BLOCK_OTA, false);
	result = CMD_ExecuteCommandArgs("ota_http", "http://test.local/fw.rbl",
									COMMAND_FLAG_SOURCE_MQTT);
	SELFTEST_ASSERT(result != CMD_RES_ERROR);

	/* ── $Version expansion ────────────────────────────────────────── */

	SIM_ClearOBK(0);

	/* $Version must expand to a non-empty firmware version string */
	CMD_ExpandConstantsWithinString("$Version", buffer, sizeof(buffer));
	SELFTEST_ASSERT(buffer[0] != '\0');

	/* ${Version} brace form must produce the same result */
	char buffer2[128];
	CMD_ExpandConstantsWithinString("${Version}", buffer2, sizeof(buffer2));
	SELFTEST_ASSERT_STRING(buffer, buffer2);

	/* $Version embedded in a URL must be substituted correctly */
	CMD_ExpandConstantsWithinString("http://nas/$ShortName?fw=$Version", buffer, sizeof(buffer));
	SELFTEST_ASSERT(strstr(buffer, "?fw=") != NULL);
	/* the version token must have been replaced (no literal "$Version" left) */
	SELFTEST_ASSERT(strstr(buffer, "$Version") == NULL);
}

#endif
