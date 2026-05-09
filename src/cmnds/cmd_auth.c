#include "../new_pins.h"
#include "../new_cfg.h"
#include "../logging/logging.h"
#include "../obk_config.h"
#include "cmd_local.h"
#include "../httpclient/http_client.h"

#if MQTT_USE_TLS
#include "../crypto/jwt_verify.h"
#include "../driver/drv_ntp.h"
#include "../httpserver/http_tls_server.h"
#endif

static commandResult_t CMD_SetCAKey(const void *context, const char *cmd, const char *args, int cmdFlags) {
#if MQTT_USE_TLS
	Tokenizer_TokenizeString(args, TOKENIZER_ALLOW_QUOTES | TOKENIZER_ALLOW_ESCAPING_QUOTATIONS);
	if (Tokenizer_CheckArgsCountAndPrintWarning(cmd, 1))
		return CMD_RES_NOT_ENOUGH_ARGUMENTS;
	const char *pem = Tokenizer_GetArg(0);
	if (!pem || !*pem) {
		ADDLOG_ERROR(LOG_FEATURE_CMD, "setCAKey: empty PEM");
		return CMD_RES_NOT_ENOUGH_ARGUMENTS;
	}
	if (!JWT_SetCAKey(pem)) {
		ADDLOG_ERROR(LOG_FEATURE_CMD, "setCAKey: failed to store CA key");
		return CMD_RES_ERROR;
	}
	return CMD_RES_OK;
#else
	ADDLOG_ERROR(LOG_FEATURE_CMD, "setCAKey: requires MQTT_USE_TLS build");
	return CMD_RES_ERROR;
#endif
}

static commandResult_t CMD_SetDeviceToken(const void *context, const char *cmd, const char *args, int cmdFlags) {
#if MQTT_USE_TLS
	Tokenizer_TokenizeString(args, TOKENIZER_ALLOW_QUOTES);
	if (Tokenizer_CheckArgsCountAndPrintWarning(cmd, 1))
		return CMD_RES_NOT_ENOUGH_ARGUMENTS;
	if (!JWT_SetDeviceToken(Tokenizer_GetArg(0))) {
		ADDLOG_ERROR(LOG_FEATURE_CMD, "setDeviceToken: failed to store token");
		return CMD_RES_ERROR;
	}
	return CMD_RES_OK;
#else
	ADDLOG_ERROR(LOG_FEATURE_CMD, "setDeviceToken: requires MQTT_USE_TLS build");
	return CMD_RES_ERROR;
#endif
}

static commandResult_t CMD_GetDeviceToken(const void *context, const char *cmd, const char *args, int cmdFlags) {
#if MQTT_USE_TLS
	const char *tok = JWT_GetDeviceToken();
	if (!tok) {
		ADDLOG_INFO(LOG_FEATURE_CMD, "getDeviceToken: no token stored");
	} else {
		unsigned int exp = JWT_GetExpiry(tok);
		unsigned int now = NTP_GetCurrentTime();
		if (exp == 0) {
			ADDLOG_INFO(LOG_FEATURE_CMD, "getDeviceToken: token loaded, no expiry");
		} else if (now > 0 && now > exp) {
			ADDLOG_INFO(LOG_FEATURE_CMD, "getDeviceToken: token EXPIRED at %u", exp);
		} else {
			int days = (int)((exp - now) / 86400);
			ADDLOG_INFO(LOG_FEATURE_CMD, "getDeviceToken: token valid, expires in ~%d days", days);
		}
	}
	return CMD_RES_OK;
#else
	ADDLOG_INFO(LOG_FEATURE_CMD, "getDeviceToken: JWT auth not compiled in");
	return CMD_RES_OK;
#endif
}

static commandResult_t CMD_SendGetAuth(const void *context, const char *cmd, const char *args, int cmdFlags) {
#if ENABLE_SEND_POSTANDGET
	Tokenizer_TokenizeString(args, TOKENIZER_ALLOW_QUOTES | TOKENIZER_ALLOW_ESCAPING_QUOTATIONS);
	const char *url_raw  = Tokenizer_GetArg(0);
	const char *tg_file  = Tokenizer_GetArg(1);
	const char *post_cmd = Tokenizer_GetArg(2);
	if (!url_raw || !*url_raw)
		return CMD_RES_NOT_ENOUGH_ARGUMENTS;
#if MQTT_USE_TLS
	const char *token = JWT_GetDeviceToken();
	if (token && *token) {
		int url_len = strlen(url_raw);
		int tok_len = strlen(token);
		char sep = (strchr(url_raw, '?') != NULL) ? '&' : '?';
		char *full_url = malloc(url_len + 1 + 6 + tok_len + 1);
		if (full_url) {
			snprintf(full_url, url_len + 1 + 6 + tok_len + 1, "%s%ctoken=%s", url_raw, sep, token);
			HTTPClient_Async_SendGet(full_url, tg_file, post_cmd);
			free(full_url);
			return CMD_RES_OK;
		}
	}
#endif
	HTTPClient_Async_SendGet(url_raw, tg_file, post_cmd);
	return CMD_RES_OK;
#else
	ADDLOG_ERROR(LOG_FEATURE_CMD, "sendGetAuth: ENABLE_SEND_POSTANDGET not compiled in");
	return CMD_RES_ERROR;
#endif
}

static commandResult_t CMD_SetHTTPSCert(const void *context, const char *cmd, const char *args, int cmdFlags) {
#if MQTT_USE_TLS
	Tokenizer_TokenizeString(args, TOKENIZER_ALLOW_QUOTES | TOKENIZER_ALLOW_ESCAPING_QUOTATIONS);
	if (Tokenizer_CheckArgsCountAndPrintWarning(cmd, 1))
		return CMD_RES_NOT_ENOUGH_ARGUMENTS;
	const char *pem = Tokenizer_GetArg(0);
	if (!pem || !*pem) {
		ADDLOG_ERROR(LOG_FEATURE_CMD, "setHTTPSCert: empty PEM");
		return CMD_RES_NOT_ENOUGH_ARGUMENTS;
	}
	if (!LFS_WriteFile(HTTPS_CERT_FILE, (const byte *)pem, strlen(pem), false)) {
		ADDLOG_ERROR(LOG_FEATURE_CMD, "setHTTPSCert: failed to write '%s'", HTTPS_CERT_FILE);
		return CMD_RES_ERROR;
	}
	ADDLOG_INFO(LOG_FEATURE_CMD, "setHTTPSCert: saved to LFS. Reboot to activate HTTPS.");
	return CMD_RES_OK;
#else
	ADDLOG_ERROR(LOG_FEATURE_CMD, "setHTTPSCert: requires MQTT_USE_TLS build");
	return CMD_RES_ERROR;
#endif
}

static commandResult_t CMD_SetHTTPSKey(const void *context, const char *cmd, const char *args, int cmdFlags) {
#if MQTT_USE_TLS
	Tokenizer_TokenizeString(args, TOKENIZER_ALLOW_QUOTES | TOKENIZER_ALLOW_ESCAPING_QUOTATIONS);
	if (Tokenizer_CheckArgsCountAndPrintWarning(cmd, 1))
		return CMD_RES_NOT_ENOUGH_ARGUMENTS;
	const char *pem = Tokenizer_GetArg(0);
	if (!pem || !*pem) {
		ADDLOG_ERROR(LOG_FEATURE_CMD, "setHTTPSKey: empty PEM");
		return CMD_RES_NOT_ENOUGH_ARGUMENTS;
	}
	if (!LFS_WriteFile(HTTPS_KEY_FILE, (const byte *)pem, strlen(pem), false)) {
		ADDLOG_ERROR(LOG_FEATURE_CMD, "setHTTPSKey: failed to write '%s'", HTTPS_KEY_FILE);
		return CMD_RES_ERROR;
	}
	ADDLOG_INFO(LOG_FEATURE_CMD, "setHTTPSKey: saved to LFS. Reboot to activate HTTPS.");
	return CMD_RES_OK;
#else
	ADDLOG_ERROR(LOG_FEATURE_CMD, "setHTTPSKey: requires MQTT_USE_TLS build");
	return CMD_RES_ERROR;
#endif
}

int CMD_InitAuthCommands(void) {
	//cmddetail:{"name":"setCAKey","args":"[PEM]",
	//cmddetail:"descr":"Stores the Step CA public key (EC P-256 PEM) used to verify inbound JWTs for web UI access. Persisted to LittleFS as 'ca_pubkey'. Requires MQTT_USE_TLS build.",
	//cmddetail:"fn":"CMD_SetCAKey","file":"cmnds/cmd_auth.c","requires":"MQTT_USE_TLS",
	//cmddetail:"examples":"setCAKey \"-----BEGIN PUBLIC KEY-----\\nMFkw...\\n-----END PUBLIC KEY-----\\n\""}
	CMD_RegisterCommand("setCAKey", CMD_SetCAKey, NULL);
	//cmddetail:{"name":"setDeviceToken","args":"[JWT]",
	//cmddetail:"descr":"Stores a Step CA issued JWT as the device identity token. Used by sendGetAuth to authenticate requests to the orchestrator. Requires MQTT_USE_TLS build.",
	//cmddetail:"fn":"CMD_SetDeviceToken","file":"cmnds/cmd_auth.c","requires":"MQTT_USE_TLS",
	//cmddetail:"examples":"setDeviceToken eyJhbGci..."}
	CMD_RegisterCommand("setDeviceToken", CMD_SetDeviceToken, NULL);
	//cmddetail:{"name":"getDeviceToken","args":"",
	//cmddetail:"descr":"Logs the status of the stored device JWT (expiry, validity). Does not print the token value.",
	//cmddetail:"fn":"CMD_GetDeviceToken","file":"cmnds/cmd_auth.c","requires":"",
	//cmddetail:"examples":"getDeviceToken"}
	CMD_RegisterCommand("getDeviceToken", CMD_GetDeviceToken, NULL);
	//cmddetail:{"name":"sendGetAuth","args":"[URL] [optionalTargetFile] [optionalCommand]",
	//cmddetail:"descr":"Like sendGet but automatically appends the device JWT (?token=...) to the URL so the orchestrator can verify device identity. Falls back to plain sendGet if no token is stored.",
	//cmddetail:"fn":"CMD_SendGetAuth","file":"cmnds/cmd_auth.c","requires":"ENABLE_SEND_POSTANDGET",
	//cmddetail:"examples":"sendGetAuth http://orchestrator.home/$ShortName cmd"}
	CMD_RegisterCommand("sendGetAuth", CMD_SendGetAuth, NULL);
	//cmddetail:{"name":"setHTTPSCert","args":"[PEM]",
	//cmddetail:"descr":"Stores the server TLS certificate (PEM) in LittleFS as 'https_cert.pem'. Can be self-signed. Reboot to activate the HTTPS server on port 443. Requires MQTT_USE_TLS build.",
	//cmddetail:"fn":"CMD_SetHTTPSCert","file":"cmnds/cmd_auth.c","requires":"MQTT_USE_TLS",
	//cmddetail:"examples":"setHTTPSCert \"-----BEGIN CERTIFICATE-----\\n...\\n-----END CERTIFICATE-----\\n\""}
	CMD_RegisterCommand("setHTTPSCert", CMD_SetHTTPSCert, NULL);
	//cmddetail:{"name":"setHTTPSKey","args":"[PEM]",
	//cmddetail:"descr":"Stores the server private key (PEM) in LittleFS as 'https_key.pem'. Supported: EC P-256 (ECDHE-ECDSA) or RSA (ECDHE-RSA). Reboot to activate the HTTPS server on port 443. Requires MQTT_USE_TLS build.",
	//cmddetail:"fn":"CMD_SetHTTPSKey","file":"cmnds/cmd_auth.c","requires":"MQTT_USE_TLS",
	//cmddetail:"examples":"setHTTPSKey \"-----BEGIN EC PRIVATE KEY-----\\n...\\n-----END EC PRIVATE KEY-----\\n\""}
	CMD_RegisterCommand("setHTTPSKey", CMD_SetHTTPSKey, NULL);
	return 0;
}
