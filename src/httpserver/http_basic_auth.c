#include "http_basic_auth.h"
#include <stdio.h>
#include "../logging/logging.h"
#include "../base64/base64.h"
#include "../new_pins.h"
#include "../new_cfg.h"
#include "../obk_config.h"

#if MQTT_USE_TLS
#include "../crypto/jwt_verify.h"
#endif

#define LOG_FEATURE LOG_FEATURE_HTTP

/*
 * Try to authenticate via a JWT ES256 token.
 * Accepts the token from (in order of priority):
 *   1. "Authorization: Bearer <jwt>" header
 *   2. "?token=<jwt>" query parameter
 *
 * On first successful JWT verification creates a session cookie.
 * Subsequent requests with a valid "session=<id>" cookie skip ECDSA
 * verification (which takes ~30-50ms on the MCU).
 *
 * Returns HTTP_BASIC_AUTH_OK or HTTP_BASIC_AUTH_FAIL.
 */
#if MQTT_USE_TLS
static int jwt_auth_eval(http_request_t *request)
{
    /* check session cookie first to avoid repeated ECDSA verify */
    for (int i = 0; i < request->numheaders; i++) {
        const char *h = request->headers[i];
        if (!my_strnicmp(h, "Cookie: ", 8)) {
            /* look for session=<id> inside the cookie string */
            const char *p = strstr(h + 8, "session=");
            if (p) {
                p += 8;
                char sid[33];
                int j = 0;
                while (p[j] && p[j] != ';' && p[j] != ' ' && j < 32)
                    sid[j] = p[j++];
                sid[j] = '\0';
                if (JWT_ValidateSession(sid))
                    return HTTP_BASIC_AUTH_OK;
            }
        }
    }

    const char *jwt_str = NULL;
    char bearer_buf[JWT_MAX_TOKEN_LEN];

    /* 1. Authorization: Bearer <jwt> */
    for (int i = 0; i < request->numheaders; i++) {
        const char *h = request->headers[i];
        if (!my_strnicmp(h, "Authorization: Bearer ", 22)) {
            strncpy(bearer_buf, h + 22, sizeof(bearer_buf) - 1);
            bearer_buf[sizeof(bearer_buf) - 1] = '\0';
            jwt_str = bearer_buf;
            break;
        }
    }

    /* 2. ?token=<jwt> query parameter */
    if (!jwt_str) {
        for (int i = 0; i < request->numqueryitems; i++) {
            if (strcmp(request->querynames[i], "token") == 0) {
                jwt_str = request->queryvalues[i];
                break;
            }
        }
    }

    if (!jwt_str || !*jwt_str)
        return HTTP_BASIC_AUTH_FAIL;

    if (!JWT_VerifyES256(jwt_str)) {
        ADDLOGF_INFO("AUTH: JWT verification failed");
        return HTTP_BASIC_AUTH_FAIL;
    }

    /* valid JWT — create a session so future requests skip ECDSA */
    JWT_CreateSession();
    return HTTP_BASIC_AUTH_OK;
}
#endif /* MQTT_USE_TLS */

int http_basic_auth_eval(http_request_t *request) {
#if ALLOW_WEB_PASSWORD
	if (strlen(g_cfg.webPassword) == 0 || (bSafeMode && CFG_HasFlag(OBK_FLAG_HTTP_DISABLE_AUTH_IN_SAFE_MODE))) {
		return HTTP_BASIC_AUTH_OK;
	}

#if MQTT_USE_TLS
	/* JWT auth takes priority over Basic Auth when TLS/JWT is compiled in */
	if (jwt_auth_eval(request) == HTTP_BASIC_AUTH_OK)
		return HTTP_BASIC_AUTH_OK;
#endif

	char tmp_auth[256];
	for (int i = 0; i < request->numheaders; i++) {
		char *header = request->headers[i];
		if (!my_strnicmp(header, "Authorization: Basic ", 21)) {
			char *basic_token = header + 21;
			size_t decoded_len = b64_decoded_size(basic_token);
			if (decoded_len > 255) {
				break;
			}
			if (!b64_decode(basic_token, (unsigned char *)tmp_auth, decoded_len + 1)) {
				ADDLOGF_ERROR("AUTH: Failed to decode B64 token.");
				break;
			}
			tmp_auth[decoded_len] = 0;
			if (!my_strnicmp(tmp_auth, "admin:", 6)) {
				char *basic_auth_password = tmp_auth + 6;
				if (strncmp(basic_auth_password, g_cfg.webPassword, 32) == 0) {
					return HTTP_BASIC_AUTH_OK;
				}
			}
            break;
		}
	}
    return HTTP_BASIC_AUTH_FAIL;
#else
	return HTTP_BASIC_AUTH_OK;
#endif
}

int http_basic_auth_run(http_request_t *request) {
    int result = http_basic_auth_eval(request);
    if (result == HTTP_BASIC_AUTH_FAIL) {
		poststr(request, "HTTP/1.1 401 Unauthorized\r\n");
        poststr(request, "Connection: close");
        poststr(request, "\r\n");
        poststr(request, "WWW-Authenticate: Basic realm=\"OpenBeken HTTP Server\"");
        poststr(request, "\r\n");
        poststr(request, "\r\n");
		poststr(request, NULL);
    }
    return result;
}