#include "jwt_verify.h"

#if MQTT_USE_TLS

#include "mbedtls/ecdsa.h"
#include "mbedtls/sha256.h"
#include "mbedtls/pk.h"
#include "../base64/base64.h"
#include "../cJSON/cJSON.h"
#include "../littlefs/our_lfs.h"
#include "../logging/logging.h"
#include "../driver/drv_ntp.h"
#include "../new_common.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* ── in-RAM state ─────────────────────────────────────────────────── */

static char g_ca_pubkey_pem[JWT_MAX_PUBKEY_PEM];
static char g_device_token[JWT_MAX_TOKEN_LEN];

typedef struct {
    char id[33];           /* 32 hex chars + NUL */
    unsigned int expires;  /* Unix timestamp */
} jwt_session_t;

static jwt_session_t g_sessions[JWT_SESSION_MAX];

/* ── base64url helpers ────────────────────────────────────────────── */

/*
 * Decode a base64url segment (no padding) into raw bytes.
 * Returns allocated buffer (caller must free) and sets *out_len,
 * or NULL on error.
 */
static unsigned char *b64url_decode(const char *in, int in_len, int *out_len)
{
    /* convert base64url → standard base64 with padding */
    int pad = (4 - in_len % 4) % 4;
    char *b64 = malloc(in_len + pad + 1);
    if (!b64) return NULL;

    memcpy(b64, in, in_len);
    for (int i = 0; i < in_len; i++) {
        if (b64[i] == '-') b64[i] = '+';
        else if (b64[i] == '_') b64[i] = '/';
    }
    for (int i = 0; i < pad; i++) b64[in_len + i] = '=';
    b64[in_len + pad] = '\0';

    size_t decoded_max = b64_decoded_size(b64);
    unsigned char *out = malloc(decoded_max + 1);
    if (!out) { free(b64); return NULL; }

    if (!b64_decode(b64, out, decoded_max)) {
        free(b64); free(out); return NULL;
    }
    free(b64);

    /* b64_decoded_size counts padding chars as data; compute real length */
    *out_len = (int)decoded_max;
    /* adjust for padding that was stripped by decode */
    while (*out_len > 0 && out[*out_len - 1] == '\0') (*out_len)--;
    out[*out_len] = '\0';
    return out;
}

/* ── payload JSON helpers ─────────────────────────────────────────── */

static cJSON *jwt_decode_payload(const char *jwt_str)
{
    const char *dot1 = strchr(jwt_str, '.');
    if (!dot1) return NULL;
    const char *dot2 = strchr(dot1 + 1, '.');
    if (!dot2) return NULL;

    int payload_b64_len = (int)(dot2 - dot1 - 1);
    int payload_len = 0;
    unsigned char *payload = b64url_decode(dot1 + 1, payload_b64_len, &payload_len);
    if (!payload) return NULL;

    cJSON *json = cJSON_Parse((char *)payload);
    free(payload);
    return json;
}

/* ── public API ───────────────────────────────────────────────────── */

void JWT_Init(void)
{
    memset(g_ca_pubkey_pem, 0, sizeof(g_ca_pubkey_pem));
    memset(g_device_token, 0, sizeof(g_device_token));
    memset(g_sessions, 0, sizeof(g_sessions));

#if ENABLE_LITTLEFS
    byte *data;

    data = LFS_ReadFile(JWT_CA_PUBKEY_FILE);
    if (data) {
        strncpy(g_ca_pubkey_pem, (char *)data, sizeof(g_ca_pubkey_pem) - 1);
        free(data);
        ADDLOG_INFO(LOG_FEATURE_CMD, "JWT: loaded CA public key");
    }

    data = LFS_ReadFile(JWT_DEVICE_TOKEN_FILE);
    if (data) {
        strncpy(g_device_token, (char *)data, sizeof(g_device_token) - 1);
        free(data);
        ADDLOG_INFO(LOG_FEATURE_CMD, "JWT: loaded device token");
    }
#endif
}

int JWT_VerifyES256(const char *jwt_str)
{
    if (!jwt_str || !*jwt_str) return 0;
    if (!g_ca_pubkey_pem[0]) {
        ADDLOG_INFO(LOG_FEATURE_CMD, "JWT: no CA key stored, verification skipped");
        return 0;
    }

    /* locate the two dots */
    const char *dot1 = strchr(jwt_str, '.');
    if (!dot1) return 0;
    const char *dot2 = strchr(dot1 + 1, '.');
    if (!dot2) return 0;

    /* message = everything before the second dot */
    int msg_len = (int)(dot2 - jwt_str);

    /* SHA-256 hash of "header_b64url.payload_b64url" */
    unsigned char hash[32];
    mbedtls_sha256_ret((const unsigned char *)jwt_str, msg_len, hash, 0);

    /* decode signature — ES256 raw format: r (32 B) || s (32 B) */
    const char *sig_b64url = dot2 + 1;
    int sig_b64url_len = (int)strlen(sig_b64url);
    int sig_len = 0;
    unsigned char *sig = b64url_decode(sig_b64url, sig_b64url_len, &sig_len);
    if (!sig || sig_len != 64) {
        ADDLOG_ERROR(LOG_FEATURE_CMD, "JWT: bad signature length %d", sig_len);
        if (sig) free(sig);
        return 0;
    }

    /* load the CA public key */
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    int ret = mbedtls_pk_parse_public_key(
        &pk,
        (const unsigned char *)g_ca_pubkey_pem,
        strlen(g_ca_pubkey_pem) + 1);   /* +1 to include NUL for PEM */
    if (ret != 0) {
        ADDLOG_ERROR(LOG_FEATURE_CMD, "JWT: failed to parse CA pubkey (%d)", ret);
        free(sig);
        mbedtls_pk_free(&pk);
        return 0;
    }

    if (mbedtls_pk_get_type(&pk) != MBEDTLS_PK_ECKEY) {
        ADDLOG_ERROR(LOG_FEATURE_CMD, "JWT: CA key is not EC");
        free(sig);
        mbedtls_pk_free(&pk);
        return 0;
    }

    /* verify ECDSA signature r||s against the public key */
    mbedtls_ecp_keypair *ec = mbedtls_pk_ec(pk);
    mbedtls_mpi r, s;
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    mbedtls_mpi_read_binary(&r, sig,      32);
    mbedtls_mpi_read_binary(&s, sig + 32, 32);
    free(sig);

    ret = mbedtls_ecdsa_verify(&ec->grp, hash, sizeof(hash), &ec->Q, &r, &s);

    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    mbedtls_pk_free(&pk);

    if (ret != 0) {
        ADDLOG_INFO(LOG_FEATURE_CMD, "JWT: signature invalid (%d)", ret);
        return 0;
    }

    /* check expiry using NTP time */
    unsigned int now = NTP_GetCurrentTime();
    unsigned int exp = JWT_GetExpiry(jwt_str);
    if (now > 0 && exp > 0 && now > exp) {
        ADDLOG_INFO(LOG_FEATURE_CMD, "JWT: token expired (exp=%u now=%u)", exp, now);
        return 0;
    }

    return 1;
}

char *JWT_GetSubject(const char *jwt_str, char *buf, int buflen)
{
    cJSON *json = jwt_decode_payload(jwt_str);
    if (!json) return NULL;

    cJSON *sub = cJSON_GetObjectItem(json, "sub");
    if (!sub || !cJSON_IsString(sub)) {
        cJSON_Delete(json);
        return NULL;
    }
    strncpy(buf, sub->valuestring, buflen - 1);
    buf[buflen - 1] = '\0';
    cJSON_Delete(json);
    return buf;
}

unsigned int JWT_GetExpiry(const char *jwt_str)
{
    cJSON *json = jwt_decode_payload(jwt_str);
    if (!json) return 0;

    cJSON *exp = cJSON_GetObjectItem(json, "exp");
    unsigned int result = 0;
    if (exp && cJSON_IsNumber(exp))
        result = (unsigned int)exp->valuedouble;

    cJSON_Delete(json);
    return result;
}

int JWT_SetCAKey(const char *pem)
{
    if (!pem || !*pem) return 0;
    strncpy(g_ca_pubkey_pem, pem, sizeof(g_ca_pubkey_pem) - 1);
    g_ca_pubkey_pem[sizeof(g_ca_pubkey_pem) - 1] = '\0';
#if ENABLE_LITTLEFS
    LFS_WriteFile(JWT_CA_PUBKEY_FILE, (const byte *)pem, strlen(pem), false);
#endif
    ADDLOG_INFO(LOG_FEATURE_CMD, "JWT: CA key updated");
    return 1;
}

int JWT_SetDeviceToken(const char *token)
{
    if (!token || !*token) return 0;
    strncpy(g_device_token, token, sizeof(g_device_token) - 1);
    g_device_token[sizeof(g_device_token) - 1] = '\0';
#if ENABLE_LITTLEFS
    LFS_WriteFile(JWT_DEVICE_TOKEN_FILE, (const byte *)token, strlen(token), false);
#endif
    ADDLOG_INFO(LOG_FEATURE_CMD, "JWT: device token updated");
    return 1;
}

const char *JWT_GetDeviceToken(void)
{
    return g_device_token[0] ? g_device_token : NULL;
}

/* ── session cookies ──────────────────────────────────────────────── */

const char *JWT_CreateSession(void)
{
    JWT_PurgeExpiredSessions();

    /* find an empty slot */
    int slot = -1;
    for (int i = 0; i < JWT_SESSION_MAX; i++) {
        if (!g_sessions[i].id[0]) { slot = i; break; }
    }
    if (slot == -1) slot = 0;   /* evict oldest */

    /* generate session ID: SHA-256(mac + time + slot) → first 16 bytes as hex */
    unsigned char seed[16];
    unsigned int now = NTP_GetCurrentTime();
    memcpy(seed, &now, 4);
    memcpy(seed + 4, &slot, 4);
    memcpy(seed + 8, g_device_token, 8);   /* mix in some device entropy */

    unsigned char hash[32];
    mbedtls_sha256_ret(seed, sizeof(seed), hash, 0);

    for (int i = 0; i < 16; i++)
        snprintf(g_sessions[slot].id + i * 2, 3, "%02x", hash[i]);
    g_sessions[slot].id[32] = '\0';
    g_sessions[slot].expires = now + JWT_SESSION_TTL;

    return g_sessions[slot].id;
}

int JWT_ValidateSession(const char *session_id)
{
    if (!session_id || !*session_id) return 0;
    unsigned int now = NTP_GetCurrentTime();
    for (int i = 0; i < JWT_SESSION_MAX; i++) {
        if (g_sessions[i].id[0] &&
            strcmp(g_sessions[i].id, session_id) == 0 &&
            (now == 0 || now < g_sessions[i].expires)) {
            return 1;
        }
    }
    return 0;
}

void JWT_PurgeExpiredSessions(void)
{
    unsigned int now = NTP_GetCurrentTime();
    if (now == 0) return;
    for (int i = 0; i < JWT_SESSION_MAX; i++) {
        if (g_sessions[i].id[0] && now >= g_sessions[i].expires)
            memset(&g_sessions[i], 0, sizeof(g_sessions[i]));
    }
}

#endif /* MQTT_USE_TLS */
