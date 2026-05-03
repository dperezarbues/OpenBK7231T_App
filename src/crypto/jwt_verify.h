#pragma once

#include "../obk_config.h"

#if MQTT_USE_TLS

/*
 * Minimal JWT ES256 (ECDSA P-256 + SHA-256) verification.
 *
 * Used to verify Step CA issued JWTs for:
 *   - Inbound: web UI access (user presents JWT as Bearer token)
 *   - Outbound: device identity (device appends JWT to orchestrator calls)
 *
 * The CA public key (PEM format, EC P-256) must be stored in LittleFS
 * at the path defined by JWT_CA_PUBKEY_FILE.
 *
 * Step CA setup:
 *   step ca init
 *   step ca provisioner add device-provisioner --type JWK --key-type EC --crv P-256
 *   step ca token --provisioner device-provisioner --expire 30d kitchen-switch
 */

#define JWT_CA_PUBKEY_FILE   "ca_pubkey"
#define JWT_DEVICE_TOKEN_FILE "device_token"

/* Maximum sizes */
#define JWT_MAX_PUBKEY_PEM   1024
#define JWT_MAX_TOKEN_LEN    1024
#define JWT_JTI_MAX          40    /* Step CA jti is a UUID (36 chars) + NUL */
#define JWT_SESSION_MAX      4     /* max simultaneous browser sessions */
#define JWT_SESSION_TTL      86400 /* fallback TTL when JWT carries no exp */

/*
 * Load CA public key and device token from LittleFS into RAM.
 * Call once at boot, after LittleFS is initialised.
 */
void JWT_Init(void);

/*
 * Verify a JWT ES256 token against the loaded CA public key.
 * Returns 1 if signature is valid and token is not expired, 0 otherwise.
 */
int JWT_VerifyES256(const char *jwt_str);

/*
 * Return the "sub" claim of a JWT without signature verification.
 * Writes into caller-supplied buffer. Returns buf, or NULL on parse error.
 */
char *JWT_GetSubject(const char *jwt_str, char *buf, int buflen);

/*
 * Return the "exp" claim of a JWT (Unix timestamp), or 0 on error.
 */
unsigned int JWT_GetExpiry(const char *jwt_str);

/*
 * Write a new CA public key PEM to LittleFS and reload it.
 */
int JWT_SetCAKey(const char *pem);

/*
 * Write a new device JWT to LittleFS and reload it.
 */
int JWT_SetDeviceToken(const char *token);

/*
 * Return the loaded device token (for use in outgoing requests).
 * Returns NULL if no token has been loaded.
 */
const char *JWT_GetDeviceToken(void);

/*
 * Extract the jti claim from a JWT without signature verification.
 * The JWT payload is base64url-encoded JSON (not encrypted), so jti can be
 * read by the client from its own token to derive its session cookie value.
 */
char *JWT_GetJTI(const char *jwt_str, char *buf, int buflen);

/*
 * Register the jti+exp of a successfully verified JWT in the session table.
 * The client can then send Cookie: session=<jti> to skip ECDSA on subsequent
 * requests — it derives the jti by base64url-decoding its own JWT payload.
 */
void JWT_RegisterVerifiedToken(const char *jwt_str);

/* Check and maintain the session table */
int JWT_ValidateSession(const char *session_id);
void JWT_PurgeExpiredSessions(void);

#endif /* MQTT_USE_TLS */
