#ifndef HTTP_CM_SECURITY_H
#define HTTP_CM_SECURITY_H

/* Load the HMAC secret from LittleFS at boot. */
void CMSec_Init(void);

/* Persist a new HMAC secret to LittleFS and update the in-memory copy. */
void CMSec_SetSecret(const char *secret);

/* Verify HMAC-SHA256(secret, cmnd) == sig_hex.
 * Returns 1 on success, 0 on failure or missing secret. */
int CMSec_VerifyHMAC(const char *cmnd, const char *sig_hex);

#endif /* HTTP_CM_SECURITY_H */
