#include "../new_common.h"
#include "../logging/logging.h"
#include "http_cm_security.h"
#include "../crypto/hmac_sha256.h"
#include <stdio.h>
#include <string.h>

#define CMSEC_SECRET_FILE  "cm_hmac_secret"
#define CMSEC_SECRET_MAX   64

#if ENABLE_LITTLEFS

static char g_cm_secret[CMSEC_SECRET_MAX + 1];
static int  g_secret_loaded = 0;

void CMSec_Init(void)
{
    g_cm_secret[0]  = '\0';
    g_secret_loaded = 0;
    byte *data = LFS_ReadFile(CMSEC_SECRET_FILE);
    if (data) {
        strncpy(g_cm_secret, (char *)data, CMSEC_SECRET_MAX);
        g_cm_secret[CMSEC_SECRET_MAX] = '\0';
        os_free(data);
        ADDLOG_INFO(LOG_FEATURE_HTTP, "CMSec: HMAC secret loaded (%d chars)", (int)strlen(g_cm_secret));
    } else {
        ADDLOG_DEBUG(LOG_FEATURE_HTTP, "CMSec: no HMAC secret file found");
    }
    g_secret_loaded = 1;
}

void CMSec_SetSecret(const char *secret)
{
    strncpy(g_cm_secret, secret, CMSEC_SECRET_MAX);
    g_cm_secret[CMSEC_SECRET_MAX] = '\0';
    LFS_WriteFile(CMSEC_SECRET_FILE, (byte *)g_cm_secret, strlen(g_cm_secret), false);
    g_secret_loaded = 1;
    ADDLOG_INFO(LOG_FEATURE_HTTP, "CMSec: HMAC secret updated");
}

int CMSec_VerifyHMAC(const char *cmnd, const char *sig_hex)
{
    if (!g_secret_loaded)
        CMSec_Init();

    if (g_cm_secret[0] == '\0') {
        ADDLOG_ERROR(LOG_FEATURE_HTTP, "CMSec: OBK_FLAG_CM_REQUIRE_HMAC set but no secret stored — run setCMSecret first");
        return 0;
    }

    uint8_t mac[32];
    hmac_sha256((uint8_t *)g_cm_secret, strlen(g_cm_secret),
                (uint8_t *)cmnd,        strlen(cmnd),
                mac);

    char computed[65];
    for (int i = 0; i < 32; i++)
        snprintf(computed + i*2, 3, "%02x", mac[i]);
    computed[64] = '\0';

    return (strcmp(computed, sig_hex) == 0);
}

#else /* !ENABLE_LITTLEFS */

void CMSec_Init(void)    {}
void CMSec_SetSecret(const char *s) { (void)s; }
int  CMSec_VerifyHMAC(const char *c, const char *s) { (void)c; (void)s; return 1; }

#endif /* ENABLE_LITTLEFS */
