#ifdef WINDOWS

#include "selftest_local.h"
#include "../crypto/hmac_sha256.h"
#include <string.h>
#include <stdio.h>

/* Verify HMAC-SHA256 against RFC 4231 test vectors */

static void check_hmac(const uint8_t *key,  size_t keylen,
                        const uint8_t *data, size_t datalen,
                        const char *expected_hex)
{
    uint8_t mac[32];
    char got[65];

    obk_hmac_sha256(key, keylen, data, datalen, mac);
    for (int i = 0; i < 32; i++)
        snprintf(got + i*2, 3, "%02x", mac[i]);
    got[64] = '\0';

    SELFTEST_ASSERT(strcmp(got, expected_hex) == 0);
}

void Test_HMAC_SHA256(void)
{
    /* RFC 4231 Test Case 1 */
    {
        uint8_t key[20];
        memset(key, 0x0b, sizeof(key));
        const uint8_t data[] = "Hi There";
        check_hmac(key, sizeof(key), data, sizeof(data) - 1,
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    }

    /* RFC 4231 Test Case 2 */
    {
        const uint8_t key[]  = "Jefe";
        const uint8_t data[] = "what do ya want for nothing?";
        check_hmac(key, sizeof(key) - 1, data, sizeof(data) - 1,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    }

    /* RFC 4231 Test Case 3 — repeated bytes */
    {
        uint8_t key[20], data[50];
        memset(key,  0xaa, sizeof(key));
        memset(data, 0xdd, sizeof(data));
        check_hmac(key, sizeof(key), data, sizeof(data),
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");
    }

    /* Verify hex output is 64 lowercase hex chars */
    {
        const char *secret = "test-secret";
        const char *cmnd   = "MqttHost 192.168.50.100";
        uint8_t mac[32];
        char hex[65];
        obk_hmac_sha256((uint8_t *)secret, strlen(secret),
                    (uint8_t *)cmnd,   strlen(cmnd),
                    mac);
        for (int i = 0; i < 32; i++)
            snprintf(hex + i*2, 3, "%02x", mac[i]);
        hex[64] = '\0';
        SELFTEST_ASSERT(strlen(hex) == 64);
        for (int i = 0; i < 64; i++) {
            int ok = (hex[i] >= '0' && hex[i] <= '9') ||
                     (hex[i] >= 'a' && hex[i] <= 'f');
            SELFTEST_ASSERT(ok);
        }
    }
}

#endif /* WINDOWS */
