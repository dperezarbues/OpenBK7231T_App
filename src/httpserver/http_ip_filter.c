#include "../new_common.h"
#include "../logging/logging.h"
#include "http_ip_filter.h"

#if ENABLE_LITTLEFS
#include "../cmnds/cmd_public.h"

#define IP_FILTER_MAX   16
#define IP_ENTRY_MAX    40

static char g_allowed[IP_FILTER_MAX][IP_ENTRY_MAX];
static int  g_count  = 0;
static int  g_loaded = 0;

static void IPFilter_Parse(char *data) {
    g_count = 0;
    char *p = data;
    while (*p && g_count < IP_FILTER_MAX) {
        while (*p == ' ' || *p == '\r' || *p == '\n' || *p == ',') p++;
        if (!*p) break;
        char *start = p;
        while (*p && *p != ',' && *p != '\r' && *p != '\n') p++;
        int len = (int)(p - start);
        while (len > 0 && (start[len-1] == ' ')) len--;
        if (len > 0 && len < IP_ENTRY_MAX) {
            strncpy(g_allowed[g_count], start, len);
            g_allowed[g_count][len] = '\0';
            g_count++;
        }
    }
}

void IPFilter_Reload(void) {
    byte *data = LFS_ReadFile(IP_FILTER_FILE);
    g_count = 0;
    if (data) {
        IPFilter_Parse((char *)data);
        os_free(data);
        ADDLOG_INFO(LOG_FEATURE_HTTP, "IPFilter: loaded %d entries from %s", g_count, IP_FILTER_FILE);
    }
    g_loaded = 1;
}

void IPFilter_Init(void) {
    IPFilter_Reload();
}

int IPFilter_IsAllowed(const char *client_ip) {
    if (!g_loaded) IPFilter_Reload();
    if (g_count == 0) return 1;
    for (int i = 0; i < g_count; i++) {
        int len = strlen(g_allowed[i]);
        if (len > 0 && g_allowed[i][len - 1] == '.') {
            if (strncmp(client_ip, g_allowed[i], len) == 0) return 1;
        } else {
            if (strcmp(client_ip, g_allowed[i]) == 0) return 1;
        }
    }
    return 0;
}

#else /* !ENABLE_LITTLEFS */

void IPFilter_Init(void) {}
void IPFilter_Reload(void) {}
int  IPFilter_IsAllowed(const char *client_ip) { return 1; }

#endif /* ENABLE_LITTLEFS */
