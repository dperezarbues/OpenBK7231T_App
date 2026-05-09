#include "../new_common.h"
#include "../logging/logging.h"
#include "../cmnds/cmd_public.h"
#include "http_ip_filter.h"

#if ENABLE_LITTLEFS

#define IP_FILTER_MAX   16
#define IP_ENTRY_MAX    40

static char g_allowed[IP_FILTER_MAX][IP_ENTRY_MAX];
static int  g_count  = 0;
static int  g_loaded = 0;

static void load(void) {
	g_count = 0;
	byte *data = LFS_ReadFile(IP_FILTER_FILE);
	if (data) {
		char *p = (char *)data;
		while (*p && g_count < IP_FILTER_MAX) {
			while (*p == ' ' || *p == ',' || *p == '\r' || *p == '\n')
				p++;
			if (!*p)
				break;
			char *end = p;
			while (*end && *end != ',' && *end != '\r' && *end != '\n')
				end++;
			int len = (int)(end - p);
			if (len > 0 && len < IP_ENTRY_MAX) {
				memcpy(g_allowed[g_count], p, len);
				g_allowed[g_count][len] = '\0';
				g_count++;
			}
			p = end;
		}
		os_free(data);
	}
	g_loaded = 1;
	if (g_count)
		ADDLOG_INFO(LOG_FEATURE_HTTP, "IPFilter: %d allowed IP(s) loaded", g_count);
	else
		ADDLOG_INFO(LOG_FEATURE_HTTP, "IPFilter: no filter configured, all IPs allowed");
}

void IPFilter_Init(void)   { load(); }
void IPFilter_Reload(void) { load(); }

int IPFilter_IsAllowed(const char *client_ip) {
	if (!g_loaded)
		load();
	if (g_count == 0)
		return 1;
	for (int i = 0; i < g_count; i++) {
		const char *e = g_allowed[i];
		int elen = strlen(e);
		if (e[elen - 1] == '.') {
			/* prefix match: "192.168.1." matches 192.168.1.* */
			if (!strncmp(client_ip, e, elen))
				return 1;
		} else {
			if (!strcmp(client_ip, e))
				return 1;
		}
	}
	return 0;
}

#else /* !ENABLE_LITTLEFS */

void IPFilter_Init(void)                    {}
void IPFilter_Reload(void)                  {}
int  IPFilter_IsAllowed(const char *ip)     { (void)ip; return 1; }

#endif /* ENABLE_LITTLEFS */
