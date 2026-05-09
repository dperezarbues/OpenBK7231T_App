#ifndef HTTP_IP_FILTER_H
#define HTTP_IP_FILTER_H

/* Load the IP filter list from LittleFS. Called once on boot. */
void IPFilter_Init(void);

/* Reload after addAllowedIP / clearAllowedIPs changes the LFS file. */
void IPFilter_Reload(void);

/*
 * Returns 1 if the client IP is allowed to connect, 0 if it should be
 * rejected.  Always returns 1 when no filter is configured.
 *
 * Entries in the filter file are comma-separated.  A trailing dot acts as
 * a prefix match: "192.168.1." matches any host in that /24.
 */
int IPFilter_IsAllowed(const char *client_ip);

#define IP_FILTER_FILE  "http_allowed_ips"

#endif /* HTTP_IP_FILTER_H */
