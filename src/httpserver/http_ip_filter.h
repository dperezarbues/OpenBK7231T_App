#ifndef HTTP_IP_FILTER_H
#define HTTP_IP_FILTER_H

#define IP_FILTER_FILE "http_allowed_ips"

void IPFilter_Init(void);
void IPFilter_Reload(void);
int  IPFilter_IsAllowed(const char *client_ip);

#endif /* HTTP_IP_FILTER_H */
