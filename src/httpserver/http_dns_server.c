#include "../new_common.h"
#include "../logging/logging.h"
#include "../hal/hal_wifi.h"
#include "lwip/sockets.h"
#include "lwip/inet.h"
#include "http_dns_server.h"

#define LOG_FEATURE LOG_FEATURE_HTTP

/*
 * Minimal DNS spoof server for captive portal use.
 * Responds to every A-record query with the device's own IP so that
 * all OS captive-portal probes (Android generate_204, Apple hotspot-detect,
 * Windows ncsi.txt …) resolve to us and the browser popup appears.
 *
 * DNS wire format used here:
 *   Header  (12 bytes): ID, flags, qdcount=1, ancount=1, nscount=0, arcount=0
 *   Question section:   copy from request
 *   Answer  RR:         pointer back to question name, A, IN, TTL=60, RDATA=4 bytes IP
 */

#define DNS_PORT     53
#define DNS_BUF_SIZE 512

static volatile int  g_dns_running = 0;
static xTaskHandle   g_dns_thread  = NULL;

/* Parse a raw 4-byte big-endian IPv4 string "a.b.c.d" into bytes. */
static int parse_ip(const char *s, uint8_t out[4]) {
    unsigned int a, b, c, d;
    if (sscanf(s, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return 0;
    out[0] = (uint8_t)a; out[1] = (uint8_t)b;
    out[2] = (uint8_t)c; out[3] = (uint8_t)d;
    return 1;
}

static void dns_server_thread(beken_thread_arg_t arg) {
    (void)arg;
    int sock;
    struct sockaddr_in srv, cli;
    socklen_t cli_len;
    uint8_t buf[DNS_BUF_SIZE];
    uint8_t resp[DNS_BUF_SIZE];

    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        ADDLOG_ERROR(LOG_FEATURE, "DNS: socket() failed");
        goto done;
    }

    /* SO_REUSEADDR so restart works without waiting for TIME_WAIT */
    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    /* Short receive timeout so the thread can notice g_dns_running==0 */
    struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    memset(&srv, 0, sizeof(srv));
    srv.sin_family      = AF_INET;
    srv.sin_addr.s_addr = INADDR_ANY;
    srv.sin_port        = htons(DNS_PORT);

    if (bind(sock, (struct sockaddr *)&srv, sizeof(srv)) < 0) {
        ADDLOG_ERROR(LOG_FEATURE, "DNS: bind() failed — port 53 in use?");
        lwip_close(sock);
        goto done;
    }

    ADDLOG_INFO(LOG_FEATURE, "DNS captive portal server started");

    while (g_dns_running) {
        cli_len = sizeof(cli);
        int len = recvfrom(sock, buf, sizeof(buf) - 1, 0,
                           (struct sockaddr *)&cli, &cli_len);
        if (len <= 0) continue;   /* timeout or error — check g_dns_running */
        if (len < 12) continue;   /* too short to be a valid DNS packet */

        /* Only answer standard queries (QR=0, opcode=0) */
        if ((buf[2] & 0xF8) != 0x00) continue;

        /* Resolve device IP */
        uint8_t ip[4];
        const char *ip_str = HAL_GetMyIPString();
        if (!ip_str || !parse_ip(ip_str, ip)) {
            ip[0] = 192; ip[1] = 168; ip[2] = 4; ip[3] = 1;
        }

        /* Build response: copy header, set QR=1 AA=1 RA=1, ancount=1 */
        int rlen = 0;
        /* Transaction ID */
        resp[rlen++] = buf[0]; resp[rlen++] = buf[1];
        /* Flags: QR=1, AA=1, RA=1, RCODE=0 */
        resp[rlen++] = 0x84; resp[rlen++] = 0x00;
        /* QDCOUNT = 1 */
        resp[rlen++] = 0x00; resp[rlen++] = 0x01;
        /* ANCOUNT = 1 */
        resp[rlen++] = 0x00; resp[rlen++] = 0x01;
        /* NSCOUNT = 0 */
        resp[rlen++] = 0x00; resp[rlen++] = 0x00;
        /* ARCOUNT = 0 */
        resp[rlen++] = 0x00; resp[rlen++] = 0x00;

        /* Copy question section verbatim (from offset 12 to end of packet) */
        int qlen = len - 12;
        if (rlen + qlen + 16 > DNS_BUF_SIZE) continue;
        memcpy(resp + rlen, buf + 12, qlen);
        rlen += qlen;

        /* Answer RR: name = pointer to offset 12 (start of question) */
        resp[rlen++] = 0xC0; resp[rlen++] = 0x0C;
        /* Type A */
        resp[rlen++] = 0x00; resp[rlen++] = 0x01;
        /* Class IN */
        resp[rlen++] = 0x00; resp[rlen++] = 0x01;
        /* TTL = 60 */
        resp[rlen++] = 0x00; resp[rlen++] = 0x00;
        resp[rlen++] = 0x00; resp[rlen++] = 0x3C;
        /* RDLENGTH = 4 */
        resp[rlen++] = 0x00; resp[rlen++] = 0x04;
        /* RDATA = IP */
        resp[rlen++] = ip[0]; resp[rlen++] = ip[1];
        resp[rlen++] = ip[2]; resp[rlen++] = ip[3];

        sendto(sock, resp, rlen, 0, (struct sockaddr *)&cli, cli_len);
    }

    lwip_close(sock);
    ADDLOG_INFO(LOG_FEATURE, "DNS captive portal server stopped");

done:
    g_dns_thread = NULL;
    rtos_delete_thread(NULL);
}

void CaptivePortalDNS_Start(void) {
    if (g_dns_running) return;
    g_dns_running = 1;
    OSStatus err = rtos_create_thread(&g_dns_thread, BEKEN_APPLICATION_PRIORITY,
        "DNS_srv",
        (beken_thread_function_t)dns_server_thread,
        0x800,
        (beken_thread_arg_t)0);
    if (err != kNoErr) {
        ADDLOG_ERROR(LOG_FEATURE, "DNS: failed to create thread (%d)", err);
        g_dns_running = 0;
    }
}

void CaptivePortalDNS_Stop(void) {
    g_dns_running = 0;
    /* thread will exit on next 1-second recv timeout */
}
