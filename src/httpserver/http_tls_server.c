#include "../new_common.h"

#if HTTP_USE_TLS

#include "lwip/sockets.h"
#include "lwip/ip_addr.h"
#include "lwip/inet.h"
#include "../logging/logging.h"
#include "new_http.h"
#include "http_tls_server.h"
#include "../cmnds/cmd_public.h"

#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/pk.h"

/* Stack size for the per-connection TLS client thread.
 * mbedTLS handshake uses significant stack; 16 KB is the safe minimum. */
#define HTTPS_CLIENT_STACK_SIZE  16384
#define HTTPS_INCOMING_BUF_SIZE  2048
#define HTTPS_REPLY_BUF_SIZE     2048

/* ── server-lifetime state (loaded once in HTTPS_Start) ────────────── */

static mbedtls_ssl_config       g_https_conf;
static mbedtls_x509_crt         g_https_srvcert;
static mbedtls_pk_context       g_https_pkey;
static mbedtls_entropy_context  g_https_entropy;
static mbedtls_ctr_drbg_context g_https_ctr_drbg;
static int                      g_https_ready = 0;

static xTaskHandle g_https_thread = NULL;

/* ── BIO callbacks (MBEDTLS_NET_C is disabled, use raw lwIP sockets) ── */

static int tls_net_send(void *ctx, const unsigned char *buf, size_t len) {
	int fd  = *(int *)ctx;
	int ret = send(fd, (const char *)buf, (int)len, 0);
	if (ret < 0) return MBEDTLS_ERR_SSL_SEND_FAILED;
	return ret;
}

static int tls_net_recv(void *ctx, unsigned char *buf, size_t len) {
	int fd  = *(int *)ctx;
	int ret = recv(fd, (char *)buf, (int)len, 0);
	if (ret == 0)  return MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY;
	if (ret < 0)   return MBEDTLS_ERR_SSL_RECV_FAILED;
	return ret;
}

/* ── public helpers ─────────────────────────────────────────────────── */

int HTTPS_HasCertAndKey(void) {
	byte *f = LFS_ReadFile(HTTPS_CERT_FILE);
	if (!f) return 0;
	os_free(f);
	f = LFS_ReadFile(HTTPS_KEY_FILE);
	if (!f) return 0;
	os_free(f);
	return 1;
}

/* ── per-connection thread ──────────────────────────────────────────── */

static void https_client_thread(beken_thread_arg_t arg) {
	int client_fd = (int)arg;
	char *buf   = NULL;
	char *reply = NULL;
	int   ret;

	mbedtls_ssl_context *ssl = (mbedtls_ssl_context *)os_malloc(sizeof(mbedtls_ssl_context));
	if (!ssl) {
		ADDLOG_ERROR(LOG_FEATURE_HTTP, "HTTPS: alloc ssl ctx failed");
		goto cleanup_fd;
	}

	mbedtls_ssl_init(ssl);
	if (mbedtls_ssl_setup(ssl, &g_https_conf) != 0) {
		ADDLOG_ERROR(LOG_FEATURE_HTTP, "HTTPS: ssl_setup failed");
		goto cleanup_ssl;
	}

	mbedtls_ssl_set_bio(ssl, &client_fd, tls_net_send, tls_net_recv, NULL);

	while ((ret = mbedtls_ssl_handshake(ssl)) != 0) {
		if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
			ADDLOG_ERROR(LOG_FEATURE_HTTP, "HTTPS: handshake failed: -0x%04x", -ret);
			goto cleanup_ssl;
		}
	}

	buf   = (char *)os_malloc(HTTPS_INCOMING_BUF_SIZE);
	reply = (char *)os_malloc(HTTPS_REPLY_BUF_SIZE);
	if (!buf || !reply) {
		ADDLOG_ERROR(LOG_FEATURE_HTTP, "HTTPS: alloc request buffers failed");
		goto cleanup_ssl;
	}

	/* Read the HTTP request over TLS */
	int received = 0;
	int maxlen   = HTTPS_INCOMING_BUF_SIZE - 2;
	while (received < maxlen) {
		int to_read = maxlen - received;
		ret = mbedtls_ssl_read(ssl, (unsigned char *)buf + received, to_read);
		if (ret <= 0) break;
		received += ret;
		if (ret < to_read) break; /* got less than asked — request is complete */
	}
	buf[received] = '\0';

	if (received > 0) {
		http_request_t request;
		memset(&request, 0, sizeof(request));
		request.fd             = client_fd;
		request.tls_ssl        = ssl;
		request.received       = buf;
		request.receivedLen    = received;
		request.receivedLenmax = maxlen;
		request.reply          = reply;
		request.replylen       = 0;
		reply[0]               = '\0';
		request.replymaxlen    = HTTPS_REPLY_BUF_SIZE - 1;
		request.responseCode   = HTTP_RESPONSE_OK;

		int lenret = HTTP_ProcessPacket(&request);
		/* Flush any data still buffered in request.reply */
		if (lenret > 0) {
			int written = 0;
			const unsigned char *rbuf = (const unsigned char *)request.reply;
			while (written < lenret) {
				ret = mbedtls_ssl_write(ssl, rbuf + written, lenret - written);
				if (ret <= 0) break;
				written += ret;
			}
		}
	}

	mbedtls_ssl_close_notify(ssl);

cleanup_ssl:
	mbedtls_ssl_free(ssl);
	os_free(ssl);

cleanup_fd:
	if (buf)   os_free(buf);
	if (reply) os_free(reply);
	lwip_close(client_fd);
	rtos_delete_thread(NULL);
}

/* ── listener thread ────────────────────────────────────────────────── */

static void https_server_thread(beken_thread_arg_t arg) {
	(void)arg;
	struct sockaddr_in server_addr, client_addr;
	socklen_t sockaddr_t_size = sizeof(client_addr);
	int listen_fd = -1, client_fd = -1;
	fd_set readfds;

	listen_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (listen_fd < 0) {
		ADDLOG_ERROR(LOG_FEATURE_HTTP, "HTTPS: socket() failed");
		goto exit;
	}

	server_addr.sin_family      = AF_INET;
	server_addr.sin_addr.s_addr = INADDR_ANY;
	server_addr.sin_port        = htons(HTTPS_SERVER_PORT);

	if (bind(listen_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) != 0) {
		ADDLOG_ERROR(LOG_FEATURE_HTTP, "HTTPS: bind() failed");
		goto exit;
	}
	if (listen(listen_fd, 2) != 0) {
		ADDLOG_ERROR(LOG_FEATURE_HTTP, "HTTPS: listen() failed");
		goto exit;
	}

	ADDLOG_INFO(LOG_FEATURE_HTTP, "HTTPS server listening on port %d", HTTPS_SERVER_PORT);

	while (1) {
		FD_ZERO(&readfds);
		FD_SET(listen_fd, &readfds);
		select(listen_fd + 1, &readfds, NULL, NULL, NULL);

		if (!FD_ISSET(listen_fd, &readfds)) continue;

		client_fd = accept(listen_fd, (struct sockaddr *)&client_addr, &sockaddr_t_size);
		if (client_fd < 0) continue;

		rtos_delay_milliseconds(20);
		OSStatus err = rtos_create_thread(NULL, BEKEN_APPLICATION_PRIORITY,
			"HTTPS Client",
			(beken_thread_function_t)https_client_thread,
			HTTPS_CLIENT_STACK_SIZE,
			(beken_thread_arg_t)client_fd);
		if (err != kNoErr) {
			ADDLOG_ERROR(LOG_FEATURE_HTTP, "HTTPS: client thread creation failed");
			lwip_close(client_fd);
		}
	}

exit:
	if (listen_fd >= 0) lwip_close(listen_fd);
	rtos_delete_thread(NULL);
}

/* ── server initialisation ──────────────────────────────────────────── */

static int https_load_and_configure(void) {
	int   ret      = 0;
	byte *cert_pem = NULL;
	byte *key_pem  = NULL;

	mbedtls_ssl_config_init(&g_https_conf);
	mbedtls_x509_crt_init(&g_https_srvcert);
	mbedtls_pk_init(&g_https_pkey);
	mbedtls_entropy_init(&g_https_entropy);
	mbedtls_ctr_drbg_init(&g_https_ctr_drbg);

	ret = mbedtls_ctr_drbg_seed(&g_https_ctr_drbg,
		mbedtls_entropy_func, &g_https_entropy,
		(const unsigned char *)"obk_https", 9);
	if (ret != 0) {
		ADDLOG_ERROR(LOG_FEATURE_HTTP, "HTTPS: drbg seed failed: -0x%04x", -ret);
		goto fail;
	}

	cert_pem = LFS_ReadFile(HTTPS_CERT_FILE);
	if (!cert_pem) {
		ADDLOG_ERROR(LOG_FEATURE_HTTP, "HTTPS: cert '%s' not found in LFS", HTTPS_CERT_FILE);
		goto fail;
	}
	ret = mbedtls_x509_crt_parse(&g_https_srvcert, cert_pem, strlen((char *)cert_pem) + 1);
	os_free(cert_pem); cert_pem = NULL;
	if (ret != 0) {
		ADDLOG_ERROR(LOG_FEATURE_HTTP, "HTTPS: cert parse failed: -0x%04x", -ret);
		goto fail;
	}

	key_pem = LFS_ReadFile(HTTPS_KEY_FILE);
	if (!key_pem) {
		ADDLOG_ERROR(LOG_FEATURE_HTTP, "HTTPS: key '%s' not found in LFS", HTTPS_KEY_FILE);
		goto fail;
	}
	ret = mbedtls_pk_parse_key(&g_https_pkey, key_pem, strlen((char *)key_pem) + 1, NULL, 0);
	os_free(key_pem); key_pem = NULL;
	if (ret != 0) {
		ADDLOG_ERROR(LOG_FEATURE_HTTP, "HTTPS: key parse failed: -0x%04x", -ret);
		goto fail;
	}

	ret = mbedtls_ssl_config_defaults(&g_https_conf,
		MBEDTLS_SSL_IS_SERVER,
		MBEDTLS_SSL_TRANSPORT_STREAM,
		MBEDTLS_SSL_PRESET_DEFAULT);
	if (ret != 0) {
		ADDLOG_ERROR(LOG_FEATURE_HTTP, "HTTPS: ssl_config_defaults failed: -0x%04x", -ret);
		goto fail;
	}

	mbedtls_ssl_conf_authmode(&g_https_conf, MBEDTLS_SSL_VERIFY_NONE);
	mbedtls_ssl_conf_rng(&g_https_conf, mbedtls_ctr_drbg_random, &g_https_ctr_drbg);

	ret = mbedtls_ssl_conf_own_cert(&g_https_conf, &g_https_srvcert, &g_https_pkey);
	if (ret != 0) {
		ADDLOG_ERROR(LOG_FEATURE_HTTP, "HTTPS: ssl_conf_own_cert failed: -0x%04x", -ret);
		goto fail;
	}

	return 0;

fail:
	if (cert_pem) os_free(cert_pem);
	if (key_pem)  os_free(key_pem);
	mbedtls_ssl_config_free(&g_https_conf);
	mbedtls_x509_crt_free(&g_https_srvcert);
	mbedtls_pk_free(&g_https_pkey);
	mbedtls_entropy_free(&g_https_entropy);
	mbedtls_ctr_drbg_free(&g_https_ctr_drbg);
	return -1;
}

void HTTPS_Start(void) {
	if (g_https_ready) return;

	if (!HTTPS_HasCertAndKey()) {
		ADDLOG_INFO(LOG_FEATURE_HTTP,
			"HTTPS: no cert/key in LFS — server not started. "
			"Use setHTTPSCert / setHTTPSKey then reboot.");
		return;
	}

	if (https_load_and_configure() != 0) {
		ADDLOG_ERROR(LOG_FEATURE_HTTP, "HTTPS: failed to configure TLS — server not started");
		return;
	}

	g_https_ready = 1;

	uint32_t stackSize = 0x800;
	OSStatus err = kGeneralErr;
	while (stackSize >= 0x100) {
		err = rtos_create_thread(&g_https_thread, BEKEN_APPLICATION_PRIORITY,
			"HTTPS_server",
			(beken_thread_function_t)https_server_thread,
			stackSize,
			(beken_thread_arg_t)0);
		if (err == kNoErr) {
			ADDLOG_INFO(LOG_FEATURE_HTTP,
				"HTTPS server started on port %d (stack=%u)", HTTPS_SERVER_PORT, stackSize);
			break;
		}
		stackSize >>= 1;
	}

	if (err != kNoErr) {
		ADDLOG_ERROR(LOG_FEATURE_HTTP, "HTTPS: failed to create server thread");
		g_https_ready = 0;
	}
}

#endif /* HTTP_USE_TLS */
