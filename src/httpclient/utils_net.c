/*
 * Copyright (C) 2015-2017 Alibaba Group Holding Limited
 */

#include "../new_common.h"
#include "../logging/logging.h"
#if ENABLE_SEND_POSTANDGET
#include "utils_net.h"
#include "utils_timer.h"
#include "errno.h"
#include "lwip/sockets.h"
#ifndef WINDOWS
#include "lwip/netdb.h"
#endif

#if HTTP_USE_TLS
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/x509_crt.h"

typedef struct {
	int                      fd;
	mbedtls_ssl_context      ssl;
	mbedtls_ssl_config       conf;
	mbedtls_x509_crt         ca_cert;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_entropy_context  entropy;
} tls_ctx_t;

static int tls_bio_send(void *ctx, const unsigned char *buf, size_t len) {
	int fd  = *(int *)ctx;
	int ret = send(fd, (const char *)buf, (int)len, 0);
	if (ret < 0) return MBEDTLS_ERR_SSL_SEND_FAILED;
	return ret;
}

static int tls_bio_recv(void *ctx, unsigned char *buf, size_t len) {
	int fd  = *(int *)ctx;
	int ret = recv(fd, (char *)buf, (int)len, 0);
	if (ret == 0) return MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY;
	if (ret < 0)  return MBEDTLS_ERR_SSL_RECV_FAILED;
	return ret;
}

static int connect_tls(utils_network_pt pNetwork) {
	uintptr_t tcp_fd = HAL_TCP_Establish(pNetwork->pHostAddress, pNetwork->port);
	if (!tcp_fd) return -1;

	tls_ctx_t *ctx = os_malloc(sizeof(tls_ctx_t));
	if (!ctx) {
		lwip_close((int)tcp_fd);
		return -1;
	}
	memset(ctx, 0, sizeof(*ctx));
	ctx->fd = (int)tcp_fd;

	mbedtls_ssl_init(&ctx->ssl);
	mbedtls_ssl_config_init(&ctx->conf);
	mbedtls_x509_crt_init(&ctx->ca_cert);
	mbedtls_ctr_drbg_init(&ctx->ctr_drbg);
	mbedtls_entropy_init(&ctx->entropy);

	int ret = mbedtls_ctr_drbg_seed(&ctx->ctr_drbg, mbedtls_entropy_func,
	                                 &ctx->entropy, NULL, 0);
	if (ret != 0) {
		ADDLOG_ERROR(LOG_FEATURE_HTTP_CLIENT, "TLS: rng seed failed -0x%04x", -ret);
		goto fail;
	}

	ret = mbedtls_ssl_config_defaults(&ctx->conf, MBEDTLS_SSL_IS_CLIENT,
	                                  MBEDTLS_SSL_TRANSPORT_STREAM,
	                                  MBEDTLS_SSL_PRESET_DEFAULT);
	if (ret != 0) {
		ADDLOG_ERROR(LOG_FEATURE_HTTP_CLIENT, "TLS: config defaults failed -0x%04x", -ret);
		goto fail;
	}

	mbedtls_ssl_conf_rng(&ctx->conf, mbedtls_ctr_drbg_random, &ctx->ctr_drbg);

	if (pNetwork->ca_crt && pNetwork->ca_crt_len > 0) {
		/* PEM parser requires a NUL terminator; ca_crt_len = strlen so +1 includes it */
		ret = mbedtls_x509_crt_parse(&ctx->ca_cert,
		                             (const unsigned char *)pNetwork->ca_crt,
		                             (size_t)pNetwork->ca_crt_len + 1);
		if (ret == 0) {
			mbedtls_ssl_conf_ca_chain(&ctx->conf, &ctx->ca_cert, NULL);
			mbedtls_ssl_conf_authmode(&ctx->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
			ADDLOG_INFO(LOG_FEATURE_HTTP_CLIENT, "TLS: server cert verification enabled");
		} else {
			ADDLOG_ERROR(LOG_FEATURE_HTTP_CLIENT,
			             "TLS: ca_crt parse failed -0x%04x; skipping verification", -ret);
			mbedtls_ssl_conf_authmode(&ctx->conf, MBEDTLS_SSL_VERIFY_NONE);
		}
	} else {
		ADDLOG_ERROR(LOG_FEATURE_HTTP_CLIENT, "TLS: no CA cert provided; skipping verification");
		mbedtls_ssl_conf_authmode(&ctx->conf, MBEDTLS_SSL_VERIFY_NONE);
	}

	if (mbedtls_ssl_setup(&ctx->ssl, &ctx->conf) != 0) {
		ADDLOG_ERROR(LOG_FEATURE_HTTP_CLIENT, "TLS: ssl_setup failed");
		goto fail;
	}

	mbedtls_ssl_set_hostname(&ctx->ssl, pNetwork->pHostAddress);
	mbedtls_ssl_set_bio(&ctx->ssl, &ctx->fd, tls_bio_send, tls_bio_recv, NULL);

	while ((ret = mbedtls_ssl_handshake(&ctx->ssl)) != 0) {
		if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
			ADDLOG_ERROR(LOG_FEATURE_HTTP_CLIENT, "TLS: handshake failed -0x%04x", -ret);
			goto fail;
		}
	}

	ADDLOG_INFO(LOG_FEATURE_HTTP_CLIENT, "TLS: connected to %s:%u",
	            pNetwork->pHostAddress, pNetwork->port);
	pNetwork->handle = (uintptr_t)ctx;
	return 0;

fail:
	mbedtls_ssl_free(&ctx->ssl);
	mbedtls_ssl_config_free(&ctx->conf);
	mbedtls_x509_crt_free(&ctx->ca_cert);
	mbedtls_ctr_drbg_free(&ctx->ctr_drbg);
	mbedtls_entropy_free(&ctx->entropy);
	lwip_close(ctx->fd);
	os_free(ctx);
	return -1;
}

static int32_t read_tls(utils_network_pt pNetwork, char *buf, uint32_t len,
                        uint32_t timeout_ms) {
	(void)timeout_ms;
	tls_ctx_t *ctx = (tls_ctx_t *)pNetwork->handle;
	int ret = mbedtls_ssl_read(&ctx->ssl, (unsigned char *)buf, len);
	if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
		return 0;
	if (ret <= 0) {
		ADDLOG_ERROR(LOG_FEATURE_HTTP_CLIENT, "TLS: read error -0x%04x", -ret);
		return -1;
	}
	return ret;
}

static int32_t write_tls(utils_network_pt pNetwork, const char *buf, uint32_t len,
                         uint32_t timeout_ms) {
	(void)timeout_ms;
	tls_ctx_t *ctx = (tls_ctx_t *)pNetwork->handle;
	uint32_t written = 0;
	while (written < len) {
		int ret = mbedtls_ssl_write(&ctx->ssl,
		                            (const unsigned char *)buf + written,
		                            len - written);
		if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
			continue;
		if (ret < 0) {
			ADDLOG_ERROR(LOG_FEATURE_HTTP_CLIENT, "TLS: write error -0x%04x", -ret);
			return -1;
		}
		written += ret;
	}
	return (int32_t)written;
}

static int disconnect_tls(utils_network_pt pNetwork) {
	tls_ctx_t *ctx = (tls_ctx_t *)pNetwork->handle;
	if (!ctx) return -1;
	mbedtls_ssl_close_notify(&ctx->ssl);
	mbedtls_ssl_free(&ctx->ssl);
	mbedtls_ssl_config_free(&ctx->conf);
	mbedtls_x509_crt_free(&ctx->ca_cert);
	mbedtls_ctr_drbg_free(&ctx->ctr_drbg);
	mbedtls_entropy_free(&ctx->entropy);
	lwip_close(ctx->fd);
	os_free(ctx);
	pNetwork->handle = 0;
	return 0;
}
#endif /* HTTP_USE_TLS */

uintptr_t HAL_TCP_Establish(const char *host, uint16_t port)
{
    struct addrinfo hints;
    struct addrinfo *addrInfoList = NULL;
    struct addrinfo *cur = NULL;
    int fd = 0;
    int rc = 0;
    char service[6];

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; //only IPv4
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    snprintf(service, sizeof(service), "%u", port);

    if ((rc = getaddrinfo(host, service, &hints, &addrInfoList)) != 0) {
        ADDLOG_ERROR(LOG_FEATURE_HTTP_CLIENT,"getaddrinfo error");
        return 0;
    }

    for (cur = addrInfoList; cur != NULL; cur = cur->ai_next) {
        if (cur->ai_family != AF_INET) {
            ADDLOG_ERROR(LOG_FEATURE_HTTP_CLIENT,"socket type error");
            rc = 0;
            continue;
        }

        fd = socket(cur->ai_family, cur->ai_socktype, cur->ai_protocol);
        if (fd < 0) {
            ADDLOG_ERROR(LOG_FEATURE_HTTP_CLIENT,"create socket error %i",fd);
            rc = 0;
            continue;
        }
		ADDLOG_INFO(LOG_FEATURE_HTTP_CLIENT, "HAL_TCP_Establish: created socket %i",(int)fd);

        if (connect(fd, cur->ai_addr, cur->ai_addrlen) == 0) {
            rc = fd;
            break;
        }

        lwip_close(fd);
        ADDLOG_ERROR(LOG_FEATURE_HTTP_CLIENT,"connect error");
        rc = 0;
    }

    if (0 == rc){
        ADDLOG_ERROR(LOG_FEATURE_HTTP_CLIENT,"fail to establish tcp");
    } else {
        ADDLOG_ERROR(LOG_FEATURE_HTTP_CLIENT,"success to establish tcp, fd=%d", rc);
    }
    freeaddrinfo(addrInfoList);

    return (uintptr_t)rc;
}


int32_t HAL_TCP_Destroy(uintptr_t fd)
{
    int rc;
	///int att;

    //Shutdown both send and receive operations.
    rc = shutdown((int) fd, 2);
    if (0 != rc) {
        ADDLOG_ERROR(LOG_FEATURE_HTTP_CLIENT,"shutdown error %i",rc);
        return -1;
    }
#if 0
	for(att = 0; att < 10; att++) {
		rc = lwip_close((int) fd);
		if (0 != rc) {
			ADDLOG_ERROR(LOG_FEATURE_HTTP_CLIENT,"closesocket(%i) error %i at attemtp %i",((int)fd),rc,att);
			delay_ms(500);
		} else {
			break;
		}
	}
#elif 1
    rc = lwip_close((int) fd);
    if (0 != rc) {
        ADDLOG_ERROR(LOG_FEATURE_HTTP_CLIENT,"closesocket(%i) error %i",((int)fd),rc);
		// same as above but without SOCK_DEINIT_SYNC check
		// There is a bug in our htttp client and this is a temporary work around for that
		// Otherwise, it leaves sockets unfried and they adds up to 38 and block all networking
		lwip_close_force((int) fd);
        return -1;
    }
#else
    rc = lwip_close((int) fd);
    if (0 != rc) {
        ADDLOG_ERROR(LOG_FEATURE_HTTP_CLIENT,"closesocket(%i) error %i",((int)fd),rc);
        return -1;
    }
#endif
    return 0;
}


int32_t HAL_TCP_Write(uintptr_t fd, const char *buf, uint32_t len, uint32_t timeout_ms)
{
#if 0
	uint32_t len_sent;
	len_sent = send(fd, buf, len, 0);
#else
    int ret, err_code;
    uint32_t len_sent;
    uint64_t t_end, t_left;
    fd_set sets;

    t_end = utils_time_get_ms() + timeout_ms;
    len_sent = 0;
    err_code = 0;
    ret = 1; //send one time if timeout_ms is value 0

    do {
        t_left = utils_time_left(t_end, utils_time_get_ms());

        if (0 != t_left) {
            struct timeval timeout;

            FD_ZERO( &sets );
            FD_SET(fd, &sets);

            timeout.tv_sec = t_left / 1000;
            timeout.tv_usec = (t_left % 1000) * 1000;

            ret = select(fd + 1, NULL, &sets, NULL, &timeout);
            if (ret > 0) {
               if (0 == FD_ISSET(fd, &sets)) {
                    ADDLOG_ERROR(LOG_FEATURE_HTTP_CLIENT,"Should NOT arrive");
                    //If timeout in next loop, it will not sent any data
                    ret = 0;
                    continue;
                }
            } else if (0 == ret) {
                ADDLOG_ERROR(LOG_FEATURE_HTTP_CLIENT,"select-write timeout %lu", fd);
                break;
            } else {
                if (EINTR == errno) {
                    ADDLOG_ERROR(LOG_FEATURE_HTTP_CLIENT,"EINTR be caught");
                    continue;
                }

                err_code = -1;
                ADDLOG_ERROR(LOG_FEATURE_HTTP_CLIENT,"select-write fail");
                break;
            }
        }

        if (ret > 0) {
            ret = send(fd, buf + len_sent, len - len_sent, 0);
            if (ret > 0) {
                len_sent += ret;
            } else if (0 == ret) {
                ADDLOG_ERROR(LOG_FEATURE_HTTP_CLIENT,"No data be sent");
            } else {
                if (EINTR == errno) {
                    ADDLOG_ERROR(LOG_FEATURE_HTTP_CLIENT,"EINTR be caught");
                    continue;
                }

                err_code = -1;
                ADDLOG_ERROR(LOG_FEATURE_HTTP_CLIENT,"send fail");
                break;
            }
        }
    } while((len_sent < len) && (utils_time_left(t_end, utils_time_get_ms()) > 0));
#endif
    return len_sent;
}


int32_t HAL_TCP_Read(uintptr_t fd, char *buf, uint32_t len, uint32_t timeout_ms)
{
#if 0
	int err_code = 0;
	uint32_t len_recv;
	len_recv = recv(fd, buf, len, 0);
#else
    int ret, err_code,data_over;
    uint32_t len_recv;
    uint64_t t_end, t_left;
    fd_set sets;
    struct timeval timeout;

    t_end = utils_time_get_ms( ) + timeout_ms ;
    len_recv = 0;
    err_code = 0;

    data_over = 0;

    do {
        t_left = utils_time_left(t_end, utils_time_get_ms());
/*        if (0 == t_left && bk_http_ptr->do_data == 0) {
            break;
        }*/
        FD_ZERO( &sets );
        FD_SET(fd, &sets);

        timeout.tv_sec = t_left / 1000;
        timeout.tv_usec = (t_left % 1000) * 1000;

        ret = select(fd + 1, &sets, NULL, NULL, NULL);
        if ( FD_ISSET( fd, &sets ) )
        {
            if (ret > 0) {
                ret = recv(fd, buf, len, 0);
                if (ret > 0) {
                    if(ret < len)
                        {
                        data_over = 1;
                    }
//                    if(bk_http_ptr->do_data == 1)
//                        {
//                        http_data_process(buf,ret);
//                    }

                    len_recv += ret;
                } else if (0 == ret) {
                    ADDLOG_ERROR(LOG_FEATURE_HTTP_CLIENT,"connection is closed");
                    err_code = -1;
                    break;
                } else {
                    if (EINTR == errno) {
                        ADDLOG_ERROR(LOG_FEATURE_HTTP_CLIENT,"EINTR be caught");
                        continue;
                    }
                    ADDLOG_ERROR(LOG_FEATURE_HTTP_CLIENT,"send fail");
                    err_code = -2;
                    break;
                }
            } else if (0 == ret) {
                break;
            } else {
                if (EINTR == errno) {
                ADDLOG_ERROR(LOG_FEATURE_HTTP_CLIENT,"EINTR be caught-------");
                //continue;
                }
                ADDLOG_ERROR(LOG_FEATURE_HTTP_CLIENT,"select-recv fail");
                err_code = -2;
                break;
            }
       }
       else
       {
       }
    }while(/*(bk_http_ptr->do_data == 1 && len_recv < bk_http_ptr->http_total) || */((len_recv < len) && (0 == data_over)));
#endif
    //priority to return data bytes if any data be received from TCP connection.
    //It will get error code on next calling
    return (0 != len_recv) ? len_recv : err_code;
}

/*** TCP connection ***/
int read_tcp(utils_network_pt pNetwork, char *buffer, uint32_t len, uint32_t timeout_ms)
{
    return HAL_TCP_Read(pNetwork->handle, buffer, len, timeout_ms);
}


static int write_tcp(utils_network_pt pNetwork, const char *buffer, uint32_t len, uint32_t timeout_ms)
{
    return HAL_TCP_Write(pNetwork->handle, buffer, len, timeout_ms);
}

static int disconnect_tcp(utils_network_pt pNetwork)
{
    if (0 == pNetwork->handle) {
        return -1;
    }

    HAL_TCP_Destroy(pNetwork->handle);
    pNetwork->handle = 0;
    return 0;
}


static int connect_tcp(utils_network_pt pNetwork)
{
    if (NULL == pNetwork) {
        ADDLOG_ERROR(LOG_FEATURE_HTTP_CLIENT,"network is null");
        return 1;
    }

    pNetwork->handle = HAL_TCP_Establish(pNetwork->pHostAddress, pNetwork->port);
    if (0 == pNetwork->handle) {
        return -1;
    }

    return 0;
}

/****** network interface ******/

int utils_net_read(utils_network_pt pNetwork, char *buffer, uint32_t len, uint32_t timeout_ms)
{
#if HTTP_USE_TLS
    if (pNetwork->ca_crt != NULL)
        return read_tls(pNetwork, buffer, len, timeout_ms);
#endif
    return read_tcp(pNetwork, buffer, len, timeout_ms);
}


int utils_net_write(utils_network_pt pNetwork, const char *buffer, uint32_t len, uint32_t timeout_ms)
{
#if HTTP_USE_TLS
    if (pNetwork->ca_crt != NULL)
        return write_tls(pNetwork, buffer, len, timeout_ms);
#endif
    return write_tcp(pNetwork, buffer, len, timeout_ms);
}


int iotx_net_disconnect(utils_network_pt pNetwork)
{
#if HTTP_USE_TLS
    if (pNetwork->ca_crt != NULL)
        return disconnect_tls(pNetwork);
#endif
    return disconnect_tcp(pNetwork);
}


int iotx_net_connect(utils_network_pt pNetwork)
{
#if HTTP_USE_TLS
    if (pNetwork->ca_crt != NULL)
        return connect_tls(pNetwork);
#endif
    return connect_tcp(pNetwork);
}


int iotx_net_init(utils_network_pt pNetwork, const char *host, uint16_t port, const char *ca_crt)
{
    if (!pNetwork || !host) {
        ADDLOG_ERROR(LOG_FEATURE_HTTP_CLIENT,"parameter error! pNetwork=%p, host = %p", pNetwork, host);
        return -1;
    }
    pNetwork->pHostAddress = host;
    pNetwork->port = port;
    pNetwork->ca_crt = ca_crt;

    if (NULL == ca_crt) {
        pNetwork->ca_crt_len = 0;
    } else {
        pNetwork->ca_crt_len = strlen(ca_crt);
    }

    pNetwork->handle = 0;
    pNetwork->doRead = utils_net_read;
    pNetwork->doWrite = utils_net_write;
    pNetwork->doDisconnect = iotx_net_disconnect;
    pNetwork->doConnect = iotx_net_connect;

    return 0;
}

#endif
