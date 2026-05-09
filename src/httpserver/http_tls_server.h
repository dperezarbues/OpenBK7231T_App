#ifndef HTTP_TLS_SERVER_H
#define HTTP_TLS_SERVER_H

#if MQTT_USE_TLS

#define HTTPS_SERVER_PORT  443
#define HTTPS_CERT_FILE    "https_cert.pem"
#define HTTPS_KEY_FILE     "https_key.pem"

/* Returns 1 if both cert and key files exist in LittleFS */
int  HTTPS_HasCertAndKey(void);

/* Start the HTTPS listener thread (no-op if cert/key not found in LittleFS) */
void HTTPS_Start(void);

#endif /* MQTT_USE_TLS */
#endif /* HTTP_TLS_SERVER_H */
