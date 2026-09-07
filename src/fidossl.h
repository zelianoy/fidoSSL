#ifndef FIDOSSL_H
#define FIDOSSL_H

#include "types.h"
#include "debug.h"
#include <openssl/ssl.h>

#define FIDOSSL_EXT_TYPE 0x1234
// Logical or of:
// - SSL_EXT_CLIENT_HELLO
// - SSL_EXT_TLS1_3_CERTIFICATE
// - SSL_EXT_TLS1_3_CERTIFICATE_REQUEST
#define FIDOSSL_CONTEXT 0x5080

// A dummy key which is not validated
#define FIDOSSL_CLIENT_KEY \
"-----BEGIN PRIVATE KEY-----\n" \
"MC4CAQAwBQYDK2VwBCIEIP+++++++++++///FIDO2+TLS+Extension///++++++\n" \
"-----END PRIVATE KEY-----\n"

// A dummy certificate which uses the dummy key
#define FIDOSSL_CLIENT_CRT \
"-----BEGIN CERTIFICATE-----\n" \
"MIHjMIGWAgEAMAUGAytlcDAeMRwwGgYDVQQDDBNGSURPMiBUTFMgRVhURU5TSU9O\n" \
"MB4XDTI0MDgyNzE0Mjg0OFoXDTM0MDgyNTE0Mjg0OFowHjEcMBoGA1UEAwwTRklE\n" \
"TzIgVExTIEVYVEVOU0lPTjAqMAUGAytlcAMhAAbz7p98S0c2oGUEDfT435miLn6u\n" \
"kXv3GZUzqDLXq357MAUGAytlcANBAKkd4iy1S9EdVlzlt6UQv334Fbk6Gk2LJztR\n" \
"pTCtt+IY3Ioos4PG8r8KwaFKdLNpf3Mof6EvtZGWa2kmqtLVsAk=\n" \
"-----END CERTIFICATE-----\n"

typedef struct fidossl_client_opts {
    enum client_mode {
        FIDOSSL_REGISTER,
        FIDOSSL_AUTHENTICATE,
    } mode;
//In the I-D the RP is choosing the user name, thus we wont use this field anymore soon. Temporary the field stays there but wont be used
//
    char *user_name;
    char *user_display_name;
    char *ticket_b64;
    char *pin;
    int debug_level;
} FIDOSSL_CLIENT_OPTS;

typedef struct fidossl_server_opts {
    char *rp_id;
    char *rp_name;
    char *ticket_b64;
    USER_VERIF_REQ user_verification;
    RESIDENT_KEY_REQ resident_key;
    AUTH_ATTACH auth_attach;
    TRANSPORT transport;
    size_t timeout;
    int debug_level;
} FIDOSSL_SERVER_OPTS;

int fidossl_client_add_cb(SSL *ssl, unsigned int ext_type, unsigned int context,
                          const unsigned char **out, size_t *outlen, X509 *x,
                          size_t chainidx, int *al, void *add_arg);

int fidossl_client_parse_cb(SSL *ssl, unsigned int ext_type, unsigned int context,
                            const unsigned char *in, size_t inlen, X509 *x,
                            size_t chainidx, int *al, void *parse_arg);

void fidossl_client_free_cb(SSL *ssl, unsigned int ext_type, unsigned int context,
                            const unsigned char *out, void *add_arg);

int fidossl_server_add_cb(SSL *ssl, unsigned int ext_type, unsigned int context,
                          const unsigned char **out, size_t *outlen, X509 *x,
                          size_t chainidx, int *al, void *add_arg);

int fidossl_server_parse_cb(SSL *ssl, unsigned int ext_type, unsigned int context,
                            const unsigned char *in, size_t inlen, X509 *x,
                            size_t chainidx, int *al, void *parse_arg);

void fidossl_server_free_cb(SSL *ssl, unsigned int ext_type, unsigned int context,
                            const unsigned char *out, void *add_arg);

int no_verify_cb(int preverify_ok, X509_STORE_CTX *x509_ctx);

void SSL_CTX_keylog_cb_func_cb(const SSL *ssl, const char *line);

void fidossl_init_client_ctx(SSL_CTX *ctx);

#endif /* FIDOSSL_H */
