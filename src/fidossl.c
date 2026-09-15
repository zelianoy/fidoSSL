#include "fidossl.h"
#include "debug.h"
#include "rp.h"
#include "types.h"
#include "ud.h"
#include "common.h"
#include <fido.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>

int fidossl_client_add_cb(
    SSL *ssl,
    unsigned int ext_type,
    unsigned int context,
    const unsigned char **out,
    size_t *outlen,
    X509 *x,
    size_t chainidx,
    int *al,
    void *add_arg
) {
    //  If the application wishes to include the extension ext_type it should
    //  set out to the extension data, set outlen to the length of the extension
    //  data and return 1. If the add_cb does not wish to include the extension
    //  it must return 0.
    if (ext_type != FIDOSSL_EXT_TYPE) {
        return 0; // Silently ignore unknown extensions
    }
    if (context == SSL_EXT_CLIENT_HELLO) {
        struct ud_data *data = get_ud_data(ssl, add_arg);

        switch (data->state) {
        case STATE_REG_INITIAL:
            if (create_pre_indication(data, out, outlen) != 0) {
                debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "Failed to create pre indication");
                ERR_put_error(ERR_LIB_USER, 0, SSL_AD_INTERNAL_ERROR, __FILE__, __LINE__);
                *al = SSL_AD_INTERNAL_ERROR;
                return -1;
            }
            data->state = STATE_PRE_INDICATION_SENT;
            break;
        case STATE_PRE_RESPONSE_RECEIVED:
            if (create_reg_indication(data, out, outlen) != 0) {
                debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "Failed to create registration indication");
                ERR_put_error(ERR_LIB_USER, 0, SSL_AD_INTERNAL_ERROR, __FILE__, __LINE__);
                *al = SSL_AD_INTERNAL_ERROR;
                return -1;
            }
            data->state = STATE_REG_INDICATION_SENT;
            break;
        case STATE_AUTH_INITIAL:
            if (create_auth_indication(data, out, outlen) != 0) {
                debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "Failed to create authentication indication");
                ERR_put_error(ERR_LIB_USER, 0, SSL_AD_INTERNAL_ERROR, __FILE__, __LINE__);
                *al = SSL_AD_INTERNAL_ERROR;
                return -1;
            }
            data->state = STATE_AUTH_INDICATION_SENT;
            break;
        default:
            debug_printf(DEBUG_LEVEL_ERROR, "Invalid state");
            ERR_put_error(ERR_LIB_USER, 0, SSL_AD_INTERNAL_ERROR, __FILE__, __LINE__);
            *al = SSL_AD_INTERNAL_ERROR;
            return -1;
        }
    } else if (context == SSL_EXT_TLS1_3_CERTIFICATE) {
        struct ud_data *data = get_ud_data(ssl, add_arg);

        switch (data->state) {
        case STATE_REG_REQUEST_RECEIVED:
            if (create_reg_response(data, ssl, out, outlen) != 0) {
                debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "Failed to create registration response");
                ERR_put_error(ERR_LIB_USER, 0, SSL_AD_ACCESS_DENIED, __FILE__, __LINE__);
                *al = SSL_AD_ACCESS_DENIED;
                return -1;
            }
            data->state = STATE_REG_RESPONSE_SENT;
            break;
        case STATE_AUTH_REQUEST_RECEIVED:
            if (create_auth_response(data, ssl, out, outlen) != 0) {
                debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "Failed to create authentication response");
                ERR_put_error(ERR_LIB_USER, 0, SSL_AD_ACCESS_DENIED, __FILE__, __LINE__);
                *al = SSL_AD_ACCESS_DENIED;
                return -1;
            }
            data->state = STATE_AUTH_RESPONSE_SENT;
            break;
        // Since the SSL_EXT_TLS1_3_CERTIFICATE context is called twice, once
        // for the server certificate and then for the certificate request,
        // the following 3 states are ignored
        case STATE_REG_RESPONSE_SENT:
        case STATE_PRE_RESPONSE_RECEIVED:
        case STATE_AUTH_RESPONSE_SENT:
            return 0;
        default:
            debug_printf(DEBUG_LEVEL_ERROR, "Invalid state");
            *al = SSL_AD_INTERNAL_ERROR;
            return -1;
        }
    } else {
        debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "Unhandeled context event in %s: %s",
                     __func__, get_ssl_ext_context_code(context));
        return -1;
    }
    return 1;
}

int fidossl_client_parse_cb(
    SSL *ssl,
    unsigned int ext_type,
    unsigned int context,
    const unsigned char *in,
    size_t inlen,
    X509 *x,
    size_t chainidx,
    int *al,
    void *parse_arg
) {
    if (ext_type != FIDOSSL_EXT_TYPE) {
        return 0; // Silently ignore unknown extensions
    }

    if (context == SSL_EXT_TLS1_3_CERTIFICATE_REQUEST) {
        struct ud_data *data = get_ud_data(ssl, NULL);

        switch (data->state) {
            case STATE_PRE_INDICATION_SENT:
                if (process_pre_response(in, inlen, data) != 0) {
                    debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "Failed to process pre response");
                    ERR_put_error(ERR_LIB_USER, 0, SSL_AD_ACCESS_DENIED, __FILE__, __LINE__);
                    *al = SSL_AD_ACCESS_DENIED;
                    return -1;
                }
                data->state = STATE_PRE_RESPONSE_RECEIVED;
                // Now, a second handshake is necessary to complete the
                // registration.
                break;
            case STATE_REG_INDICATION_SENT:
                if (process_reg_request(in, inlen, data) != 0) {
                    debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "Failed to process registration request");
                    ERR_put_error(ERR_LIB_USER, 0, SSL_AD_ACCESS_DENIED, __FILE__, __LINE__);
                    *al = SSL_AD_ACCESS_DENIED;
                    return -1;
                }
                data->state = STATE_REG_REQUEST_RECEIVED;
                break;
            case STATE_AUTH_INDICATION_SENT:
                if (process_auth_request(in, inlen, data) != 0) {
                    debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "Failed to process authentication request");
                    ERR_put_error(ERR_LIB_USER, 0, SSL_AD_ACCESS_DENIED, __FILE__, __LINE__);
                    *al = SSL_AD_ACCESS_DENIED;
                    return -1;
                }
                data->state = STATE_AUTH_REQUEST_RECEIVED;
                break;
            default:
                debug_printf(DEBUG_LEVEL_ERROR, "Invalid state");
                ERR_put_error(ERR_LIB_USER, 0, SSL_AD_INTERNAL_ERROR, __FILE__, __LINE__);
                *al = SSL_AD_INTERNAL_ERROR;
                return -1;
        }
    } else if (context == SSL_EXT_TLS1_3_CERTIFICATE) {
        // Do nothing here. We need that context only in the add cb.
        return 0;
    } else {
        debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "Unhandeled context event in %s: %s",
                     __func__, get_ssl_ext_context_code(context));
        return -1;
    }
    return 1;
}

int fidossl_server_add_cb(
    SSL *ssl,
    unsigned int ext_type,
    unsigned int context,
    const unsigned char **out,
    size_t *outlen,
    X509 *x,
    size_t chainidx,
    int *al,
    void *add_arg
) {
    if (ext_type != FIDOSSL_EXT_TYPE) {
        return 0; // Silently ignore unknown extensions
    }
    if (context == SSL_EXT_TLS1_3_CERTIFICATE_REQUEST) {
        struct rp_data *data = get_rp_data(ssl, NULL);
        if (data == NULL) {
            // No FIDO data for this connection. This means that the client
            // does not support the fido extension. This is not an error.
            return 0;
        }
        switch (data->state) {
            case STATE_PRE_INDICATION_RECEIVED:
                if (create_pre_response(data, out, outlen) != 0) {
                    debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "Failed to create pre response");
                    ERR_put_error(ERR_LIB_USER, 0, SSL_AD_ACCESS_DENIED, __FILE__, __LINE__);
                    *al = SSL_AD_ACCESS_DENIED;
                    return -1;
                }
                data->state = STATE_PRE_RESPONSE_SENT;
                break;
            case STATE_REG_INDICATION_RECEIVED:
                if (create_reg_request(data, out, outlen) != 0) {
                    debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "Failed to create registration request");
                    ERR_put_error(ERR_LIB_USER, 0, SSL_AD_ACCESS_DENIED, __FILE__, __LINE__);
                    *al = SSL_AD_ACCESS_DENIED;
                    return -1;
                }
                data->state = STATE_REG_REQUEST_SENT;
                break;
            case STATE_AUTH_INDICATION_RECEIVED:
                if (create_auth_request(data, out, outlen) != 0) {
                    debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "Failed to create authentication request");
                    ERR_put_error(ERR_LIB_USER, 0, SSL_AD_ACCESS_DENIED, __FILE__, __LINE__);
                    *al = SSL_AD_ACCESS_DENIED;
                    return -1;
                }
                data->state = STATE_AUTH_REQUEST_SENT;
                break;
            default:
                debug_printf(DEBUG_LEVEL_ERROR, "Invalid state");
                ERR_put_error(ERR_LIB_USER, 0, SSL_AD_INTERNAL_ERROR, __FILE__, __LINE__);
                *al = SSL_AD_INTERNAL_ERROR;
                return -1;
        }
    } else if (context == SSL_EXT_TLS1_3_CERTIFICATE) {
        // Do nothing here. We need that context only in the parse cb.
        return 0;
    } else {
        debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "Unhandeled context event in %s: %s",
                     __func__, get_ssl_ext_context_code(context));
        return -1;
    }
    return 1;
}

int fidossl_server_parse_cb(
    SSL *ssl,
    unsigned int ext_type,
    unsigned int context,
    const unsigned char *in,
    size_t inlen,
    X509 *x,
    size_t chainidx,
    int *al,
    void *parse_arg
) {
    if (ext_type != FIDOSSL_EXT_TYPE) {
        return 0; // Silently ignore unknown extensions
    }
    if (context == SSL_EXT_CLIENT_HELLO) {
        struct rp_data *data = get_rp_data(ssl, parse_arg);
        // The server has no state yet and can accept any indication. The
        // process_inication function will set the state accordingly.
        if (process_indication(in, inlen, data) != 0) {
            debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "Failed to parse FIDO indication");
            ERR_put_error(ERR_LIB_USER, 0, SSL_AD_ACCESS_DENIED, __FILE__, __LINE__);
            *al = SSL_AD_ACCESS_DENIED;
            return -1;
        }
    } else if (context == SSL_EXT_TLS1_3_CERTIFICATE) {
        struct rp_data *data = get_rp_data(ssl, parse_arg);
        switch (data->state) {
            case STATE_REG_REQUEST_SENT:
                if (process_reg_response(in, inlen, data) != 0) {
                    debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "Failed to parse registration response");
                    ERR_put_error(ERR_LIB_USER, 0, SSL_AD_ACCESS_DENIED, __FILE__, __LINE__);
                    *al = SSL_AD_ACCESS_DENIED;
                    return -1;
                }
                data->state = STATE_REG_SUCCESS;
                debug_printf(DEBUG_LEVEL_VERBOSE, "FIDO registration success!");
                break;
            case STATE_AUTH_REQUEST_SENT:
                if (process_auth_response(in, inlen, data) != 0) {
                    debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "Failed to parse authenticaton response");
                    ERR_put_error(ERR_LIB_USER, 0, SSL_AD_ACCESS_DENIED, __FILE__, __LINE__);
                    *al = SSL_AD_ACCESS_DENIED;
                    return -1;
                }
                debug_printf(DEBUG_LEVEL_VERBOSE, "FIDO authentication success!");
                break;
            default:
                debug_printf(DEBUG_LEVEL_ERROR, "Invalid state");
                ERR_put_error(ERR_LIB_USER, 0, SSL_AD_INTERNAL_ERROR, __FILE__, __LINE__);
                *al = SSL_AD_INTERNAL_ERROR;
                return -1;
        }
    } else {
        debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "Unhandeled context event in %s: %s",
                     __func__, get_ssl_ext_context_code(context));
        return -1;
    }
    return 1;
}

int no_verify_cb(int preverify_ok, X509_STORE_CTX *x509_ctx) {
    // Don't validae the client certificate.
    // The client certificate request is necessary to trigger the fido extension
    // but fido authentication replaces the client certificate authentication.
    return 1;
}

//function for logging SSL keys
void SSL_CTX_keylog_cb_func_cb(const SSL *ssl, const char *line){
    char  *filename = getenv("SSLKEYLOGFILE");
	if(!filename){
		return;
	}
    FILE *fp = fopen(filename, "a");
    if (fp == NULL)
    {
        printf("Failed to create log file\n");
    }
    fprintf(fp, "%s\n", line);
    fclose(fp);
}    

void fidossl_init_client_ctx(SSL_CTX *ctx) {
    SSL_CTX_set_keylog_callback(ctx, SSL_CTX_keylog_cb_func_cb);

    // Enforce TLS 1.3
    if (!SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION)) {
        printf("Failed to set the minimum TLS protocol version\n");
    }

    // Create a BIO with the PEM certificate string
    BIO *cert_bio = BIO_new_mem_buf(FIDOSSL_CLIENT_CRT, -1);
    if (!cert_bio) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // Load the certificate from the BIO
    X509 *cert = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL);
    BIO_free(cert_bio);
    if (!cert) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // Use the certificate in the SSL_CTX
    if (SSL_CTX_use_certificate(ctx, cert) <= 0) {
        ERR_print_errors_fp(stderr);
        X509_free(cert);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }
    X509_free(cert);

    // Create a BIO with the PEM private key string
    BIO *key_bio = BIO_new_mem_buf(FIDOSSL_CLIENT_KEY, -1);
    if (!key_bio) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // Load the private key from the BIO
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(key_bio, NULL, NULL, NULL);
    BIO_free(key_bio);
    if (!pkey) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // Use the private key in the SSL_CTX
    if (SSL_CTX_use_PrivateKey(ctx, pkey) <= 0) {
        ERR_print_errors_fp(stderr);
        EVP_PKEY_free(pkey);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    if(SSL_CTX_check_private_key(ctx)<=0){
        printf("Dummy certificate and private key do not match");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_free(pkey);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }


    EVP_PKEY_free(pkey);
}
