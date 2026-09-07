#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <fidossl.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 12345

void print_error() {
    unsigned long err_code;
    while ((err_code = ERR_get_error()) != 0) {
        int reason = ERR_GET_REASON(err_code);
        if (reason == SSL_R_TLSV1_ALERT_ACCESS_DENIED) {
            // This alert is send from the other peer if the FIDO operation
            // failed
            printf("Peer signaled FIDO operation failed\n");
        } else if (reason == SSL_AD_ACCESS_DENIED) {
            // This alert is pushed to the error stack if the FIDO operation
            // failed on this peer
            printf("FIDO operation failed\n");
        } else if (reason == SSL_R_CALLBACK_FAILED || reason == SSL_R_BAD_EXTENSION) {
            // Do nothing here. If the extension fails, this errors are always
            // part of the error stack but not descriptive.
        } else if (reason == SSL_R_UNEXPECTED_EOF_WHILE_READING) {
            printf("Peer disconnected\n");
        } else {
            // Generic error handling
            const char *error_string = ERR_reason_error_string(err_code);
            printf("Failed with reason: %d. Error: %s\n", reason, error_string);
        }
    }
}

int main() {
    SSL_CTX *ctx;
    SSL *ssl;
    int sockfd;
    struct sockaddr_in server_addr;

    // Initialize OpenSSL
    SSL_library_init();
    ctx = SSL_CTX_new(TLS_client_method());

    // Tell the client which CA should be trusted for server certificate verification
    if (!SSL_CTX_load_verify_locations(ctx, "./test/certs/ca.crt", NULL)) {
        printf("Failed to load CA certificate\n");
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // Configure the client to abort the handshake if certificate
    // verification fails.
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    //-------------------------------------------------------------------------
    // FIDOSSL START

    // The init function enforces TLS 1.3 and loads a dummy certificate + key
    // for the client, which is not verified
    fidossl_init_client_ctx(ctx);

    FIDOSSL_CLIENT_OPTS *opts = malloc(sizeof(FIDOSSL_CLIENT_OPTS));
    // Either FIDOSSL_REGISTER or FIDOSSL_AUTHENTICATE
    opts->mode = FIDOSSL_REGISTER;
    opts->user_name = "alice";
    opts->user_display_name = "Alice";
    opts->ticket_b64 = "y1v2BsTzi6baajWpU5WSDw6AYorx2MSDO1iVFSQC8VQ=";
    opts->pin = "1234";
    opts->debug_level = DEBUG_LEVEL_MORE_VERBOSE;

    // Add extension
    SSL_CTX_add_custom_ext(
        ctx,
        FIDOSSL_EXT_TYPE,
        FIDOSSL_CONTEXT,
        fidossl_client_add_cb,
        NULL,
        // void * add_arg is a pointer to arbitrary data that you can use within
        // your add_cb function.
        opts,
        fidossl_client_parse_cb,
        // void * parse_args is like add_arg but it passes arbitrary data into
        // the parse_cb
        NULL
    );

    //-------------------------------------------------------------------------
    // FIDOSSL END

    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("Socket creation failed");
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // Initialize server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);

    // Connect to server
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("Could not connect to socket");
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // Create SSL connection
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);

    // Set the SNI hostname
    if (!SSL_set_tlsext_host_name(ssl, "demo.fido2.tls.edu")) {
        printf("Failed to set the SNI hostname\n");
    }

    // Additionally set hostname validation
    if (!SSL_set1_host(ssl, "demo.fido2.tls.edu")) {
        printf("Failed to set the certificate verification hostname");
    }

    // Do the TLS handshake
    if (SSL_connect(ssl) != 1) {
        print_error();
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("=== TLS connection established.\n");

    while (SSL_shutdown(ssl) != 1) {}

    // Only do a second handshake if we want to register a new credential
    if (opts->mode == FIDOSSL_REGISTER) {
        // Create new SSL connection. Unfortunately, we cant reuse the SSL object
        SSL_free(ssl);
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, sockfd);

        // Set the SNI hostname
        if (!SSL_set_tlsext_host_name(ssl, "demo.fido2.tls.edu")) {
            printf("Failed to set the SNI hostname\n");
        }

        // Additionally set hostname validation
        if (!SSL_set1_host(ssl, "demo.fido2.tls.edu")) {
            printf("Failed to set the certificate verification hostname");
        }

        // Connect to server again
        if (SSL_connect(ssl) != 1) {
            print_error();
        } else {
            printf("=== Second TLS connection established.\n");

            // Shutdown SSL connection
            while (SSL_shutdown(ssl) != 1) {}
        }
    }

    // Clean up
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(sockfd);

    return 0;
}
