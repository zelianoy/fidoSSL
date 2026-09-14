#include "types.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <fidossl.h>

// #include <arpa/inet.h>
// #include <openssl/err.h>
// #include <openssl/ssl.h>
// #include <signal.h>
// #include <stdio.h>
// #include <string.h>
// #include <sys/socket.h>
// #include <unistd.h>

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
    int sockfd, clientfd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len;
    fido_init(0);

    // Initialize OpenSSL
    SSL_library_init();
    ctx = SSL_CTX_new(TLS_server_method());

    // Load certificate and private key
    SSL_CTX_use_certificate_file(ctx, "./test/certs/demo.fido2.tls.edu.crt", SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, "./test/certs/demo.fido2.tls.edu.key", SSL_FILETYPE_PEM);
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the certificate.\n");
        exit(EXIT_FAILURE);
    }

    //-------------------------------------------------------------------------
    // FIDOSSL START

    FIDOSSL_SERVER_OPTS *opts = malloc(sizeof(FIDOSSL_SERVER_OPTS));
    opts->rp_id = "demo.fido2.tls.edu";
    opts->rp_name = "Demo Fido2 TLS";
    opts->ticket_b64 = "XSQrGrqft2dkPdWBKqkAT86wmQCGE2xZh8ODh7FTADxv17q7a9sWdCSsWysPTElhSGvtZEc6Ejp257ju6fcCT4aoSXSlgIlqRNId0htgesEHmCKMRwoytZugYjr2gbCDErHsCHVhZAaFfHb6SueZ+tGINFrGMyGk2HYnM8Jvnofp0AJYkBu9t76h4cMfMKBZdtAvIOlvoo4i9UaZOVyjff2jSd/sTILAHzUqtj85Ipp8yecanqUPVkwBAXGlvjBYmnPvnOKcxGLXmetOkOYG8Q6s4e8LeHdGsF8sFypv+lL2g+L+/YBLaKlsys2aABbaXP6evVp3/7ACEkdTHpreuA==";
    opts->user_verification = UV_PREFERRED;
    opts->resident_key = RK_REQUIRED;
    opts->auth_attach = CROSS_PLATFORM;
    opts->transport = USB;
    opts->timeout = 60000; // 1 Minute
    opts->debug_level = DEBUG_LEVEL_MORE_VERBOSE;
    opts->attestation = DIRECT;
    SSL_CTX_add_custom_ext(
        ctx,
        FIDOSSL_EXT_TYPE,
        FIDOSSL_CONTEXT,
        fidossl_server_add_cb,
        NULL,
        NULL, // No add_args on the server side
        fidossl_server_parse_cb,
        opts // Server options are passed as the parse_arg
    );
    // Ask for a client certificate in order to trigger the SSL_EXT_TLS1_3_CERTIFICATE event
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, no_verify_cb);

    //-------------------------------------------------------------------------
    // FIDOSSL END

    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // The program remains in a TIME_WAIT state for a period after the
    // application has been closed. This is a normal part of the TCP protocol,
    // designed to ensure that all packets have been received and to handle
    // delayed packets in the network that may still be routed to your socket.
    // To allow this program to immediately reuse the port, we set the
    // SO_REUSEADDR socket option
    int optval = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) == -1) {
        perror("setsockopt SO_REUSEADDR failed");
        exit(EXIT_FAILURE);
    }

    // Initialize server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(SERVER_PORT);

    // Bind socket
    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("Binding failed");
        exit(EXIT_FAILURE);
    }

    // Listen for connections
    if (listen(sockfd, 5) == -1) {
        perror("Listening failed");
        exit(EXIT_FAILURE);
    }

    // Accept incoming connections
    addr_len = sizeof(client_addr);
    clientfd = accept(sockfd, (struct sockaddr *)&client_addr, &addr_len);
    if (clientfd == -1) {
        perror("Accepting connection failed");
        exit(EXIT_FAILURE);
    }

    // Create SSL connection
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, clientfd);
    if (SSL_accept(ssl) != 1) {
        print_error();
        close(clientfd);
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("=== TLS connection established.\n");

    // Shutdown SSL connection
    while (SSL_shutdown(ssl) != 1) {}

    // Create new SSL connection. Unfortunately, we cant reuse the SSL object.
    SSL_free(ssl);
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, clientfd);

    if (SSL_accept(ssl) != 1) {
        print_error();
    } else {
        printf("=== Second TLS connection established.\n");

        // Shutdown SSL connection
        while (SSL_shutdown(ssl) != 1) {}
    }

    SSL_free(ssl);
    SSL_CTX_free(ctx);

    // Close sockets
    close(clientfd);
    close(sockfd);

    return 0;
}
