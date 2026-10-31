# FIDO2 TLS1.3 Extension



**fidoSSL** is a proof of concept implementation of a TLS1.3 extension that integrates [FIDO](https://fidoalliance.org/what-is-fido/) authentication with [openSSL](https://www.openssl.org/). This extension leverages the secure, hardware-based storage of cryptographic keys through FIDO, offering a robust alternative to traditional client certificates. Beyond its security advantages, FIDO authentication stands out for its user-friendly and easier-to-manage nature, significantly improving the user experience. Additionally, its phishing-resistant features make it a safer choice, reducing the risk of security breaches.

This project serves as a foundational draft for further studies and development in the realm of secure communications. It was presented as a master’s thesis at Humboldt University of Berlin. The full thesis can be accessed [here](https://sar.informatik.hu-berlin.de/research/publications/index.htm#SAR-PR-2024-02).

The implementation in this repository was further developed as
part of a bachelor's thesis, based on David
Wedekind's Internet-Draft for the FIDO2 TLS 1.3 Extension.

The changes include revised CBOR message formats, adapted
handshake processing, and support for authentication using
server-side credential selection. The implementation supports
registration of both discoverable and non-discoverable
credentials, as well as authentication with discoverable credentials or server-side credentials.

### Features

- Implements FIDO2 authentication within the TLS protocol
- Uses the TLS1.3 extension mechanism ([RFC 8446](https://datatracker.ietf.org/doc/html/rfc8446#section-4.2))
- fidoSSL is compiled as C-library, facilitating its addition to projects as OpenSSL callbacks. This design allows the use of a custom extension without the need for modifying or patching the OpenSSL source code. However, it necessitates adaptations within the application's source code to integrate the FIDO-based authentication capabilities effectively.

### Prerequisites

- C programming environment (GCC, Clang, etc.)
- Dependencies: 
  - **libssl**, **libcrypto** (openSSL)
  - **libfido2** (high level API for WebAuthn & CTAP)
  - **tinycbor** (CBOR encoder & parser)
  - **sqlite3** (SQLite database)
  - **libjansson** (JSON encoder & parser)
  - **libpsl** (Public Suffix List validation for RP IDs)
- Basic TLS concepts and how it is used in openSSL [[link1](https://www.openssl.org/docs/man3.2/man7/ossl-guide-introduction.html), [link2](https://www.openssl.org/docs/man3.2/man7/ossl-guide-tls-introduction.html), [link3](https://www.openssl.org/docs/man3.2/man7/ossl-guide-tls-client-non-block.html), [link4](https://www.openssl.org/docs/man3.2/man7/ossl-guide-tls-client-block.html)]

### Installation

This section provides a step-by-step guide to downloading and setting up `fidoSSL` on your system.

#### Dependencies

While Docker and containerization offer numerous benefits for application deployment, including isolation and reproducibility, this project has opted **not to use Docker** for the following reason:

Application build ontop of TLS often dependent on the ability to interact closely with network adapters and hardware. Docker's network abstraction, designed to isolate and secure container environments, can limit direct access to the network hardware. Such limitations can be restrictive for applications that need to manage or modify network traffic or require detailed information about the network's physical layer for optimal operation.

To fulfill the project's requirements for isolation and reproducibility without relying on Docker, a `install-dependencies.sh` script is employed. This script downloads and builds selected dependencies from source.
The additional dependency libpsl must be installed separately
using the system's package manager. Dependencies are **installed locally** within the project's directory, maintaining isolation by avoiding conflicts with system-wide libraries. The make system, with the help of `pkg-config`, link against libraries either installed system-wide or locally within the project directory. This means if you already have certain dependencies installed globally, there is no need to install them again locally.

##### Option 1: Local installation with script:

```sh
# Install all dependencies
./install-dependencies.sh all

# Install a subset of dependencies 
./install-dependencies.sh openssl libfido2 tinycbor sqlite3 jansson
```

##### Option 2: System wide installation with packet manager:

###### macOS

On macOS, the dependencies can be installed with [homebrew](https://brew.sh/)

```bash
# Update homebrew in order to get the newest formulas
brew update

# Install dependencies
brew install openssl libfido2 sqlite jansson libpsl pkg-config cmake 
```

###### ubuntu

On Ubuntu, dependencies can be installed with [aptitude](https://wiki.ubuntuusers.de/aptitude/)

```sh
# Update apt in order to get the newest packages sources
sudo apt update

# Install dependencies
sudo apt install build-essential libssl-dev libfido2-dev libsqlite3-dev libjansson-dev libpsl-dev cmake pkg-config curl unzip
```

For either package-manager installation above, TinyCBOR can
additionally be built locally using the provided script.
Run this command from the repository root:

```sh
bash ./install-dependencies.sh tinycbor
```

#### Building the Static Library

1. **Build the Library**: Navigate into the cloned repository directory and build the `libfidossl.a` static library

   ```bash
   make
   ```

2. **Installation (Optional)**: After building, you have the option to install the library and header files to standard system locations, simplifying the process of linking against `fidoSSL` for future projects. This step is not mandatory; you can also choose to link against the library manually by specifying its path.
   To install `fidoSSL` to the default locations (`/usr/local/lib` for libraries and `/usr/local/include` for headers)

   ```bash
   sudo make install
   ```



**Note on Manual Linking**: If you prefer not to install `fidoSSL` globally or need to use it in a specific project without affecting the system-wide configuration, you can directly reference the library and header files in your compilation command. The compiled library can be found under `fidoSSL/build/libfidossl.a` and the pkg-config file can be found under `fidoSSL/build/fidossl.pc`.

#### Compiling Your Application with fidoSSL

If `fidoSSL` was installed with `sudo make install` and **all dependencies are installed system wide in standart locations**, adjust the makefile of your application as following:

```bash
# Using pkg-config
CFLAGS += $(shell pkg-config --cflags fidossl)
LIBS += $(shell pkg-config --libs fidossl)

# Without pkg-config
CFLAGS+= -I/path/to/fidossl/headers 
LIBS += -L/path/to/fidossl/library -lfidossl -lssl -lcrypto -lfido2 -ltinycbor -ljansson -lsqlite3 -lpsl
```

If the **dependencies are in non-standard locations**, you can use the `PKG_CONFIG_PATH` environment variable to point to the location of the `.pc` file.

```bash
CFLAGS += $(shell PKG_CONFIG_PATH=~/path/to/pkgconfig/dir pkg-config --cflags fidossl)
LIBS += $(shell PKG_CONFIG_PATH=~/path/to/pkgconfig/dir pkg-config --libs fidossl)
```

### Usage

This section outlines the steps required to seamlessly incorporate `fidoSSL` into your project. Ensure you've met all [Prerequisites](#Prerequisites), including a basic understanding of OpenSSL in C, before proceeding.

The following comprehensive example demonstrates how to integrate the FIDO authentication extension within a client and server application, utilizing OpenSSL for the setup. 

**Please note**: This example specifically focuses on illustrating how to add `fidoSSL` to your application. It intentionally skips intermediate steps related to general OpenSSL setup and usage, which should be implemented as per OpenSSL's documentation and best practices.

#### Client

```c
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <fidossl/fidossl.h>

// Initialize your SSL context (ctx) as per your application's requirements
SSL_CTX *ctx;

// The init function enforces TLS 1.3 and loads a dummy certificate + key
// for the client, which is not verified
fidossl_init_client_ctx(ctx);

// Prepare FIDOSSL client options
FIDOSSL_CLIENT_OPTS *opts = malloc(sizeof(FIDOSSL_CLIENT_OPTS));
if (opts == NULL) {
    // Handle malloc error
}

// Modes are: FIDOSSL_REGISTER, FIDOSSL_AUTHENTICATE_DISCOVERABLE OR FIDOSSL_AUTHENTICATE_SERVER_SIDE
opts->mode = FIDOSSL_REGISTER;

// FIDOSSL_REGISTER uses user_display_name; the server also uses it as user_name.
// When in FIDOSSL_AUTHENTICATE_SERVER_SIDE a registered user_name is required. When in FIDOSSL_AUTHENTICATE_DISCOVERABLE this setting is ignored
// Discoverable authentication does not require a user_name.
opts->user_name = "Alice";
opts->user_display_name = "Alice";

// In FIDOSSL_REGISTER mode, new fido keys are only enrolled if the client provides a valid ticket.
// Client and Server must be configured with the same ticket. The ticket is base64 encoded.
opts->ticket_b64 = "XSQrGrqft2dkPdWBKqkAT86wmQCGE2xZh8ODh7FTADxv17q7a9sWdCSsWysPTElhSGvtZEc6Ejp257ju6fcCT4aoSXSlgIlqRNId0htgesEHmCKMRwoytZugYjr2gbCDErHsCHVhZAaFfHb6SueZ+tGINFrGMyGk2HYnM8Jvnofp0AJYkBu9t76h4cMfMKBZdtAvIOlvoo4i9UaZOVyjff2jSd/sTILAHzUqtj85Ipp8yecanqUPVkwBAXGlvjBYmnPvnOKcxGLXmetOkOYG8Q6s4e8LeHdGsF8sFypv+lL2g+L+/YBLaKlsys2aABbaXP6evVp3/7ACEkdTHpreuA==";


// The PIN of the FIDO token.
opts->pin = "1234";

// Optional: Debug levels are: DEBUG_LEVEL_ERROR, DEBUG_LEVEL_VERBOSE, DEBUG_LEVEL_MORE_VERBOSE.
opts->debug_level = DEBUG_LEVEL_MORE_VERBOSE;

// Register the FIDOSSL extension with the SSL context
SSL_CTX_add_custom_ext(
    ctx,
    FIDOSSL_EXT_TYPE,
    FIDOSSL_CONTEXT,
    fidossl_client_add_cb,
    NULL,
    opts,
    fidossl_client_parse_cb,
    NULL
);

// Create an SSL object and proceed with the connection and TLS handshake as usual
// Remember to configure SNI and handle the connection appropriately

// If we want to register new fido keys or authenticate with server-side credentials, a second handshake is necessary.
if (opts->mode == FIDOSSL_REGISTER ||
    opts->mode == FIDOSSL_AUTHENTICATE_SERVER_SIDE) {
  
    // Shutdown the first connection
    while (SSL_shutdown(ssl) != 1) {}
  
    // Create new SSL object out of the context object
    SSL_free(ssl);
    ssl = SSL_new(ctx);
  
  	// Connect the SSL object to the socket as usual. The socket should be kept open,
  	// so the new TLS handshake reuses the TCP connection. Don't forget to set the SNI.

    // Connect to server again
    if (SSL_connect(ssl) != 1) {
        // Handle error
    }

    // Shutdown SSL connection. It is not allowed to send data after a key enrollment
    while (SSL_shutdown(ssl) != 1) {}
}

// Keep the options valid until all handshakes using this SSL_CTX have completed.
free(opts);

// Remember to also free SSL and SSL_CTX objects, and close the network socket as usual
```

#### Server

```c
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <fidossl/fidossl.h>

// Initialize your SSL context (ctx) as per your application's requirements
SSL_CTX *ctx;

// Initialize the FIDOSSL server options structure. This structure configures the FIDO authentication
// parameters, including the relying party identifier, user verification requirements, and debug level.
FIDOSSL_SERVER_OPTS *opts = malloc(sizeof(FIDOSSL_SERVER_OPTS));

// Set the relying party identifier to the servers domain. This is a unique identifier for the FIDO 
// relying party.
opts->rp_id = "mydomain.com";

// Configure the relying party name to a more descriptive human-readable name, for example, 
// "My Domain Example".
opts->rp_name = "My Domain Example";

// Specify the base64 encoded ticket for the FIDO operation. This ticket is crucial for the 
// FIDO key registration process, acting as a shared secret between the client and server.
opts->ticket_b64 = "XSQrGrqft2dkPdWBKqkAT86wmQCGE2xZh8ODh7FTADxv17q7a9sWdCSsWysPTElhSGvtZEc6Ejp257ju6fcCT4aoSXSlgIlqRNId0htgesEHmCKMRwoytZugYjr2gbCDErHsCHVhZAaFfHb6SueZ+tGINFrGMyGk2HYnM8Jvnofp0AJYkBu9t76h4cMfMKBZdtAvIOlvoo4i9UaZOVyjff2jSd/sTILAHzUqtj85Ipp8yecanqUPVkwBAXGlvjBYmnPvnOKcxGLXmetOkOYG8Q6s4e8LeHdGsF8sFypv+lL2g+L+/YBLaKlsys2aABbaXP6evVp3/7ACEkdTHpreuA==";

// Values for user verification are: UV_REQUIRED, UV_PREFERRED, UV_DISCOURAGED
opts->user_verification = UV_PREFERRED;

// Resident keys can be: RK_REQUIRED, RK_PREFERRED, RK_DISCOURAGED
opts->resident_key = RK_REQUIRED;

// Authenticator modes: CROSS_PLATFORM, PLATFORM
opts->auth_attach = CROSS_PLATFORM;

// How the authenticator is connected to the client: USB, NFC, BLE, INTERNAL
opts->transport = USB;

// Timeout for CTAP in [ms]
opts->timeout = 60000; // 1 Minute

// Optional: Debug levels are: DEBUG_LEVEL_ERROR, DEBUG_LEVEL_VERBOSE, DEBUG_LEVEL_MORE_VERBOSE.
opts->debug_level = DEBUG_LEVEL_MORE_VERBOSE;

//Only direct attestation is supported
opts->attestation = DIRECT;

// Register the `libfidossl` extension with the SSL context. This step is critical as it
// integrates FIDO authentication into the TLS handshake process.
SSL_CTX_add_custom_ext(
    ctx,
    FIDOSSL_EXT_TYPE,
    FIDOSSL_CONTEXT,
    fidossl_server_add_cb,
    NULL,
    NULL,
    fidossl_server_parse_cb,
    opts
);

// Configure the SSL context to request a client certificate. This configuration is essential for triggering
// the SSL_EXT_TLS1_3_CERTIFICATE event, which is necessary for the FIDO extension to operate correctly.
SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, no_verify_cb);

// Create and bind a listening socket to an IP and port. Listen for incoming connections on the socket.
// Accept a connection from a client, creating a new socket for this client.
// Associate the client socket with an SSL object and perform the TLS handshake.

// Shut down the SSL connection properly

// Keep the options valid until all handshakes using this SSL_CTX have completed.
free(opts);
```

### Testing `fidossl`

Run both programs from the repository root, in separate terminals:

1. Start the server with `./build/server`.
2. Start the client with `./build/client`.

This initiates a TLS handshake with the test server using the fidossl extension, both running on localhost.

Before authenticating, register a credential by selecting
FIDOSSL_REGISTER in test/client.c. The resident_key setting
in test/server.c controls the requested credential storage:
RK_REQUIRED requests a discoverable credential, while
RK_DISCOURAGED requests a non-discoverable credential.

Rebuild with make after changing the configuration.
For subsequent authentication, select
FIDOSSL_AUTHENTICATE_DISCOVERABLE or
FIDOSSL_AUTHENTICATE_SERVER_SIDE.
Restart the demonstration server for each new run.
### Disclaimer

This codebase, including the `fidoSSL` library and its accompanying utilities, is a **proof of concept** and is primarily intended for **research and development purposes**. It has been made available to the public to foster understanding, experimentation, and further study into integrating FIDO authentication within the TLS 1.3 protocol using OpenSSL.

**It is strongly advised against using this codebase in production environments or in any application where security, stability, and reliability are critical.** While every effort has been made to adhere to best practices and standards, this project has not undergone the rigorous testing and security auditing that production-ready software demands. As such, it may contain vulnerabilities, bugs, or other issues that could potentially compromise security.

Users are encouraged to explore and experiment with the codebase in controlled, secure environments. Contributions, feedback, and discussions around improvements, security enhancements, and potential use cases are welcome, as they contribute to the ongoing development and understanding of secure authentication practices within the TLS ecosystem.

By using or referencing this codebase, you acknowledge and accept that you do so at your own risk, and you bear full responsibility for any consequences arising from its use.

### License

This project is licensed under the [BSD 2-Clause License](https://opensource.org/license/bsd-2-clause).

The BSD 2-Clause License is one of the simplest and most permissive free software licenses available. This license allows for nearly unrestricted freedom with the software, provided that two key conditions are met:

1. **Redistributions of source code must retain the above copyright notice, this list of conditions, and the following disclaimer.**
2. **Redistributions in binary form must reproduce the above copyright notice, this list of conditions, and the following disclaimer in the documentation and/or other materials provided with the distribution.**

This approach encourages wide adoption and utilization of the software while ensuring that credit is maintained with the original authors. It supports both private and commercial use, making the `fidoSSL` project suitable for a broad array of projects, from academic research to industry applications.

By adopting the BSD 2-Clause License, `fidoSSL` aims to foster an environment of collaboration and open innovation, allowing for enhancements, modifications, and integrations in a way that respects the creators' contributions while offering the community significant freedom to leverage and build upon the project.

For further details about the BSD 2-Clause License, you can refer to the official BSD License page.
