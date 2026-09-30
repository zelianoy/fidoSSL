#!/usr/bin/env bash

# This script downloads and builds the required libraries for the fidoSSL
# project. Since we compile the libraries from source, the installation
# should be compatible with any platform.

# Exit on error
set -e

# List of required commands
required_commands=("unzip" "curl" "cmake" "make" "tar" "pkg-config")

for cmd in "${required_commands[@]}"; do
    if ! command -v "$cmd" &> /dev/null; then
        echo "$cmd could not be found, please install $cmd and run this script again."
        exit 1
    fi
done

# Directory structure
PROJECT_ROOT="$(pwd)"
LIBS_DIR="${PROJECT_ROOT}/libs"
PKGCONFIG_DIR="${LIBS_DIR}/pkgconfig"
mkdir -p "${LIBS_DIR}"
mkdir -p "${PKGCONFIG_DIR}"

#################### SQLite ####################

build_sqlite() {
    SQLITE_VERSION="3.45.2"
    SQLITE_URL="https://github.com/sqlite/sqlite/archive/refs/tags/version-${SQLITE_VERSION}.zip"
    SQLITE_DIR="${LIBS_DIR}/sqlite-v${SQLITE_VERSION}"
    SQLITE_BUILD_DIR="${SQLITE_DIR}/build"

    if [ ! -d "${SQLITE_BUILD_DIR}" ]; then
        echo "Downloading SQLite ${SQLITE_VERSION}..."
        curl -L -o "${LIBS_DIR}/${SQLITE_VERSION}.zip" "${SQLITE_URL}"

        echo "Extracting SQLite..."
        unzip -q "${LIBS_DIR}/${SQLITE_VERSION}.zip" -d "${LIBS_DIR}"
        rm "${LIBS_DIR}/${SQLITE_VERSION}.zip"
        mv "${LIBS_DIR}/sqlite-version-${SQLITE_VERSION}" "${SQLITE_DIR}"

        echo "Building SQLite..."
        pushd "${SQLITE_DIR}" > /dev/null
        mkdir build
        pushd build > /dev/null
        ../configure
        make
        if [ "$(uname)" = "Darwin" ]; then
            install_name_tool -id "$(pwd)/.libs/libsqlite3.0.dylib" "$(pwd)/.libs/libsqlite3.0.dylib"
        fi
        popd > /dev/null
        popd > /dev/null

        # Generate the pkg-config file
        cat <<EOF > "${PKGCONFIG_DIR}/sqlite3.pc"
prefix=${PROJECT_ROOT}
exec_prefix=\${prefix}
libdir=\${exec_prefix}/libs/sqlite-v3.45.2/build/.libs
includedir=\${prefix}/libs/sqlite-v3.45.2/src

Name: sqlite3
Description: SQLite3 library
Version: 3.45.2
Libs: -L\${libdir} -lsqlite3
Cflags: -I\${includedir}
EOF
    fi
}

#################### tinycbor ####################

build_tinycbor() {
    TINYCBOR_VERSION="0.6.0"
    TINYCBOR_URL="https://github.com/intel/tinycbor/archive/refs/tags/v${TINYCBOR_VERSION}.zip"
    TINYCBOR_DIR="${LIBS_DIR}/tinycbor-v${TINYCBOR_VERSION}"

    if [ ! -d "${TINYCBOR_DIR}" ]; then
        echo "Downloading tinycbor ${TINYCBOR_VERSION}..."
        curl -L -o "${LIBS_DIR}/${TINYCBOR_VERSION}.zip" "${TINYCBOR_URL}"

        echo "Extracting tinycbor..."
        unzip -q "${LIBS_DIR}/${TINYCBOR_VERSION}.zip" -d "${LIBS_DIR}"
        rm "${LIBS_DIR}/${TINYCBOR_VERSION}.zip"
        mv "${LIBS_DIR}/tinycbor-${TINYCBOR_VERSION}" "${TINYCBOR_DIR}"

        echo "Building tinycbor..."
        pushd "${TINYCBOR_DIR}" > /dev/null
        make
        popd > /dev/null

    # Generate the pkg-config file
    cat <<EOF > "${PKGCONFIG_DIR}/tinycbor.pc"
prefix=${PROJECT_ROOT}
exec_prefix=\${prefix}
libdir=\${exec_prefix}/libs/tinycbor-v0.6.0/lib
includedir=\${prefix}/libs/tinycbor-v0.6.0/src

Name: TinyCBOR
Description: A tiny CBOR encoder and decoder library
Version: 0.6.0
Libs: -L\${libdir} -ltinycbor
Cflags: -I\${includedir}
EOF
    fi
}


#################### libfido2 ####################

build_libfido() {
    LIBFIDO2_VERSION="1.15.0"
    LIBFIDO2_URL="https://developers.yubico.com/libfido2/Releases/libfido2-${LIBFIDO2_VERSION}.tar.gz"
    LIBFIDO2_DIR="${LIBS_DIR}/libfido2-v${LIBFIDO2_VERSION}"
    LIBFIDO2_BUILD_DIR="${LIBFIDO2_DIR}/build"

    if [ ! -d "${LIBFIDO2_BUILD_DIR}" ]; then
        echo "Downloading libfido2 ${LIBFIDO2_VERSION}..."
        curl -L -o "${LIBS_DIR}/${LIBFIDO2_VERSION}.tar.gz" "${LIBFIDO2_URL}"

        echo "Extracting libfido2..."
        tar -xzf "${LIBS_DIR}/${LIBFIDO2_VERSION}.tar.gz" -C "${LIBS_DIR}"
        rm "${LIBS_DIR}/${LIBFIDO2_VERSION}.tar.gz"
        mv "${LIBS_DIR}/libfido2-${LIBFIDO2_VERSION}" "${LIBFIDO2_DIR}"

        echo "Building libfido2..."
        pushd "${LIBFIDO2_DIR}" > /dev/null
        mkdir build
        cmake -B build
        make -C build
        popd > /dev/null
    fi
    # Regenerate pkg-config even if libfido2 is already built.
    cat <<EOF > "${PKGCONFIG_DIR}/libfido2.pc"
prefix=${PROJECT_ROOT}
exec_prefix=\${prefix}
libdir=\${exec_prefix}/libs/libfido2-v${LIBFIDO2_VERSION}/build/src
includedir=\${prefix}/libs/libfido2-v${LIBFIDO2_VERSION}/src

Name: libfido2
Description: Library for FIDO U2F and FIDO 2.0
Version: ${LIBFIDO2_VERSION}
Requires: libcrypto
Libs: -L\${libdir} -lfido2
Cflags: -I\${includedir}
EOF
}

#################### jansson ####################

build_jansson() {
    JANSSON_VERSION="2.14"
    JANSSON_URL="https://github.com/akheron/jansson/releases/download/v${JANSSON_VERSION}/jansson-${JANSSON_VERSION}.tar.gz"
    JANSSON_DIR="${LIBS_DIR}/jansson-v${JANSSON_VERSION}"

    if [ ! -d "${JANSSON_DIR}" ]; then
        echo "Downloading jansson ${JANSSON_VERSION}..."
        curl -L -o "${LIBS_DIR}/${JANSSON_VERSION}.tar.gz" "${JANSSON_URL}"

        echo "Extracting jansson..."
        tar -xzf "${LIBS_DIR}/${JANSSON_VERSION}.tar.gz" -C "${LIBS_DIR}"
        rm "${LIBS_DIR}/${JANSSON_VERSION}.tar.gz"
        mv "${LIBS_DIR}/jansson-${JANSSON_VERSION}" "${JANSSON_DIR}"

        echo "Building jansson..."
        pushd "${JANSSON_DIR}" > /dev/null
        ./configure
        make

        # Fix the library path for macOS
        if [ "$(uname)" = "Darwin" ]; then
            install_name_tool -id "$(pwd)/src/.libs/libjansson.4.dylib" "$(pwd)/src/.libs/libjansson.4.dylib"
        fi

        popd > /dev/null

        # Generate the pkg-config file
        cat <<EOF > "${PKGCONFIG_DIR}/jansson.pc"
prefix=${PROJECT_ROOT}
exec_prefix=\${prefix}
libdir=\${exec_prefix}/libs/jansson-v2.14/src/.libs
includedir=\${prefix}/libs/jansson-v2.14/src

Name: jansson
Description: C library for encoding, decoding and manipulating JSON data
Version: 2.14
Libs: -L\${libdir} -ljansson
Cflags: -I\${includedir}
EOF
    fi
}

#################### OpenSSL ####################

build_openssl() {
    OPENSSL_VERSION="3.2.1"
    OPENSSL_URL="https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz"
    OPENSSL_DIR="${LIBS_DIR}/openssl-v${OPENSSL_VERSION}"

    if [ ! -d "${OPENSSL_DIR}" ]; then
        echo "Downloading OpenSSL ${OPENSSL_VERSION}..."
        curl -L -o "${LIBS_DIR}/${OPENSSL_VERSION}.tar.gz" "${OPENSSL_URL}"

        echo "Extracting OpenSSL..."
        tar -xzf "${LIBS_DIR}/${OPENSSL_VERSION}.tar.gz" -C "${LIBS_DIR}"
        rm "${LIBS_DIR}/${OPENSSL_VERSION}.tar.gz"
        mv "${LIBS_DIR}/openssl-${OPENSSL_VERSION}" "${OPENSSL_DIR}"

        echo "Building OpenSSL..."
        pushd "${OPENSSL_DIR}" > /dev/null
        ./Configure
        make

        # Fix the library path for macOS
        if [ "$(uname)" = "Darwin" ]; then
            install_name_tool -id "$(pwd)/libssl.3.dylib" "$(pwd)/libssl.3.dylib"
            install_name_tool -id "$(pwd)/libcrypto.3.dylib" "$(pwd)/libcrypto.3.dylib"
            install_name_tool -change "/usr/local/lib/libcrypto.3.dylib" \
                "$(pwd)/libcrypto.3.dylib" "$(pwd)/libssl.3.dylib"
        fi
        popd > /dev/null

        # Generate the pkg-config files
    cat <<EOF > "${PKGCONFIG_DIR}/libssl.pc"
prefix=${PROJECT_ROOT}
exec_prefix=\${prefix}
libdir=\${exec_prefix}/libs/openssl-v3.2.1
includedir=\${prefix}/libs/openssl-v3.2.1/include

Name: OpenSSL-libssl
Description: Secure Sockets Layer library
Version: 3.2.1
Requires.private: libcrypto
Libs: -L\${libdir} -lssl
Cflags: -I\${includedir}
EOF

    cat <<EOF > "${PKGCONFIG_DIR}/libcrypto.pc"
prefix=${PROJECT_ROOT}
exec_prefix=\${prefix}
libdir=\${exec_prefix}/libs/openssl-v3.2.1
includedir=\${prefix}/libs/openssl-v3.2.1/include

Name: OpenSSL-libcrypto
Description: OpenSSL cryptography library
Version: 3.2.1
Libs: -L\${libdir} -lcrypto
Cflags: -I\${includedir}
EOF
    fi
}

build_all() {
    build_sqlite
    build_tinycbor
    build_libfido
    build_jansson
    build_openssl
}

if [[ $# -eq 0 ]]; then
    echo "No arguments provided. Please specify the libraries to install or 'all' for all libraries."
    exit 1
fi

# Check if 'all' is one of the arguments
for arg in "$@"; do
    if [[ $arg == "all" ]]; then
        build_all
        exit 0
    fi
done

# If 'all' was not found, proceed with individual installation
for arg in "$@"; do
    case $arg in
        openssl)
            build_openssl
            ;;
        libfido2)
            build_libfido
            ;;
        tinycbor)
            build_tinycbor
            ;;
        jansson)
            build_jansson
            ;;
        sqlite3)
            build_sqlite
            ;;
        *)
            echo "Invalid argument: $arg. Accepted values: openssl, libfido2, tinycbor, jansson, sqlite3, all."
            ;;
    esac
done
