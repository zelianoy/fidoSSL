#include "rp.h"
#include "common.h"
#include "debug.h"
#include "encoding.h"
#include "fido.h"
#include "fidossl.h"
#include "persistence.h"
#include "serialize.h"
#include "types.h"
#include <assert.h>
#include <cbor.h>
#include <fido/es256.h>
#include <jansson.h>
#include <openssl/decoder.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <sys/stat.h>

// SSL_CTX objects can hold arbitray external data. This index points to the
// struct which holds the relying party data.
static int ctx_data_index = -1;

void rp_free(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp) {
    struct rp_data *data = (struct rp_data *)ptr;
    if (data == NULL) {
        return;
    }
    debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "Freeing all data allocated by FIDOSSL");
    free_rp_data(data);
    debug_cleanup();
}

struct rp_data *init_rp(SSL *ssl, void *server_opts) {
    // Get the server options
    if (server_opts == NULL) {
        return NULL;
    }
    // Validate server options
    FIDOSSL_SERVER_OPTS *opts = (FIDOSSL_SERVER_OPTS *)server_opts;
    if (opts->rp_id == NULL) {
        return NULL;
    }
    // Initialize the debug system.
    debug_initialize();
    set_debug_level(opts->debug_level);

    if (!opts->rp_id || !opts->rp_name) {
        debug_printf(DEBUG_LEVEL_ERROR, "FIDOSSL: A rp id, rp name must be set");
        return NULL;
    }
    // Create the relying party data.
    struct rp_data *data = OPENSSL_malloc(sizeof(struct rp_data));
    if (data == NULL) {
        debug_printf(DEBUG_LEVEL_ERROR, "Memory allocation failed");
        return NULL;
    }
    memset(data, 0, sizeof(struct rp_data));

    debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "Configuring Relying Party:");
    // Generate an episode key
    data->k_ep_len = 32;
    data->k_ep = OPENSSL_zalloc(data->k_ep_len);
    RAND_priv_bytes(data->k_ep, data->k_ep_len);
    //For debug purposes we can display the episode key
    debug_print_hex(DEBUG_LEVEL_MORE_VERBOSE, "    Episode key: ", data->k_ep, data->k_ep_len);

    // Copy required data from the server options
    data->rp_id = OPENSSL_zalloc(strlen(opts->rp_id) + 1);
    memcpy(data->rp_id, opts->rp_id, strlen(opts->rp_id));
    debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    RP ID: %s", data->rp_id);
    data->rp_name = OPENSSL_zalloc(strlen(opts->rp_name) + 1);
    memcpy(data->rp_name, opts->rp_name, strlen(opts->rp_name));
    debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    RP Name: %s", data->rp_name);

    // The ticket is base64 encoded, so we decode it
    if (opts->ticket_b64 != NULL) {
        if (decode_base64(opts->ticket_b64, &data->ticket, &data->ticket_len) !=
            0) {
            debug_printf(
                DEBUG_LEVEL_ERROR,
                "Failed to base64 decode user id from the FIDOSSL_SERVER_OPTS");
            OPENSSL_free(data);
            return NULL;
        }
    }

    // Optional data has a default value if not set in the server options
    if (opts->user_verification != 0) {
        data->user_verification = opts->user_verification;
        debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    User verification: %s",
                     get_user_verification_requirements_name(opts->user_verification));
    }
    if (opts->resident_key != 0) {
        data->resident_key = opts->resident_key;
        debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    Resident key: %s",
                     get_resident_key_requirements_name(opts->resident_key));
    }
    if (opts->auth_attach != 0) {
        data->auth_attach = opts->auth_attach;
        debug_printf(DEBUG_LEVEL_MORE_VERBOSE,
                     "    Authenticator attachment: %s",
                     0 ? "PLATFORM" : "CROSS_PLATFORM");
    }
    if (opts->transport != 0 && opts->transport != USB) {
        debug_printf(DEBUG_LEVEL_ERROR, "Only USB transport is supported");
    }
    data->transport = USB;
    debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    Transport: USB");
    if (opts->timeout != 0) {
        data->timeout = opts->timeout;
        debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    Timeout: %d ms",
                     data->timeout);
    }
    if(opts->attestation != 0){
        data->attestation = opts->attestation;
    }
    // Init the state
    data->state = STATE_INITIAL;

    // Open the database
    data->db = init_db("fido2.db");

    // Save the relying party data to the SSL_CTX object
    SSL_CTX *ctx = SSL_get_SSL_CTX(ssl);
    ctx_data_index = CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_SSL_CTX, 0, NULL, NULL, NULL, rp_free);
    if (ctx_data_index == -1) {
        debug_printf(DEBUG_LEVEL_ERROR, "Failed to get ex new index");
        return NULL;
    }
    if (!SSL_CTX_set_ex_data(ctx, ctx_data_index, data)) {
        debug_printf(DEBUG_LEVEL_ERROR, "Failed to set ex data");
        free_rp_data(data);
        return NULL;
    }

    return data;
}

struct rp_data *get_rp_data(SSL *ssl, void *server_opts) {
    if (ctx_data_index == -1) {
        // Relying party is not initialized
        return init_rp(ssl, server_opts);
    }
    SSL_CTX *ctx = SSL_get_SSL_CTX(ssl);
    return SSL_CTX_get_ex_data(ctx, ctx_data_index);
}

// Extract authData from a CBOR-encoded attestation object
// Returns 0 on success, -1 on failure, 1 when
int extract_authdata_from_attobj(const uint8_t *attObjBuf, const size_t attObjLen,
                                 uint8_t **authDataPtr, size_t *authDataLen) {
    CborParser parser;
    CborValue mapIt;
    CborValue it;

    if (!attObjBuf || !authDataPtr || !authDataLen)
        return -1;

    CborError err = cbor_parser_init(attObjBuf, attObjLen, 0, &parser, &it);
    if (err != CborNoError || !cbor_value_is_map(&it)) {
        fprintf(stderr, "CBOR parse error or not a map\n");
        return -1;
    }

    err = cbor_value_enter_container(&it, &mapIt);
    if (err != CborNoError) {
        fprintf(stderr, "Failed to enter map: %d\n", err);
        return -1;
    }

    // Walk through the map to find "authData"
    while (!cbor_value_at_end(&mapIt)) {
        char key[32] = {0};
        size_t keyLen = sizeof(key) - 1;

        if (!cbor_value_is_text_string(&mapIt)) {
            fprintf(stderr, "CBOR map key is missing");
            return -1;
        }

        err = cbor_value_copy_text_string(&mapIt, key, &keyLen, &mapIt);
        if (err != CborNoError) {
            fprintf(stderr, "Could not copy CBOR map key");
            return -1;
        }

        // Check key
        if (strcmp(key, "authData") == 0) {
            if (!cbor_value_is_byte_string(&mapIt)) {
                fprintf(stderr, "authData corrupt");
                return -1;
            }
            err = cbor_value_calculate_string_length(&mapIt, authDataLen);
            if (err != CborNoError) {
                fprintf(stderr, "cbor_value_calculate_string_length()");
                return -1;
            }
            *authDataPtr = OPENSSL_malloc(*authDataLen);
            err = cbor_value_copy_byte_string(&mapIt, *authDataPtr, authDataLen, NULL);
            if (err != CborNoError) {
                fprintf(stderr, "cbor_value_copy_byte_string()");
                return -1;
            }
            return 0;
        } else {
            // Skip the value if it's not "authData"
            err = cbor_value_advance(&mapIt);
            if (err != CborNoError) {
                fprintf(stderr, "Failed to advance map");
                return -1;
            }
        }
    }

    return -1;  // authData not found
}

struct authdata *parse_authdata(const u8 *authDataBytes, size_t authDataBytesLen) {
    // Authdata has a fixed structure, so we can parse it without a CBOR
    // library. See: https://www.w3.org/TR/webauthn-2/#authenticator-data
    if (authDataBytes == NULL || authDataBytesLen == 0) {
        return NULL;
    }

    struct authdata *ad = OPENSSL_malloc(sizeof(struct authdata));
    if (ad == NULL) {
        debug_printf(DEBUG_LEVEL_ERROR, "Memory allocation failed");
        return NULL;
    }
    memset(ad, 0, sizeof(struct authdata));
    size_t offset = 0;
    // RP ID hash
    ad->rp_id_hash = OPENSSL_malloc(32);
    if (ad->rp_id_hash == NULL) {
        debug_printf(DEBUG_LEVEL_ERROR, "Memory allocation failed");
        free_authdata(ad);
        return NULL;
    }
    memcpy(ad->rp_id_hash, authDataBytes + offset, 32);
    offset += 32;
    // Flags
    ad->flags = authDataBytes[offset];
    offset += 1;
    // If ED bit is set, authdata contains an extension. For now, we don't
    // support extensions.
    if (ad->flags & (1 << 7)) {
        debug_printf(DEBUG_LEVEL_ERROR, "Extensions are not supported");
    }
    // Signature counter
    ad->sign_count = (authDataBytes[offset] << 24) | (authDataBytes[offset + 1] << 16) |
                     (authDataBytes[offset + 2] << 8) | authDataBytes[offset + 3];
    offset += 4;
    // If the AT bit is set, parse the attestation credential data. The bit is
    // expected to be set for registration, but not for authentication.
    if (ad->flags & (1 << 6)) {
        // AAGUID
        ad->aaguid_len = 16;
        ad->aaguid = OPENSSL_malloc(16);
        if (ad->aaguid == NULL) {
            debug_printf(DEBUG_LEVEL_ERROR, "Memory allocation failed");
            free_authdata(ad);
            return NULL;
        }
        memcpy(ad->aaguid, authDataBytes + offset, 16);
        offset += 16;
        // 2 bytes for the length of the credential id
        ad->cred_id_len = (authDataBytes[offset] << 8) | authDataBytes[offset + 1];
        offset += 2;
        // Credential ID
        ad->cred_id = OPENSSL_malloc(ad->cred_id_len);
        if (ad->cred_id == NULL) {
            debug_printf(DEBUG_LEVEL_ERROR, "Memory allocation failed");
            free_authdata(ad);
            return NULL;
        }
        memcpy(ad->cred_id, authDataBytes + offset, ad->cred_id_len);
        offset += ad->cred_id_len;
        // Now at the start of the COSE-encoded public key. We must use a CBOR
        // library to parse the public key. For now we just store it in binary
        // format.
        ad->pubkey_len = authDataBytesLen - offset;
        ad->pubkey = OPENSSL_malloc(ad->pubkey_len);
        if (ad->pubkey == NULL) {
            debug_printf(DEBUG_LEVEL_ERROR, "Memory allocation failed");
            free_authdata(ad);
            return NULL;
        }
        memcpy(ad->pubkey, authDataBytes + offset, ad->pubkey_len);
        offset += ad->pubkey_len;
    }
    // Since we allow no extensions, we assume that the offset is equal to the
    // length of the authdata.
    if (offset != authDataBytesLen) {
        debug_printf(DEBUG_LEVEL_ERROR, "Invalid authdata length");
        free_authdata(ad);
        return NULL;
    }
    return ad;
}

PublicKey *parse_cose_key(const u8 *in, size_t in_len) {
    if (in == NULL || in_len == 0) {
        return NULL;
    }
    CborParser parser;
    CborValue root, map;
    CborError err;
    int key;
    PublicKey *pk = OPENSSL_malloc(sizeof(PublicKey));
    size_t len;
    // The uncompressed format of a EC public key starts with the byte 0x04,
    // followed by the x and y coordinates of the point. 512 bytes is a large
    // enough buffer for the x and y coordinates + the 0x04 byte.
    u8 point[512];
    point[0] = 0x04;

    err = cbor_parser_init(in, in_len, 0, &parser, &root);
    if (err != CborNoError) {
        debug_printf(DEBUG_LEVEL_ERROR, "Error initializing CBOR parser");
        return NULL;
    }
    if (!cbor_value_is_map(&root)) {
        debug_printf(DEBUG_LEVEL_ERROR, "Root container is not a map");
        return NULL;
    }
    cbor_value_enter_container(&root, &map);

    while (!cbor_value_at_end(&map)) {
        // Get map key
        if (!cbor_value_is_integer(&map)) {
            debug_printf(DEBUG_LEVEL_ERROR, "Map key is not an integer");
            return NULL;
        }
        cbor_value_get_int(&map, &key);
        err = cbor_value_advance(&map);
        if (err != CborNoError) {
            debug_printf(DEBUG_LEVEL_ERROR, "Error advancing map");
            return NULL;
        }
        switch (key) {
        case 1: // kty
            if (!cbor_value_is_integer(&map)) {
                debug_printf(DEBUG_LEVEL_ERROR, "kty is not an integer");
                return NULL;
            }
            int kty;
            cbor_value_get_int(&map, &kty);
            if (kty != 2) {
                debug_printf(DEBUG_LEVEL_ERROR,
                             "COSE kty is not EC2. Only EC2 is "
                             "supported at the moment");
                return NULL;
            }
            break;
        case 3: // alg
            if (!cbor_value_is_integer(&map)) {
                debug_printf(DEBUG_LEVEL_ERROR, "alg is not an integer");
                return NULL;
            }
            cbor_value_get_int(&map, &pk->alg);
            if (pk->alg != COSE_ES256) {
                debug_printf(DEBUG_LEVEL_ERROR,
                             "COSE alg is not ES256. Only ES256 is "
                             "supported at the moment");
                return NULL;
            }
            break;
        case -1: // crv
            if (!cbor_value_is_integer(&map)) {
                debug_printf(DEBUG_LEVEL_ERROR, "crv is not an integer");
                return NULL;
            }
            cbor_value_get_int(&map, &pk->crv);
            if (pk->crv != COSE_P256) {
                debug_printf(DEBUG_LEVEL_ERROR,
                             "COSE crv is not P-256. Only P-256 is "
                             "supported at the moment");
                return NULL;
            }
            break;
        case -2: // x
            if (!cbor_value_is_byte_string(&map)) {
                debug_printf(DEBUG_LEVEL_ERROR, "x is not a byte string");
                return NULL;
            }
            cbor_value_get_string_length(&map, &len);
            cbor_value_copy_byte_string(&map, point + 1, &len, NULL);
            break;
        case -3: // y
            if (!cbor_value_is_byte_string(&map)) {
                debug_printf(DEBUG_LEVEL_ERROR, "y is not a byte string");
                return NULL;
            }
            cbor_value_get_string_length(&map, &len);
            cbor_value_copy_byte_string(&map, point + 33, &len, NULL);
            break;
        default:
            debug_printf(DEBUG_LEVEL_ERROR, "Unknown key COSE map: %d", key);
            return NULL;
        }
        cbor_value_advance(&map);
    }
    if (pk->alg == COSE_ES256) {
        pk->es256 = es256_pk_new();
        if (es256_pk_from_ptr(pk->es256, point, 65) != FIDO_OK) {
            debug_printf(DEBUG_LEVEL_ERROR, "Failed to convert public key");
            es256_pk_free(&pk->es256);
            return NULL;
        }
        debug_printf(DEBUG_LEVEL_MORE_VERBOSE,
                     "Successfully parsed ES256 COSE key");
    } else {
        // Only ES256 is supported at the moment
        debug_printf(DEBUG_LEVEL_ERROR, "Unsupported COSE algorithm");
        return NULL;
    }
    return pk;
}

/**
 * @brief This function retrieves the public key from the fido_data struct and
 * converts it to an es256_pk_t structure.
 *
 * @param data fido_data struct which must contain the public key
 * @return es256_pk_t* The public key in es256_pk_t format, or NULL if the
 * public key is missing or invalid.
 */
es256_pk_t *get_public_key(const u8 *cose_key, size_t cose_key_len) {
    if (cose_key == NULL || cose_key_len == 0) {
        return NULL;
    }
    // The hardcoded public key is a DER encoded ES256 (ECDSA over P-256) public
    // key. We need to convert it to an EVP_PKEY structure with openssl before
    // libfido2 can convert it to an es256_pk_t structure.

    // We make a copy of the public key data and length because the decoder will
    // modify the pointers.
    const unsigned char *pubkey = cose_key;
    size_t pubkey_len = cose_key_len;

    // Create a decoder context for the public key
    EVP_PKEY *pkey = NULL;
    OSSL_DECODER_CTX *decoder_ctx = OSSL_DECODER_CTX_new_for_pkey(
        &pkey, "DER", NULL, "EC", EVP_PKEY_PUBLIC_KEY, NULL, NULL);
    if (decoder_ctx == NULL) {
        return NULL;
    }
    // Use the decoder context to parse the public key.
    if (!OSSL_DECODER_from_data(decoder_ctx, &pubkey, &pubkey_len)) {
        debug_printf(DEBUG_LEVEL_ERROR, "Failed to parse public key");
        OSSL_DECODER_CTX_free(decoder_ctx);
        EVP_PKEY_free(pkey);
        return NULL;
    }
    OSSL_DECODER_CTX_free(decoder_ctx);

    // Convert the EVP_PKEY to an es256_pk_t
    es256_pk_t *pk = es256_pk_new();
    if (pk == NULL) {
        debug_printf(DEBUG_LEVEL_ERROR, "Failed to allocate es256_pk_t");
        EVP_PKEY_free(pkey);
        return NULL;
    }
    if (es256_pk_from_EVP_PKEY(pk, pkey) != FIDO_OK) {
        debug_printf(DEBUG_LEVEL_ERROR,
                     "Failed to convert EVP_PKEY to es256_pk_t");
        EVP_PKEY_free(pkey);
        es256_pk_free(&pk);
        return NULL;
    }
    EVP_PKEY_free(pkey);

    return pk;
}
//TODO
int verify_clientdata(struct rp_data *data, const char *clientdata_json,
    const size_t clientdata_json_len,  enum fido_mode mode) {
    // We could drop the JSON dependency here and parse the client data manually.
    assert(data->challenge != NULL && data->challenge_len != 0 &&
           data->rp_id != NULL);

    // Parse the client data JSON string
    json_error_t error;
    json_t *root = json_loadb(clientdata_json, clientdata_json_len, 0, &error);
    if (!root) {
        debug_printf(DEBUG_LEVEL_ERROR, "Failed to parse client data: %s",
                     error.text);
        return -1;
    }
    debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "Verify client data:");

    // Extract the type string
    json_t *json_type = json_object_get(root, "type");
    if (!json_type || !json_is_string(json_type)) {
        debug_printf(DEBUG_LEVEL_ERROR,
                     "Type is missing or not a string in client data");
        json_decref(root);
        return -1;
    }
    const char *type = json_string_value(json_type);
    if (mode == REGISTER) {
        // compare the type with "webauthn.create"
        if (strcmp(type, "webauthn.create") != 0) {
            debug_printf(DEBUG_LEVEL_ERROR, "    Type is not webauthn.create");
            json_decref(root);
            return -1;
        }
        debug_printf(DEBUG_LEVEL_MORE_VERBOSE,
                     "    Type matches \"webauthn.create\"");
    } else if (mode == AUTHENTICATE) {
        // compare the type with "webauthn.get"
        if (strcmp(type, "webauthn.get") != 0) {
            debug_printf(DEBUG_LEVEL_ERROR, "    Type is not webauthn.get");
            json_decref(root);
            return -1;
        }
        debug_printf(DEBUG_LEVEL_MORE_VERBOSE,
                     "    Type matches \"webauthn.get\"");
    } 


    // Extract the origin string
    json_t *json_origin = json_object_get(root, "origin");
    if (!json_origin || !json_is_string(json_origin)) {
        debug_printf(DEBUG_LEVEL_ERROR,
                     "    Origin is missing or not a string in client data");
        json_decref(root);
        return -1;
    }
    const char *origin = json_string_value(json_origin);
    // prepend https:// to the expected origin
    char *expected_origin = OPENSSL_malloc(strlen(data->rp_id) + 1 + 8);
    if (expected_origin == NULL) {
        debug_printf(DEBUG_LEVEL_ERROR, "Memory allocation failed");
        json_decref(root);
        return -1;
    }
    strcpy(expected_origin, "https://");
    strcat(expected_origin, data->rp_id);
    if (strcmp(origin, expected_origin) != 0) {
        debug_printf(DEBUG_LEVEL_ERROR, "    Origin does not match the expected one");
        json_decref(root);
        OPENSSL_free(expected_origin);
        return -1;
    } else {
        debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    Origin is valid: %s", origin);
    }
    OPENSSL_free(expected_origin);
 
    //Extract the crossOrigin boolean
    json_t *json_cross_origin = json_object_get(root, "crossOrigin");
    if(!json_is_false(json_cross_origin)){
        debug_printf(DEBUG_LEVEL_ERROR,
                     "    crossOrigin is missing or not a boolean false in client data");
        json_decref(root);
        return -1;
   }



    // Extract the challenge string
    json_t *json_challenge = json_object_get(root, "challenge");
    if (!json_challenge || !json_is_string(json_challenge)) {
        debug_printf(DEBUG_LEVEL_ERROR,
                     "    Challenge is missing or not a string in client data");
        json_decref(root);
        return -1;
    }

    // Decode the challenge
    u8 *decoded_challenge = NULL;
    size_t decoded_challenge_len = 0;
    if (base64url_decode(json_string_value(json_challenge), &decoded_challenge,
                         &decoded_challenge_len) != 0) {
        debug_printf(DEBUG_LEVEL_ERROR, "    Failed to decode challenge");
        json_decref(root);
        return -1;
    }

    // Compare the decoded challenge with the stored challenge
    if (decoded_challenge_len == data->challenge_len &&
        memcmp(decoded_challenge, data->challenge, data->challenge_len) == 0) {
        debug_printf(DEBUG_LEVEL_MORE_VERBOSE,
                     "    The client-provided challenge corresponds to the "
                     "specified one");
    } else {
        debug_printf(DEBUG_LEVEL_ERROR,
                     "    The client-provided challenge does not correspond to "
                     "the specified one");
        json_decref(root);
        OPENSSL_free(decoded_challenge);
        return -1;
    }

    // Cleanup
    json_decref(root);
    OPENSSL_free(decoded_challenge);

    return 0;
}

//TODO
int verify_authdata(struct rp_data *data, struct authdata *authdata,
                    enum fido_mode mode, int sign_count) {
    if (data == NULL || authdata == NULL) {
        return -1;
    }
    // - The rp id hash in the auth data must be equal to the hash of the rp id
    // - Check if the user present flag is set (or not if not required)
    // - Check if the user verified flag is set (or not if not required)
    debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "Verify auth data:");

    // Create the rp id hash
    u8 hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)data->rp_id, strlen(data->rp_id), hash);

    // Compare the rp id hash
    if (memcmp(authdata->rp_id_hash, hash, SHA256_DIGEST_LENGTH) != 0) {
        debug_printf(DEBUG_LEVEL_ERROR, "    RP ID hash does not match");
        free_authdata(authdata);
        return -1;
    }
    debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    RP ID hash matches");

    // Verify if the sign count is bigger than the stored sign count
    // SEE: https://www.w3.org/TR/webauthn/#sctn-sign-counter
    if (mode == AUTHENTICATE) {
        if (authdata->sign_count <= sign_count) {
            debug_printf(DEBUG_LEVEL_ERROR,
                         "    Sign count did not increase. This may indicate a "
                         "possible cloned token or device malfunction");
            free_authdata(authdata);
            return -1;
        }
    }
    debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    Sign count was increased");

    // If the user is required to be verified
    if (data->user_verification == UV_REQUIRED) {
        // But not performed
        if (!(authdata->flags & (1 << 2))) {
            debug_printf(
                DEBUG_LEVEL_ERROR,
                "    User verification was required but not performed");
            free_authdata(authdata);
            return -1;
        } else {
            debug_printf(DEBUG_LEVEL_MORE_VERBOSE,
                         "    User was performed as requested");
        }
    } else {
        debug_printf(DEBUG_LEVEL_MORE_VERBOSE,
                     "    User verification was not required");
    }
    // TODO: what about user presence? What can we check it against?
    // if (!(authdata->flags & (1 << 0))) {
    //     debug_printf(DEBUG_LEVEL_ERROR, "    User present flag is not
    //     set"); free_authdata(authdata); return -1;
    // }
    // debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    User present flag is
    // set");
    return 0;
}

int create_pre_response(struct rp_data *data, const u8 **out,
                           size_t *out_len) {
    // Relying Party creates a 256 byte ephemeral user ID, according to I-D, Section 12.2
    //Create a ephemeral user id but do not save it to the rp yet
    data->eph_user_id_len = 256;
    u8 *eph_user_id;
    if (create_random_bytes(data->eph_user_id_len, &eph_user_id) != 0) {
        debug_printf(DEBUG_LEVEL_ERROR, "Failed to create random bytes");
        return -1;
    }
    debug_printf(DEBUG_LEVEL_MORE_VERBOSE,
                 "Created an ephemeral user id from random bytes");
    // Derived AES-256-GCM from ephemeral user id using HMAC-SHA256
    size_t gcm_key_len = 32;
    u8 *gcm_key = OPENSSL_zalloc(gcm_key_len);
    unsigned int md_len = 0;
    HMAC(EVP_sha256(), data->k_ep, data->k_ep_len, eph_user_id, data->eph_user_id_len, gcm_key, &md_len);
    debug_print_hex(DEBUG_LEVEL_MORE_VERBOSE,
                 "Derived AES-256-GCM key from ephemeral user id with HMAC-SHA256: ", gcm_key, md_len );

    //extra checking whether the size of resulting HMAC is 32 bytes
    if(md_len != 32){
        debug_printf(DEBUG_LEVEL_ERROR, "The length of HMAC output is not the extpected 32 bytes");
        return -1;
    }
    // Prepare the response packet
    struct pre_response packet;
    memset(&packet, 0, sizeof(struct pre_response));
    packet.eph_user_id = eph_user_id;
    packet.eph_user_id_len = data->eph_user_id_len;
    packet.gcm_key = gcm_key;
    packet.gcm_key_len = md_len;


    int result = cbor_build(&packet, PKT_PRE_RESPONSE, out, out_len);
    OPENSSL_free(eph_user_id);
    OPENSSL_clear_free(gcm_key, gcm_key_len);
    return result;

}
//TODO!
int create_reg_request(struct rp_data *data, const u8 **out,
                       size_t *out_len) {
    struct reg_request packet;
    memset(&packet, 0, sizeof(struct reg_request));

    packet.rp_id = data->rp_id;
    packet.rp_name = data->rp_name;
    // Create a challenge and save it to the rp_data struct
    data->challenge_len = 32; // 256 bits
    if (create_random_bytes(data->challenge_len, &data->challenge) != 0) {
        debug_printf(DEBUG_LEVEL_ERROR, "Failed to create challenge");
        return -1;
    }
    debug_printf(DEBUG_LEVEL_MORE_VERBOSE,
                 "Created a challenge from random bytes");

    packet.challenge = data->challenge;
    packet.challenge_len = data->challenge_len;


    packet.pub_key_cred_params = OPENSSL_malloc(sizeof(*packet.pub_key_cred_params));
    if(packet.pub_key_cred_params == NULL){
        return -1;
    }
    //TODO: Implement all of the other 6 COSE Algorithms
    packet.pub_key_cred_params_len = 1;
    packet.pub_key_cred_params[0].alg = COSE_ES256;
    packet.pub_key_cred_params[0].type = PUBLIC_KEY;
    //packet.pub_key_cred_params[1].alg = COSE_ES384;
    //packet.pub_key_cred_params[2].alg = COSE_ES512;
    //packet.pub_key_cred_params[3].alg = COSE_EDDSA;
    //packet.pub_key_cred_params[4].alg = COSE_ECDH_ES256;
    //packet.pub_key_cred_params[5].alg = COSE_RS256;
    //packet.pub_key_cred_params[6].alg = COSE_RS1;
   // for(size_t i = 0; i < 1; i++){
    //    packet.pub_key_cred_params[i].type = PUBLIC_KEY;
    //}

    

    // Check if the user already exists in the database
    if (get_user_id(data->db, data->user_name, &data->user_id, &data->user_id_len) == 0) {
        debug_print_hex(
            DEBUG_LEVEL_MORE_VERBOSE,
            "User has already been registered and has a user id: ", data->user_id,
            data->user_id_len);
    } else {
        // Create a user id and save it to the rp_data struct
        data->user_id_len = 64;
        if (create_random_bytes(data->user_id_len, &data->user_id) != 0) {
            debug_printf(DEBUG_LEVEL_ERROR, "Failed to create user id");
            return -1;
        }
        debug_printf(DEBUG_LEVEL_MORE_VERBOSE,
                     "Created a user id from random bytes");
    }

    // According to the FIDO2 spec, there must not be a relation between the
    // user id and the user name. However this implementation would allow for
    // that.
    assert(data->user_name != NULL);


   //Now there exists a CBOR Array, which contains padded user_name, padded user display name, user_id and Optional
   //parameter: List of public key credentials to limit creation of multiple credentials for the same account on the same
   //authenticator

    u8 *padded_user_display_name = NULL;
    const size_t padded_user_display_name_len = 256;
    padded_user_display_name = OPENSSL_zalloc(padded_user_display_name_len);
    if(padded_user_display_name == NULL){
        debug_printf(DEBUG_LEVEL_ERROR, "Memory allocation for padded user display name failed");
        return -1;
    }
    if(bit_padding(padded_user_display_name, data->user_display_name, 
        strlen(data->user_display_name)) != 0){
        debug_printf(DEBUG_LEVEL_ERROR, "Failed to pad user display name");
        return -1;     
    }


    u8 *padded_user_name = NULL;
    const size_t padded_user_name_len = 256;
    padded_user_name = OPENSSL_zalloc(padded_user_name_len);
    if(padded_user_name == NULL){
        debug_printf(DEBUG_LEVEL_ERROR, "Memory allocation for padded user name failed");
        return -1;
    }
    if(bit_padding(padded_user_name, data->user_name, 
        strlen(data->user_name)) != 0){
        debug_printf(DEBUG_LEVEL_ERROR, "Failed to pad user name");
        return -1;     
    }

    struct reg_request_encrypted_data encrypted_data = {0};
    struct public_key_credential_descriptor *exclude_credentials = NULL;
    size_t exclude_credentials_len = 0; 
    encrypted_data.padded_user_display_name = padded_user_display_name;
    encrypted_data.padded_user_display_name_len = padded_user_display_name_len;
    encrypted_data.padded_user_name = padded_user_name;
    encrypted_data.padded_user_name_len = padded_user_name_len;
    encrypted_data.user_id = data->user_id;
    encrypted_data.user_id_len = data->user_id_len;
    
    if(get_excluded_credential_descriptors(data->db, data->user_id, data->user_id_len, &exclude_credentials, &exclude_credentials_len) != 0 ){
        debug_printf(DEBUG_LEVEL_ERROR, "Database error");
        return -1;
    }
    encrypted_data.exclude_credentials = exclude_credentials;
    encrypted_data.exclude_credentials_len = exclude_credentials_len; 
 
    u8 *inner_cbor_out = NULL;
    size_t inner_cbor_out_len = 0;

    if(cbor_build_reg_request_encrypted_data(&encrypted_data, &inner_cbor_out, &inner_cbor_out_len)!=0){
        debug_printf(DEBUG_LEVEL_ERROR, "Failed building a CBOR array");
        return -1;
    }

    u8 *ciphertext_out = NULL;
    size_t ciphertext_out_len = 0;
    if(aes_gcm_encrypt(inner_cbor_out, inner_cbor_out_len, &ciphertext_out, &ciphertext_out_len, data->gcm_key, data->gcm_key_len)){
        debug_printf(DEBUG_LEVEL_ERROR, "Failed encrypting the CBOR array");
        return -1;
    }
    packet.encrypted_data = ciphertext_out;
    packet.encrypted_data_len = ciphertext_out_len;
  
    // Optional fields
    if (data->timeout != 0) {
        packet.timeout = data->timeout;
    }

    if (data->auth_attach != 0 ) {
        packet.auth_sel.attachment = data->auth_attach;
     }

    if(data->resident_key != 0) {
        packet.auth_sel.resident_key = data->resident_key;
    }

    if(data->user_verification != 0){
        packet.auth_sel.user_verification = data->user_verification;
    }
    if(data->attestation !=0 ){
        packet.attestation = data->attestation;
    }



    if(data->extensions!=0 && data->extensions_len > 0){
        packet.extensions = data->extensions;
        packet.extensions_len = data->extensions_len;
    }

    // Encode the packet to CBOR
    if (cbor_build(&packet, PKT_REG_REQUEST, out, out_len) != 0) {
        debug_printf(DEBUG_LEVEL_ERROR, "Failed to build registration request");
        return -1;
    }

    OPENSSL_free(packet.pub_key_cred_params);
    return 0;
}

int create_auth_request(struct rp_data *data, const u8 **out,
                        size_t *out_len) {
    // Create a challenge and save it to the rp_data struct
    data->challenge_len = 32; // 256 bits
    if (create_random_bytes(data->challenge_len, &data->challenge) != 0) {
        debug_printf(DEBUG_LEVEL_ERROR, "Failed to create challenge");
        return -1;
    }
    debug_printf(DEBUG_LEVEL_MORE_VERBOSE,
                 "Created a challenge from random bytes");
    struct auth_request packet;
    memset(&packet, 0, sizeof(struct auth_request));
    packet.challenge = data->challenge;
    packet.challenge_len = data->challenge_len;

    // Optional fields
    if (data->rp_id != NULL) {
        packet.rp_id = data->rp_id;
    }
    if (data->timeout != 0) {
        packet.timeout = data->timeout;
    }
    if (data->user_verification != 0) {
        packet.user_verification = data->user_verification;
    }
    return cbor_build(&packet, PKT_AUTH_REQUEST, out, out_len);
}

int process_indication(const u8 *in, size_t in_len, struct rp_data *data) {
    if (in == NULL || in_len == 0) {
        return -1;
    }
    enum packet_type type = UNDEFINED;
    struct reg_indication packet = {0};
    if (cbor_parse(in, in_len, &type, &packet) != 0) {
        debug_printf(DEBUG_LEVEL_ERROR, "Failed to parse indication");     
        OPENSSL_free(packet.eph_user_id);
        OPENSSL_free(packet.encrypted_data);
        return -1;
    }
    // Pre indication has no data. We simply set the new state
    if (data->state == STATE_INITIAL && type == PKT_PRE_INDICATION) {
        data->state = STATE_PRE_INDICATION_RECEIVED;
    } else if (data->state == STATE_PRE_RESPONSE_SENT &&
               type == PKT_REG_INDICATION) {
        //we check only length because the server does not store the ephemeral user id after the pre response
        if (data->eph_user_id_len != packet.eph_user_id_len) {
            debug_printf(DEBUG_LEVEL_ERROR, "Unknown ephemeral user id");
            OPENSSL_free(packet.encrypted_data);
            return -1;
        }
    //Derive the gcm key from provided ephemeral user id
    data->gcm_key = OPENSSL_zalloc(32);
    unsigned int md_len = 0;
    HMAC(EVP_sha256(), data->k_ep, data->k_ep_len, packet.eph_user_id, packet.eph_user_id_len, data->gcm_key, &md_len);
    debug_print_hex(DEBUG_LEVEL_MORE_VERBOSE, "The derived key after the start of the registartion is ", data->gcm_key, md_len);
    if(md_len != 32){
        debug_printf(DEBUG_LEVEL_ERROR, "The size of a derived gcm key is not 32");
        return -1;
    }
    data->gcm_key_len = md_len;

    u8 *cbor_array_decrypted = NULL;
    size_t cbor_array_decrypted_len = 0;
    if (aes_gcm_decrypt(packet.encrypted_data, packet.encrypted_data_len,
                        &cbor_array_decrypted, &cbor_array_decrypted_len, data->gcm_key,
                        data->gcm_key_len) != 0) {
        debug_printf(DEBUG_LEVEL_ERROR, "Failed to decrypt CBOR array");
        OPENSSL_free(packet.eph_user_id);
        OPENSSL_free(packet.encrypted_data);
        return -1;
    }
    struct encrypted_data encrypted_data = {0};

    if(cbor_parse_encrypted_data(cbor_array_decrypted, cbor_array_decrypted_len, &encrypted_data)!=0){
        OPENSSL_free(encrypted_data.padded_user_display_name);
        OPENSSL_free(encrypted_data.ticket);
        OPENSSL_free(packet.eph_user_id);
        OPENSSL_free(packet.encrypted_data);
        free(cbor_array_decrypted);
        return -1;
    }
    
   
    char *unpadded_data = OPENSSL_malloc(257 * sizeof(*unpadded_data));
    if (unpadded_data == NULL){
        OPENSSL_free(packet.eph_user_id);
        OPENSSL_free(encrypted_data.padded_user_display_name);
        OPENSSL_free(encrypted_data.ticket);
        OPENSSL_free(packet.encrypted_data);      
        free(cbor_array_decrypted);
        return -1;
    }
    size_t unpadded_data_len = 0 ;


    if(remove_bit_padding(unpadded_data, encrypted_data.padded_user_display_name, &unpadded_data_len)!=0){
        OPENSSL_free(unpadded_data);
        OPENSSL_free(packet.eph_user_id);
        OPENSSL_free(encrypted_data.padded_user_display_name);
        OPENSSL_free(encrypted_data.ticket);
        OPENSSL_free(packet.encrypted_data);
        free(cbor_array_decrypted);
        return -1;
    }


    if (data->ticket_len != encrypted_data.ticket_len ||
            CRYPTO_memcmp(data->ticket, encrypted_data.ticket, data->ticket_len) != 0) {
            debug_printf(DEBUG_LEVEL_ERROR, "Invalid Ticket");
            OPENSSL_free(unpadded_data);
            OPENSSL_free(encrypted_data.padded_user_display_name);
            OPENSSL_free(encrypted_data.ticket);
            OPENSSL_free(packet.eph_user_id);
            OPENSSL_free(packet.encrypted_data);
            free(cbor_array_decrypted);
            return -1;
    }

    //According to the I-D, the user name may be the same as the user display name
    //Thus this implementation uses this design choice
    data->user_display_name = unpadded_data;
    char *unpadded_data_copy = OPENSSL_malloc(257 * sizeof(*unpadded_data_copy));
    memcpy(unpadded_data_copy, unpadded_data, unpadded_data_len + 1);
    data->user_name = unpadded_data_copy;

   

    debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "Client provided a valid ticket");
    OPENSSL_free(packet.eph_user_id);
    OPENSSL_free(encrypted_data.padded_user_display_name);
    OPENSSL_free(encrypted_data.ticket);
    OPENSSL_free(packet.encrypted_data);
    free(cbor_array_decrypted);

    data->state = STATE_REG_INDICATION_RECEIVED;
    }
    // Again, the auth indication has no data. We simply set the state
    else if (data->state == STATE_INITIAL && type == PKT_AUTH_INDICATION) {
        // Check if a database exists
        struct stat buffer;
        if (stat("fido2.db", &buffer) != 0) {
            debug_printf(DEBUG_LEVEL_ERROR,
                         "Detected an authentication request "
                         "but no database exists. You must enroll "
                         "a credential before you can authenticate");
            return -1;
        }
        data->state = STATE_AUTH_INDICATION_RECEIVED;
    } else {
        debug_printf(DEBUG_LEVEL_ERROR, "Received unexpected packet");
        OPENSSL_free(packet.eph_user_id);
        OPENSSL_free(packet.encrypted_data);
        return -1;
    }
    return 0;
}

int process_reg_response(const u8 *in, size_t in_len, struct rp_data *data) {
    if (in == NULL || in_len == 0 || data == NULL) {
        return -1;
    }
    struct reg_response packet;
    memset(&packet, 0, sizeof(packet));
    enum packet_type type = PKT_REG_RESPONSE;
    if (cbor_parse(in, in_len, &type, &packet) != 0) {
        debug_printf(DEBUG_LEVEL_ERROR,
                     "Failed to parse registration response");
        return -1;
    }
    // Verify the client data
    if (verify_clientdata(data, packet.clientdata_json, packet.clientdata_json_len, REGISTER) != 0) {
        debug_printf(DEBUG_LEVEL_ERROR, "Failed to verify client data");
        return -1;
    }
    // Enforce the server-saved attestation policy. Currently only DIRECT attestation is supported
    if(data->attestation != DIRECT){
        return -1;
    }
    // Reconstruct the server's expected credential state in libfido2
    fido_cred_t *server_side_credential = fido_cred_new();
    if(server_side_credential == NULL){
        return -1;
    }
    // Configure the RP ID, RP name, ES256 algorithm and options saved for this request
    if(fido_cred_set_rp(server_side_credential, data->rp_id, data->rp_name) != FIDO_OK){
        return -1;
    }
    if(fido_cred_set_type(server_side_credential, COSE_ES256) != FIDO_OK){
        return -1;
    }
    // Enforce user verification only if the request required them
    fido_opt_t uv_preference = FIDO_OPT_OMIT;
    if(data->user_verification == UV_REQUIRED){
        uv_preference = FIDO_OPT_TRUE;
    }
    if(fido_cred_set_uv(server_side_credential, uv_preference)!=FIDO_OK){
        return -1;
    }
    // Enforce the usage of discoverable credentials only if the request required them
    fido_opt_t rk_preference = FIDO_OPT_OMIT;
    if(data->resident_key == RK_REQUIRED){
        rk_preference = FIDO_OPT_TRUE;
    }
    if(fido_cred_set_rk(server_side_credential, rk_preference)!= FIDO_OK){
        return -1;
    }

    // The attestation object and ClientDataJSON are untrusted client input
    // libfido2 hashes the exact ClientDataJSON bytes internally and uses them for attestation verification
    if(fido_cred_set_clientdata(server_side_credential, (const unsigned char *)packet.clientdata_json, packet.clientdata_json_len)!= FIDO_OK){
        return -1;
    }
    // Parse the complete WebAuthn attestation object, which includes authData, fmt and attStmt
    if(fido_cred_set_attobj(server_side_credential, packet.attestation_object, packet.attestation_object_len)!= FIDO_OK){
        return -1;
    }

    // DIRECT attestation in this implementation is restricted to the packed format with a nonempty x5c certificate list
    const char *fmt = fido_cred_fmt(server_side_credential);
    if(fmt == NULL){
        return -1;
    }
    if(strcmp(fmt, "packed")!= 0){
        return -1;
    }
    if(fido_cred_x5c_list_count(server_side_credential) == 0){
        return -1;
    }

    const unsigned char *leaf_cert = fido_cred_x5c_list_ptr(server_side_credential, 0);
    size_t leaf_cert_len = fido_cred_x5c_list_len(server_side_credential, 0);
    if(leaf_cert == NULL || leaf_cert_len == 0){
        return -1;
    }

    // Verify the packed attestation signature and its binding to the
    // ClientDataJSON hash, RP ID, credential ID, COSE algorithm and credential options
    // The validation of x5c trust path or certificate profile is missing
    if(fido_cred_verify(server_side_credential) != FIDO_OK){
        return -1;
    }

    // Prepare the cryptographically verified credential data that is going to be stored in the database
    struct credential *cred = OPENSSL_malloc(sizeof(struct credential));
    if (cred == NULL) {
        debug_printf(DEBUG_LEVEL_ERROR, "Memory allocation failed");
        return -1;
    }
    memset(cred, 0, sizeof(struct credential));
    const unsigned char *cred_id_ptr = fido_cred_id_ptr(server_side_credential);
    if(cred_id_ptr == NULL){
        return -1;
    }
    size_t cred_id_len = fido_cred_id_len(server_side_credential);
    if(cred_id_len > 1023 || cred_id_len == 0){
        return -1;
    }
    cred->id = OPENSSL_zalloc(cred_id_len);
    if(cred->id == NULL){
        return -1;
    }
    memcpy(cred->id, cred_id_ptr, cred_id_len);
    cred->id_len = cred_id_len;

    // Parse the verified authenticator data to obtain the COSE public key
    const unsigned char *cred_authdata = fido_cred_authdata_raw_ptr(server_side_credential);
    size_t cred_authdata_len = fido_cred_authdata_raw_len(server_side_credential);
    struct authdata *ad = parse_authdata(cred_authdata, cred_authdata_len);
    if (ad == NULL) {
        debug_printf(DEBUG_LEVEL_ERROR, "Failed to parse authdata");
        return -1;
    }
    cred->pubkey_cose = ad->pubkey;
    ad->pubkey = NULL;
    cred->pubkey_cose_len = ad->pubkey_len;
  
    cred->sign_count = fido_cred_sigcount(server_side_credential);
    cred->type = "public-key";

    if (add_creds(data->db, data->user_id, data->user_id_len, data->user_name,
                  data->rp_id, cred) != 0) {
        debug_printf(DEBUG_LEVEL_ERROR, "Failed to add credential to database");
        //free_authdata(ad);
        free_credential(cred);
        sqlite3_close(data->db);
        return -1;
    }
    OPENSSL_free(data->challenge);
    data->challenge = NULL;
    data->challenge_len = 0;
    free_authdata(ad);
    cred->type = NULL; // The type is not dynamically allocated
    free_credential(cred);
    OPENSSL_free(packet.attestation_object);
    OPENSSL_free(packet.clientdata_json);
    return 0;
}

int process_auth_response(const u8 *in, size_t in_len, struct rp_data *data) {
    if (in == NULL || in_len == 0 || data == NULL) {
        return -1;
    }
    struct auth_response packet;
    memset(&packet, 0, sizeof(packet));
    enum packet_type type = PKT_AUTH_RESPONSE;
    if (cbor_parse(in, in_len, &type, &packet) != 0) {
        debug_printf(DEBUG_LEVEL_ERROR,
                     "Failed to parse authentication response");
        return -1;
    }
    // Access the database
    struct credential cred;
    char *rp_id;
    if (get_credential(data->db, packet.user_id, packet.user_id_len,
                       packet.cred_id, packet.cred_id_len, &cred,
                       &rp_id) != 0) {
        debug_printf(DEBUG_LEVEL_ERROR,
                     "Failed to get credential from database");
        sqlite3_close(data->db);
        return -1;
    }

    // Verify the client data
    if (verify_clientdata(data, packet.clientdata_json, packet.clientdata_json_len, AUTHENTICATE) != 0) {
        debug_printf(DEBUG_LEVEL_ERROR, "Failed to verify client data");
        return -1;
    }
    // Parse authdata
    struct authdata *ad = parse_authdata(packet.authdata, packet.authdata_len);
    if (ad == NULL) {
        debug_printf(DEBUG_LEVEL_ERROR, "Failed to parse authdata");
        return -1;
    }
    // Verify the authdata
    if (verify_authdata(data, ad, AUTHENTICATE, cred.sign_count) != 0) {
        debug_printf(DEBUG_LEVEL_ERROR, "Failed to verify authdata");
        return -1;
    }

    // Prepare the public key
    PublicKey *pk = parse_cose_key(cred.pubkey_cose, cred.pubkey_cose_len);
    if (pk == NULL) {
        debug_printf(DEBUG_LEVEL_ERROR, "Failed to parse public key");
        free_authdata(ad);
        sqlite3_close(data->db);
        return -1;
    }

    // Prepare the assertion data to verify the signature
    fido_assert_t *assert = fido_assert_new();
    // Set the relying party id
    fido_assert_set_rp(assert, data->rp_id);
    // Set the client data hash
    u8 hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)packet.clientdata_json,
           packet.clientdata_json_len, hash);
    if (fido_assert_set_clientdata_hash(assert, hash, SHA256_DIGEST_LENGTH) !=
        FIDO_OK) {
        debug_printf(DEBUG_LEVEL_ERROR,
                     "Failed to set client data hash in fido_assert_t");
        fido_assert_free(&assert);
        return -1;
    }
    // Set the number of assertions to 1. We only have one credential to
    // verify.
    fido_assert_set_count(assert, 1);
    fido_assert_set_authdata_raw(assert, 0, packet.authdata,
                                 packet.authdata_len);
    fido_assert_set_sig(assert, 0, packet.signature, packet.signature_len);

    // Verify the signature
    if (fido_assert_verify(assert, 0, COSE_ES256, pk->es256) != FIDO_OK) {
        debug_printf(DEBUG_LEVEL_ERROR, "Failed to verify signature");
        return -1;
    }
    debug_printf(DEBUG_LEVEL_MORE_VERBOSE,
                 "Signature verified with public key from database");

    // Update the sign count in the database
    if (update_sign_count(data->db, packet.cred_id, packet.cred_id_len,
                          ad->sign_count) != 0) {
        debug_printf(DEBUG_LEVEL_ERROR, "Failed to update sign count");
        free_authdata(ad);
        sqlite3_close(data->db);
        return -1;
    }
    debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "Sign count updated in database");

    return 0;
}
