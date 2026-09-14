#include <openssl/evp.h>
#include <openssl/rand.h>
#include "common.h"
#include <jansson.h>
#include "debug.h"
#include <fido/es256.h>

const char* get_ssl_ext_context_code(unsigned int context) {
    switch (context) {
        case SSL_EXT_TLS_ONLY: return "SSL_EXT_TLS_ONLY";
        case SSL_EXT_DTLS_ONLY: return "SSL_EXT_DTLS_ONLY";
        case SSL_EXT_TLS_IMPLEMENTATION_ONLY: return "SSL_EXT_TLS_IMPLEMENTATION_ONLY";
        case SSL_EXT_SSL3_ALLOWED: return "SSL_EXT_SSL3_ALLOWED";
        case SSL_EXT_TLS1_2_AND_BELOW_ONLY: return "SSL_EXT_TLS1_2_AND_BELOW_ONLY";
        case SSL_EXT_TLS1_3_ONLY: return "SSL_EXT_TLS1_3_ONLY";
        case SSL_EXT_IGNORE_ON_RESUMPTION: return "SSL_EXT_IGNORE_ON_RESUMPTION";
        case SSL_EXT_CLIENT_HELLO: return "SSL_EXT_CLIENT_HELLO";
        case SSL_EXT_TLS1_2_SERVER_HELLO: return "SSL_EXT_TLS1_2_SERVER_HELLO";
        case SSL_EXT_TLS1_3_SERVER_HELLO: return "SSL_EXT_TLS1_3_SERVER_HELLO";
        case SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS: return "SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS";
        case SSL_EXT_TLS1_3_HELLO_RETRY_REQUEST: return "SSL_EXT_TLS1_3_HELLO_RETRY_REQUEST";
        case SSL_EXT_TLS1_3_CERTIFICATE: return "SSL_EXT_TLS1_3_CERTIFICATE";
        case SSL_EXT_TLS1_3_NEW_SESSION_TICKET: return "SSL_EXT_TLS1_3_NEW_SESSION_TICKET";
        case SSL_EXT_TLS1_3_CERTIFICATE_REQUEST: return "SSL_EXT_TLS1_3_CERTIFICATE_REQUEST";
        default: return "Unknown Context";
    }
}

int sha256_hash(const u8 *in, size_t inlen, u8 **out, size_t *outlen) {
    if (in == NULL || inlen == 0 || out == NULL || outlen == NULL) {
        return -1;
    }
    // Initialize the hash context for SHA-256
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        debug_printf(DEBUG_LEVEL_ERROR, "Failed to initialize the Digest Context");
        return -1;
    }
    if (1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL)) {
        debug_printf(DEBUG_LEVEL_ERROR, "Failed to initialize the Digest");
        EVP_MD_CTX_free(mdctx);
        return -1;
    }
    if (1 != EVP_DigestUpdate(mdctx, in, inlen)) {
        debug_printf(DEBUG_LEVEL_ERROR, "Failed to update the Digest");
        EVP_MD_CTX_free(mdctx);
        return -1;
    }
    // Allocate memory for the output hash. SHA-256 hash size is 32 bytes.
    *out = (u8 *)OPENSSL_malloc(EVP_MD_size(EVP_sha256()));
    if (*out == NULL) {
        debug_printf(DEBUG_LEVEL_ERROR, "Failed to allocate memory for the Digest");
        EVP_MD_CTX_free(mdctx);
        return -1;
    }
    // Compute the hash
    if (1 != EVP_DigestFinal_ex(mdctx, *out, (unsigned int *)outlen)) {
        debug_printf(DEBUG_LEVEL_ERROR, "Failed to finalize the Digest");
        free(*out);
        EVP_MD_CTX_free(mdctx);
        return -1;
    }
    EVP_MD_CTX_free(mdctx);

    return 0;
}

int aes_gcm_encrypt(const u8 *plain, size_t plain_len, u8 **cypher, size_t *cypher_len, const u8 *key, size_t key_len) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;
    // Hardcoded IV. We must not generate a new one since the GCM key is only
    // used once
    // Needs to be 12 Bytes long
    //TODO: since we now have encrypted data arrays in more than one message, IV can not be reused and should be generated for every new encryption
    //we should transmit it with the tag
    u8 *iv = (u8 *)"012345678901";
    u8 tag[16]; // GCM Tag

    // Check for valid key length
    if (key_len != 16 && key_len != 24 && key_len != 32) {
        printf("Invalid key length.\n");
        return -1;
    }

    // Allocate memory for cypher text and 16 bytes extra for GCM tag
    *cypher = (u8 *)malloc(plain_len + 16);

    // Create and initialize the context
    if(!(ctx = EVP_CIPHER_CTX_new())) return -1;

    // Initialize encryption operation
    if(1 != EVP_EncryptInit_ex(ctx, (key_len == 32) ? EVP_aes_256_gcm() : (key_len == 24) ? EVP_aes_192_gcm() : EVP_aes_128_gcm(), NULL, NULL, NULL))
        return -1;

    // Set IV length, OpenSSL might not set this automatically for GCM
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL))
        return -1;

    // Initialize key and IV
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
        return -1;

    // Provide the message to be encrypted, and obtain the encrypted output.
    // EVP_EncryptUpdate can be called multiple times if necessary
    if(1 != EVP_EncryptUpdate(ctx, *cypher, &len, plain, plain_len))
        return -1;
    ciphertext_len = len;

    // Finalize the encryption. Normally ciphertext bytes may be written at
    // this stage, but this does not occur in GCM mode
    if(1 != EVP_EncryptFinal_ex(ctx, *cypher + len, &len)) return -1;
    ciphertext_len += len;

    // Get the tag
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
        return -1;

    // Append the tag to the end of the cipher text
    memcpy(*cypher + ciphertext_len, tag, sizeof(tag));
    ciphertext_len += sizeof(tag);

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    *cypher_len = ciphertext_len;
    return 0;
}

int aes_gcm_decrypt(const u8 *cypher, size_t cypher_len, u8 **plain, size_t *plain_len, const u8 *key, size_t key_len) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ret = -1;
    // Assume IV is the same 12 bytes as used in encryption, and tag is appended at the end of cypher
    // Needs to be 12 Bytes long
    u8 *iv = (u8 *)"012345678901";
    u8 tag[16];

    // Check key length for validity
    if (key_len != 16 && key_len != 24 && key_len != 32) {
        printf("Invalid key length.\n");
        return -1;
    }

    // Extract the tag from the end of the cypher
    memcpy(tag, cypher + cypher_len - 16, 16);

    // Adjust cypher_len to exclude the tag
    cypher_len -= 16;

    // Allocate memory for plain text
    *plain = (u8 *)malloc(cypher_len);
    if (*plain == NULL) {
        printf("Memory allocation failed.\n");
        return -1;
    }

    // Create and initialize the context
    if (!(ctx = EVP_CIPHER_CTX_new()))
        goto cleanup;

    // Initialize decryption operation
    if (!EVP_DecryptInit_ex(ctx, (key_len == 32) ? EVP_aes_256_gcm() : (key_len == 24) ? EVP_aes_192_gcm() : EVP_aes_128_gcm(), NULL, NULL, NULL))
        goto cleanup;

    // Set IV length. Not necessary if default 12 bytes is used
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL))
        goto cleanup;

    // Initialize key and IV
    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
        goto cleanup;

    // Provide the message to be decrypted
    if (!EVP_DecryptUpdate(ctx, *plain, &len, cypher, cypher_len))
        goto cleanup;
    *plain_len = len;

    // Set expected tag value
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
        goto cleanup;

    // Finalize the decryption. A positive return value indicates success, negative indicates a failure.
    ret = EVP_DecryptFinal_ex(ctx, *plain + len, &len);

cleanup:
    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0) {
        // Success, return plaintext length
        *plain_len += len;
        return 0; // Decryption is successful
    } else {
        // Verification failed
        free(*plain);
        *plain = NULL;
        *plain_len = 0;
        return -1; // Decryption failed
    }
}

int create_random_bytes(size_t len, u8 **out) {
    if (len == 0 || out == NULL) {
        return -1;
    }
    // Allocate memory for the random challenge
    *out = (u8 *)OPENSSL_malloc(len);
    if (*out == NULL) {
        debug_printf(DEBUG_LEVEL_ERROR, "Memory allocation failed");
        return -1;
    }

    // Generate the random challenge
    if (RAND_bytes(*out, (int)len) != 1) {
        debug_printf(DEBUG_LEVEL_ERROR, "Failed to generate random bytes");
        OPENSSL_free(*out);
        *out = NULL;
        return -1;
    }
    return 0;
}

int hex_to_u8(const char *hex, u8 **out, size_t *outlen) {
    size_t len = strlen(hex);
    if (len % 2 != 0) {
        printf("Invalid hex string length.\n");
        return -1;
    }
    *outlen = len / 2;
    *out = (u8 *)OPENSSL_malloc(*outlen);
    if (*out == NULL) {
        printf("Memory allocation failed.\n");
        return -1;
    }
    for (size_t i = 0; i < *outlen; i++) {
        sscanf(hex + 2 * i, "%2hhx", *out + i);
    }
    return 0;
}

void printBits(unsigned char byte) {
    for (int i = 7; i >= 0; i--) {
        unsigned char bit = (byte >> i) & 1;
        printf("%u", bit);
    }
    printf("\n");
}

const char *get_action_policy_name(unsigned int type) {
    switch (type) {
    case REQUIRED:
        return "REQUIRED";
    case PREFERRED:
        return "PREFERRED";
    case DISCOURAGED:
        return "DISCOURAGED";
    default:
        return "Unknown Action Policy";
    }
}



const char *get_attestation_conveyance_pref_name(unsigned int type){
    switch (type) {
        case NONE:
            return "NONE";
        case INDIRECT:
            return "INDIRECT";
        case DIRECT:
            return "DIRECT";
        case ENTERPRISE:
            return "ENTERPRISE";
        default:
            return "Unknown attestation conveyance prefernce";       
    }
}


const char *get_user_verification_requirements_name( unsigned int type){
  
    switch (type) {
        case UV_DISCOURAGED:
           return "DISCOURAGED";

        case UV_PREFERRED:
           return "PREFERRED";

        case UV_REQUIRED:
           return "REQUIRED";

        default: 
            return " Unknown user verification requirement";
    }
}







const char *get_resident_key_requirements_name(unsigned int type){

    switch (type) {
        case RK_DISCOURAGED:
            return "DISCOURAGED";
        
        case RK_PREFERRED:
            return "PREFERRED";

        case RK_REQUIRED:
            return "REQUIRED";

        default:
            return "Unknown resident key requirement name";    
    }
}


const char *get_cose_algorithm_name(int alg) {
    switch (alg) {
    case COSE_ES256:
        return "ES256";
    case COSE_EDDSA:
        return "EDDSA";
    case COSE_ECDH_ES256:
        return "ECDH_ES256";
    case COSE_ES384:
        return "ES384";
    case COSE_RS256:
        return "RS256";
    case COSE_RS1:
        return "RS1";  
    //Added new COSE algorithm, according to the I-D      
    case COSE_ES512:
        return "ES512";
    default:
        return "Unknown Algorithm";
    }
}

int bit_padding(u8 *padded_data, const char *data, size_t data_len){
    if(padded_data == NULL||data == NULL){
        return -1;
    }

    if(data_len == 0){
        debug_printf(DEBUG_LEVEL_ERROR, "Empty user display name");
        return -1;
    }

    if(data_len > 256){
        debug_printf(DEBUG_LEVEL_ERROR, "Size of user display name is bigger than 256 bytes");
        return -1;
    }

    memcpy(padded_data, data, data_len);
    if(data_len < 256){
        memset(padded_data + data_len, 0x80, 1);
        memset(padded_data + data_len + 1, 0x00, 256 - data_len - 1);
    }
  return 0;
}


int remove_bit_padding(char *unpadded_data, const u8 *padded_data, size_t *unpadded_len){
    if(unpadded_data == NULL || padded_data == NULL ||  unpadded_len == NULL){
        return -1;
    }
    *unpadded_len = 0;
    for(int i  = 255; i >= 0; i--){
        if(padded_data[i] == 0x00 && i > 0){
            continue;
        }
        if(padded_data[i] == 0x80 && i > 0){
            memcpy(unpadded_data, padded_data, i);
            unpadded_data[i] = '\0';
            *unpadded_len = (size_t)i;
            return 0;
        }
        if(padded_data[i]!= 0x80 && i == 255){
            memcpy(unpadded_data, padded_data, i + 1);
            unpadded_data[i + 1] = '\0';
            *unpadded_len = (size_t)i+1;
            return 0;
        }
        else{
            return -1;  
        }  
    }
    return -1;
}


