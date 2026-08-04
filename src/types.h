#ifndef FIDO_TYPES_H
#define FIDO_TYPES_H

#include <stddef.h>
#include <fido/es256.h>
#include <sqlite3.h>
typedef unsigned char u8;

typedef enum fido_mode {
    REGISTER = 1,
    AUTHENTICATE = 2,
} MODE;

// Used for the user_verification and resident_key fields.
typedef enum action_policy {
    REQUIRED = 1,
    PREFERRED = 2,
    DISCOURAGED = 3
} POLICY;

typedef enum authenticator_attchment {
    PLATFORM = 1,
    CROSS_PLATFORM = 2
} AUTH_ATTACH;

typedef enum transport {
    USB = 1,
    NFC = 2,
    BLE = 3,
    INTERNAL = 4
} TRANSPORT;

enum fido_state {
    STATE_INITIAL,
    STATE_AUTH_INITIAL,
    STATE_AUTH_INDICATION_SENT,
    STATE_AUTH_INDICATION_RECEIVED,
    STATE_AUTH_REQUEST_SENT,
    STATE_AUTH_REQUEST_RECEIVED,
    STATE_AUTH_RESPONSE_SENT,
    STATE_AUTH_RESPONSE_RECEIVED,
    STATE_AUTH_SUCCESS,
    STATE_AUTH_FAILURE,
    STATE_REG_INITIAL,
    STATE_PRE_INDICATION_SENT,
    STATE_PRE_INDICATION_RECEIVED,
    STATE_PRE_RESPONSE_SENT,
    STATE_PRE_RESPONSE_RECEIVED,
    STATE_REG_INDICATION_SENT,
    STATE_REG_INDICATION_RECEIVED,
    STATE_REG_REQUEST_SENT,
    STATE_REG_REQUEST_RECEIVED,
    STATE_REG_RESPONSE_SENT,
    STATE_REG_RESPONSE_RECEIVED,
    STATE_REG_SUCCESS,
    STATE_REG_FAILURE
};

enum packet_type {
    UNDEFINED = 0,
    PKT_PRE_INDICATION = 1,
    //change of the name, according to I-D
    PKT_PRE_RESPONSE = 2,
    PKT_REG_INDICATION = 3,
    PKT_REG_REQUEST = 4,
    PKT_REG_RESPONSE = 5,
    PKT_AUTH_INDICATION = 6,
    PKT_AUTH_REQUEST = 7,
    PKT_AUTH_RESPONSE = 8
};

struct rp_data {
    enum fido_state state;
    u8 *challenge;
    size_t challenge_len;
    char *rp_id;
    char *rp_name;
    POLICY user_verification;
    // TODO
    POLICY user_presence;
    POLICY resident_key;
    AUTH_ATTACH auth_attach;
    TRANSPORT transport;
    size_t timeout;
    u8 *user_id;
    size_t user_id_len;
    char *user_name;
    char *user_display_name;
    u8 *eph_user_id;
    size_t eph_user_id_len;
    u8 *gcm_key;
    size_t gcm_key_len;
    u8 *ticket;
    size_t ticket_len;
    sqlite3 *db;
};

struct ud_data {
    enum fido_state state;
    u8 *challenge;
    size_t challenge_len;
    char *rp_id;
    char *rp_name;
    POLICY user_verification;
    POLICY user_presence;
    POLICY resident_key;
    // This value is not further processed at the client because only
    // CROSS_PLATFORM is supported.
    AUTH_ATTACH auth_attach;
    // This value is not further processed at the client because only
    // USB is supported.
    TRANSPORT transport;
    size_t timeout;
    u8 *authdata;
    size_t authdata_len;
    char *clientdata_json;
    u8 *signature;
    size_t signature_len;
    u8 *user_id;
    size_t user_id_len;
    char *user_name;
    char *user_display_name;
    u8 *eph_user_id;
    size_t eph_user_id_len;
    u8 *gcm_key;
    size_t gcm_key_len;
    u8 *cred_id;
    size_t cred_id_len;
    u8 *ticket;
    size_t ticket_len;
    struct credential *exclude_creds;
    size_t exclude_creds_len;
    char *pin;
    char *origin;
    int *cred_params;
    size_t cred_params_len;
};

typedef struct {
    union {
        es256_pk_t *es256;
        es384_pk_t *es384;
    };
    int alg;
    int crv;
} PublicKey;

struct credential {
    char *type; // e.g. "public-key"
    u8 *id;
    size_t id_len;
    TRANSPORT *transports; // e.g. [ USB, NFC ]
    size_t transports_len;
    u8 *pubkey_cose;
    size_t pubkey_cose_len;
    int sign_count;
};

struct authdata {
    u8 *rp_id_hash;
    size_t rp_id_hash_len;
    char flags;
    int sign_count;
    u8 *aaguid;
    size_t aaguid_len;
    u8 *cred_id;
    size_t cred_id_len;
    // The pubkey is a COSE Key. Not DER encoded like in the
    // AuthenticatorAttestationResponse.
    u8 *pubkey;
    size_t pubkey_len;
};

struct auth_request {
    // Required fileds
    u8 *challenge;
    size_t challenge_len;

    // Optional fields
    char *rp_id; 
    enum action_policy user_verification;
    int timeout;
};

struct auth_response {
    // Required fields
    u8 *authdata;
    size_t authdata_len;
    char *clientdata_json;
    u8 *signature;
    size_t signature_len;

    // Optional fields
    u8 *user_id; 
    size_t user_id_len;
    u8 *cred_id;
    size_t cred_id_len;
};
//change of the name, according to the I-D
struct pre_response {
    // Required fields
    u8 * eph_user_id;
    size_t eph_user_id_len;
    // AES-GCM key
    u8 * gcm_key;
    size_t gcm_key_len;
};

struct reg_indication {
    // Required fields
    u8 *eph_user_id;
    size_t eph_user_id_len;
    u8 * gcm_user_name;
    size_t gcm_user_name_len;
    u8 *gcm_user_display_name;
    size_t gcm_user_display_name_len;
    u8 *gcm_ticket;
    size_t gcm_ticket_len;
};

struct reg_request {
    // Required fields
    u8 *challenge;
    size_t challenge_len;
    char *rp_id;
    char *rp_name;
    u8 *gcm_user_name;
    size_t gcm_user_name_len;
    u8 *gcm_user_display_name;
    size_t gcm_user_display_name_len;
    u8 *gcm_user_id;
    size_t gcm_user_id_len;
    // Array of enum values (int) defined in libfido2 param.h. Values are:
    // COSE_UNSPEC COSE_ES256 COSE_EDDSA COSE_ECDH_ES256 COSE_ES384 COSE_RS256 COSE_RS1
    int *pubkey_cred_params; 
    size_t pubkey_cred_params_len;

    // Optional fields
    int timeout;
    struct credential  *exclude_creds;
    size_t exclude_creds_len;
    struct authenticator_sel {
        enum authenticator_attchment attachment;
        enum action_policy resident_key;
        enum action_policy user_verification;
    } auth_sel;
};

struct reg_response {
    u8 *authdata;
    size_t authdata_len;
    char *clientdata_json;
};

void free_rp_data(struct rp_data *rp_data);

void free_ud_data(struct ud_data *rp_data);

void free_auth_request(struct auth_request *auth_request);

void free_auth_response(struct auth_response *auth_response);

//change of the name, according to the I-D
void free_pre_response(struct pre_response *pre_response);

void free_reg_indication(struct reg_indication *reg_indication);

void free_reg_request(struct reg_request *reg_request);

void free_reg_response(struct reg_response *reg_response);

void free_authdata(struct authdata *authdata);

void free_credential(struct credential *cred);

#endif // FIDO_TYPES_H
