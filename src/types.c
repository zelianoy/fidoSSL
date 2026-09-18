#include "types.h"
#include <openssl/crypto.h>
//TODO: Speicherbereinigung vervollständigen
void free_rp_data(struct rp_data *rp_data) {
    OPENSSL_free(rp_data->challenge);
    OPENSSL_free(rp_data->rp_id);
    OPENSSL_free(rp_data->rp_name);
    OPENSSL_free(rp_data->user_id);
    OPENSSL_free(rp_data->user_name);
    OPENSSL_free(rp_data->user_display_name);
    OPENSSL_free(rp_data->eph_user_id);
    OPENSSL_clear_free(rp_data->gcm_key, rp_data->gcm_key_len);
    OPENSSL_free(rp_data->ticket);
    OPENSSL_clear_free(rp_data->k_ep, rp_data->k_ep_len);
    OPENSSL_free(rp_data);
}

void free_ud_data(struct ud_data *ud_data) {
    OPENSSL_free(ud_data->challenge);
    OPENSSL_free(ud_data->rp_id);
    OPENSSL_free(ud_data->rp_name);
    OPENSSL_free(ud_data->authdata);
    OPENSSL_free(ud_data->attestation_object);
    OPENSSL_free(ud_data->clientdata_json);
    OPENSSL_free(ud_data->signature);
    OPENSSL_free(ud_data->user_id);
    OPENSSL_free(ud_data->user_name);
    OPENSSL_free(ud_data->user_display_name);
    OPENSSL_free(ud_data->eph_user_id);
    OPENSSL_clear_free(ud_data->gcm_key, ud_data->gcm_key_len);
    OPENSSL_free(ud_data->cred_id);
    OPENSSL_free(ud_data->ticket);
    if (ud_data->exclude_credentials != NULL && ud_data->exclude_credentials_len > 0) {
        for (size_t i = 0; i < ud_data->exclude_credentials_len; i++) {
            OPENSSL_free(ud_data->exclude_credentials[i].id);
            OPENSSL_free(ud_data->exclude_credentials[i].transports);
            //OPENSSL_free(ud_data->exclude_credentials[i].pubkey_cose);
        }
    }
    OPENSSL_free(ud_data->exclude_credentials);
    OPENSSL_free(ud_data->pin);
    OPENSSL_free(ud_data->origin);
    OPENSSL_free(ud_data->pub_key_cred_params);
}

void free_auth_request(struct auth_request *auth_request) {
    if (auth_request == NULL) {
        return;
    }
    OPENSSL_free(auth_request->challenge);
    OPENSSL_free(auth_request->rp_id);
    OPENSSL_free(auth_request);
}

void free_auth_response(struct auth_response *auth_response) {
    if (auth_response == NULL) {
        return;
    }
    OPENSSL_free(auth_response->authdata);
    OPENSSL_free(auth_response->clientdata_json);
    OPENSSL_free(auth_response->signature);
    OPENSSL_free(auth_response->user_id);
    OPENSSL_free(auth_response);
}

void free_pre_response(struct pre_response *pre_response) {
    if (pre_response == NULL) {
        return;
    }
    OPENSSL_free(pre_response->eph_user_id);
    OPENSSL_clear_free(pre_response->gcm_key, pre_response->gcm_key_len);
    OPENSSL_free(pre_response);
}

void free_reg_indication(struct reg_indication *reg_indication) {
    if (reg_indication == NULL) {
        return;
    }
    OPENSSL_free(reg_indication->eph_user_id);
    OPENSSL_free(reg_indication->encrypted_data);
    OPENSSL_free(reg_indication);
}

void free_reg_request(struct reg_request *reg_request) {
    if (reg_request == NULL) {
        return;
    }
    OPENSSL_free(reg_request->challenge);
    OPENSSL_free(reg_request->rp_id);
    OPENSSL_free(reg_request->rp_name);

    OPENSSL_free(reg_request->pub_key_cred_params);
    OPENSSL_free(reg_request);
}

void free_reg_response(struct reg_response *reg_response) {
    if (reg_response == NULL) {
        return;
    }
    OPENSSL_free(reg_response->attestation_object);
    OPENSSL_free(reg_response->clientdata_json);
    OPENSSL_free(reg_response);
}

void free_authdata(struct authdata *authdata) {
    if (authdata == NULL) {
        return;
    }
    OPENSSL_free(authdata->rp_id_hash);
    OPENSSL_free(authdata->aaguid);
    OPENSSL_free(authdata->cred_id);
    OPENSSL_free(authdata->pubkey);
    OPENSSL_free(authdata);
}

void free_credential(struct credential *cred) {
    OPENSSL_free(cred->type);
    OPENSSL_free(cred->id);
    OPENSSL_free(cred->transports);
    OPENSSL_free(cred->pubkey_cose);
    OPENSSL_free(cred);
}
