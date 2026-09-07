#include "serialize.h"
#include "common.h"
#include "debug.h"
#include "types.h"
#include <cbor.h>
#include <openssl/crypto.h>

#define CBOR_ATTR_PACKET_TYPE 0
#define CBOR_ATTR_CHALLENGE 1
#define CBOR_ATTR_RP_ID 2
#define CBOR_ATTR_RP_NAME 3
#define CBOR_ATTR_USER_VERIFICATION 4
#define CBOR_ATTR_CLIENT_DATA 5
#define CBOR_ATTR_AUTHENTICATOR_DATA 6
#define CBOR_ATTR_SIGNATURE 7
#define CBOR_ATTR_USER_ID 8
#define CBOR_ATTR_CRED_ID 9
#define CBOR_ATTR_CRED_PARAMS 10
#define CBOR_ATTR_EPH_USER_ID 11
#define CBOR_ATTR_USER_ID_KEY 12
#define CBOR_ATTR_USER_NAME 13
#define CBOR_ATTR_ENC_USER_ID 14
#define CBOR_ATTR_ENC_USER_NAME 15
#define CBOR_ATTR_ATT_STMT 16
#define CBOR_ATTR_PUBKEY 17

#define TIMEOUT 1
#define AUTH_SEL 2
#define EXCLUDE_CREDS 3
#define RPID 2
#define USER_VERIFICATION 3
#define USER_ID 1
#define CRED_ID 2
#define AUTH_ATTACH 1
#define RESIDENT_KEY 2
#define ATTESTATION 4
#define EXTENSIONS 5

// Buf size is limited by the TLS record size (~16KB). For the fido protocol
// however, 128 bytes should be enough for the largest packet.
#define BUF_SIZE 2000
//Define buf size for the encrypted data CBOR array
#define ENC_DATA_BUF_SIZE 1000

const char *get_package_type_name(unsigned int type) {
    switch (type) {
    case PKT_PRE_INDICATION:
        return "PRE_INDICATION";
    case PKT_PRE_RESPONSE:
        return "PRE_RESPONSE";
    case PKT_REG_INDICATION:
        return "REG_INDICATION";
    case PKT_REG_REQUEST:
        return "REG_REQUEST";
    case PKT_REG_RESPONSE:
        return "REG_RESPONSE";
    case PKT_AUTH_INDICATION:
        return "AUTH_INDICATION";
    case PKT_AUTH_REQUEST:
        return "AUTH_REQUEST";
    case PKT_AUTH_RESPONSE:
        return "AUTH_RESPONSE";
    default:
        return "Unknown Type";
    }
}

int cbor_parse(const u8 *in_buf, size_t in_len, enum packet_type *type, void *out) {
    CborParser parser;
    CborValue root, it, sub_it, sub_sub_it, map_it, sub_map_it;
    CborError err;
    size_t len, array_len;
    if (in_len <= 0) {
        debug_printf(DEBUG_LEVEL_ERROR, "No data to parse");
        return -1;
    }
    err = cbor_parser_init(in_buf, in_len, 0, &parser, &root);
    if (err != CborNoError) {
        debug_printf(DEBUG_LEVEL_ERROR, "Error initializing CBOR parser");
        goto err;
    }
    if (!cbor_value_is_array(&root)) {
        debug_printf(DEBUG_LEVEL_ERROR, "Root container is not an array\n");
        return -1;
    }
    cbor_value_get_array_length(&root, &array_len);
    cbor_value_enter_container(&root, &it);
    if (!cbor_value_is_integer(&it)) {
        debug_printf(DEBUG_LEVEL_ERROR, "Packet type is not an integer");
        goto err;
    }
    int packet_type;
    cbor_value_get_int_checked(&it, &packet_type);
    // If the caller does not specify the expected packet type, we accept any
    // packet type and return the actual packet type in the type parameter
    if (*type == UNDEFINED) {
        *type = packet_type;
    } else if (packet_type != *type) {
        debug_printf(DEBUG_LEVEL_ERROR,
                     "Received packet type: %d, expected: %d", packet_type,
                     *type);
        goto err;
    }
    debug_printf(DEBUG_LEVEL_VERBOSE, "Received packet: %s",
                 get_package_type_name(*type));
    switch (*type) {
    case PKT_PRE_INDICATION: {
        out = NULL;
        break;
    }
    case PKT_PRE_RESPONSE: {
        //The parser should accept exactly 3
        if (array_len != 3) {
            debug_printf(DEBUG_LEVEL_ERROR, "Malformed pre response");
            goto err;
        }
        struct pre_response *p = (struct pre_response *)out;
        if (!p) {
            debug_printf(DEBUG_LEVEL_ERROR, "Memory allocation failed");
            goto err;
        }
        cbor_value_advance(&it);
        if (!cbor_value_is_byte_string(&it)) {
            debug_printf(DEBUG_LEVEL_ERROR,
                         "Ephemeral user id is not a byte string");
            goto err;
        }
        cbor_value_calculate_string_length(&it, &p->eph_user_id_len);
        //the length of ephemeral user id should be exactly 256 bytes according to I-D, Section 12.2
        //the length should be checked directly after it was read from CBOR header
        if(p->eph_user_id_len!=256){
            debug_printf(DEBUG_LEVEL_ERROR, "Length of ephemeral user id is not 256 bytes");
            goto err;
        }
        p->eph_user_id = OPENSSL_zalloc(p->eph_user_id_len);
        cbor_value_copy_byte_string(&it, p->eph_user_id, &p->eph_user_id_len,
                                    &it);
        debug_print_hex(DEBUG_LEVEL_VERBOSE,
                        "    eph user id: ", p->eph_user_id,
                        p->eph_user_id_len);
        if (!cbor_value_is_byte_string(&it)) {
            debug_printf(DEBUG_LEVEL_ERROR, "GCM key is not a byte string");
            goto err;
        }
        cbor_value_calculate_string_length(&it, &p->gcm_key_len);
        //the length of GCM key should be exactly 32 bytes according to I-D, Section 12.2
        //the length should be checked directly after it was read from CBOR header
        if(p->gcm_key_len!=32){
            debug_printf(DEBUG_LEVEL_ERROR, "Length of gcm key is not 32 bytes");
            goto err;
        }
        p->gcm_key = OPENSSL_zalloc(p->gcm_key_len);
        cbor_value_copy_byte_string(&it, p->gcm_key, &p->gcm_key_len, &it);
        debug_print_hex(DEBUG_LEVEL_VERBOSE, "    gcm key: ", p->gcm_key,
                        p->gcm_key_len);
        break;
    }
    case PKT_REG_INDICATION: {
        if (array_len != 3) {
            debug_printf(DEBUG_LEVEL_ERROR, "Malformed reg indication");
            goto err;
        }
        struct reg_indication *p = (struct reg_indication *)out;
        if (!p) {
            debug_printf(DEBUG_LEVEL_ERROR, "Memory allocation failed!");
            goto err;
        }
        cbor_value_advance(&it);
        if (!cbor_value_is_byte_string(&it)) {
            debug_printf(DEBUG_LEVEL_ERROR,
                         "Ephemeral user id is not a byte string");
            goto err;
        }
        cbor_value_calculate_string_length(&it, &p->eph_user_id_len);
        if(p->eph_user_id_len != 256){
            debug_printf(DEBUG_LEVEL_ERROR, "Length of ephemeral user id is not 256 byte");
            goto err;
        }
        p->eph_user_id = OPENSSL_zalloc(p->eph_user_id_len);
        cbor_value_copy_byte_string(&it, p->eph_user_id, &p->eph_user_id_len,
                                    &it);
        debug_print_hex(DEBUG_LEVEL_VERBOSE,
                        "    eph user id: ", p->eph_user_id,
                        p->eph_user_id_len);
        if (!cbor_value_is_byte_string(&it)) {
            debug_printf(DEBUG_LEVEL_ERROR,
                         "Encrypted data is not a byte string");
            goto err;
        }
        cbor_value_calculate_string_length(&it, &p->encrypted_data_len);
        p->encrypted_data = OPENSSL_zalloc(p->encrypted_data_len);
        cbor_value_copy_byte_string(&it, p->encrypted_data,
                                    &p->encrypted_data_len, &it);
        debug_print_hex(DEBUG_LEVEL_VERBOSE,
                        "    encrypted data: ", p->encrypted_data,
                        p->encrypted_data_len);
        break;
    }
    case PKT_REG_REQUEST: {
        //Now less than 6, because only 6 are required and optionals ill implement later
        if (array_len != 6 && array_len != 7) {
            debug_printf(DEBUG_LEVEL_ERROR, "Malformed reg request");
            goto err;
        }
        struct reg_request *p = (struct reg_request *)out;
        if (!p) {
            debug_printf(DEBUG_LEVEL_ERROR, "Memory allocation failed!");
            goto err;
        }

        //Parsing RP ID
        cbor_value_advance(&it);
        if (!cbor_value_is_text_string(&it)) {
            debug_printf(DEBUG_LEVEL_ERROR, "RP ID is not a text string");
            goto err;
        }
        cbor_value_calculate_string_length(&it, &len);
        if (len<1||len>256){
            debug_printf(DEBUG_LEVEL_ERROR, "Size of RP ID is not within allowed range");
            goto err;
        }
        p->rp_id = OPENSSL_zalloc(len + 1); // +1 for null terminator
        cbor_value_copy_text_string(&it, p->rp_id, &len, &it);
        debug_printf(DEBUG_LEVEL_VERBOSE, "    rp id: %s", p->rp_id);

        //Parsing RP name

        if (!cbor_value_is_text_string(&it)) {
            debug_printf(DEBUG_LEVEL_ERROR, "RP name is not a text string");
            goto err;
        }
        cbor_value_calculate_string_length(&it, &len);
        if(len<1||len>256){
            debug_printf(DEBUG_LEVEL_ERROR, "Size of RP name is not within allowed range");
            goto err;
        }
        p->rp_name = OPENSSL_zalloc(len + 1); // +1 for null terminator
        cbor_value_copy_text_string(&it, p->rp_name, &len, &it);
        debug_printf(DEBUG_LEVEL_VERBOSE, "    rp name: %s", p->rp_name);
     
        //Parsing Challenge
       
        if (!cbor_value_is_byte_string(&it)) {
            debug_printf(DEBUG_LEVEL_ERROR, "Challenge is not a byte string");
            goto err;
        }
        cbor_value_calculate_string_length(&it, &p->challenge_len);
        if(p->challenge_len<16||p->challenge_len>64){
            debug_printf(DEBUG_LEVEL_ERROR, "Size of challenge is not within allowed range");
            goto err;
        }
        p->challenge = OPENSSL_zalloc(p->challenge_len);
        cbor_value_copy_byte_string(&it, p->challenge, &p->challenge_len, &it);
        debug_print_hex(DEBUG_LEVEL_VERBOSE, "    challenge: ", p->challenge,
                        p->challenge_len);

        //Parsing Pub key cred params                 
        //Der Vorgang ist hier gleich wie beim encrypted data array, verschachtelte arrays
        if (!cbor_value_is_array(&it)) {
            debug_printf(DEBUG_LEVEL_ERROR,
                         "Pubkey cred params is not an array");
            goto err;
        }
        cbor_value_get_array_length(&it, &p->pub_key_cred_params_len);
        p->pub_key_cred_params =
            OPENSSL_zalloc(p->pub_key_cred_params_len * sizeof(struct pub_key_cred_param));
        if (p->pub_key_cred_params_len < 1) {
            debug_printf(DEBUG_LEVEL_ERROR,
                         "Pub key cred params array is empty");
            goto err;
        }
        uint64_t type_temp;
        cbor_value_enter_container(&it, &sub_it);
        debug_printf(DEBUG_LEVEL_VERBOSE, "    pub key cred params:");
        for (size_t i = 0; i < p->pub_key_cred_params_len; i++) {
            if (!cbor_value_is_array(&sub_it)) {
                debug_printf(DEBUG_LEVEL_ERROR,  "pub key cred param is not an array");
            goto err;
            }
            cbor_value_enter_container(&sub_it, &sub_sub_it);
            if (!cbor_value_is_unsigned_integer(&sub_sub_it)) {
                debug_printf(DEBUG_LEVEL_ERROR,  "Type is not an unsigned integer");
                goto err;
            }
            cbor_value_get_uint64(&sub_sub_it, &type_temp);
            if(type_temp != PUBLIC_KEY){
                debug_printf(DEBUG_LEVEL_ERROR, "Type is not a public key");
                return -1;
            }
            p->pub_key_cred_params[i].type = PUBLIC_KEY;

            cbor_value_advance(&sub_sub_it);

            if(!cbor_value_is_integer(&sub_sub_it)){
                debug_printf(DEBUG_LEVEL_ERROR, "The alg is not an integer");
                return -1;
            }
            cbor_value_get_int_checked(&sub_sub_it, &p->pub_key_cred_params[i].alg);
            cbor_value_advance(&sub_sub_it);
            debug_printf(DEBUG_LEVEL_VERBOSE, "        %s",
                         get_cose_algorithm_name(p->pub_key_cred_params[i].alg));
            if(!cbor_value_at_end(&sub_sub_it)){
    //TODO: Später die allgemeneine goto err implementieren
                return -1;
            }
            err = cbor_value_leave_container(&sub_it, &sub_sub_it);     
            if(err!=CborNoError){
                debug_printf(DEBUG_LEVEL_ERROR, "Leaving the sub sub container failed");
                return -1;
            }        
        }
        if(!cbor_value_at_end(&sub_it)){
            return -1;
        }
        err = cbor_value_leave_container(&it, &sub_it);
        if (err != CborNoError) {
            debug_printf(DEBUG_LEVEL_ERROR, "Leaving sub container failed");
            goto err;
        }   
        if (!cbor_value_is_byte_string(&it)) {
            debug_printf(DEBUG_LEVEL_ERROR,
                         "Encrypted data is not a byte string");
            goto err;
        }
        cbor_value_calculate_string_length(&it, &p->encrypted_data_len);
        p->encrypted_data = OPENSSL_zalloc(p->encrypted_data_len);
        cbor_value_copy_byte_string(&it, p->encrypted_data, &p->encrypted_data_len, &it);
        debug_print_hex(DEBUG_LEVEL_VERBOSE, 
                    "    encrypted_data: ", p->encrypted_data, 
                    p->encrypted_data_len);
       

        //default values
        p->auth_sel.resident_key = RK_DISCOURAGED;
        p->auth_sel.user_verification = UV_PREFERRED;
        p->attestation = NONE;

        //If the message contains 6 elements we must check, whether we are at the end of the array and exit properly orr display an error
        if(array_len == 6){
            if(!cbor_value_at_end(&it)){
                return -1;
                break;       
            }
        }
        //else then process the optional map 
        if (!cbor_value_is_map(&it)) {
            debug_printf(DEBUG_LEVEL_ERROR,
                         "Expected a map container for optional values");
            goto err;
        }
         cbor_value_enter_container(&it, &map_it);
         while(!cbor_value_at_end(&map_it)){
            uint64_t key;
            if (!cbor_value_is_unsigned_integer(&map_it)) {
                debug_printf(DEBUG_LEVEL_ERROR, "Map key is not an integer");
                goto err;
            }
            cbor_value_get_uint64(&map_it, &key);
            cbor_value_advance(&map_it); 
            switch (key) {  
                case TIMEOUT:
                if (!cbor_value_is_unsigned_integer(&map_it)) {
                    debug_printf(DEBUG_LEVEL_ERROR,
                                "Timeout is not an unsigned integer");
                    goto err;
                }
                uint64_t timeout;
                cbor_value_get_uint64(&map_it, &timeout);
                p->timeout = timeout;
                debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    timeout: %d ms",
                             timeout);
                cbor_value_advance(&map_it);             
                break;



                case AUTH_SEL:
                if (!cbor_value_is_map(&map_it)) {
                    debug_printf(DEBUG_LEVEL_ERROR,
                        "Expected a map container for authenticator selection criteria");
                    goto err;
                }
                cbor_value_enter_container(&map_it, &sub_map_it);
                while(!cbor_value_at_end(&sub_map_it)){
                    uint64_t criteria;
                    if (!cbor_value_is_unsigned_integer(&sub_map_it)) {
                        debug_printf(DEBUG_LEVEL_ERROR, "Map key is not an integer");
                        goto err;
                    }
                    cbor_value_get_uint64(&sub_map_it, &criteria);
                    cbor_value_advance(&sub_map_it); 
                    switch (criteria){
                        case AUTH_ATTACH:
                        if(!cbor_value_is_unsigned_integer(&sub_map_it)){
                            debug_printf(DEBUG_LEVEL_ERROR, "Authenticator attachment is not an unsigned integer");
                            return -1;
                        }

                        uint64_t attachment;
                        cbor_value_get_uint64(&sub_map_it, &attachment);
                        if(attachment != PLATFORM && attachment != CROSS_PLATFORM){
                            debug_printf(DEBUG_LEVEL_ERROR, "Not recognized autheticator attachment");
                            return -1;
                        }
                        p->auth_sel.attachment = attachment;
                        debug_printf(DEBUG_LEVEL_MORE_VERBOSE,
                            "    authenticator attachment: %s",  attachment == 1 ? "PLATFORM" : "CROSS_PLATFORM" );

                        break;

                        case RESIDENT_KEY:
                        if(!cbor_value_is_unsigned_integer(&sub_map_it)){
                            debug_printf(DEBUG_LEVEL_ERROR, "Resident key is not an unsigned integer");
                            return -1;
                        }
                        uint64_t resident_key;
                        cbor_value_get_uint64(&sub_map_it, &resident_key);
                        if(resident_key != RK_DISCOURAGED && resident_key != RK_PREFERRED && resident_key != RK_REQUIRED){
                            debug_printf(DEBUG_LEVEL_ERROR, "Not recognized resident key");
                            return -1;
                        }
                        p->auth_sel.resident_key = resident_key;


                        //TODO: Ausgabe von resident key reqirements


                        debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    resident key: %s",
                                get_resident_key_requirements_name(resident_key));   
                        break;

                
                        case USER_VERIFICATION:
                        if(!cbor_value_is_unsigned_integer(&sub_map_it)){
                            debug_printf(DEBUG_LEVEL_ERROR, " User verification requirement is not an unsigned integer");
                            return -1;
                        }
                        uint64_t user_verification;
                        cbor_value_get_uint64(&sub_map_it, &user_verification);
                        if(user_verification != UV_DISCOURAGED && user_verification != UV_PREFERRED && user_verification != UV_REQUIRED){
                            debug_printf(DEBUG_LEVEL_ERROR, "Not recognized user verification requirement");
                            return -1;
                        }
                        p->auth_sel.user_verification = user_verification;
                        break;
        


                        default:
                        debug_printf(DEBUG_LEVEL_ERROR, "Unknown optional parameter");
                        return -1;
                    
                        break;
                    }
                    cbor_value_advance(&sub_map_it);
                }
                err = cbor_value_leave_container(&map_it, &sub_map_it);
                if (err != CborNoError) {
                    debug_printf(DEBUG_LEVEL_ERROR, "Leaving sub map container failed");
                    goto err;
                }
                break;  

                case ATTESTATION:
                if(!cbor_value_is_unsigned_integer(&map_it)){
                    debug_printf(DEBUG_LEVEL_ERROR, "Attestation conveyance is not an unsigned integer");
                    return -1;
                }
                uint64_t attestation;
                cbor_value_get_uint64(&map_it, &attestation);
                if(attestation != NONE && attestation != INDIRECT && attestation != DIRECT && attestation != ENTERPRISE){
                    debug_printf(DEBUG_LEVEL_ERROR, "Not recognized attestation conveyance prefernce");
                    return -1;
                }
                p->attestation = attestation;
                debug_printf(DEBUG_LEVEL_VERBOSE, "        %s",
                        get_attestation_conveyance_pref_name(p->attestation));
                cbor_value_advance(&map_it);
                break;                
                case EXTENSIONS:
                if (!cbor_value_is_map(&map_it)) {
                    debug_printf(DEBUG_LEVEL_ERROR,
                        "Expected a map container for extensions");
                    goto err;
                }
                cbor_value_get_map_length(&map_it, &len);
                p->extensions_len = len;
                p->extensions = OPENSSL_zalloc(p->extensions_len * sizeof(struct extension));
                cbor_value_enter_container(&map_it, &sub_map_it);
                    for(size_t i = 0;i < p->extensions_len; i++ ){
                        if (!cbor_value_is_text_string(&sub_map_it)) {
                            debug_printf(DEBUG_LEVEL_ERROR, "Extension id is not a text string");
                            return -1;
                        }
                        cbor_value_calculate_string_length(&sub_map_it, &len);
                        if(len<1||len>256){
                            debug_printf(DEBUG_LEVEL_ERROR, "Size of extension id is not within allowed range");
                            goto err;
                        }
                        p->extensions[i].extension_id_len = len;
                        p->extensions[i].extension_id = OPENSSL_zalloc(len + 1);
                        cbor_value_copy_text_string(&sub_map_it, p->extensions[i].extension_id, &len, &sub_map_it);
                       // debug_print(DEBUG_LEVEL_VERBOSE, "   extension id:  ",  p->extensions[i].extension_id, p->extensions[i].extension_id_len);

                        if(!cbor_value_is_byte_string(&sub_map_it)) {
                            debug_printf(DEBUG_LEVEL_ERROR, "extension data is not a byte string");
                            return -1;
                        }
                        cbor_value_calculate_string_length(&sub_map_it, &len);
                        if(len<1||len>4096){
                            debug_printf(DEBUG_LEVEL_ERROR, "Size of extension data is not within allowed range");
                            goto err;
                        }
                        p->extensions[i].extension_data_len = len;
                        p->extensions[i].extension_data = OPENSSL_zalloc(len);
                        cbor_value_copy_byte_string(&sub_map_it, p->extensions[i].extension_data, &len, &sub_map_it);
                        //debug_print_hex(DEBUG_LEVEL_VERBOSE, " extension data:  %zu ", p->extensions[i].extension_data,  p->extensions[i].extension_data_len);
                    }
                    if(!cbor_value_at_end(&sub_map_it)){
                        return -1;
                    }
                    cbor_value_leave_container(&map_it, &sub_map_it);
                break;
                


                default:
                debug_printf(DEBUG_LEVEL_ERROR, "Unknown optional parameter");
                cbor_value_advance(&map_it);
                break;
            }
        }
        cbor_value_leave_container(&it, &map_it);
         
        if(!cbor_value_at_end(&it)){
            return -1;
        }
        break;
    }
    case PKT_REG_RESPONSE: {
        if (array_len < 2) {
            debug_printf(DEBUG_LEVEL_ERROR, "Malformed reg response");
            goto err;
        }
        struct reg_response *p = (struct reg_response *)out;
        if (!p) {
            debug_printf(DEBUG_LEVEL_ERROR, "Memory allocation failed!");
            goto err;
        }
        cbor_value_advance(&it);
        if (!cbor_value_is_byte_string(&it)) {
            debug_printf(DEBUG_LEVEL_ERROR, "Authdata is not a byte string");
            goto err;
        }
        cbor_value_calculate_string_length(&it, &p->authdata_len);
        p->authdata = OPENSSL_zalloc(p->authdata_len);
        cbor_value_copy_byte_string(&it, p->authdata, &p->authdata_len, &it);
        debug_print_hex(DEBUG_LEVEL_MORE_VERBOSE, "    authdata: ", p->authdata,
                        p->authdata_len);
        if (!cbor_value_is_text_string(&it)) {
            debug_printf(DEBUG_LEVEL_ERROR, "Clientdata is not a text string");
            goto err;
        }
        cbor_value_calculate_string_length(&it, &len);
        p->clientdata_json = OPENSSL_zalloc(len + 1); // +1 for null terminator
        cbor_value_copy_text_string(&it, p->clientdata_json, &len, &it);
        debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    clientdata: %s",
                     p->clientdata_json);
        break;
    }
    case PKT_AUTH_INDICATION: {
        out = NULL;
        break;
    }
    case PKT_AUTH_REQUEST: {
        struct auth_request *p = (struct auth_request *)out;
        if (!p) {
            debug_printf(DEBUG_LEVEL_ERROR, "Memory allocation failed!");
            goto err;
        }
        err = cbor_value_advance(&it);
        if (err != CborNoError) {
            debug_printf(DEBUG_LEVEL_ERROR, "Advancing failed");
            goto err;
        }
        if (!cbor_value_is_byte_string(&it)) {
            debug_printf(DEBUG_LEVEL_ERROR, "Challenge is not a byte string");
            goto err;
        }
        cbor_value_calculate_string_length(&it, &p->challenge_len);
        p->challenge = OPENSSL_zalloc(p->challenge_len);
        cbor_value_copy_byte_string(&it, p->challenge, &p->challenge_len, &it);
        debug_print_hex(DEBUG_LEVEL_MORE_VERBOSE, "    challenge: ", p->challenge,
                        p->challenge_len);
        if (cbor_value_at_end(&it)) {
            break;
        }
        // Optional values
        if (!cbor_value_is_map(&it)) {
            debug_printf(DEBUG_LEVEL_ERROR,
                         "Expected a map for optional values");
            goto err;
        }
        cbor_value_enter_container(&it, &map_it);
        while (!cbor_value_at_end(&map_it)) {
            int key;
            if (!cbor_value_is_integer(&map_it)) {
                debug_printf(DEBUG_LEVEL_ERROR, "Map key is not an integer");
                goto err;
            }
            cbor_value_get_int_checked(&map_it, &key);
            cbor_value_advance(&map_it);
            switch (key) {
            case TIMEOUT:
                if (!cbor_value_is_integer(&map_it)) {
                    debug_printf(DEBUG_LEVEL_ERROR,
                                 "Timeout is not an integer");
                    goto err;
                }
                cbor_value_get_int_checked(&map_it, &p->timeout);
                debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    timeout: %d ms",
                             p->timeout);
                cbor_value_advance(&map_it);
                break;
            case RPID:
                if (!cbor_value_is_text_string(&map_it)) {
                    debug_printf(DEBUG_LEVEL_ERROR,
                                 "RP ID is not a text string");
                    goto err;
                }
                cbor_value_calculate_string_length(&map_it, &len);
                p->rp_id = OPENSSL_zalloc(len + 1); // +1 for null terminator
                cbor_value_copy_text_string(&map_it, p->rp_id, &len, &map_it);
                debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    rp id: %s", p->rp_id);
                break;
            case USER_VERIFICATION:
                if (!cbor_value_is_integer(&map_it)) {
                    debug_printf(DEBUG_LEVEL_ERROR,
                                 "User verification is not an integer");
                    goto err;
                }
                int user_verification;
                cbor_value_get_int_checked(&map_it, &user_verification);
                p->user_verification = user_verification;
                debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    user verification: %s",
                             get_user_verification_requirements_name(user_verification));
                cbor_value_advance(&map_it);
                break;
            default:
                // We dont error out here, because the fido spec mandates to be
                // graceful with unknown keys, as the spec might be extended in
                // the future.
                debug_printf(DEBUG_LEVEL_VERBOSE, "Unknown map key");
                break;
            }
        }
        break;
    }
    case PKT_AUTH_RESPONSE: {
        struct auth_response *p = (struct auth_response *)out;
        if (!p) {
            debug_printf(DEBUG_LEVEL_ERROR, "Memory allocation failed!");
            goto err;
        }
        err = cbor_value_advance(&it);
        if (err != CborNoError) {
            debug_printf(DEBUG_LEVEL_ERROR, "Advancing failed");
            goto err;
        }
        if (!cbor_value_is_text_string(&it)) {
            debug_printf(DEBUG_LEVEL_ERROR, "Clientdata is not a text string");
            goto err;
        }
        cbor_value_calculate_string_length(&it, &len);
        p->clientdata_json = OPENSSL_zalloc(len + 1); // +1 for null terminator
        cbor_value_copy_text_string(&it, p->clientdata_json, &len, &it);
        debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    clientdata: %s",
                     p->clientdata_json);
        if (!cbor_value_is_byte_string(&it)) {
            debug_printf(DEBUG_LEVEL_ERROR,
                         "Authenticator data is not a byte string");
            goto err;
        }
        cbor_value_calculate_string_length(&it, &p->authdata_len);
        p->authdata = OPENSSL_zalloc(p->authdata_len);
        cbor_value_copy_byte_string(&it, p->authdata, &p->authdata_len, &it);
        debug_print_hex(DEBUG_LEVEL_MORE_VERBOSE,
                        "    authenticator data: ", p->authdata,
                        p->authdata_len);
        if (!cbor_value_is_byte_string(&it)) {
            debug_printf(DEBUG_LEVEL_ERROR, "Signature is not a byte string");
            goto err;
        }
        cbor_value_calculate_string_length(&it, &p->signature_len);
        p->signature = OPENSSL_zalloc(p->signature_len);
        cbor_value_copy_byte_string(&it, p->signature, &p->signature_len, &it);
        debug_print_hex(DEBUG_LEVEL_MORE_VERBOSE, "    signature: ", p->signature,
                        p->signature_len);
        if (cbor_value_at_end(&it)) {
            break;
        }
        // Optional values
        if (!cbor_value_is_map(&it)) {
            debug_printf(DEBUG_LEVEL_ERROR,
                         "Expected a map for optional values");
            goto err;
        }
        cbor_value_enter_container(&it, &map_it);
        while (!cbor_value_at_end(&map_it)) {
            int key;
            if (!cbor_value_is_integer(&map_it)) {
                debug_printf(DEBUG_LEVEL_ERROR, "Map key is not an integer");
                goto err;
            }
            cbor_value_get_int_checked(&map_it, &key);
            cbor_value_advance(&map_it);
            switch (key) {
            case USER_ID:
                if (!cbor_value_is_byte_string(&map_it)) {
                    debug_printf(DEBUG_LEVEL_ERROR, "User id is not a byte string");
                    goto err;
                }
                cbor_value_calculate_string_length(&map_it, &p->user_id_len);
                p->user_id = OPENSSL_zalloc(p->user_id_len);
                cbor_value_copy_byte_string(&map_it, p->user_id, &p->user_id_len, &map_it);
                debug_print_hex(DEBUG_LEVEL_MORE_VERBOSE, "    user id: ", p->user_id,
                                p->user_id_len);
                break;
            case CRED_ID:
                if (!cbor_value_is_byte_string(&map_it)) {
                    debug_printf(DEBUG_LEVEL_ERROR, "Cred id is not a byte string");
                    goto err;
                }
                cbor_value_calculate_string_length(&map_it, &p->cred_id_len);
                p->cred_id = OPENSSL_zalloc(p->cred_id_len);
                cbor_value_copy_byte_string(&map_it, p->cred_id, &p->cred_id_len, &map_it);
                debug_print_hex(DEBUG_LEVEL_MORE_VERBOSE, "    cred id: ", p->cred_id,
                                p->cred_id_len);
                break;
            default:
                // We dont error out here, because the fido spec mandates to be
                // graceful with unknown keys, as the spec might be extended in
                // the future.
                debug_printf(DEBUG_LEVEL_VERBOSE, "Unknown map key");
                break;
            }
        }
        break;
    }
    default:
        debug_printf(DEBUG_LEVEL_ERROR, "Unknown packet type");
        goto err;
    }
    return 0;
err:
    // TODO cleanup
    return -1;
}



int cbor_parse_encrypted_data( const u8 *in_buf, size_t in_len, struct encrypted_data *output){
    CborParser parser;
    CborValue root, it;
    CborError err;
    size_t  array_len;
    if (in_len <= 0) {
        debug_printf(DEBUG_LEVEL_ERROR, "No data to parse");
        return -1;
    }
    err = cbor_parser_init(in_buf, in_len, 0, &parser, &root);
    if (err != CborNoError) {
        debug_printf(DEBUG_LEVEL_ERROR, "Error initializing CBOR parser");
        goto err;
    }
    if (!cbor_value_is_array(&root)) {
        debug_printf(DEBUG_LEVEL_ERROR, "Root container is not an array\n");
        return -1;
    }
    cbor_value_get_array_length(&root, &array_len);
    cbor_value_enter_container(&root, &it);

    if (array_len != 2) {
        debug_printf(DEBUG_LEVEL_ERROR, "Malformed encrypted data");
        goto err;
    }
    if(!output){
        debug_printf(DEBUG_LEVEL_ERROR, "Memory allocation failed");
        goto err;
    }
    if(!cbor_value_is_byte_string(&it)){
        debug_printf(DEBUG_LEVEL_ERROR, "Display user name is not a byte string");
        goto err;
    }
    cbor_value_calculate_string_length(&it, &output->padded_user_display_name_len);
    if(output->padded_user_display_name_len!=256){
        debug_printf(DEBUG_LEVEL_ERROR, "Length of the user display name is not 256 bytes"); 
        goto err;   
    }
    output->padded_user_display_name = OPENSSL_zalloc(output->padded_user_display_name_len);
    cbor_value_copy_byte_string(&it, output->padded_user_display_name, &output->padded_user_display_name_len,
                                &it);
    debug_print_hex(DEBUG_LEVEL_VERBOSE, 
                    "    user display name: ", output->padded_user_display_name,
                                               output->padded_user_display_name_len); 

    if(!cbor_value_is_byte_string(&it)){
        debug_printf(DEBUG_LEVEL_ERROR, "ticket is not a byte string");
        goto err;
    }   
    cbor_value_calculate_string_length(&it,&output->ticket_len);
    if(output->ticket_len!=256){
        debug_printf(DEBUG_LEVEL_ERROR, "Length of the ticket is not 256 bytes");  
        goto err; 
    }
    output->ticket = OPENSSL_zalloc(output->ticket_len);
    cbor_value_copy_byte_string(&it, output->ticket, &output->ticket_len,&it);
    
    return 0;

    err: 
        return -1;
}

int cbor_parse_reg_request_encrypted_data(const u8 *in_buf, size_t in_len, struct reg_request_encrypted_data *output){
    CborParser parser;
    CborValue root, it, sub_it, sub_sub_it;
    CborError err;
    size_t  array_len;
    uint64_t type_temp;
    if (in_len <= 0) {
        debug_printf(DEBUG_LEVEL_ERROR, "No data to parse");
        return -1;
    }
    err = cbor_parser_init(in_buf, in_len, 0, &parser, &root);
    if (err != CborNoError) {
        debug_printf(DEBUG_LEVEL_ERROR, "Error initializing CBOR parser");
        goto err;
    }
    if (!cbor_value_is_array(&root)) {
        debug_printf(DEBUG_LEVEL_ERROR, "Root container is not an array\n");
        return -1;
    }
    cbor_value_get_array_length(&root, &array_len);
    cbor_value_enter_container(&root, &it);
    if (array_len > 4 || array_len < 3 ) {
        debug_printf(DEBUG_LEVEL_ERROR, "Malformed encrypted data");
        goto err;
    }
   

    if(!cbor_value_is_byte_string(&it)){
        debug_printf(DEBUG_LEVEL_ERROR, "User name is not a byte string");
        goto err;
    }
    cbor_value_calculate_string_length(&it, &output->padded_user_name_len);
    if(output->padded_user_name_len!=256){
        debug_printf(DEBUG_LEVEL_ERROR, "Length of padded user name is not 256");
        goto err;
    }
    output->padded_user_name = OPENSSL_zalloc(output->padded_user_name_len);
    if(output->padded_user_name == NULL){
        debug_printf(DEBUG_LEVEL_VERBOSE, "Memory allocation for padded user name failed");
        return -1;
    }
    cbor_value_copy_byte_string(&it, output->padded_user_name, &output->padded_user_name_len, &it);


    if(!cbor_value_is_byte_string(&it)){
        debug_printf(DEBUG_LEVEL_ERROR, "User name is not a byte string");
        goto err;
    }
    cbor_value_calculate_string_length(&it, &output->padded_user_display_name_len);
    if(output->padded_user_display_name_len!=256){
        debug_printf(DEBUG_LEVEL_ERROR, "Length of padded user display name is not 256");
        goto err;
    }
    output->padded_user_display_name = OPENSSL_zalloc(output->padded_user_display_name_len);
    if(output->padded_user_display_name == NULL){
        debug_printf(DEBUG_LEVEL_VERBOSE, "Memory allocation for padded user display name failed");
        return -1;
    }
    cbor_value_copy_byte_string(&it, output->padded_user_display_name, &output->padded_user_display_name_len, &it);
    //Soll man hier die gepaddete user display name ausgeben?


    if(!cbor_value_is_byte_string(&it)){
        debug_printf(DEBUG_LEVEL_ERROR, "User name is not a byte string");
        goto err;
    }
    cbor_value_calculate_string_length(&it, &output->user_id_len);
    if(output->user_id_len!=64){
        debug_printf(DEBUG_LEVEL_ERROR, "Length of user id is not 64");
        goto err;
    }
    output->user_id = OPENSSL_zalloc(output->user_id_len);
    if(output->user_id == NULL){
        debug_printf(DEBUG_LEVEL_ERROR, "Memory allocation for user id failed");
        return -1;
    }
    cbor_value_copy_byte_string(&it, output->user_id, &output->user_id_len, &it);

    if(array_len == 4){
        if(!cbor_value_is_array(&it)){
            debug_printf(DEBUG_LEVEL_ERROR, "Pub key credential descriptor is not an array");
            goto err;
        }
        cbor_value_get_array_length(&it, &output->exclude_credentials_len);
        output->exclude_credentials = OPENSSL_zalloc(output->exclude_credentials_len *  sizeof(*output->exclude_credentials));
        if(output->exclude_credentials == NULL){
            debug_printf(DEBUG_LEVEL_ERROR, "Memory allocation for the exclude credentials failed");
            goto err;
        }
        if(output->exclude_credentials_len < 1){
            debug_printf(DEBUG_LEVEL_ERROR, "Pub key credential descriptor is empty");
            goto err;
        }
        cbor_value_enter_container(&it, &sub_it);
        for(size_t i = 0; i < output->exclude_credentials_len; i++){
            if(!cbor_value_is_array(&sub_it)){
                debug_printf(DEBUG_LEVEL_ERROR, " Credential is not an array");
                goto err;
            }
            cbor_value_enter_container(&sub_it, &sub_sub_it);

            if(!cbor_value_is_unsigned_integer(&sub_sub_it)){
                debug_printf(DEBUG_LEVEL_ERROR, "Type is not an unsigned integer");
                goto err;
            }
            cbor_value_get_uint64(&sub_sub_it, &type_temp);
            if(type_temp != PUBLIC_KEY ){
                debug_printf(DEBUG_LEVEL_ERROR, "Descriptor type is not a public key");
                goto err;
            }
            output->exclude_credentials[i].type = PUBLIC_KEY;
       
            cbor_value_advance(&sub_sub_it);

            if(!cbor_value_is_byte_string(&sub_sub_it)){
                debug_printf(DEBUG_LEVEL_ERROR, "The id is not a byte string");
                return -1;
            }
            cbor_value_calculate_string_length(&sub_sub_it, &output->exclude_credentials[i].id_len);
            output->exclude_credentials[i].id = OPENSSL_zalloc(output->exclude_credentials[i].id_len);
            if(output->exclude_credentials[i].id == NULL){
                debug_printf(DEBUG_LEVEL_ERROR, "Memory allocation failed");
                return -1;
            }
            cbor_value_copy_byte_string(&sub_sub_it, output->exclude_credentials[i].id, &output->exclude_credentials[i].id_len, &sub_sub_it);
            if(!cbor_value_at_end(&sub_sub_it)){
                return -1;
            }
            err = cbor_value_leave_container(&sub_it, &sub_sub_it);
            if (err != CborNoError) {
                debug_printf(DEBUG_LEVEL_ERROR, "Leaving sub container failed");
                goto err;
            }
        }
        if(!cbor_value_at_end(&sub_it)){
            return -1;
        }  
        err = cbor_value_leave_container(&it, &sub_it);
        if (err != CborNoError) {
            debug_printf(DEBUG_LEVEL_ERROR, "Leaving sub container failed");
            goto err;
        } 
    }
    if(!cbor_value_at_end(&it)){
            return -1;
    }
    err = cbor_value_leave_container(&root, &it);
    if (err != CborNoError) {
        debug_printf(DEBUG_LEVEL_ERROR, "Leaving container failed");
        goto err;
    } 
    return 0;

    err:
        return -1;
}







int cbor_build(const void *input, enum packet_type type, const u8 **out_buf,
          size_t *out_len) {
    assert(type != UNDEFINED);

    u8 *buf = OPENSSL_zalloc(BUF_SIZE);
    if (!buf) {
        debug_printf(DEBUG_LEVEL_ERROR,
                     "Could not allocate memory for CBOR encoding");
        return -1;
    }
    CborEncoder encoder, array, sub_array, sub_sub_array, map, sub_map;
    cbor_encoder_init(&encoder, buf, 2000, 0);
    CborError err;

    debug_printf(DEBUG_LEVEL_VERBOSE, "Sending packet: %s",
                 get_package_type_name(type));
    switch (type) {
    case PKT_PRE_INDICATION: {
        // Encode just the packet type
        cbor_encoder_create_array(&encoder, &array, 1);
        cbor_encode_int(&array, PKT_PRE_INDICATION);
        break;
    }
    case PKT_PRE_RESPONSE: {
        struct pre_response *in = (struct pre_response *)input;
        assert(in->eph_user_id != NULL && in->eph_user_id_len != 0 &&
               in->gcm_key != NULL && in->gcm_key_len != 0);
        if(in->eph_user_id_len!=256){
            debug_printf(DEBUG_LEVEL_ERROR, "Length of ephemeral user id is not 256 bytes");
            goto err;
        }
        if(in->gcm_key_len != 32){
            debug_printf(DEBUG_LEVEL_ERROR, "Length of gcm key is not 32 bytes");
            goto err;
        }
        // Required fields are packet type, eph_user_id and gcm_key
        cbor_encoder_create_array(&encoder, &array, 3);
        cbor_encode_int(&array, PKT_PRE_RESPONSE);
        cbor_encode_byte_string(&array, in->eph_user_id, in->eph_user_id_len);
        debug_print_hex(DEBUG_LEVEL_MORE_VERBOSE,
                        "    eph user id: ", in->eph_user_id,
                        in->eph_user_id_len);
        cbor_encode_byte_string(&array, in->gcm_key, in->gcm_key_len);
        debug_print_hex(DEBUG_LEVEL_MORE_VERBOSE, "    gcm key: ", in->gcm_key,
                        in->gcm_key_len);
        break;
    }
    case PKT_REG_INDICATION: {
        struct reg_indication *in = (struct reg_indication *)input;
        assert(in->eph_user_id != NULL && in->eph_user_id_len != 0);
        assert(in->encrypted_data!=NULL && in->encrypted_data_len!=0);
        cbor_encoder_create_array(&encoder, &array, 3);
        cbor_encode_int(&array, PKT_REG_INDICATION);
        cbor_encode_byte_string(&array, in->eph_user_id, in->eph_user_id_len);
        debug_print_hex(DEBUG_LEVEL_MORE_VERBOSE,
                        "    eph user id: ", in->eph_user_id,
                        in->eph_user_id_len);
        cbor_encode_byte_string(&array, in->encrypted_data,
                        in->encrypted_data_len);
        debug_print_hex(DEBUG_LEVEL_MORE_VERBOSE,
                        "    encrypted data: ", in->encrypted_data,
                        in->encrypted_data_len);
        break;
    }
    case PKT_REG_REQUEST: {
        size_t pub_key_cred_param_len = 2;
        struct reg_request *in = (struct reg_request *)input;
        assert(in->challenge != NULL && in->challenge_len > 0 && 
               in->rp_id != NULL && in->rp_name != NULL &&
               in->pub_key_cred_params != NULL && in->pub_key_cred_params_len != 0 &&
               in->encrypted_data != NULL && in->encrypted_data_len > 0);

        // Count optional parameters
        size_t num_optionals = 0;
        size_t num_auth_sel_criteria = 0;
        bool attachment = false;
        bool resident_key = false;
        bool user_verification = false;

        if (in->timeout != 0)
            ++num_optionals;

        if (in->attestation != 0)   
            ++num_optionals;
         
        if (in->extensions != 0)
            ++num_optionals;
        
        if(in->auth_sel.attachment != 0 || in->auth_sel.resident_key != 0 || in->auth_sel.user_verification != 0) {
            ++num_optionals;
        } 
        if(in->auth_sel.attachment != 0){
            ++num_auth_sel_criteria;
            attachment = true;
        }
            
        if(in->auth_sel.resident_key != 0){
            ++num_auth_sel_criteria;  
            resident_key = true;
        }
         
        if(in->auth_sel.user_verification != 0){
            ++num_auth_sel_criteria;  
            user_verification = true;
        }
        // Required fields are packet type, challenge, rp_id, rp_name,
        // encrypted_data, which includes user_name, user_display_name, user_id and optional list
        // of excluded credentials; pubkey_cred_params: list of desiredd properties of the credential to be created.
        // If there are optional parameters, the last field
        cbor_encoder_create_array(&encoder, &array, num_optionals > 0 ? 7 : 6);
        cbor_encode_int(&array, PKT_REG_REQUEST);

        cbor_encode_text_stringz(&array, in->rp_id);
        debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    rp id: %s", in->rp_id);

        cbor_encode_text_stringz(&array, in->rp_name);
        debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    rp name: %s", in->rp_name);

        cbor_encode_byte_string(&array, in->challenge, in->challenge_len);
        debug_print_hex(DEBUG_LEVEL_MORE_VERBOSE, "    challenge: ", in->challenge,
                        in->challenge_len);

        
        cbor_encoder_create_array(&array, &sub_array, in->pub_key_cred_params_len);
        debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    pub key cred params:");
        for (size_t i = 0; i < in->pub_key_cred_params_len; i++) {
            cbor_encoder_create_array(&sub_array, &sub_sub_array, pub_key_cred_param_len);
            cbor_encode_uint(&sub_sub_array, in->pub_key_cred_params[i].type);
            cbor_encode_int(&sub_sub_array, in->pub_key_cred_params[i].alg);
            debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "        %s",
                         get_cose_algorithm_name(in->pub_key_cred_params[i].alg));

            err = cbor_encoder_close_container(&sub_array, &sub_sub_array);
            if (err != CborNoError) {
                debug_printf(DEBUG_LEVEL_ERROR, "Could not close CBOR array");
                goto err;
            }    
        }
        err = cbor_encoder_close_container(&array, &sub_array);
        if (err != CborNoError) {
            debug_printf(DEBUG_LEVEL_ERROR, "Could not close CBOR array");
            goto err;
        }                    
        cbor_encode_byte_string(&array, in->encrypted_data, in->encrypted_data_len);
        debug_print_hex(DEBUG_LEVEL_MORE_VERBOSE, "    encrypted data: ", in->encrypted_data,
                        in->encrypted_data_len);

        if(num_optionals > 0) {
            cbor_encoder_create_map(&array, &map, num_optionals);
            if (in->timeout != 0){
                cbor_encode_uint(&map, TIMEOUT);
                cbor_encode_uint(&map, in->timeout);
                debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    timeout: %d ms", in->timeout);
            }
            if (in->auth_sel.attachment != 0 || in->auth_sel.resident_key != 0 || in->auth_sel.user_verification != 0) {
                cbor_encode_uint(&map, AUTH_SEL);
                //auth sel is a map
                cbor_encoder_create_map(&map, &sub_map, num_auth_sel_criteria);
                if(attachment){
                    cbor_encode_uint(&sub_map, AUTH_ATTACH);
                    cbor_encode_uint(&sub_map, in->auth_sel.attachment);
                    debug_printf(DEBUG_LEVEL_MORE_VERBOSE,
                                 "    authenticator attachment: %s",     in->auth_sel.attachment == 1 ? "PLATFORM"  : "CROSS-PLATFORM");
                }
                if(resident_key){
                    cbor_encode_uint(&sub_map, RESIDENT_KEY);
                    cbor_encode_uint(&sub_map, in->auth_sel.resident_key);
                    debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    resident key: %s",
                                 get_resident_key_requirements_name(in->auth_sel.resident_key));
                }
                if(user_verification){
                    cbor_encode_uint(&sub_map, USER_VERIFICATION);
                    cbor_encode_uint(&sub_map, in->auth_sel.user_verification);
                    debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    user verification: %s",
                                 get_user_verification_requirements_name(in->auth_sel.user_verification));
                }     
                err = cbor_encoder_close_container(&map, &sub_map);
                if (err) {
                    debug_printf(DEBUG_LEVEL_ERROR, "Could not close CBOR map");
                    return -1;
                }
            }

            if(in->attestation){
                cbor_encode_uint(&map, ATTESTATION);
                cbor_encode_uint(&map, in->attestation);
                debug_printf(DEBUG_LEVEL_MORE_VERBOSE, " attestation conveyance preference: %s",
                                 get_attestation_conveyance_pref_name(in->attestation));
            }

            if(in->extensions){
                cbor_encode_uint(&map, EXTENSIONS);
                cbor_encoder_create_map(&map, &sub_map, in->extensions_len);
                for(size_t i = 0; i < in->extensions_len; i++ ){
                        cbor_encode_text_string(&sub_map, in->extensions[i].extension_id, in->extensions[i].extension_id_len );
                        cbor_encode_byte_string(&sub_map, in->extensions[i].extension_data, in->extensions[i].extension_data_len);
                }
                err = cbor_encoder_close_container(&map, &sub_map);
                if (err) {
                    debug_printf(DEBUG_LEVEL_ERROR, "Could not close CBOR map");
                    return -1;
                }
            }
            err = cbor_encoder_close_container(&array, &map );
            if (err) {
                debug_printf(DEBUG_LEVEL_ERROR, "Could not close CBOR map");
                return -1;
            }   
        }
        break;
    }

    case PKT_REG_RESPONSE: {
        struct reg_response *in = (struct reg_response *)input;
        assert(in->authdata != NULL && in->authdata_len != 0 &&
               in->clientdata_json != NULL);
        // Required fields are packet type, att_obj and clientdata_json
        cbor_encoder_create_array(&encoder, &array, 3);
        cbor_encode_int(&array, PKT_REG_RESPONSE);
        cbor_encode_byte_string(&array, in->authdata, in->authdata_len);
        debug_print_hex(DEBUG_LEVEL_MORE_VERBOSE,
                        "    authenticator data: ", in->authdata,
                        in->authdata_len);
        cbor_encode_text_stringz(&array, in->clientdata_json);
        debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    clientdata: %s",
                     in->clientdata_json);
        break;
    }
    case PKT_AUTH_INDICATION: {
        // Encode just the packet type
        cbor_encoder_create_array(&encoder, &array, 1);
        cbor_encode_int(&array, PKT_AUTH_INDICATION);
        break;
    }
    case PKT_AUTH_REQUEST: {
        struct auth_request *in = (struct auth_request *)input;
        assert(in->challenge != NULL && in->challenge_len > 0);
        // Count optional parameters
        size_t num_optionals = 0;
        if (in->rp_id != NULL)
            ++num_optionals;
        if (in->user_verification != 0)
            ++num_optionals;
        if (in->timeout != 0)
            ++num_optionals;
        // Required fields are packet type and challenge. The last field of the
        // array is a map if there are optional parameters
        cbor_encoder_create_array(&encoder, &array, num_optionals > 0 ? 3 : 2);
        cbor_encode_int(&array, PKT_AUTH_REQUEST);
        cbor_encode_byte_string(&array, in->challenge, in->challenge_len);
        debug_print_hex(DEBUG_LEVEL_MORE_VERBOSE, "    challenge: ", in->challenge,
                        in->challenge_len);
        if (num_optionals > 0) {
            cbor_encoder_create_map(&array, &map, num_optionals);
            if (in->timeout != 0) {
                cbor_encode_int(&map, TIMEOUT);
                cbor_encode_int(&map, in->timeout);
                debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    timeout: %d ms",
                             in->timeout);
            }
            if (in->rp_id != NULL) {
                cbor_encode_int(&map, RPID);
                cbor_encode_text_stringz(&map, in->rp_id);
                debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    rp id: %s", in->rp_id);
            }
            if (in->user_verification != 0) {
                cbor_encode_int(&map, USER_VERIFICATION);
                cbor_encode_int(&map, in->user_verification);
                debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    user verification: %s",
                             get_action_policy_name(in->user_verification));
            }
            err = cbor_encoder_close_container(&array, &map);
            if (err) {
                debug_printf(DEBUG_LEVEL_ERROR, "Could not close CBOR map");
                goto err;
            }
        }
        break;
    }
    case PKT_AUTH_RESPONSE: {
        struct auth_response *in = (struct auth_response *)input;
        assert(in->authdata != NULL && in->authdata_len != 0 &&
               in->clientdata_json != NULL && in->signature != NULL &&
               in->signature_len != 0);
        // Count optional parameters
        size_t num_optionals =  0;
        if (in->user_id_len != 0 && in->user_id)
            ++num_optionals;
        if (in->cred_id_len != 0 && in->cred_id)
            ++num_optionals;
        // Required fields are packet type, clientdata_json, authdata, signature
        // The last field of the array is a map if there are optional parameters
        cbor_encoder_create_array(&encoder, &array, 5);
        cbor_encode_int(&array, PKT_AUTH_RESPONSE);
        cbor_encode_text_stringz(&array, in->clientdata_json);
        debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    clientdata: %s",
                     in->clientdata_json);
        cbor_encode_byte_string(&array, in->authdata, in->authdata_len);
        debug_print_hex(DEBUG_LEVEL_MORE_VERBOSE,
                        "    authenticator data: ", in->authdata,
                        in->authdata_len);
        cbor_encode_byte_string(&array, in->signature, in->signature_len);
        debug_print_hex(DEBUG_LEVEL_MORE_VERBOSE, "    signature: ", in->signature,
                        in->signature_len);
        if (num_optionals > 0) {
            cbor_encoder_create_map(&array, &map, num_optionals);
            if (in->user_id_len != 0 && in->user_id) {
                cbor_encode_int(&map, USER_ID);
                cbor_encode_byte_string(&map, in->user_id, in->user_id_len);
                debug_print_hex(DEBUG_LEVEL_MORE_VERBOSE, "    user id: ", in->user_id,
                        in->user_id_len);
            }
            if (in->cred_id_len != 0 && in->cred_id) {
                cbor_encode_int(&map, CRED_ID);
                cbor_encode_byte_string(&map, in->cred_id, in->cred_id_len);
                debug_print_hex(DEBUG_LEVEL_MORE_VERBOSE, "    cred id: ", in->cred_id,
                        in->cred_id_len);
            }
            err = cbor_encoder_close_container(&array, &map);
            if (err) {
                debug_printf(DEBUG_LEVEL_ERROR, "Could not close CBOR map");
                goto err;
            }
        }
        break;
    }
    default:
        debug_printf(DEBUG_LEVEL_ERROR, "Unknown packet type");
        goto err;
    }
    // Close the array
    err = cbor_encoder_close_container(&encoder, &array);
    if (err != CborNoError) {
        debug_printf(DEBUG_LEVEL_ERROR, "Could not close CBOR array");
        debug_printf(DEBUG_LEVEL_ERROR, "Error: %s", cbor_error_string(err));
        goto err;
    }
    // Output is meant to be passed to the out parameter of the openssl custom
    // ext callback functions. Casting away of const is safe, as we're
    // immediately transferring ownership to openssl, which understands thats
    // it's now responsible for freeing the memory.
    *out_buf = buf;
    *out_len = cbor_encoder_get_buffer_size(&encoder, buf);
    return 0;
err:
    OPENSSL_free(buf);
    return -1;
}

int cbor_build_encrypted_data(const struct encrypted_data *input ,  u8 **out_buf, size_t *out_len){
    u8 *buf = OPENSSL_zalloc(ENC_DATA_BUF_SIZE);
    if (!buf){
        debug_printf(DEBUG_LEVEL_ERROR, "Could not allocate the memory for CBOR encoding");
        return -1;
    }
    CborEncoder encoder, array;
    cbor_encoder_init(&encoder, buf, 1000, 0);
    CborError err; 

   
    assert(input->padded_user_display_name != NULL && input->padded_user_display_name_len == 256
    && input->ticket != NULL && input->ticket_len == 256);
    cbor_encoder_create_array(&encoder, &array, 2);
    cbor_encode_byte_string(&array, input->padded_user_display_name, input->padded_user_display_name_len);
    cbor_encode_byte_string(&array, input->ticket, input->ticket_len); 
    err = cbor_encoder_close_container(&encoder, &array);
    if (err != CborNoError) {
        debug_printf(DEBUG_LEVEL_ERROR, "Could not close CBOR array");
        debug_printf(DEBUG_LEVEL_ERROR, "Error: %s", cbor_error_string(err));
        goto err;
    }
    *out_buf = buf;
    *out_len = cbor_encoder_get_buffer_size(&encoder, buf);
    return 0;
err:
    OPENSSL_free(buf);
    return -1;                 
}



int cbor_build_reg_request_encrypted_data(const struct reg_request_encrypted_data *input, u8 **out_buf, size_t *out_len){
    u8 *buf = OPENSSL_zalloc(ENC_DATA_BUF_SIZE);
    if (!buf){
        debug_printf(DEBUG_LEVEL_ERROR, "Could not allocate the memory for CBOR encoding");
        return -1;
    }
    CborEncoder encoder, array, sub_array, descriptor_array;
    cbor_encoder_init(&encoder, buf, ENC_DATA_BUF_SIZE, 0);
    CborError err; 
    assert(input->padded_user_display_name != NULL && input->padded_user_display_name_len == 256 
        && input->padded_user_name != NULL && input->padded_user_name_len == 256 && input->user_id != NULL
        && input->user_id_len == 64);

    if(input->exclude_credentials_len !=0 ){
        cbor_encoder_create_array(&encoder, &array, 4);
    }
    else{
        cbor_encoder_create_array(&encoder, &array, 3);
    }  
    cbor_encode_byte_string(&array, input->padded_user_name, input->padded_user_name_len);
    cbor_encode_byte_string(&array, input->padded_user_display_name, input->padded_user_display_name_len);
    cbor_encode_byte_string(&array, input->user_id, input->user_id_len);
    if(input->exclude_credentials_len != 0){
        cbor_encoder_create_array(&array, &sub_array, input->exclude_credentials_len);
        for(size_t i = 0; i < input->exclude_credentials_len; i++){
            //Parent-Array ist der sub_array, Kind-Array ist descriptor_array wobei jeder Descroptor bisher zwei Felder hat, bzw. type und id, weil noch transports nicht implementiert sind
            cbor_encoder_create_array(&sub_array, &descriptor_array, 2);
            cbor_encode_uint(&descriptor_array, input->exclude_credentials[i].type);
            cbor_encode_byte_string(&descriptor_array, input->exclude_credentials[i].id, input->exclude_credentials[i].id_len);
            //hier noch ohne transports
            err = cbor_encoder_close_container(&sub_array, &descriptor_array);
            if (err != CborNoError){
                debug_printf(DEBUG_LEVEL_ERROR, "Could not close CBOR array");
                debug_printf(DEBUG_LEVEL_ERROR, "Error: %s", cbor_error_string(err));
                goto err;
            }  
        }
        err = cbor_encoder_close_container(&array, &sub_array);
        if (err != CborNoError) {
            debug_printf(DEBUG_LEVEL_ERROR, "Could not close CBOR array");
            debug_printf(DEBUG_LEVEL_ERROR, "Error: %s", cbor_error_string(err));
            goto err;
        }
    }

    err = cbor_encoder_close_container(&encoder, &array);
    if (err != CborNoError) {
        debug_printf(DEBUG_LEVEL_ERROR, "Could not close CBOR array");
        debug_printf(DEBUG_LEVEL_ERROR, "Error: %s", cbor_error_string(err));
        goto err;
    }
    *out_buf = buf;
    *out_len = cbor_encoder_get_buffer_size(&encoder, buf);
    return 0;
    err:
        OPENSSL_free(buf);
        return -1;      
}





/*
 * Copyright (c) 2020 Pedro Martelletto. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 * Modified to use tinyCBOR
 */

static void
warnx(const char *fmt, const char *arg) {
    fprintf(stderr, fmt, arg);
    fprintf(stderr, "\n");
}

// Helper: encode COSE algorithm (negative int) as per COSE spec
static CborError
cbor_encode_cose_alg(CborEncoder *mapEncoder, const char *key, int cose_alg) {
    CborError err;

    err = cbor_encode_text_stringz(mapEncoder, key);
    if (err) return err;

    return cbor_encode_int(mapEncoder, cose_alg);
}

// Helper: encode a bytestring field
static CborError
cbor_encode_bytestring(CborEncoder *mapEncoder, const char *key,
                       const uint8_t *data, size_t len) {
    CborError err;

    err = cbor_encode_text_stringz(mapEncoder, key);
    if (err) return err;

    return cbor_encode_byte_string(mapEncoder, data, len);
}

// Helper: wrap bytestring in single-element array for "x5c"
static CborError
cbor_encode_wrap_blob(CborEncoder *mapEncoder, const char *key,
                      const uint8_t *data, size_t len) {
    CborError err;
    CborEncoder arrayEncoder;

    err = cbor_encode_text_stringz(mapEncoder, key);
    if (err) return err;

    err = cbor_encoder_create_array(mapEncoder, &arrayEncoder, 1);
    if (err) return err;

    err = cbor_encode_byte_string(&arrayEncoder, data, len);
    if (err) return err;

    return cbor_encoder_close_container(mapEncoder, &arrayEncoder);
}

// Encode the attestation statement map
static CborError
cbor_encode_attestation_statement(CborEncoder *mapEncoder,
                                 const fido_cred_t *cred,
                                 const char *fmt) {
    CborError err = CborNoError;
    int type = fido_cred_type(cred);
    const unsigned char *sig_ptr = fido_cred_sig_ptr(cred);
    size_t sig_len = fido_cred_sig_len(cred);
    const unsigned char *x5c_ptr = fido_cred_x5c_ptr(cred);
    size_t x5c_len = fido_cred_x5c_len(cred);

    if (type != COSE_ES256 || sig_ptr == NULL || sig_len == 0 ||
        x5c_ptr == NULL || x5c_len == 0) {
        warnx("cbor_encode_attestation_statement: fido_cred invalid", "");
        return CborUnknownError;
    }

    // Create attStmt map with 2 or 3 keys (depending on fmt)
    int map_size = strcmp(fmt, "packed") == 0 ? 3 : 2;

    CborEncoder attStmtMap;
    err = cbor_encoder_create_map(mapEncoder, &attStmtMap, map_size);
    if (err) return err;

    if (map_size == 3) {
        err = cbor_encode_cose_alg(&attStmtMap, "alg", type);
        if (err) return err;
    }

    err = cbor_encode_bytestring(&attStmtMap, "sig", sig_ptr, sig_len);
    if (err) return err;

    err = cbor_encode_wrap_blob(&attStmtMap, "x5c", x5c_ptr, x5c_len);
    if (err) return err;

    return cbor_encoder_close_container(mapEncoder, &attStmtMap);
}

// Main function to build attestation object (CBOR bytes)
unsigned char *
cbor_build_attestation_object(const fido_cred_t *cred, size_t *out_len) {
    if (cred == NULL || out_len == NULL) {
        return NULL;
    }

    const char *fmt = fido_cred_fmt(cred);
    const unsigned char *authdata_ptr = fido_cred_authdata_raw_ptr(cred);
    size_t authdata_len = fido_cred_authdata_raw_len(cred);

    if (fmt == NULL || authdata_ptr == NULL || authdata_len == 0) {
        warnx("cbor_build_attestation_object: fido_cred invalid", "");
        return NULL;
    }

    // Allocate a buffer for encoding. Adjust size if necessary.
    size_t buf_size = 4048; // initial guess
    unsigned char *buf = malloc(buf_size);
    if (buf == NULL) {
        return NULL;
    }

    CborEncoder encoder, attObjMap;
    CborError err;

    cbor_encoder_init(&encoder, buf, buf_size, 0);

    // Create attestation object map with 3 keys: fmt, attStmt, authData
    err = cbor_encoder_create_map(&encoder, &attObjMap, 3);
    if (err) goto fail;

    // fmt : text string
    err = cbor_encode_text_stringz(&attObjMap, "fmt");
    if (err) goto fail;
    err = cbor_encode_text_stringz(&attObjMap, fmt);
    if (err) goto fail;

    // attStmt : map
    err = cbor_encode_text_stringz(&attObjMap, "attStmt");
    if (err) goto fail;

    // Encode attestation statement inline
    err = cbor_encode_attestation_statement(&attObjMap, cred, fmt);
    if (err) goto fail;

    // authData : bytestring
    err = cbor_encode_text_stringz(&attObjMap, "authData");
    if (err) goto fail;
    err = cbor_encode_byte_string(&attObjMap, authdata_ptr, authdata_len);
    if (err) goto fail;

    err = cbor_encoder_close_container(&encoder, &attObjMap);
    if (err) goto fail;

    *out_len = cbor_encoder_get_buffer_size(&encoder, buf);
    return buf;

fail:
    free(buf);
    warnx("cbor_build_attestation_object: encoding failed", "");
    return NULL;
}
