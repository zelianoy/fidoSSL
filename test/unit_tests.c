#include "common.h"
#include "types.h"
#include "debug.h"
#include "rp.h"
#include "ud.h"
#include "serialize.h"
int test_parse_authdata() {
    debug_printf(DEBUG_LEVEL_VERBOSE, "TEST: parse_authdata");

    char *hex = "c46cef82ad1b546477591d008b08759ec3e6d2ecb4f39474bfea6969925d03b74100000002000000000000000000000000000000000030e6e5eee103907ac2f44f60c7997970c147db201d5c83efde152af2bb9532ddad186baae36f883ff579c174d4998e2311a4010103272006215820e6e5eee103907ac2f44f60c799147414dbef7e8a6b01dc1960726bea573202d3";
    u8 *data = NULL;
    size_t data_len;

    hex_to_u8(hex, &data, &data_len);
    if (data == NULL) {
        printf("Error: hex_to_u8\n");
        return -1;
    }
    struct authdata *ad = parse_authdata(data, data_len);
    if (ad == NULL) {
        printf("Error: parse_authdata\n");
        return -1;
    }
    debug_print_hex(DEBUG_LEVEL_VERBOSE, "rp_id_hash: ", ad->rp_id_hash, ad->rp_id_hash_len);
    debug_printf(DEBUG_LEVEL_VERBOSE, "flags: %d", ad->flags);
    debug_printf(DEBUG_LEVEL_VERBOSE, "sign_count: %d", ad->sign_count);
    debug_print_hex(DEBUG_LEVEL_VERBOSE, "aaguid: ", ad->aaguid, ad->aaguid_len);
    debug_print_hex(DEBUG_LEVEL_VERBOSE, "cred_id: ", ad->cred_id, ad->cred_id_len);
    debug_print_hex(DEBUG_LEVEL_VERBOSE, "pubkey: ", ad->pubkey, ad->pubkey_len);
    puts("");
    return 0;
}

int test_cbor_encrypted_data_roundtrip(){
    u8 *out = NULL;
    size_t out_len = 0;
    u8 *user_display_name = NULL;
    size_t user_display_name_len = 0;
    u8 *ticket = NULL;
    size_t ticket_len = 0;
    int result = -1;
    debug_printf(DEBUG_LEVEL_VERBOSE, "TEST: cbor_encrypted_data_roundtrip");

    const char *hex = "8c56c187cd725a20596fba3cc0904a1e1da2fe9eb80b6d885a3ec707aa09df683815000b6c90e32e0961ea33f16a194d354846ce697190359d0ab8ced386742635a4856c89138f5979574979c4a0d286a8af8d9ba5d3d2648e2e6f6b01cb315973eb65305c6e9dbec8da468d9947fd8b42c4297b02040af6e20426d23736269e78b4797ae4872f4ebdb9f24a46026f42203097cad12189457096f419d5a8fc4d6798f88807b415d99122d3ceb0cfe59803aeb87678daa4e8aa40e3f3f40e6776c546b813759fed7f6d05b13d961f013704a26537b1f8a4b597173e07844a152f8dacf70c45041183b77b23caa17f8ac4c2e31341752388df91c085c2569dbd2a";
    if(hex_to_u8(hex, &user_display_name, &user_display_name_len)!=0){
        debug_printf(DEBUG_LEVEL_ERROR, "Conversion to u8 failed;");
        return -1;
    }
    if(user_display_name_len!=256){
        debug_printf(DEBUG_LEVEL_ERROR, "Length of user display name is not 256");
        OPENSSL_free(user_display_name);
        return -1;
    }

    const char *hex2 = "cb9caef928cdc97ff0a92a589dc23919b7e3355f3e8f9a0514c6e9235cec673c01cdedbe1f7c79fad7b68d2337d288bc91b2a19de2654e432d81c73ea4feb9233ed13c1b12d091096a08010299ac086fb42492efdab7c27502442fa20dac1cf92624de41cd35cbffd9d1cdf578350ff20f7c3c557b9cbe35c18ba77a626ced15d7244169cd2089c722c73cbb4503089b62d99dab01c7862d2204cd402222a6512de0421fd0c5af8ec6c2dc068e8fd561a897690a6a7cf8695cce7ef5f5e89578f305dbd8b40462ea8b9fd2d8ee04a75ad71c4ae505423fe6cc6d127658b5f2ded522668466d1fda5b57ec6e9ca8ef563e4b85eff0b7439ea62d3f15e98417f14";
    if(hex_to_u8(hex2, &ticket, &ticket_len)!=0){
        debug_printf(DEBUG_LEVEL_ERROR, "Conversion to u8 failed;");
        OPENSSL_free(user_display_name);
        return -1;
    }
    if(ticket_len!=256) {
        debug_printf(DEBUG_LEVEL_ERROR, "Length of ticket is not 256");
        OPENSSL_free(ticket);
        OPENSSL_free(user_display_name);
        return -1;
    }
    //Struktur für die Erzeugung des CBOR-Arrays erstellen
    struct encrypted_data *encrypted_data = OPENSSL_zalloc(sizeof(*encrypted_data));
    if(encrypted_data==NULL){
        debug_printf(DEBUG_LEVEL_ERROR, "Memory allocation for the structure failed");
        OPENSSL_free(ticket);
        OPENSSL_free(user_display_name);
        return -1;
    }
    encrypted_data->ticket = ticket;
    encrypted_data->ticket_len = ticket_len;
    encrypted_data->padded_user_display_name = user_display_name;
    encrypted_data->padded_user_display_name_len = user_display_name_len;
    if(cbor_build_encrypted_data(encrypted_data, &out, &out_len)!=0){
        debug_printf(DEBUG_LEVEL_ERROR, "Failed creating a CBOR array");
        OPENSSL_free(encrypted_data);
        OPENSSL_free(ticket);
        OPENSSL_free(user_display_name);
        return -1;
    }
    
    //Strukrur für das Parsen des CBOR-Arrays erzeugen
    struct encrypted_data *encrypted_data1 = OPENSSL_zalloc(sizeof(*encrypted_data1));
    if(encrypted_data1==NULL){
        debug_printf(DEBUG_LEVEL_ERROR, "Memory allocation for the structure failed");
        OPENSSL_free(out);
        OPENSSL_free(encrypted_data);
        OPENSSL_free(ticket);
        OPENSSL_free(user_display_name);
        return -1;
    }
    if(cbor_parse_encrypted_data(out, out_len, encrypted_data1)!=0){
        goto end;
    }

    if(encrypted_data1->padded_user_display_name_len == user_display_name_len &&
       encrypted_data1->ticket_len == ticket_len){
        if(memcmp(encrypted_data1->padded_user_display_name, user_display_name, 256) != 0 || 
          (memcmp(encrypted_data1->ticket, ticket, 256) != 0)){
            goto end;
        }
        result = 0;
    }
    else{
        goto end;
    }
    end:
        OPENSSL_free(encrypted_data1->ticket);
        OPENSSL_free(encrypted_data1->padded_user_display_name);
        OPENSSL_free(encrypted_data1);
        OPENSSL_free(out);
        OPENSSL_free(encrypted_data);
        OPENSSL_free(ticket);
        OPENSSL_free(user_display_name);
        if(result == -1){ debug_printf(DEBUG_LEVEL_ERROR, "The cbor roundtrip failed"); }
        if(result ==  0){ debug_printf(DEBUG_LEVEL_VERBOSE, "The cbor roundtrip succeeded");}
        return result;
}



int test_padding() {
    const size_t padded_len = 256;
    /*Case with length between 1 and 256*/
    //const char *data = "Alicey";
    /*Case with length exactly 256*/
    //const char *data = "llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll11";
   /*Case with length 0*/
    const char *data = "7";
    size_t data_len = strlen(data);
    u8 *padded_data = malloc(padded_len);
    size_t unpadded_data_len = 0 ;
    if(padded_data == NULL){
        debug_printf(DEBUG_LEVEL_ERROR, 
            "Memory allocation for padded_data failed");
        return -1;
    }

    //To see whether the bit_padding function overwrites correcctly the whole buffer
    memset(padded_data, 0xAA, padded_len);

    if(bit_padding(padded_data, data, data_len) != 0 ){
        debug_printf(DEBUG_LEVEL_ERROR, "Padding the data failed" );
        free(padded_data);
        return -1;
    }

    if (memcmp(padded_data, data, data_len) != 0) {
        debug_printf(DEBUG_LEVEL_ERROR, "Original data was not copied correctly");
        free(padded_data);
        return -1;
    }

    if(data_len<256){
        if(padded_data[data_len]!=0x80){
            debug_printf(DEBUG_LEVEL_ERROR, "First padding byte is not 0x80 ");
            free(padded_data);
            return -1;
        }
    }
    
    for (size_t i = data_len + 1; i < padded_len; i++){
        if(padded_data[i] != 0x00){
            debug_printf(DEBUG_LEVEL_ERROR, "Padding byte at the position %zu is not zero", i);
            free(padded_data);
            return -1;
        }
    }
    debug_print_hex(DEBUG_LEVEL_VERBOSE, 
                 "    user name: ", data, data_len); 
    debug_print_hex(DEBUG_LEVEL_VERBOSE, 
                 "    padded user name: ", padded_data, padded_len ); 

    debug_printf(DEBUG_LEVEL_VERBOSE, "Padding the data succeeded" );
   
    char *unpadded_data = malloc(257 * sizeof(*unpadded_data));
    
    if(unpadded_data == NULL){
        debug_printf(DEBUG_LEVEL_ERROR,
            "Memory allocation for unpadded_data failed");
            free(padded_data);
            free(unpadded_data);
            return -1;
    }

    if(remove_bit_padding(unpadded_data, padded_data, &unpadded_data_len) != 0){
        debug_printf(DEBUG_LEVEL_ERROR, " Removing the padding failed");
        free(padded_data);
        free(unpadded_data);
        return -1;
    }

   if(unpadded_data_len != data_len || memcmp(unpadded_data, data, data_len) != 0 || unpadded_data[unpadded_data_len] != '\0'){
    free(padded_data);
    free(unpadded_data);
    return -1;
   }



    debug_print_hex(DEBUG_LEVEL_VERBOSE, 
     "    unpadded user name: ", unpadded_data, unpadded_data_len ); 


    free(padded_data);
    free(unpadded_data);
    return 0;

}



int test_padding_and_rtp(){
    const size_t padded_len = 256;
    const char *data = "Alicey";
    u8 *ticket = NULL;
    size_t ticket_len = 0;
    int result = -1;
    size_t data_len = strlen(data);
    u8 *padded_data = OPENSSL_zalloc(padded_len);
    u8 *out = NULL;
    size_t out_len = 0;

    if(padded_data == NULL){
        debug_printf(DEBUG_LEVEL_ERROR, 
            "Memory allocation for padded_data failed");
        return -1;
    }

    if(bit_padding(padded_data, data, data_len) != 0 ){
        debug_printf(DEBUG_LEVEL_ERROR, "Padding the data failed" );
        OPENSSL_free(padded_data);
        return -1;
    }

    const char *hex2 = "cb9caef928cdc97ff0a92a589dc23919b7e3355f3e8f9a0514c6e9235cec673c01cdedbe1f7c79fad7b68d2337d288bc91b2a19de2654e432d81c73ea4feb9233ed13c1b12d091096a08010299ac086fb42492efdab7c27502442fa20dac1cf92624de41cd35cbffd9d1cdf578350ff20f7c3c557b9cbe35c18ba77a626ced15d7244169cd2089c722c73cbb4503089b62d99dab01c7862d2204cd402222a6512de0421fd0c5af8ec6c2dc068e8fd561a897690a6a7cf8695cce7ef5f5e89578f305dbd8b40462ea8b9fd2d8ee04a75ad71c4ae505423fe6cc6d127658b5f2ded522668466d1fda5b57ec6e9ca8ef563e4b85eff0b7439ea62d3f15e98417f14";
    if(hex_to_u8(hex2, &ticket, &ticket_len)!=0){
        debug_printf(DEBUG_LEVEL_ERROR, "Conversion to u8 failed;");
        OPENSSL_free(padded_data);
        return -1;
    }
    if(ticket_len!=256) {
        debug_printf(DEBUG_LEVEL_ERROR, "Length of ticket is not 256");
        OPENSSL_free(ticket);
        OPENSSL_free(padded_data);
        return -1;
    }
    struct encrypted_data *encrypted_data = OPENSSL_zalloc(sizeof(*encrypted_data));
    if(encrypted_data==NULL){
        debug_printf(DEBUG_LEVEL_ERROR, "Memory allocation for the structure failed");
        OPENSSL_free(ticket);
        OPENSSL_free(padded_data);
        return -1;
    }
    encrypted_data->ticket = ticket;
    encrypted_data->ticket_len = ticket_len;
    encrypted_data->padded_user_display_name = padded_data;
    encrypted_data->padded_user_display_name_len = padded_len;
    if(cbor_build_encrypted_data(encrypted_data, &out, &out_len)!=0){
        debug_printf(DEBUG_LEVEL_ERROR, "Failed creating a CBOR array");
        OPENSSL_free(encrypted_data);
        OPENSSL_free(ticket);
        OPENSSL_free(padded_data);
        return -1;
    }
    //Strukrur für das Parsen des CBOR-Arrays erzeugen
    struct encrypted_data *encrypted_data1 = OPENSSL_zalloc(sizeof(*encrypted_data1));
    if(encrypted_data1==NULL){
        debug_printf(DEBUG_LEVEL_ERROR, "Memory allocation for the structure failed");
        OPENSSL_free(out);
        OPENSSL_free(encrypted_data);
        OPENSSL_free(ticket);
        OPENSSL_free(padded_data);
        return -1;
    }
    if(cbor_parse_encrypted_data(out, out_len, encrypted_data1)!=0){
        goto end;
    }

    if(encrypted_data1->padded_user_display_name_len == padded_len &&
       encrypted_data1->ticket_len == ticket_len){
        if(memcmp(encrypted_data1->padded_user_display_name, padded_data, 256) != 0 || 
          (memcmp(encrypted_data1->ticket, ticket, 256) != 0)){
            goto end;
        }
        result = 0;
    }
    else{
        goto end;
    }
    end:
        if(result == -1){ debug_printf(DEBUG_LEVEL_ERROR, "The cbor roundtrip failed"); }
        if(result ==  0){ debug_printf(DEBUG_LEVEL_VERBOSE, "The cbor roundtrip succeeded");}
        OPENSSL_free(encrypted_data1->ticket);
        OPENSSL_free(encrypted_data1->padded_user_display_name);
        OPENSSL_free(encrypted_data1);
        OPENSSL_free(out);
        OPENSSL_free(encrypted_data);
        OPENSSL_free(ticket);
        OPENSSL_free(padded_data);
        return result;

}


int test_reg_request_padding_and_rtp(){
    const size_t padded_len = 256;
    const char *user_name = "Alice";
    size_t user_name_len = strlen(user_name);
    u8 *credential_id = OPENSSL_malloc(16);
    if(credential_id == NULL){
        return -1;
    }
    u8 *credential_id1 = OPENSSL_malloc(16);
     if(credential_id1 == NULL){
        return -1;
    }

    memset(credential_id, 0x11, 16);
    memset(credential_id1, 0x12, 16);
   

    struct public_key_credential_descriptor *exclude_credential = OPENSSL_zalloc(2 * sizeof(*exclude_credential));
    if(exclude_credential == NULL) {
        return -1;
    }

    exclude_credential[0].type = PUBLIC_KEY;
    exclude_credential[0].id = credential_id;
    exclude_credential[0].id_len = 16;
    exclude_credential[0].transports = NULL;
    exclude_credential[0].transports_len = 0;


    exclude_credential[1].type = PUBLIC_KEY;
    exclude_credential[1].id = credential_id1;
    exclude_credential[1].id_len = 16;
    exclude_credential[1].transports = NULL;
    exclude_credential[1].transports_len = 0;





    
    
    const char *user_display_name = "alice_wonderland";
    size_t user_display_name_len = strlen(user_display_name);

    u8 *id = NULL;
    size_t id_len = 0;

    int result = -1;

    u8 *padded_user_name = OPENSSL_zalloc(padded_len);
    u8 *padded_user_display_name = OPENSSL_zalloc(padded_len);

    u8 *out = NULL;
    size_t out_len = 0;

    if(padded_user_name == NULL){
        debug_printf(DEBUG_LEVEL_ERROR, 
            "Memory allocation for padded user name failed");
        return -1;
    }

    if(padded_user_display_name == NULL){
        debug_printf(DEBUG_LEVEL_ERROR, 
        "Memory allocation for padded user display name failed");
        return -1;
    }

    if(bit_padding(padded_user_name, user_name, user_name_len) != 0 ){
        debug_printf(DEBUG_LEVEL_ERROR, "Padding the user name failed" );
        return -1;
    }

    if(bit_padding(padded_user_display_name, user_display_name, user_display_name_len) != 0 ){
        debug_printf(DEBUG_LEVEL_ERROR, "Padding the user display name failed" );
        return -1;
    }    

    const char *hex2 = "9b9caef928cdc97ff0a92a589dc23919b7e3355f3e8f9a0514c6e9235cec673c01cdedbe1f7c79fad7b68d2337d288bc91b2a19d999999999999999999999999";
    if(hex_to_u8(hex2, &id, &id_len)!=0){
        debug_printf(DEBUG_LEVEL_ERROR, "Conversion to u8 failed");
        return -1;
    }
    if(id_len!=64) {
        debug_printf(DEBUG_LEVEL_ERROR, "Length of ID is not 64");
        return -1;
    }
    debug_print_hex(DEBUG_LEVEL_VERBOSE, 
                 "   padded  user name before parsing: ", padded_user_name, padded_len); 
   
    debug_print_hex(DEBUG_LEVEL_VERBOSE, 
                 "   padded user display name before parsing: ", padded_user_display_name, padded_len); 
   
    debug_print_hex(DEBUG_LEVEL_VERBOSE, 
                 "    user id before parsing: ", id, id_len); 
    
    debug_print_hex(DEBUG_LEVEL_VERBOSE, 
                 "    first exclude credential id before parsing: ", exclude_credential[0].id, exclude_credential[0].id_len); 

    debug_print_hex(DEBUG_LEVEL_VERBOSE, 
                 "    second exclude credential id before parsing: ", exclude_credential[1].id, exclude_credential[1].id_len); 





    struct reg_request_encrypted_data *encrypted_data = OPENSSL_zalloc(sizeof(*encrypted_data));
    if(encrypted_data == NULL){
        debug_printf(DEBUG_LEVEL_ERROR, "Memory allocation for the structure failed");
        return -1;
    }
    encrypted_data->padded_user_name = padded_user_name;
    encrypted_data->padded_user_name_len = padded_len;
    encrypted_data->padded_user_display_name = padded_user_display_name;
    encrypted_data->padded_user_display_name_len = padded_len;
    encrypted_data->user_id = id;
    encrypted_data->user_id_len = id_len;
    encrypted_data->exclude_credentials = exclude_credential;
    
    encrypted_data->exclude_credentials_len = 2;
    if(cbor_build_reg_request_encrypted_data(encrypted_data, &out, &out_len)!= 0){
       //später Speicherbereinugung organisieren
        debug_printf(DEBUG_LEVEL_ERROR, "Failed creating a CBOR array");
        return -1;
    }
    

    //Struktur für das Parsen des CBOR-Arrays erzeugen
    struct reg_request_encrypted_data *encrypted_data1 = OPENSSL_zalloc(sizeof(*encrypted_data1));
    if(encrypted_data1==NULL){
        debug_printf(DEBUG_LEVEL_ERROR, "Memory allocation for the structure failed");
        //später die Speicherbereinigung organisieren
        return -1;
    }
    if(cbor_parse_reg_request_encrypted_data(out, out_len, encrypted_data1)!=0){
        goto end;
    }
    


    debug_print_hex(DEBUG_LEVEL_VERBOSE, 
                 "    user name after parsing: ", encrypted_data1->padded_user_name, encrypted_data1->padded_user_name_len); 
   
    debug_print_hex(DEBUG_LEVEL_VERBOSE, 
                 "    user display name after parsing: ", encrypted_data1->padded_user_display_name, encrypted_data1->padded_user_display_name_len); 
 
    debug_print_hex(DEBUG_LEVEL_VERBOSE, 
                 "    user id after parsing: ", encrypted_data1->user_id, encrypted_data1->user_id_len); 

    debug_print_hex(DEBUG_LEVEL_VERBOSE, 
                 "    first exclude credential id after parsing: ", encrypted_data1->exclude_credentials[0].id, encrypted_data1->exclude_credentials[0].id_len); 

    debug_print_hex(DEBUG_LEVEL_VERBOSE, 
                 "    first exclude credentials transports after parsing: ", encrypted_data1->exclude_credentials[0].transports, encrypted_data1->exclude_credentials[0].transports_len); 


    debug_print_hex(DEBUG_LEVEL_VERBOSE, 
                 "    second exclude credential id after parsing: ", encrypted_data1->exclude_credentials[1].id, encrypted_data1->exclude_credentials[1].id_len); 

    debug_print_hex(DEBUG_LEVEL_VERBOSE, 
                 "    second exclude credential transports after parsing: ", encrypted_data1->exclude_credentials[1].transports, encrypted_data1->exclude_credentials[1].transports_len); 



    if(encrypted_data1->padded_user_display_name_len == padded_len &&
       encrypted_data1->padded_user_name_len == padded_len && encrypted_data1->user_id_len == id_len){
        if(memcmp(encrypted_data1->padded_user_display_name, padded_user_display_name, padded_len) != 0 || 
          (memcmp(encrypted_data1->padded_user_name, padded_user_name, padded_len) != 0) || 
          (memcmp(encrypted_data1->user_id, id, id_len))){
            goto end;
        }
        result = 0;
    }
    else{
        goto end;
    }
    end:
        if(result == -1){ debug_printf(DEBUG_LEVEL_ERROR, "The cbor roundtrip failed"); }
        if(result ==  0){ debug_printf(DEBUG_LEVEL_VERBOSE, "The cbor roundtrip succeeded");}
        //Speicherbereinigung erst später
        return result;

}







int test_parse_cose_key() {
    char *hex = "2b662ac619c2e71c3ef2af752bb757180bebe21ef288588f277f656f9eec007f47d00a9054f4f44b7efab2fd9796f63c64cfcab25e891a65508d06ed7b77d0ee";
    u8 *data = NULL;
    size_t data_len;

    hex_to_u8(hex, &data, &data_len);
    if (data == NULL) {
        printf("Error: hex_to_u8\n");
        return -1;
    }
    printf("data_len: %zu\n", data_len);
    PublicKey *pk = parse_cose_key(data, data_len);
    if (pk == NULL) {
        printf("Error: parse_cose_key\n");
        return -1;
    }
    return 0;
}

int main(int argc, char *argv[]) {
    debug_initialize();
    set_debug_level(DEBUG_LEVEL_MORE_VERBOSE);
   /**  if(test_cbor_encrypted_data_roundtrip()!=0){
        printf("Error: failed to test cbor encrypted data roundtrip \n");
        return -1;
    }

    if(test_padding()!=0){
        printf("Error: failed to pad the user name correctly\n");
        return -1;
    }

    if(test_padding_and_rtp()!=0){
        printf("Error: failed to test padding and inner CBOR array creation and parsing\n");
        return -1;
    }
    */



    if(test_reg_request_padding_and_rtp()!=0){
        printf("Error: failed to test padding and inner req request CBOR array creation\n");
        return -1;
    }
    return 0;
}
