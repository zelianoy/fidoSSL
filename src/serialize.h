#ifndef SERIALIZE_H
#define SERIALIZE_H

#include <stddef.h>
#include <openssl/bio.h>
#include "types.h"

int get_packet_type(const u8 *in_buf, size_t in_len, enum packet_type *type);

int cbor_build(const void *input, enum packet_type type, const u8 **out_buf, size_t *out_len);

int cbor_parse(const u8 *in_buf, size_t in_len, enum packet_type *type, void *out);

//defined helper functions to build and parse the inner CBOR array of RegistrationIndication
int cbor_build_encrypted_data(const struct encrypted_data *input, u8 **out_buf, size_t *out_len);

int cbor_parse_encrypted_data(const u8 *input, size_t in_len, struct encrypted_data *out);

//defined helper functions to build and parse the inner CBOR array of the ReqistrationRequest
int cbor_build_reg_request_encrypted_data(const struct reg_request_encrypted_data *input, u8 **out_buf, size_t *out_len);

int cbor_parse_reg_request_encrypted_data(const u8 *in_buf, size_t in_len, struct reg_request_encrypted_data *out);

int cbor_build_allowed_credentials(const struct public_key_credential_descriptor *input, size_t allowed_cledentials_len, u8 **out_buf, size_t *out_len);

int cbor_parse_allowed_credentials(const u8 *in_buf, size_t in_len, struct public_key_credential_descriptor **output, size_t *allowed_cledentials_len);

unsigned char *cbor_build_attestation_object(const fido_cred_t *cred, size_t *out_len);

#endif // SERIALIZE_H
