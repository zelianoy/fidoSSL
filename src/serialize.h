#ifndef SERIALIZE_H
#define SERIALIZE_H

#include <stddef.h>
#include <openssl/bio.h>
#include "types.h"

int cbor_build(const void *input, enum packet_type type, const u8 **out_buf, size_t *out_len);

int cbor_parse(const u8 *in_buf, size_t in_len, enum packet_type *type, void *out);

//defined helper functions to build and parse the inner CBOR array
int cbor_build_encrypted_data(const struct encrypted_data *input, u8 **out_buf, size_t *out_len);

int cbor_parse_encrypted_data(const u8 *input, size_t in_len, struct encrypted_data *out);

//defined helper functions to builf and parse the array inside of the ReqistrationRequest
int cbor_build_reg_request_encrypted_data(const struct reg_request_encrypted_data *input, u8 **out_buf, size_t *out_len);

int cbor_parse_reg_request_encrypted_data(const u8 *input, size_t in_len, struct reg_request_encrypted_data *out);

unsigned char *cbor_build_attestation_object(const fido_cred_t *cred, size_t *out_len);

#endif // SERIALIZE_H
