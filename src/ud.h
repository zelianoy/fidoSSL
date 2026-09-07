#include "types.h"
#include <openssl/bio.h>

struct ud_data *get_ud_data(SSL *ssl, void *add_arg);

int create_auth_indication(struct ud_data *data, const u8 **out,
                           size_t *out_len);

int create_pre_indication(struct ud_data *data, const u8 **out,
                              size_t *out_len);

int create_reg_indication(struct ud_data *data, const u8 **out,
                          size_t *out_len);

int process_auth_request(const u8 *in, size_t in_len, struct ud_data *data);

int process_reg_request(const u8 *in, size_t in_len, struct ud_data *data);

int process_pre_response(const u8 *in, size_t in_len,
                            struct ud_data *data);

int create_auth_response(struct ud_data *data, SSL *ssl, const u8 **out,
                         size_t *out_len);

int create_reg_response(struct ud_data *data, SSL *ssl, const u8 **out,
                        size_t *out_len);                
