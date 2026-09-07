#include "types.h"
#include <sqlite3.h>

sqlite3 *init_db(const char *db_path);

int get_credential(sqlite3 *db, const u8 *user_id, size_t user_id_len,
                   const u8 *cred_id, size_t cred_id_len,
                   struct credential *cred, char **rpid);

int update_sign_count(sqlite3 *db, const u8 *cred_id, size_t cred_id_len,
                     int sign_count);

int get_user_id(sqlite3 *db, const char *user_name, u8 **user_id,
                size_t *user_id_len);

int get_excluded_credential_descriptors(sqlite3 *db, const u8 *user_id, size_t user_id_len,
                            struct public_key_credential_descriptor **creds, size_t *creds_len);

int add_creds(sqlite3 *db, const u8 *user_id, size_t user_id_len,
              const char *user_name, const char *rpid, struct credential *cred);
