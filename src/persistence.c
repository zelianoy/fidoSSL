#include "persistence.h"
#include "debug.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Function to execute an SQL statement for table creation
int execute_sql(sqlite3 *db, const char *sql) {
    char *err_msg = 0;
    int rc = sqlite3_exec(db, sql, 0, 0, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
        return -1;
    }
    return 0;
}

sqlite3 *init_db(const char *db_path) {
    sqlite3 *db;
    int rc;

    // Open the database
    rc = sqlite3_open(db_path, &db);
    if (rc) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        return NULL;
    }

    // SQL statement for creating the 'users' table
    const char *sql_create_users = "CREATE TABLE IF NOT EXISTS users ("
                                   "user_id BLOB PRIMARY KEY,"
                                   "user_name TEXT NOT NULL UNIQUE"
                                   ");";

    // SQL statement for creating the 'credentials' table
    const char *sql_create_credentials =
        "CREATE TABLE IF NOT EXISTS credentials ("
        "cred_id BLOB PRIMARY KEY,"
        "type TEXT NOT NULL,"
        "transports INTEGER NOT NULL,"
        "rp_id TEXT NOT NULL,"
        "pubkey_cose BLOB NOT NULL,"
        "sign_count INTEGER NOT NULL,"
        "user_id BLOB NOT NULL,"
        "FOREIGN KEY (user_id) REFERENCES users(user_id)"
        ");";

    // Execute SQL statements. These calls are indepotent, so even if the tables
    // already exist, they are not created again.
    if (execute_sql(db, sql_create_users) != 0)
        return NULL;
    if (execute_sql(db, sql_create_credentials) != 0)
        return NULL;

    return db;
}

int get_user_id(sqlite3 *db, const char *user_name, u8 **user_id,
                size_t *user_id_len) {
    // SQL query to select the user_id for a given user_name
    const char *sql = "SELECT user_id FROM users WHERE user_name = ?";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK)
        return -1;

    sqlite3_bind_text(stmt, 1, user_name, -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        *user_id_len = sqlite3_column_bytes(stmt, 0);
        *user_id = malloc(*user_id_len);
        memcpy(*user_id, sqlite3_column_blob(stmt, 0), *user_id_len);
    } else {
        // No record found or an error occurred
        sqlite3_finalize(stmt);
        return -1;
    }

    sqlite3_finalize(stmt);
    return 0; // Success
}

int get_credential(sqlite3 *db, const u8 *user_id, size_t user_id_len,
                   const u8 *cred_id, size_t cred_id_len,
                   struct credential *cred, char **rpid) {
    // SQL query to select the public key, rpid, and sign count for a given
    // user_id and cred_id
    const char *sql = "SELECT type, transports, pubkey_cose, sign_count, rp_id "
                      "FROM credentials WHERE user_id = ? AND cred_id = ?";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK)
        return -1;

    sqlite3_bind_blob(stmt, 1, user_id, user_id_len, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, cred_id, cred_id_len, SQLITE_STATIC);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "Found credential in database");
        debug_print_hex(DEBUG_LEVEL_MORE_VERBOSE, "    user_id: ", user_id,
                        user_id_len);
        debug_print_hex(DEBUG_LEVEL_MORE_VERBOSE, "    cred_id: ", cred_id,
                        cred_id_len);
        cred->type = strdup((const char *)sqlite3_column_text(stmt, 0));

        int transports = sqlite3_column_int(stmt, 1);
        cred->transports_len = 0;
        for (TRANSPORT t = USB; t <= INTERNAL; t <<= 1) {
            if (transports & t)
                cred->transports_len++;
        }
        cred->transports = malloc(cred->transports_len * sizeof(TRANSPORT));
        size_t idx = 0;
        for (TRANSPORT t = USB; t <= INTERNAL; t <<= 1) {
            if (transports & t) {
                cred->transports[idx++] = t;
            }
        }

        cred->pubkey_cose_len = sqlite3_column_bytes(stmt, 2);
        cred->pubkey_cose = malloc(cred->pubkey_cose_len);
        memcpy(cred->pubkey_cose, sqlite3_column_blob(stmt, 2),
               cred->pubkey_cose_len);
        debug_print_hex(DEBUG_LEVEL_MORE_VERBOSE,
                        "    pubkey_cose: ", cred->pubkey_cose,
                        cred->pubkey_cose_len);

        cred->sign_count = sqlite3_column_int(stmt, 3);
        debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    sign_count: %d",
                     cred->sign_count);

        *rpid = strdup((const char *)sqlite3_column_text(stmt, 4));
        debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    rp_id: %s", *rpid);
    } else {
        // No record found or an error occurred
        sqlite3_finalize(stmt);
        return -1;
    }

    sqlite3_finalize(stmt);
    return 0; // Success
}

int update_sign_count(sqlite3 *db, const u8 *cred_id, size_t cred_id_len,
                     int sign_count) {
    // SQL statement to update the sign count to a new value for a specific credential ID
    const char *sql =
        "UPDATE credentials SET sign_count = ? WHERE cred_id = ?";
    sqlite3_stmt *stmt;
    int rc;

    // Prepare the SQL statement
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        // Error in preparing the statement
        return -1;
    }

    // Bind the new sign_count to the prepared statement as the first parameter
    sqlite3_bind_int(stmt, 1, sign_count);

    // Bind the cred_id to the prepared statement as the second parameter
    sqlite3_bind_blob(stmt, 2, cred_id, cred_id_len, SQLITE_STATIC);

    // Execute the update statement
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        // The update did not complete successfully
        sqlite3_finalize(stmt);
        return -1;
    }

    // Clean up
    sqlite3_finalize(stmt);
    return 0;
}
//TODO: Anpassung der Name von Funktion zu get_excluded_credentials
int get_excluded_credential_descriptors(sqlite3 *db, const u8 *user_id, size_t user_id_len,
                            struct public_key_credential_descriptor **creds, size_t *creds_len) {
    const char *sql = "SELECT cred_id, type, transports "
                      "FROM credentials WHERE user_id == ?";
    sqlite3_stmt *stmt;
    int rc;

    *creds_len = 0;
    *creds = NULL;

    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK)
        return -1;

    sqlite3_bind_blob(stmt, 1, user_id, user_id_len, SQLITE_STATIC);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        *creds = realloc(*creds, (*creds_len + 1) * sizeof(struct public_key_credential_descriptor));
        struct public_key_credential_descriptor *cred = &(*creds)[*creds_len];

        // Assuming `id` is the first column
        size_t id_len = sqlite3_column_bytes(stmt, 0);
        cred->id = malloc(id_len);
        memcpy(cred->id, sqlite3_column_blob(stmt, 0), id_len);
        cred->id_len = id_len;

      
        if(sqlite3_column_type(stmt, 1) != SQLITE_TEXT){
            return -1;
        }
        int type_len = sqlite3_column_bytes(stmt, 1);
        if(type_len != strlen("public-key")){
            return -1;
        }
        if(memcmp(sqlite3_column_text(stmt, 1), "public-key", type_len)!=0){
            return -1;
        }
        cred->type = PUBLIC_KEY;   
        //Zuerst bewusst die Transport-Liste weglassen, weil die standartkonforme Entwicklung mit einem YubiKy erwartet wird
        cred->transports_len = 0;
        cred->transports = NULL;
        (*creds_len)++;
    }
    debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "Number of excluded credentials: %zu",
                 *creds_len);

    sqlite3_finalize(stmt);
    return 0; // Success
}

int add_creds(sqlite3 *db, const u8 *user_id, size_t user_id_len,
              const char *user_name, const char *rpid,
              struct credential *cred) {
    sqlite3_stmt *stmt;
    int rc;

    // Check if user exists
    const char *sql_check_user = "SELECT user_id FROM users WHERE user_id = ?";
    rc = sqlite3_prepare_v2(db, sql_check_user, -1, &stmt, NULL);
    if (rc != SQLITE_OK)
        return -1;

    sqlite3_bind_blob(stmt, 1, user_id, user_id_len, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_DONE) {    // No user found, need to insert
        sqlite3_finalize(stmt); // Finalize the current statement before reusing

        debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "Adding new user to database");

        // Insert new user
        const char *sql_insert_user =
            "INSERT INTO users (user_id, user_name) VALUES (?, ?)";
        rc = sqlite3_prepare_v2(db, sql_insert_user, -1, &stmt, NULL);
        if (rc != SQLITE_OK)
            return -1;

        sqlite3_bind_blob(stmt, 1, user_id, user_id_len, SQLITE_STATIC);
        debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    user_name: %s", user_name);
        sqlite3_bind_text(stmt, 2, user_name, -1, SQLITE_STATIC);
        debug_print_hex(DEBUG_LEVEL_MORE_VERBOSE, "    user_id: ", user_id,
                        user_id_len);

        if (sqlite3_step(stmt) != SQLITE_DONE) {
            sqlite3_finalize(stmt);
            return -1; // Failed to insert new user
        }
    }
    sqlite3_finalize(stmt); // Finalize to reuse the stmt variable

    // Insert the credential
    const char *sql_insert_cred =
        "INSERT INTO credentials (user_id, rp_id, type, cred_id, pubkey_cose, "
        "sign_count, transports) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)";
    rc = sqlite3_prepare_v2(db, sql_insert_cred, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
        return -1;
    }
    debug_printf(DEBUG_LEVEL_MORE_VERBOSE,
                 "Adding new credential to database for user: %s", user_name);

    // Bind the parameters for credentials
    sqlite3_bind_blob(stmt, 4, cred->id, cred->id_len, SQLITE_STATIC);
    debug_print_hex(DEBUG_LEVEL_MORE_VERBOSE, "    cred_id: ", cred->id,
                    cred->id_len);
    sqlite3_bind_blob(stmt, 1, user_id, user_id_len, SQLITE_STATIC);
    debug_print_hex(DEBUG_LEVEL_MORE_VERBOSE, "    user_id: ", user_id,
                    user_id_len);
    sqlite3_bind_text(stmt, 2, rpid, -1, SQLITE_STATIC);
    debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    rp_id: %s", rpid);
    sqlite3_bind_text(stmt, 3, cred->type, -1, SQLITE_STATIC);
    debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    type: %s", cred->type);
    sqlite3_bind_blob(stmt, 5, cred->pubkey_cose, cred->pubkey_cose_len,
                      SQLITE_STATIC);
    debug_print_hex(DEBUG_LEVEL_MORE_VERBOSE,
                    "    pubkey_cose: ", cred->pubkey_cose,
                    cred->pubkey_cose_len);
    sqlite3_bind_int(stmt, 6, cred->sign_count);
    debug_printf(DEBUG_LEVEL_MORE_VERBOSE, "    sign_count: %d",
                 cred->sign_count);
    sqlite3_bind_int(stmt, 7, 0); // No transports specified

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? 0 : -1;
}


int cred_id_exists(sqlite3 *db, const u8 *cred_id, size_t cred_id_len){
    sqlite3_stmt *stmt;
    int rc;

    // Check if credential ID exists
    const char *sql_check_credential_id = "SELECT cred_id FROM credentials WHERE cred_id = ?";
    rc = sqlite3_prepare_v2(db, sql_check_credential_id, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
        return -1;
    }
    sqlite3_bind_blob64(stmt, 1, cred_id, cred_id_len, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc==SQLITE_ROW){
        return 1;
    }
    if(rc == SQLITE_DONE){
        return 0;
    }
    else{
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
        return -1;
    }
}