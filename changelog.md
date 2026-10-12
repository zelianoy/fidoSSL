# fidoSSL Changelog



## Message changes
//TODO : Write changes
### Pre-Registration Indication

- has been renamed to Pre Indication
//TODO
### Pre-Registration Request

- has been renamed to Pre Response, including structures, functions and states
- changed the length of ephemeral user ID to 256 bytes




### Pre-Registration Response

- removed

### Registration Indication

- message type is now 3
- Registration Indication contains now one encrypted data CBOR array and 256-byte  ephemeral user ID
- created an inner encrypted data CBOR array, which contains padded user display name and 256-byte ticket
- added builder and parser functions for the encrypted data array
- added padding and unpadding of the user display name 
- added AES-256-GCM encryption and decryption of the encrypted data

### Registration Request

- message type is now 4
- Registration Request contains now RP ID, RP name, challenge, public-key credential parameters, encrypted data and optional parameters
- changed the length of user ID from 16 to 64 bytes
- public key credential parameters are now arrays, which contain credential type and COSE algorithm, though only the ES256 is currently supported
- created an inner encrypted data CBOR array, which contains padded user name, padded user display name, 64-byte user ID and optional excluded credentials into an inner CBOR array
- added serialization and parsing of excluded credentials descriptors
- added AES-256-GCM encryption and decryption of the encrypted data
- moved timeout, authenticator selection criteria, attestation preference and extensions to the optional parameters map
- the AES-GCM-KEY is now derived from ephemeral user id

### Registration Response

- message type is now 5
- now the authenticator creates an attestation object, which contains authenticator data and attestation statement. The Relying Party cryptographically validates the attestation statement, using the certificate supplied by authenticator. The certificate trust chain is not validated.

### Authentication Indication (discoverable credential)

- message type is now 6

### Authentication Indication (server-side credential)

- added a new message type for authentication with server-side credentials
- message type is 7
- message contains ephemeral user id, which is established in a Pre Handshake 
- message contains the user name, which is padded and encrypted with AES-256-GCM

### Authentication Request

- message type is now 8
- CBOR map called optionals now contains a list of credentials acceptable to the caller. This list is encrypted, MUST be present when server-side credentials are used and MUST NOT be present when discoverable credentials are used
- CBOR map contains now additional parameters called extensions
- added CBOR serialisation and parsing of allowed credential descriptors
- we now filter credential descriptors by user ID and RP ID
- the allowed credential IDs are passed to authenticator with fido_assert_allow_cred() 
- saved the allow list on server side for response verification

### Authentication Response

- message type is now 9
- user handle is now part of a CBOR map called optionals with key 1
- Selected Credential ID is now part of a CBOR map called optionals with key 2
- required a User Handle only for discoverable credentials, when server-side credentials are used, the user handle can be omitted
- checked the provided user handle against the expected user id in server-side authentication
- rejected credential IDs that are not included in the requests allow list
- required User Presence flag during server-side assertion verification
- checked that the stored credential belongs to the current RP ID
- we still include an additional credential ID, which does not align with the draft's response format


## Other Changes

- added option to use SSLKEYLOGFILE to log SSL session keys
- updated the dummy tls certificate
- corrected encryption and decryption functions
- limited the user name and user display name to 255 bytes. This preserves one byte for the 0x80 delimiter and enables unambiguous removal of the padding
- updated the dummy tls certificate to use the RFC 5280-compliant serial number '0x01' and added its matching all zero-Ed25519 test key
- updated dependencies to SQLite 3.53.4, TinyCBOR 7.0, libfido 1.17.0, Jansson 2.15.1 and OpenSSL 3.6.4
- migrated the TinyCBOR from Make to CMake
- changed the macOS OpenSSL install names to use '@rpath'
- IV is deterministically derived from the message type
- added separate client modes and state-machine paths for discoverable and server-side authentication
- removed trailing padding characters from Base64URL encoding and restored missing padding before decoding
