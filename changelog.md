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
- added serialization and parsing of excluded credebtials descriptors
- added AES-256-GCM encryption and decryption of the encrypted data
- moved timeout, authenticator selection criteria, attestation preference and extensions to the optional parameters map

### Registration Response

- message type is now 5
- now correctly uses the complete attestation object

### Authentication Indication

- message type is now 6

### Authentication Request

- message type is now 7

### Authentication Response

- message type is now 8
- user handle is now part of a CBOR map called optionals with key 1
- Selected Credential ID is now part of a CBOR map called optionals with key 2
- both User Handle and Selected Credential ID are not actually optional, as only 
  discoverable credentials can be used as of now

## Other Changes

- added option to use SSLKEYLOGFILE to log SSL session keys