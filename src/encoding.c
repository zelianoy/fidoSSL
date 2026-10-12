#include "encoding.h"

int encode_base64(const u8 *input, size_t input_len, char** output) {
    if (input == NULL || output == NULL) return -1;

    // Calculate the output length: 4 characters for every 3 bytes
    size_t output_len = 4 * ((input_len + 2) / 3);

    // Allocate memory for the base64 encoded data and null terminator
    *output = (char *)OPENSSL_malloc(output_len + 1);
    if (*output == NULL) return -1;

    // Perform Base64 encoding
    int encoded_len = EVP_EncodeBlock((unsigned char*)*output, input, input_len);
    if (encoded_len < 0) {
        OPENSSL_free(*output);
        return -1;
    }
    // Null-terminate the encoded string
    (*output)[encoded_len] = '\0';

    return 0;
}

int decode_base64(const char *input, u8 **output, size_t *output_len) {
    if (input == NULL || output == NULL) return -1;

    size_t len = strlen(input);

    // Allocate memory for the output buffer. The decoded size will be less than
    // the input size
    *output = (u8*)OPENSSL_malloc(len);
    if (*output == NULL) return -1;

    // Decode the Base64 string
    int decode_len = EVP_DecodeBlock(*output, (const unsigned char *)input, len);
    if (decode_len < 0) {
        free(*output);
        return -1;
    }
    // Adjust for padding. EVP_DecodeBlock does not handle padding.
    if (len > 0 && input[len - 1] == '=') {
        decode_len--;
        if (len > 1 && input[len - 2] == '=') decode_len--;
    }
    *output_len = decode_len; // Set the actual decoded length
    return 0;
}

int base64url_encode(const u8 *input, size_t input_len, char** output) {
    if (encode_base64(input, input_len, output) != 0) {
        return -1;
    }
    // Replace base64 characters which are not URL safe
    for (char *p = *output; *p; p++) {
        if (*p == '+') *p = '-';
        else if (*p == '/') *p = '_';
    }
    // Remove the trailing '='
    size_t output_len = strlen(*output);
    for (size_t i = output_len; i > 0; i-- ) {
        if ((*output)[i - 1] == '=') {
            output_len--;  
        }
        else {
            break;
        }
    }
    (*output)[output_len] = '\0';  
    return 0;
}

int base64url_decode(const char *input, u8 **output, size_t *output_len) {
    // Calculate length of the input string
    size_t len = strlen(input);

    // Base64 encodes each group of 3 bytes as 4 characters;
    // The input length modulo 4 determines how many '=' padding characters must be restored before decoding. 
    // Thus we can notice whether the last group of 4 chars was complete or not.
    size_t padding_num = len % 4;
    if (padding_num == 1) {
        return -1;
    }

    // Allocate a temporary buffer for the modified input
    char *modifiedInput = (char *)malloc(len + padding_num + 1); //+padding_num for the '=' chars and +1 for null terminator
    if (!modifiedInput) {
        return -1;
    }

    // Copy input to the modifiable buffer
    strcpy(modifiedInput, input);

    // Replace '-' with '+' and '_' with '/' for Base64URL to Base64 conversion
    for (size_t i = 0; i < len; ++i) {
        if (modifiedInput[i] == '-') modifiedInput[i] = '+';
        else if (modifiedInput[i] == '_') modifiedInput[i] = '/';
    }
    
    if (padding_num == 2) {
        modifiedInput[len] = '=';
        modifiedInput[len+1] = '=';
        modifiedInput[len+2] = '\0';
    }
    else if (padding_num == 3) {
        modifiedInput[len] = '=';
        modifiedInput[len+1] = '\0';
    }

    // Use the base64_decode function on the modified input
    int decodeResult = decode_base64(modifiedInput, output, output_len);

    // Free the temporary buffer
    free(modifiedInput);

    return decodeResult;
}
