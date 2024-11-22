#ifndef ECC_H
#define ECC_H

#include <windows.h>
#include <openssl/ec.h>

void handle_errors();
void print_uint_array(const UINT *arr, size_t size);
void print_public_key(const EC_KEY *key);
void print_private_key(const EC_KEY *key);
size_t ecc_encrypt(const EC_KEY *public_key, const UINT *data, size_t data_len, unsigned char *encrypted);
size_t ecc_decrypt(const EC_KEY *private_key, const unsigned char *encrypted, size_t encrypted_len, UINT *decrypted, size_t data_len);

#endif // ECC_H
