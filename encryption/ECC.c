#include "ECC.h"
#include <openssl/ecdh.h>
#include <openssl/obj_mac.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void handle_errors() {
    // ERR_print_errors_fp(stderr);
    // abort();
}

void print_public_key(const EC_KEY *key) {
    const EC_GROUP *group = EC_KEY_get0_group(key);
    const EC_POINT *pub_key = EC_KEY_get0_public_key(key);

    unsigned char pub_key_buf[256];
    size_t pub_key_len = EC_POINT_point2oct(group, pub_key, POINT_CONVERSION_UNCOMPRESSED, pub_key_buf, sizeof(pub_key_buf), NULL);

    if (pub_key_len == 0) {
        handle_errors();
    }

    printf("Public Key: ");
    for (size_t i = 0; i < pub_key_len; ++i) {
        printf("%02X", pub_key_buf[i]);
    }
    printf("\n");
}

void print_private_key(const EC_KEY *key) {
    const BIGNUM *priv_key = EC_KEY_get0_private_key(key);
    if (!priv_key) {
        handle_errors();
    }

    char *priv_key_hex = BN_bn2hex(priv_key);
    printf("Private Key: %s\n", priv_key_hex);
    OPENSSL_free(priv_key_hex);
}

size_t ecc_encrypt(const EC_KEY *public_key, const UINT *data, size_t data_len, unsigned char *encrypted) {
    const EC_GROUP *group = EC_KEY_get0_group(public_key);
    const EC_POINT *pub_point = EC_KEY_get0_public_key(public_key);

    if (!group || !pub_point) {
        handle_errors();
    }

    EC_KEY *ephemeral_key = EC_KEY_new_by_curve_name(EC_GROUP_get_curve_name(group));
    if (!ephemeral_key || !EC_KEY_generate_key(ephemeral_key)) {
        handle_errors();
    }

    unsigned char shared_secret[32];
    int secret_len = ECDH_compute_key(shared_secret, sizeof(shared_secret), pub_point, ephemeral_key, NULL);
    if (secret_len <= 0) {
        handle_errors();
    }

    size_t ephemeral_len = EC_POINT_point2oct(group, EC_KEY_get0_public_key(ephemeral_key),
                                              POINT_CONVERSION_UNCOMPRESSED, encrypted, 256, NULL);
    if (ephemeral_len == 0) {
        handle_errors();
    }

    for (size_t i = 0; i < data_len * sizeof(UINT); ++i) {
        encrypted[ephemeral_len + i] = ((unsigned char *)data)[i] ^ shared_secret[i % secret_len];
    }

    EC_KEY_free(ephemeral_key);
    return ephemeral_len + (data_len * sizeof(UINT));
}

size_t ecc_decrypt(const EC_KEY *private_key, const unsigned char *encrypted, size_t encrypted_len, UINT *decrypted, size_t data_len) {
    const EC_GROUP *group = EC_KEY_get0_group(private_key);

    if (!group) {
        handle_errors();
    }

    EC_POINT *ephemeral_point = EC_POINT_new(group);
    size_t ephemeral_len = EC_POINT_point2oct(group, EC_KEY_get0_public_key(private_key),
                                              POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);

    if (!EC_POINT_oct2point(group, ephemeral_point, encrypted, ephemeral_len, NULL)) {
        handle_errors();
    }

    unsigned char shared_secret[32];
    int secret_len = ECDH_compute_key(shared_secret, sizeof(shared_secret), ephemeral_point, private_key, NULL);
    if (secret_len <= 0) {
        handle_errors();
    }

    for (size_t i = 0; i < data_len * sizeof(UINT); ++i) {
        ((unsigned char *)decrypted)[i] = encrypted[ephemeral_len + i] ^ shared_secret[i % secret_len];
    }

    EC_POINT_free(ephemeral_point);
    return data_len * sizeof(UINT);
}
