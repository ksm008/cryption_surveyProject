#ifndef CHACHA20_H
#define CHACHA20_H

#include <stdint.h>
#include <stdlib.h>

// 상수 정의
#define ROUNDS 20
typedef uint8_t BYTE;
typedef uint32_t UINT;

// 함수 원형 선언
void quarter_round(UINT *a, UINT *b, UINT *c, UINT *d);
void chacha20_block(UINT output[16], const UINT input[16]);
void chacha20_encrypt(BYTE *plaintext, BYTE *ciphertext, uint32_t length, UINT key[8], UINT counter, UINT nonce[3]);
void generate_nonce(UINT nonce[3]);
void expand_key(char *input_key, UINT key[8]);
void poly1305_mac(const BYTE *msg, size_t msg_len, const BYTE key[32], BYTE mac[16]);

#endif // CHACHA20_V2_H
