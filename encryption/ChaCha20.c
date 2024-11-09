#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#define ROUNDS 20
typedef uint8_t BYTE;
typedef uint32_t UINT;
#define ROTL(a, b) (((a) << (b)) | ((a) >> (32 - (b))))

// 쿼터 라운드 함수
void quarter_round(UINT *a, UINT *b, UINT *c, UINT *d) {
    *a += *b; *d ^= *a; *d = ROTL(*d, 16);
    *c += *d; *b ^= *c; *b = ROTL(*b, 12);
    *a += *b; *d ^= *a; *d = ROTL(*d, 8);
    *c += *d; *b ^= *c; *b = ROTL(*b, 7);
}

// ChaCha20 블록 함수
void chacha20_block(UINT output[16], const UINT input[16]) {
    int i;
    for (i = 0; i < 16; i++) output[i] = input[i];
    
    for (i = 0; i < ROUNDS; i += 2) {
        quarter_round(&output[0], &output[4], &output[8], &output[12]);
        quarter_round(&output[1], &output[5], &output[9], &output[13]);
        quarter_round(&output[2], &output[6], &output[10], &output[14]);
        quarter_round(&output[3], &output[7], &output[11], &output[15]);
        
        quarter_round(&output[0], &output[5], &output[10], &output[15]);
        quarter_round(&output[1], &output[6], &output[11], &output[12]);
        quarter_round(&output[2], &output[7], &output[8], &output[13]);
        quarter_round(&output[3], &output[4], &output[9], &output[14]);
    }
    
    for (i = 0; i < 16; i++) output[i] += input[i];
}

// ChaCha20 암호화 함수
void chacha20_encrypt(BYTE *plaintext, BYTE *ciphertext, uint32_t length, UINT key[8], UINT counter, UINT nonce[3]) {
    UINT state[16];
    UINT keystream[16];
    BYTE block[64];
    uint32_t i, j;
    
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;
    memcpy(&state[4], key, 32);
    state[12] = counter;
    memcpy(&state[13], nonce, 12);
    
    for (i = 0; i < length; i += 64) {
        chacha20_block(keystream, state);
        
        for (j = 0; j < 16; j++) {
            block[4 * j + 0] = (keystream[j] >> 0) & 0xFF;
            block[4 * j + 1] = (keystream[j] >> 8) & 0xFF;
            block[4 * j + 2] = (keystream[j] >> 16) & 0xFF;
            block[4 * j + 3] = (keystream[j] >> 24) & 0xFF;
        }

        for (j = 0; j < 64 && i + j < length; j++) {
            ciphertext[i + j] = plaintext[i + j] ^ block[j];
        }
        
        state[12]++;
    }
}

// Nonce 자동 생성 함수
void generate_nonce(UINT nonce[3]) {
    for (int i = 0; i < 3; i++) {
        nonce[i] = rand();
    }
}

void expand_key(char *input_key, UINT key[8]) {
    int len = strlen(input_key);

    // 32글자가 안 되면 부족한 부분을 숫자로 채움
    if (len < 32) {
        // 부족한 길이만큼 숫자로 채우기 (예: 0x01, 0x02, ... )
        for (int i = len; i < 32; i++) {
            input_key[i] = (i - len + 1); // 숫자로 채움
        }
        input_key[32] = '\0'; // 널 문자 추가
    }

    // 4바이트씩 끊어서 key 배열에 넣기
    for (int i = 0; i < 8; i++) {
        key[i] = ((uint32_t)input_key[i * 4] << 24) |
                 ((uint32_t)input_key[i * 4 + 1] << 16) |
                 ((uint32_t)input_key[i * 4 + 2] << 8) |
                 ((uint32_t)input_key[i * 4 + 3]);
    }
}
// Poly1305 MAC 생성 함수 (ChaCha20-Poly1305 조합, 클램핑 없이)
void poly1305_mac(const BYTE *msg, size_t msg_len, const BYTE key[32], BYTE mac[16]) {
    UINT r[4], s[4], acc[4] = {0};  
    memcpy(r, key, 16);  
    memcpy(s, key + 16, 16);

    // 클램핑을 생략함 (ChaCha20-Poly1305 조합에서는 클램핑을 하지 않음)

    // 메시지 처리 루프
    for (size_t i = 0; i < msg_len; i += 16) {
        UINT chunk[4] = {0};
        for (size_t j = 0; j < 16 && i + j < msg_len; j++) {
            chunk[j / 4] |= ((UINT)msg[i + j]) << (8 * (j % 4));
        }
        chunk[3] |= 1 << 24;

        // acc += chunk
        for (int j = 0; j < 4; j++) acc[j] += chunk[j];

        // acc = (acc * r) mod p
        for (int j = 0; j < 4; j++) {
            acc[j] *= r[j];
            acc[j] %= 0x3ffffff; // 예시로 단순화한 모듈러 연산
        }
    }

    // 최종 단계: h + s 계산 및 128비트 제한
    UINT carry = 0;
    for (int i = 0; i < 4; i++) {
        acc[i] += s[i] + carry;
        carry = (acc[i] < s[i]) ? 1 : 0;  // Carry propagation
    }

    // 128비트로 제한하여 mac에 저장
    memcpy(mac, acc, 16);
}