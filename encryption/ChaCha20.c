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

// 키 확장 함수 (32글자가 안 되면 랜덤으로 채우기)
void expand_key(char *input_key, UINT key[8]) {
    int len = strlen(input_key);

    if (len < 32) {
        for (int i = len; i < 32; i++) {
            input_key[i] = 'A' + (rand() % 26); // 랜덤한 알파벳으로 채우기
        }
        input_key[32] = '\0'; // 널 문자 추가
    }

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

// 메인 함수
int main() {
    BYTE *plaintext;
    BYTE *ciphertext;
    BYTE *decrypted;
    BYTE mac[16];
    UINT key[8];
    UINT nonce[3];
    char input_key[33];
    int i, repeat_count;
    size_t text_len = 0;

    srand(time(NULL));

    // 1. 평문 입력 방식을 선택
    int input_mode;
    printf("* 1. 문자열 입력\n* 2. 파일로부터 입력\n* 입력 방식 선택 (1 또는 2): ");
    scanf("%d", &input_mode);
    getchar(); // Enter 키 제거

    if (input_mode == 1) {
        // 문자열로 평문 입력 받기
        size_t buffer_size = 1024;
        plaintext = malloc(buffer_size);
        ciphertext = malloc(buffer_size);
        decrypted = malloc(buffer_size);

        printf("* 평문 입력: ");
        fgets((char *)plaintext, buffer_size, stdin);
        plaintext[strcspn((char *)plaintext, "\n")] = '\0'; // 개행 제거
        text_len = strlen((char *)plaintext);
    } else if (input_mode == 2) {
        // 파일로부터 평문 읽기
        FILE *file = fopen("plainExample.txt", "rb");
        if (file == NULL) {
            perror("파일 열기 실패");
            return 1;
        }
        
        // 파일 크기 계산
        fseek(file, 0, SEEK_END);
        text_len = ftell(file);
        fseek(file, 0, SEEK_SET);

        // 파일 크기에 맞게 메모리 할당
        plaintext = malloc(text_len);
        ciphertext = malloc(text_len);
        decrypted = malloc(text_len);

        if (plaintext == NULL || ciphertext == NULL || decrypted == NULL) {
            perror("메모리 할당 실패");
            fclose(file);
            return 1;
        }

        // 파일 내용 읽기
        fread(plaintext, 1, text_len, file);
        fclose(file);
        printf("* 파일로부터 %zu 바이트의 평문을 읽었습니다.\n", text_len);
    } else {
        printf("잘못된 입력입니다.\n");
        return 1;
    }

    // 2. 비밀 키 입력
    printf("* 비밀 키 입력 (최대 32자리): ");
    fgets(input_key, sizeof(input_key), stdin);
    input_key[strcspn(input_key, "\n")] = '\0'; // 개행 제거

    // 키 확장 및 nonce 생성
    expand_key(input_key, key);
    generate_nonce(nonce);
    printf("* 생성된 Nonce 값: %08x %08x %08x\n", nonce[0], nonce[1], nonce[2]);

    // 3. 반복 횟수 입력
    printf("암호화 및 복호화 반복 횟수를 입력하세요: ");
    scanf("%d", &repeat_count);

    // 암호화 및 MAC 생성 테스트
    clock_t start = clock();
    for (int j = 0; j < repeat_count; j++) {
        chacha20_encrypt(plaintext, ciphertext, text_len, key, 1, nonce);
        poly1305_mac(ciphertext, text_len, (BYTE *)key, mac);
    }
    clock_t end = clock();
    printf("\n* 암호화 및 MAC 생성 %d번 수행 시간: %f초\n", repeat_count, (double)(end - start) / CLOCKS_PER_SEC);

    // 암호문 파일에 저장
    FILE *crypted_file = fopen("cryptedExample.txt", "wb");
    if (crypted_file != NULL) {
        fwrite(ciphertext, 1, text_len, crypted_file);
        fclose(crypted_file);
        printf("* 암호화된 파일 cryptedExample.txt에 저장됨\n");
    } else {
        perror("cryptedExample.txt 파일 열기 실패");
    }

    // 복호화 테스트
    start = clock();
    for (int j = 0; j < repeat_count; j++) {
        chacha20_encrypt(ciphertext, decrypted, text_len, key, 1, nonce);
    }
    end = clock();
    printf("\n* 복호화 %d번 수행 시간: %f초\n", repeat_count, (double)(end - start) / CLOCKS_PER_SEC);

    // 복호문 파일에 저장
    FILE *decrypted_file = fopen("decryptedExample.txt", "wb");
    if (decrypted_file != NULL) {
        fwrite(decrypted, 1, text_len, decrypted_file);
        fclose(decrypted_file);
        printf("* 복호화된 파일 decryptedExample.txt에 저장됨\n");
    } else {
        perror("decryptedExample.txt 파일 열기 실패");
    }

    // 메모리 해제
    free(plaintext);
    free(ciphertext);
    free(decrypted);

    printf("\n* 프로그램을 종료하려면 엔터 키를 누르세요.");

    return 0;
}
