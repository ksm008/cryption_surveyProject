#include <winsock2.h>
#include <windows.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/obj_mac.h>
#include <openssl/err.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "../encryption/ChaCha20.h"  
#include "../encryption/ECC.h" 

#pragma comment(lib, "ws2_32.lib")
#define PORT 8084
#define BUFFER_SIZE 8192

#define WINDOW_WIDTH 800
#define WINDOW_HEIGHT 800

HWND hEditOutput, hEditDisplay;
HFONT hFont; 
SOCKET server_socket, client_socket;
UINT key[8];
EC_KEY *key_pair = NULL;

LRESULT CALLBACK WindowProcedure(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp);

const wchar_t* fontName = L"-윤고딕320";  
int fontSize = 16;  

void initialize_openssl() {
    if (OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL) == 0) {
        fprintf(stderr, "OpenSSL 초기화 실패\n");
        abort();
    }
}

void ECC_Dec(BYTE *input, size_t input_len, UINT *output, size_t output_len) {
    // ECC 그룹 생성 (개인 키와 같은 곡선 사용)
    const EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    if (!group) {
        MessageBox(NULL, L"ECC 그룹 생성 실패", L"오류", MB_OK);
        return;
    }

    // 개인 키를 이용하여 복호화 수행
    if (!key_pair) {
        MessageBox(NULL, L"ECC 개인 키가 초기화되지 않았습니다.", L"오류", MB_OK);
        EC_GROUP_free((EC_GROUP *)group);
        return;
    }

    // 복호화 수행
    size_t decrypted_len = ecc_decrypt(key_pair, input, input_len, output, output_len);
    if (decrypted_len != output_len * sizeof(UINT)) {
        // MessageBox(NULL, L"ECC 복호화 실패", L"오류", MB_OK);
        EC_GROUP_free((EC_GROUP *)group);
        return;
    }

    // 메모리 해제
    EC_GROUP_free((EC_GROUP *)group);
}

DWORD WINAPI ServerThread(LPVOID lpParam) {
    WSADATA wsa;
    struct sockaddr_in server_addr, client_addr;
    int client_addr_size = sizeof(client_addr);

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        SetWindowText(hEditOutput, L"Winsock 초기화 실패!");
        return 1;
    }

    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == INVALID_SOCKET) {
        SetWindowText(hEditOutput, L"소켓 생성 실패!");
        WSACleanup();
        return 1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        SetWindowText(hEditOutput, L"바인딩 실패!");
        closesocket(server_socket);
        WSACleanup();
        return 1;
    }

    listen(server_socket, 3);
    SetWindowText(hEditOutput, L"클라이언트를 기다리는 중...");

    client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_addr_size);
    if (client_socket == INVALID_SOCKET) {
        SetWindowText(hEditOutput, L"클라이언트 연결 실패");
        closesocket(server_socket);
        WSACleanup();
        return 1;
    }

    int nid = NID_secp256k1;
    key_pair = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!key_pair || !EC_KEY_generate_key(key_pair)) {
        handle_errors();
    }

    // 공개 키 직렬화
    const EC_GROUP *group = EC_KEY_get0_group(key_pair);
    const EC_POINT *pub_key = EC_KEY_get0_public_key(key_pair);
    unsigned char pub_key_buf[256];
    size_t pub_key_len = EC_POINT_point2oct(group, pub_key, POINT_CONVERSION_UNCOMPRESSED, pub_key_buf, sizeof(pub_key_buf), NULL);
    if (pub_key_len == 0) {
        handle_errors();
    }

    // 개인 키 가져오기
    const BIGNUM *priv_key = EC_KEY_get0_private_key(key_pair);
    if (!priv_key) {
        handle_errors();
    }

    // 개인 키를 16진수 문자열로 변환
    char *priv_key_hex = BN_bn2hex(priv_key);
    if (!priv_key_hex) {
        handle_errors();
    }

    send(client_socket, (char*)pub_key_buf, pub_key_len, 0);

    // 서버 로그에 공개 키와 개인 키 출력
    wchar_t displayMessage[BUFFER_SIZE * 8] = L"클라이언트와 연결되었습니다!\r\n공개 키 전송 완료:\r\n";
    for (size_t i = 0; i < pub_key_len; i++) {
        wchar_t temp[4];
        wsprintf(temp, L"%02X", pub_key_buf[i]);
        wcscat(displayMessage, temp);
    }
    wcscat(displayMessage, L"\r\n");

    wcscat(displayMessage, L"개인 키:\r\n");
    size_t priv_key_len = strlen(priv_key_hex);
    for (size_t i = 0; i < priv_key_len; i++) {
        wchar_t temp[2];
        wsprintf(temp, L"%c", priv_key_hex[i]);
        wcscat(displayMessage, temp);
    }
    wcscat(displayMessage, L"\r\n");

    SetWindowText(hEditOutput, displayMessage);

    // 개인 키 문자열 메모리 해제
    OPENSSL_free(priv_key_hex);

    while (1) {
        wchar_t displayMessage[BUFFER_SIZE * 12] = L"";
        wchar_t displayResult[BUFFER_SIZE * 6] = L"";      

        int enc_length = 0;
        BYTE enc_key[512] = {0};
        BYTE ciphertext[BUFFER_SIZE];
        BYTE mac[16];
        BYTE mac_2[16];
        BYTE poly1305_key[32];   
        BYTE enc_poly1305_key[512] = {0}; 
        size_t enc_len = 0;
        size_t enc_polyLen = 0;

        UINT nonce[3];
        UINT counter = 1;
        int plainTextLen;
        int isConn;

        isConn = recv(client_socket, (char*)&enc_length, sizeof(enc_length), 0);

        if (isConn == 0) {
        // 클라이언트가 연결 종료
            MessageBox(NULL, L"클라이언트가 연결을 종료했습니다. 서버를 종료합니다.", L"알림", MB_OK);
                closesocket(client_socket);  
                closesocket(server_socket);  
                WSACleanup();             
                PostQuitMessage(0);
                ExitProcess(0);         
            break;
        } 

        recv(client_socket, (char*)enc_key, enc_length, 0);

        ECC_Dec(enc_key, enc_length, key, 8);

        wcscpy(displayMessage, L"ECC의 개인 키로 복호화된 ChaCha20 키:\r\n");
        for (int i = 0; i < 8; i++) {
            wchar_t temp[16];
            wsprintf(temp, L"%08X ", key[i]);
            wcscat(displayMessage, temp);
        }
        wcscat(displayMessage, L"\r\n");

        recv(client_socket, (char*)&enc_length, sizeof(enc_length), 0);
        recv(client_socket, (char*)enc_poly1305_key, enc_length, 0);

        ECC_Dec(enc_poly1305_key, enc_length, (UINT*)poly1305_key, 8);

        int len = recv(client_socket, (char*)&plainTextLen, sizeof(plainTextLen), 0);
        if (len <= 0) break;
        recv(client_socket, (char*)ciphertext, plainTextLen, 0);
        recv(client_socket, (char*)mac, sizeof(mac), 0);
        recv(client_socket, (char*)nonce, sizeof(nonce), 0);
               
        wcscat(displayMessage, L"암호문:\r\n");
        for (int i = 0; i < plainTextLen; i++) {
            wchar_t temp[4];
            wsprintf(temp, L"%02X ", ciphertext[i]);
            wcscat(displayMessage, temp);
        }
        wcscat(displayMessage, L"\r\n");
               
        wcscat(displayMessage, L"Nonce:\r\n");
        for (int i = 0; i < 3; i++) {
            wchar_t temp[16];
            wsprintf(temp, L"%08X ", nonce[i]);
            wcscat(displayMessage, temp);
        }
        wcscat(displayMessage, L"\r\n");
       
        wcscat(displayMessage, L"ECC의 개인 키로 복호화된 Poly1305 키:\r\n");
        for (int i = 0; i < 32; i++) {
            wchar_t temp[4];
            wsprintf(temp, L"%02X ", poly1305_key[i]);
            wcscat(displayMessage, temp);
        }
        wcscat(displayMessage, L"\r\n");    
        wcscat(displayMessage, L"MAC:\r\n");
        for (int i = 0; i < 16; i++) {
            wchar_t temp[4];
            wsprintf(temp, L"%02X ", mac[i]);
            wcscat(displayMessage, temp);
        }
        wcscat(displayMessage, L"\r\n");

        BYTE decrypted[BUFFER_SIZE] = {0};
        chacha20_encrypt(ciphertext, decrypted, plainTextLen, key, counter, nonce);
        poly1305_mac(ciphertext, plainTextLen, poly1305_key, mac_2);

        wcscat(displayMessage, L"재생성된 Poly1305 MAC:\r\n");
        for (int i = 0; i < 16; i++) {
            wchar_t temp[4];
            wsprintf(temp, L"%02X ", mac_2[i]);
            wcscat(displayMessage, temp);
        }
        wcscat(displayMessage, L"\r\n");

        if (memcmp(mac, mac_2, sizeof(mac)) == 0) {
            wcscat(displayMessage, L"무결성 인증에 성공하였습니다.\r\n");
            // Decrypted data 출력
            wcscat(displayMessage, L"복호문 (16진수):\r\n");
            for (int i = 0; i < plainTextLen; i++) {
                wchar_t temp[4];
                wsprintf(temp, L"%02X ", decrypted[i]);
                wcscat(displayMessage, temp);
            }

            // 16진수 데이터의 텍스트로 변환해서 출력
            wcscat(displayResult, L"복호화된 결과:");

            // 텍스트로 변환
            char decrypted_text[BUFFER_SIZE] = {0};
            for (int i = 0; i < plainTextLen; i++) {
                decrypted_text[i] = decrypted[i];  // 바이트 배열을 텍스트 배열로 변환
            }

            // UTF-8로 변환된 텍스트를 출력
            wchar_t utf16Buffer[BUFFER_SIZE] = {0};
            MultiByteToWideChar(CP_UTF8, 0, decrypted_text, -1, utf16Buffer, BUFFER_SIZE);
            
            // 구분자 '|'을 기준으로 문자열 분할
            wchar_t* context = NULL;
            wchar_t* token = wcstok(utf16Buffer, L"|", &context);
            int fieldIndex = 0;

            // 각 필드를 항목 제목과 함께 출력
            while (token != NULL) {
                switch (fieldIndex) {
                    case 0:
                        wcscat(displayResult, L"\r\n제출자 이름: ");
                        break;
                    case 1:
                        wcscat(displayResult, L"\r\n제출일자: ");
                        break;
                    case 2:
                        wcscat(displayResult, L"\r\n\r\n1. 현대암호학은 어떤 과목이라고 생각합니까?\r\n- ");
                        break;
                    case 3:
                        wcscat(displayResult, L"\r\n\r\n2. 현대암호학의 강의 난이도는 어떻습니까?\r\n- ");
                        break;
                    case 4:
                        wcscat(displayResult, L"\r\n\r\n3. 난이도에 대한 이유는 무엇입니까?\r\n- ");
                        break;
                    case 5:
                        wcscat(displayResult, L"\r\n\r\n4. 현재 알고 있는 암호화 방식을 알려주세요.\r\n- ");
                        break;
                    case 6:
                        wcscat(displayResult, L"\r\n\r\n5. 암호학에 관하여 더 알고 싶은 것들이 있습니까?\r\n- ");
                        break;
                    case 7:
                        wcscat(displayResult, L"\r\n\r\n6. 본 강의를 들으면서 바라는 점이 있다면 적어주세요.\r\n- ");
                        break;
                    default:
                        break;
                }

                wcscat(displayResult, token);
                fieldIndex++;
                token = wcstok(NULL, L"|", &context);
            }            

        } else {
            wcscat(displayMessage,L"MAC 인증에 실패하였습니다.\r\n");
        }
        SetWindowText(hEditOutput, displayMessage);
        SetWindowText(hEditDisplay, displayResult);
        
    }

    closesocket(client_socket);
    closesocket(server_socket);
    WSACleanup();
    return 0;
}

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE hPrevInst, LPWSTR args, int ncmdshow) {
    initialize_openssl();
    WNDCLASS wc = {0};
    wc.hbrBackground = (HBRUSH)COLOR_WINDOW;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hInstance = hInst;
    wc.lpszClassName = L"ServerWindowClass";
    wc.lpfnWndProc = WindowProcedure;

    if (!RegisterClass(&wc))
        return -1;
  
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);
    int posX = (screenWidth - WINDOW_WIDTH) / 2;
    int posY = (screenHeight - WINDOW_HEIGHT) / 2;

    HWND hwnd = CreateWindow(
        L"ServerWindowClass", L"현대암호학 강의 만족도 설문조사 서버",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
        posX, posY, WINDOW_WIDTH, WINDOW_HEIGHT,
        NULL, NULL, hInst, NULL
    );

    CreateThread(NULL, 0, ServerThread, NULL, 0, NULL);

    MSG msg = {0};
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return 0;
}

LRESULT CALLBACK WindowProcedure(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    static HFONT hFontTitle;  
    static HFONT hFont;  
    switch (msg) {
        case WM_CREATE:         
            hFont = CreateFont(fontSize, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
                            DEFAULT_PITCH | FF_SWISS, fontName);

            // hEditOutput 생성
            hEditOutput = CreateWindow(L"EDIT", L"", 
                WS_VISIBLE | WS_CHILD | WS_BORDER | ES_MULTILINE | WS_VSCROLL | ES_AUTOVSCROLL | ES_READONLY,
                20, 20, WINDOW_WIDTH - 40, (WINDOW_HEIGHT - 340) * 3 / 5, hwnd, NULL, NULL, NULL);  
            SendMessage(hEditOutput, WM_SETFONT, (WPARAM)hFont, TRUE);

            // hEditDisplay 생성 - hEditOutput 아래에 위치
            hEditDisplay = CreateWindow(L"EDIT", L"", 
                WS_VISIBLE | WS_CHILD | WS_BORDER | ES_MULTILINE | WS_VSCROLL | ES_AUTOVSCROLL | ES_READONLY,
                20, 30 + (WINDOW_HEIGHT - 340) * 3 / 5, WINDOW_WIDTH - 40, 440, hwnd, NULL, NULL, NULL);  
            SendMessage(hEditDisplay, WM_SETFONT, (WPARAM)hFont, TRUE);
            break;
        case WM_DESTROY:
            closesocket(client_socket);
            closesocket(server_socket);
            WSACleanup();
            PostQuitMessage(0);
            break;
        default:
            return DefWindowProc(hwnd, msg, wp, lp);
    }
    return 0;
}


