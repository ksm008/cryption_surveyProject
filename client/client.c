#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <time.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/obj_mac.h>
#include <openssl/err.h>
#include <stdlib.h>
#include <string.h>
#include <blake3.h> 
#include "../encryption/ChaCha20.h"  
#include "../encryption/ECC.h" 

#pragma comment(lib, "ws2_32.lib")
#define PORT 8084
#define SERVER_IP "127.0.0.1"
#define BUFFER_SIZE 8192

#define WINDOW_WIDTH 800
#define WINDOW_HEIGHT 800
#define CONTROL_WIDTH 600
#define BUTTON_SUBMIT 1

HWND hEditSend, hEditName, hEditQ1, hEditQ3, hEditQ4, hEditQ5, hEditQ6, hEditDisplay;  
HWND hCheckQ2_1, hCheckQ2_2, hCheckQ2_3, hCheckQ2_4, hCheckQ2_5;
HFONT hFont;
SOCKET client_socket;  
UINT key[8];
BYTE server_pub_key_buf[256];
size_t server_pub_key_len = 0;
int enc_length = 0;

const wchar_t* fontName = L"-윤고딕320";  
int fontSize = 16;   

void initialize_openssl() {
    if (OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL) == 0) {
        fprintf(stderr, "OpenSSL 초기화 실패\n");
        abort();
    }
}

void InitializeSocketAndConnect() {
    initialize_openssl();
    WSADATA wsa;
    struct sockaddr_in server;

    WSAStartup(MAKEWORD(2, 2), &wsa);
    client_socket = socket(AF_INET, SOCK_STREAM, 0);
    server.sin_addr.s_addr = inet_addr(SERVER_IP);
    server.sin_family = AF_INET;
    server.sin_port = htons(PORT);

    if (connect(client_socket, (struct sockaddr*)&server, sizeof(server)) == SOCKET_ERROR) {
        MessageBox(NULL, L"서버 연결 실패", L"오류", MB_OK);
    } else {
        // 서버로부터 공개 키 수신
        server_pub_key_len = recv(client_socket, (char*)server_pub_key_buf, sizeof(server_pub_key_buf), 0);
        if (server_pub_key_len <= 0) {
            MessageBox(NULL, L"공개 키 수신 실패", L"오류", MB_OK);
        } else {
            wchar_t displayMessage[512] = L"서버와 연결되었습니다.\r\n\r\n서버로부터 받은 공개 키: ";
            for (size_t i = 0; i < server_pub_key_len; i++) {
                wchar_t temp[4];
                wsprintf(temp, L"%02X", server_pub_key_buf[i]);
                wcscat(displayMessage, temp);
            }
            MessageBox(NULL, displayMessage, L"알림", MB_OK);
        }
    }
}

void GetCurrentTimeFormatted(wchar_t* buffer, int bufferSize) {
    SYSTEMTIME st;
    GetLocalTime(&st);

    // AM/PM 계산
    wchar_t ampm[3] = L"AM";
    int hour = st.wHour;
    if (hour >= 12) {
        ampm[0] = L'P';
        if (hour > 12) hour -= 12;
    } else if (hour == 0) {
        hour = 12;
    }

    // 포맷된 문자열 생성
    swprintf(buffer, bufferSize, L"%04d-%02d-%02d %02d:%02d:%02d.%03d %s",
        st.wYear, st.wMonth, st.wDay,
        hour, st.wMinute, st.wSecond, st.wMilliseconds, ampm);
}

void GenerateBlake3Key(const char* input, size_t inputLength, UINT key[8]) {
    blake3_hasher hasher;
    BYTE output[32]; // BLAKE3 해시 출력은 32바이트

    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, input, inputLength);
    blake3_hasher_finalize(&hasher, output, 32);  // 32바이트 출력 생성

    // 32바이트를 4바이트 단위로 변환하여 UINT 배열에 저장
    for (int i = 0; i < 8; i++) {
        key[i] = ((UINT)output[i * 4] << 24) |
                 ((UINT)output[i * 4 + 1] << 16) |
                 ((UINT)output[i * 4 + 2] << 8) |
                 ((UINT)output[i * 4 + 3]);
    }
}

void ECC_Enc(UINT *key, size_t key_len, BYTE *output, size_t *output_len) {
    // ECC 그룹 생성 (서버 공개 키와 같은 곡선 사용)
    const EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    if (!group) {
        MessageBox(NULL, L"ECC 그룹 생성 실패", L"오류", MB_OK);
        return;
    }

    // 서버의 공개 키를 복원
    EC_POINT *server_pub_key = EC_POINT_new(group);
    if (!server_pub_key) {
        MessageBox(NULL, L"서버 공개 키 복원 실패", L"오류", MB_OK);
        return;
    }

    if (!EC_POINT_oct2point(group, server_pub_key, server_pub_key_buf, server_pub_key_len, NULL)) {
        MessageBox(NULL, L"서버 공개 키 변환 실패", L"오류", MB_OK);
        return;
    }

    // 서버 공개 키를 EC_KEY 객체로 변환
    EC_KEY *server_key = EC_KEY_new();
    if (!server_key) {
        MessageBox(NULL, L"서버 키 생성 실패", L"오류", MB_OK);
        return;
    }

    if (!EC_KEY_set_group(server_key, group) || !EC_KEY_set_public_key(server_key, server_pub_key)) {
        MessageBox(NULL, L"서버 공개 키 설정 실패", L"오류", MB_OK);
        return;
    }

    // 암호화 수행
    enc_length = ecc_encrypt(server_key, key, key_len, output);
    *output_len = enc_length;

    // 메모리 해제
    EC_KEY_free(server_key);
    EC_POINT_free(server_pub_key);
    EC_GROUP_free((EC_GROUP *)group);
}


void OnSendData(HWND hwnd) {
    wchar_t name[50], q1[100], q3[100], q4[100], q5[100], q6[7000];
    wchar_t q2[100], timestamp[50];
    char resultUtf8[BUFFER_SIZE];

    // 사용자 입력 값 가져오기
    GetWindowText(hEditName, name, 50);
    GetWindowText(hEditQ1, q1, 100);
    GetWindowText(hEditQ3, q3, 100);
    GetWindowText(hEditQ4, q4, 100);
    GetWindowText(hEditQ5, q5, 100);
    GetWindowText(hEditQ6, q6, 7000);
    GetCurrentTimeFormatted(timestamp, 50);

    // 모든 필드가 비어있지 않은지 확인
    if (name[0] == L'\0') {
        MessageBox(hwnd, L"참여자 이름을 입력해주세요.", L"오류", MB_OK | MB_ICONERROR);
        return;
    }
    if (q1[0] == L'\0') {
        MessageBox(hwnd, L"1번 질문에 답해주세요.", L"오류", MB_OK | MB_ICONERROR);
        return;
    }
    if (q3[0] == L'\0') {
        MessageBox(hwnd, L"3번 질문에 답해주세요.", L"오류", MB_OK | MB_ICONERROR);
        return;
    }
    if (q4[0] == L'\0') {
        MessageBox(hwnd, L"4번 질문에 답해주세요.", L"오류", MB_OK | MB_ICONERROR);
        return;
    }
    if (q5[0] == L'\0') {
        MessageBox(hwnd, L"5번 질문에 답해주세요.", L"오류", MB_OK | MB_ICONERROR);
        return;
    }
    if (q6[0] == L'\0') {
        MessageBox(hwnd, L"6번 질문에 답해주세요.", L"오류", MB_OK | MB_ICONERROR);
        return;
    }

    // 체크박스 상태 확인
    if (SendMessage(hCheckQ2_1, BM_GETCHECK, 0, 0) != BST_CHECKED &&
        SendMessage(hCheckQ2_2, BM_GETCHECK, 0, 0) != BST_CHECKED &&
        SendMessage(hCheckQ2_3, BM_GETCHECK, 0, 0) != BST_CHECKED &&
        SendMessage(hCheckQ2_4, BM_GETCHECK, 0, 0) != BST_CHECKED &&
        SendMessage(hCheckQ2_5, BM_GETCHECK, 0, 0) != BST_CHECKED) {
        MessageBox(hwnd, L"2번 질문에 답해주세요.", L"오류", MB_OK | MB_ICONERROR);
        return;
    }

    // 체크박스 상태에 따라 q2에 텍스트 값 저장
    if (SendMessage(hCheckQ2_1, BM_GETCHECK, 0, 0) == BST_CHECKED) wcscpy(q2, L"매우 쉬움");
    else if (SendMessage(hCheckQ2_2, BM_GETCHECK, 0, 0) == BST_CHECKED) wcscpy(q2, L"쉬움");
    else if (SendMessage(hCheckQ2_3, BM_GETCHECK, 0, 0) == BST_CHECKED) wcscpy(q2, L"보통");
    else if (SendMessage(hCheckQ2_4, BM_GETCHECK, 0, 0) == BST_CHECKED) wcscpy(q2, L"어려움");
    else if (SendMessage(hCheckQ2_5, BM_GETCHECK, 0, 0) == BST_CHECKED) wcscpy(q2, L"매우 어려움");
    wchar_t result[BUFFER_SIZE];
    swprintf(result, BUFFER_SIZE, L"%s|%s|%s|%s|%s|%s|%s|%s", name, timestamp, q1, q2, q3, q4, q5, q6);

    // UTF-16 데이터를 UTF-8로 변환
    int utf8PlainTextLen = WideCharToMultiByte(CP_UTF8, 0, result, -1, NULL, 0, NULL, NULL);
    BYTE utf8Plaintext[BUFFER_SIZE] = {0};
    WideCharToMultiByte(CP_UTF8, 0, result, -1, (char*)utf8Plaintext, utf8PlainTextLen, NULL, NULL);

    // UTF-8 데이터 길이를 바이트 단위로 계산
    int plainTextLen = utf8PlainTextLen - 1; // null 문자 제외

    BYTE ciphertext[BUFFER_SIZE] = {0};
    BYTE mac[16] = {0};
    UINT nonce[3] = {0};
    BYTE enc_key[512] = {0};
    size_t enc_len = 0;
    BYTE poly1305_key[32] = {0};
    BYTE enc_poly1305_key[512] = {0};
    size_t enc_polyLen = 0;
    UINT counter = 1;  // 초기 counter 값
    wchar_t displayMessage[BUFFER_SIZE * 8];    

    // BLAKE3로 32바이트 키 생성
    GenerateBlake3Key(utf8Plaintext, plainTextLen, key);

    wcscpy(displayMessage, L"::생성된 데이터::\r\n- 1-1. BLAKE3로 생성된 ChaCha20키\r\n");
    for (int i = 0; i < 8; i++) {
        wchar_t temp[16];
        wsprintf(temp, L"%08X ", key[i]);
        wcscat(displayMessage, temp);
    }
    wcscat(displayMessage, L"\r\n");

    ECC_Enc(key, 8, enc_key, &enc_len);

    BYTE enc_key_backup[512];
    memcpy(enc_key_backup, enc_key, enc_length);

    wcscat(displayMessage, L"- 1-2. ECC로 암호화된 ChaCha20키\r\n");
    for (size_t i = 0; i < enc_length; i++) {
        wchar_t temp[4];
        wsprintf(temp, L"%02X ", enc_key_backup[i]);
        wcscat(displayMessage, temp);
    }
    wcscat(displayMessage, L"\r\n");

    send(client_socket, (char*)&enc_length, sizeof(enc_length), 0);
    send(client_socket, (char*)enc_key_backup, enc_length, 0);

    // Nonce 생성
    generate_nonce(nonce);

    // Poly1305 키 생성
    chacha20_block((UINT*)poly1305_key, key);

    // ChaCha20 암호화 수행 (UTF-8 데이터 사용)
    chacha20_encrypt(utf8Plaintext, ciphertext, plainTextLen, key, counter, nonce);

    // Poly1305 MAC 생성
    poly1305_mac(ciphertext, plainTextLen, poly1305_key, mac);

    // Plaintext (UTF-8) 출력
    wcscat(displayMessage, L"- 2. 평문:\r\n");
    for (int i = 0; i < plainTextLen; i++) {
        wchar_t temp[4];
        wsprintf(temp, L"%02X ", utf8Plaintext[i]);
        wcscat(displayMessage, temp);

    }    

    // Ciphertext 출력
    wcscat(displayMessage, L"\r\n- 3. 암호문:\r\n");
    for (int i = 0; i < plainTextLen; i++) {
        wchar_t temp[4];
        wsprintf(temp, L"%02X ", ((BYTE*)ciphertext)[i]);
        wcscat(displayMessage, temp);

    }
    wcscat(displayMessage, L"\r\n");

    // Nonce 출력
    wcscat(displayMessage, L"- 4. Nonce:\r\n");
    for (int i = 0; i < 3; i++) {
        wchar_t temp[16];
        wsprintf(temp, L"%08X ", nonce[i]);
        wcscat(displayMessage, temp);
    }
    wcscat(displayMessage, L"\r\n");

    // Poly1305 Key 출력
    wcscat(displayMessage, L"- 5-1. Poly1305 키:\r\n");
    for (int i = 0; i < 32; i++) {
        wchar_t temp[4];
        wsprintf(temp, L"%02X ", poly1305_key[i]);
        wcscat(displayMessage, temp);
    }
    wcscat(displayMessage, L"\r\n");

    ECC_Enc((UINT*)poly1305_key, 8, enc_poly1305_key, &enc_polyLen);

    send(client_socket, (char*)&enc_length, sizeof(enc_length), 0);
    send(client_socket, (char*)enc_poly1305_key, enc_length, 0);

    wcscat(displayMessage, L"- 5-2. ECC로 암호화된 Poly1305키\r\n");
    for (size_t i = 0; i < enc_length; i++) {
        wchar_t temp[4];
        wsprintf(temp, L"%02X ", enc_poly1305_key[i]);
        wcscat(displayMessage, temp);
    }
    wcscat(displayMessage, L"\r\n");
    // MAC 출력
    wcscat(displayMessage, L"- 6. MAC:\r\n");
    for (int i = 0; i < 16; i++) {
        wchar_t temp[4];
        wsprintf(temp, L"%02X ", mac[i]);
        wcscat(displayMessage, temp);
    }
    wcscat(displayMessage, L"\r\n");

    // 전송된 데이터를 표시할 창에 결과 출력
    SetWindowText(hEditDisplay, displayMessage);

    send(client_socket, (char*)&plainTextLen, sizeof(plainTextLen), 0);
    send(client_socket, (char*)ciphertext, plainTextLen, 0);
    send(client_socket, (char*)mac, sizeof(mac), 0);
    send(client_socket, (char*)nonce, sizeof(nonce), 0);

    // GUI에 전송 상태 표시
    SetWindowText(hEditSend, L"메시지 전송 완료");
}


LRESULT CALLBACK WindowProcedure(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    static HFONT hFontTitle;  // 제목 폰트를 저장할 변수
    static HFONT hFont;  
    switch (msg) {
        case WM_CREATE: 
        {
            int centerX = (WINDOW_WIDTH - CONTROL_WIDTH) / 2;
            int radioButtonWidth = 200;
            int buttonWidth = 80;

            hFontTitle = CreateFont(24, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                                    DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
                                    DEFAULT_PITCH | FF_SWISS, fontName);

            HWND hTitle = CreateWindow(L"STATIC", L"현대암호학 강의 만족도 설문조사", WS_VISIBLE | WS_CHILD | SS_CENTER, 
                                       centerX, 10, CONTROL_WIDTH, 40, hwnd, NULL, NULL, NULL);
            SendMessage(hTitle, WM_SETFONT, (WPARAM)hFontTitle, TRUE);  // 제목에 큰 폰트 적용

            // 일반 폰트 생성
            hFont = CreateFont(fontSize, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                               DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
                               DEFAULT_PITCH | FF_SWISS, fontName);

            // 참여자 이름 레이블을 화면 중앙에 정렬
            HWND hStaticName = CreateWindow(L"STATIC", L"참여자 이름:", WS_VISIBLE | WS_CHILD, centerX, 60, 100, 20, hwnd, NULL, NULL, NULL);
            SendMessage(hStaticName, WM_SETFONT, (WPARAM)hFont, TRUE);

            // 참여자 이름 입력란을 중앙에 배치
            hEditName = CreateWindow(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | WS_TABSTOP, centerX + 110, 60, 200, 20, hwnd, NULL, NULL, NULL);
            SendMessage(hEditName, WM_SETFONT, (WPARAM)hFont, TRUE);

            // 나머지 문항들도 동일한 방식으로 처리
            HWND hStaticQ1 = CreateWindow(L"STATIC", L"1. 현대암호학은 어떤 과목이라고 생각합니까?", WS_VISIBLE | WS_CHILD, centerX, 90, CONTROL_WIDTH, 20, hwnd, NULL, NULL, NULL);
            SendMessage(hStaticQ1, WM_SETFONT, (WPARAM)hFont, TRUE);

            hEditQ1 = CreateWindow(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | WS_TABSTOP, centerX, 110, CONTROL_WIDTH, 20, hwnd, NULL, NULL, NULL);
            SendMessage(hEditQ1, WM_SETFONT, (WPARAM)hFont, TRUE);

            HWND hStaticQ2 = CreateWindow(L"STATIC", L"2. 현대암호학의 강의 난이도는 어떻습니까?", WS_VISIBLE | WS_CHILD, centerX, 140, CONTROL_WIDTH, 20, hwnd, NULL, NULL, NULL);
            SendMessage(hStaticQ2, WM_SETFONT, (WPARAM)hFont, TRUE);

            hCheckQ2_1 = CreateWindow(L"BUTTON", L"매우 쉬움", WS_VISIBLE | WS_CHILD | BS_AUTORADIOBUTTON | WS_TABSTOP, centerX, 160, radioButtonWidth, 20, hwnd, NULL, NULL, NULL);
            SendMessage(hCheckQ2_1, WM_SETFONT, (WPARAM)hFont, TRUE);

            hCheckQ2_2 = CreateWindow(L"BUTTON", L"쉬움", WS_VISIBLE | WS_CHILD | BS_AUTORADIOBUTTON | WS_TABSTOP, centerX, 180, radioButtonWidth, 20, hwnd, NULL, NULL, NULL);
            SendMessage(hCheckQ2_2, WM_SETFONT, (WPARAM)hFont, TRUE);

            hCheckQ2_3 = CreateWindow(L"BUTTON", L"보통", WS_VISIBLE | WS_CHILD | BS_AUTORADIOBUTTON | WS_TABSTOP, centerX, 200, radioButtonWidth, 20, hwnd, NULL, NULL, NULL);
            SendMessage(hCheckQ2_3, WM_SETFONT, (WPARAM)hFont, TRUE);

            hCheckQ2_4 = CreateWindow(L"BUTTON", L"어려움", WS_VISIBLE | WS_CHILD | BS_AUTORADIOBUTTON | WS_TABSTOP, centerX, 220, radioButtonWidth, 20, hwnd, NULL, NULL, NULL);
            SendMessage(hCheckQ2_4, WM_SETFONT, (WPARAM)hFont, TRUE);

            hCheckQ2_5 = CreateWindow(L"BUTTON", L"매우 어려움", WS_VISIBLE | WS_CHILD | BS_AUTORADIOBUTTON | WS_TABSTOP, centerX, 240, radioButtonWidth, 20, hwnd, NULL, NULL, NULL);
            SendMessage(hCheckQ2_5, WM_SETFONT, (WPARAM)hFont, TRUE);

            HWND hStaticQ3 = CreateWindow(L"STATIC", L"3. 난이도에 대한 이유는 무엇입니까?", WS_VISIBLE | WS_CHILD, centerX, 270, CONTROL_WIDTH, 20, hwnd, NULL, NULL, NULL);
            SendMessage(hStaticQ3, WM_SETFONT, (WPARAM)hFont, TRUE);

            hEditQ3 = CreateWindow(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | WS_TABSTOP, centerX, 290, CONTROL_WIDTH, 20, hwnd, NULL, NULL, NULL);
            SendMessage(hEditQ3, WM_SETFONT, (WPARAM)hFont, TRUE);

            HWND hStaticQ4 = CreateWindow(L"STATIC", L"4. 현재 알고 있는 암호화 방식을 알려주세요.", WS_VISIBLE | WS_CHILD, centerX, 320, CONTROL_WIDTH, 20, hwnd, NULL, NULL, NULL);
            SendMessage(hStaticQ4, WM_SETFONT, (WPARAM)hFont, TRUE);

            hEditQ4 = CreateWindow(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | WS_TABSTOP, centerX, 340, CONTROL_WIDTH, 20, hwnd, NULL, NULL, NULL);
            SendMessage(hEditQ4, WM_SETFONT, (WPARAM)hFont, TRUE);

            HWND hStaticQ5 = CreateWindow(L"STATIC", L"5. 암호학에 관하여 더 알고 싶은 것들이 있습니까?", WS_VISIBLE | WS_CHILD, centerX, 370, CONTROL_WIDTH, 20, hwnd, NULL, NULL, NULL);
            SendMessage(hStaticQ5, WM_SETFONT, (WPARAM)hFont, TRUE);

            hEditQ5 = CreateWindow(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | WS_TABSTOP, centerX, 390, CONTROL_WIDTH, 20, hwnd, NULL, NULL, NULL);
            SendMessage(hEditQ5, WM_SETFONT, (WPARAM)hFont, TRUE);

            HWND hStaticQ6 = CreateWindow(L"STATIC", L"6. 본 강의를 들으면서 바라는 점이 있다면 적어주세요.", WS_VISIBLE | WS_CHILD, centerX, 420, CONTROL_WIDTH, 20, hwnd, NULL, NULL, NULL);
            SendMessage(hStaticQ6, WM_SETFONT, (WPARAM)hFont, TRUE);

            hEditQ6 = CreateWindow(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | WS_TABSTOP | ES_MULTILINE | WS_VSCROLL, centerX, 450, CONTROL_WIDTH, 60, hwnd, NULL, NULL, NULL);
            SendMessage(hEditQ6, WM_SETFONT, (WPARAM)hFont, TRUE);

            HWND hButtonSubmit = CreateWindow(L"BUTTON", L"제출", WS_VISIBLE | WS_CHILD | WS_TABSTOP, (WINDOW_WIDTH - buttonWidth) / 2, 530, buttonWidth, 25, hwnd, (HMENU)BUTTON_SUBMIT, NULL, NULL);
            SendMessage(hButtonSubmit, WM_SETFONT, (WPARAM)hFont, TRUE);

            hEditDisplay = CreateWindow(L"EDIT", NULL, WS_VISIBLE | WS_CHILD | WS_BORDER | ES_MULTILINE | WS_VSCROLL | ES_READONLY, 
                                       centerX, 580, CONTROL_WIDTH, 100, hwnd, NULL, NULL, NULL); 
            SendMessage(hEditDisplay, WM_SETFONT, (WPARAM)hFont, TRUE);
            InitializeSocketAndConnect();  
            break;
        }
        case WM_COMMAND:
            if (LOWORD(wp) == 1) OnSendData(hwnd);
            break;
        case WM_DESTROY:
            closesocket(client_socket);  
            WSACleanup();                
            PostQuitMessage(0);
            break;
    }
    return DefWindowProc(hwnd, msg, wp, lp);
}

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE hPrevInst, LPWSTR args, int ncmdshow) {
    WNDCLASS wc = {0};
    wc.hbrBackground = (HBRUSH)COLOR_WINDOW;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hInstance = hInst;
    wc.lpszClassName = L"SurveyWindowClass";
    wc.lpfnWndProc = WindowProcedure;

    if (!RegisterClass(&wc)) return -1;

    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);

    int posX = (screenWidth - WINDOW_WIDTH) / 2;
    int posY = (screenHeight - WINDOW_HEIGHT) / 2;

    HWND hwnd = CreateWindow(
        L"SurveyWindowClass", L"현대암호학 강의 만족도 설문조사", 
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_VISIBLE, 
        posX, posY, WINDOW_WIDTH, WINDOW_HEIGHT,
        NULL, NULL, hInst, NULL
    );

    MSG msg = {0};
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return 0;
}
