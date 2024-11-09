#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include "../encryption/ChaCha20.h"  // 암호화 헤더 파일

#pragma comment(lib, "ws2_32.lib")
#define PORT 8080
#define SERVER_IP "127.0.0.1"
#define BUFFER_SIZE 1024

HWND hEditSend, hEditDisplay;  // 두 개의 텍스트 상자: 전송할 메시지와 전송된 데이터 표시
SOCKET client_socket;  // 전역 변수로 선언하여 모든 함수에서 접근 가능하게 함
UINT key[8];
BYTE key_bytes[32] = "security12345678";  // 비밀 키

void InitializeSocketAndConnect() {
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
        MessageBox(NULL, L"서버에 연결됨", L"알림", MB_OK);
    }
}

void OnSendData(HWND hwnd) {
    wchar_t wBuffer[BUFFER_SIZE];
    GetWindowText(hEditSend, wBuffer, BUFFER_SIZE);

    // UTF-16 데이터를 UTF-8로 변환
    int utf8PlainTextLen = WideCharToMultiByte(CP_UTF8, 0, wBuffer, -1, NULL, 0, NULL, NULL);
    BYTE utf8Plaintext[BUFFER_SIZE] = {0};
    WideCharToMultiByte(CP_UTF8, 0, wBuffer, -1, (char*)utf8Plaintext, utf8PlainTextLen, NULL, NULL);

    // UTF-8 데이터 길이를 바이트 단위로 계산
    int plainTextLen = utf8PlainTextLen - 1; // null 문자 제외

    BYTE ciphertext[BUFFER_SIZE] = {0};
    BYTE mac[16] = {0};
    UINT nonce[3] = {0};
    BYTE poly1305_key[32] = {0};
    UINT counter = 1;  // 초기 counter 값

    // 암호화 키 확장
    expand_key((char*)key_bytes, key);

    // 확장된 키 출력
    wchar_t displayMessage[BUFFER_SIZE * 4];
    wcscpy(displayMessage, L"Expanded Key:\r\n");
    for (int i = 0; i < 8; i++) {
        wchar_t temp[16];
        wsprintf(temp, L"%08X ", key[i]);
        wcscat(displayMessage, temp);
        if ((i + 1) % 4 == 0) wcscat(displayMessage, L"\r\n");
    }

    // Nonce 생성
    generate_nonce(nonce);

    // Poly1305 키 생성
    chacha20_block((UINT*)poly1305_key, key);

    // ChaCha20 암호화 수행 (UTF-8 데이터 사용)
    chacha20_encrypt(utf8Plaintext, ciphertext, plainTextLen, key, counter, nonce);

    // Poly1305 MAC 생성
    poly1305_mac(ciphertext, plainTextLen, poly1305_key, mac);

    // Plaintext (UTF-8) 출력
    wcscat(displayMessage, L"Plaintext (UTF-8 Hex):\r\n");
    for (int i = 0; i < plainTextLen; i++) {
        wchar_t temp[4];
        wsprintf(temp, L"%02X ", utf8Plaintext[i]);
        wcscat(displayMessage, temp);
        if ((i + 1) % 16 == 0) wcscat(displayMessage, L"\r\n");
    }

    // Ciphertext 출력
    wcscat(displayMessage, L"Ciphertext:\r\n");
    for (int i = 0; i < plainTextLen; i++) {
        wchar_t temp[4];
        wsprintf(temp, L"%02X ", ((BYTE*)ciphertext)[i]);
        wcscat(displayMessage, temp);
        if ((i + 1) % 16 == 0) wcscat(displayMessage, L"\r\n");
    }
    wcscat(displayMessage, L"\r\n");

    // Nonce 출력
    wcscat(displayMessage, L"Nonce:\r\n");
    for (int i = 0; i < 3; i++) {
        wchar_t temp[16];
        wsprintf(temp, L"%08X ", nonce[i]);
        wcscat(displayMessage, temp);
    }
    wcscat(displayMessage, L"\r\n");

    // Poly1305 Key 출력
    wcscat(displayMessage, L"Poly1305 Key:\r\n");
    for (int i = 0; i < 32; i++) {
        wchar_t temp[4];
        wsprintf(temp, L"%02X ", poly1305_key[i]);
        wcscat(displayMessage, temp);
        if ((i + 1) % 16 == 0) wcscat(displayMessage, L"\r\n");
    }

    // MAC 출력
    wcscat(displayMessage, L"MAC:\r\n");
    for (int i = 0; i < 16; i++) {
        wchar_t temp[4];
        wsprintf(temp, L"%02X ", mac[i]);
        wcscat(displayMessage, temp);
    }
    wcscat(displayMessage, L"\r\n");

    // 전송된 데이터를 표시할 창에 결과 출력
    SetWindowText(hEditDisplay, displayMessage);

    // 서버로 데이터 전송 (실제 암호문 길이를 사용하여 바이너리로 전송)
    send(client_socket, (char*)&plainTextLen, sizeof(plainTextLen), 0);
    send(client_socket, (char*)ciphertext, plainTextLen, 0);
    send(client_socket, (char*)mac, sizeof(mac), 0);
    send(client_socket, (char*)nonce, sizeof(nonce), 0);
    send(client_socket, (char*)poly1305_key, sizeof(poly1305_key), 0);

    // GUI에 전송 상태 표시
    SetWindowText(hEditSend, L"메시지 전송 완료");
}


LRESULT CALLBACK WindowProcedure(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
        case WM_CREATE:
            CreateWindow(L"STATIC", L"보낼 메시지:", WS_VISIBLE | WS_CHILD, 20, 20, 100, 20, hwnd, NULL, NULL, NULL);
            hEditSend = CreateWindow(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER, 120, 20, 300, 20, hwnd, NULL, NULL, NULL);
            CreateWindow(L"BUTTON", L"전송", WS_VISIBLE | WS_CHILD, 440, 20, 60, 20, hwnd, (HMENU)1, NULL, NULL);
            // 결과 표시용 텍스트 박스 추가
            hEditDisplay = CreateWindow(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_MULTILINE | WS_VSCROLL | ES_AUTOVSCROLL, 
                                         20, 60, 480, 200, hwnd, NULL, NULL, NULL);  // 결과 텍스트 박스
            InitializeSocketAndConnect();  // 소켓 초기화 및 서버 연결
            break;
        case WM_COMMAND:
            if (LOWORD(wp) == 1) OnSendData(hwnd);
            break;
        case WM_DESTROY:
            closesocket(client_socket);  // 프로그램 종료 시 소켓 닫기
            WSACleanup();                // Winsock 정리
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
    wc.lpszClassName = L"ClientWindowClass";
    wc.lpfnWndProc = WindowProcedure;

    if (!RegisterClass(&wc)) return -1;

    CreateWindow(L"ClientWindowClass", L"클라이언트", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 100, 100, 550, 300, NULL, NULL, NULL, NULL);

    MSG msg = {0};
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return 0;
}
