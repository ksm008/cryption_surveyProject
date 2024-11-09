#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include "../encryption/ChaCha20.h"  // 암호화 헤더 파일

#pragma comment(lib, "ws2_32.lib")
#define PORT 8080
#define BUFFER_SIZE 1024

UINT key[8];
BYTE key_bytes[32] = "security12345678";  // 비밀 키

LRESULT CALLBACK WindowProcedure(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp);

SOCKET server_socket, client_socket;
HWND hEditOutput;


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
    SetWindowText(hEditOutput, L"클라이언트와 연결되었습니다!");

    while (1) {
        wchar_t displayMessage[BUFFER_SIZE * 6] = L"";
        
        int plainTextLen;
        BYTE ciphertext[BUFFER_SIZE];
        BYTE mac[16];
        UINT nonce[3];
        BYTE poly1305_key[32];
        UINT counter = 1;

        expand_key((char*)key_bytes, key);

         // 확장된 키 출력
    
        wcscpy(displayMessage, L"Expanded Key:\r\n");
        for (int i = 0; i < 8; i++) {
            wchar_t temp[16];
            wsprintf(temp, L"%08X ", key[i]);
            wcscat(displayMessage, temp);
            if ((i + 1) % 4 == 0) wcscat(displayMessage, L"\r\n");
        }

        // 1. 데이터 길이 수신 (plainTextLen)
        int len = recv(client_socket, (char*)&plainTextLen, sizeof(plainTextLen), 0);
        if (len <= 0) break;

        // 2. 암호문 (ciphertext) 수신
        recv(client_socket, (char*)ciphertext, plainTextLen, 0);
        wcscat(displayMessage, L"Ciphertext:\r\n");
        for (int i = 0; i < plainTextLen; i++) {
            wchar_t temp[4];
            wsprintf(temp, L"%02X ", ciphertext[i]);
            wcscat(displayMessage, temp);
            if ((i + 1) % 16 == 0) wcscat(displayMessage, L"\r\n");
        }
        wcscat(displayMessage, L"\r\n");

        // 3. MAC 수신
        recv(client_socket, (char*)mac, sizeof(mac), 0);
        wcscat(displayMessage, L"MAC:\r\n");
        for (int i = 0; i < 16; i++) {
            wchar_t temp[4];
            wsprintf(temp, L"%02X ", mac[i]);
            wcscat(displayMessage, temp);
        }
        wcscat(displayMessage, L"\r\n");

        // 4. Nonce 수신
        recv(client_socket, (char*)nonce, sizeof(nonce), 0);
        wcscat(displayMessage, L"Nonce:\r\n");
        for (int i = 0; i < 3; i++) {
            wchar_t temp[16];
            wsprintf(temp, L"%08X ", nonce[i]);
            wcscat(displayMessage, temp);
        }
        wcscat(displayMessage, L"\r\n");

        // 5. Poly1305 Key 수신
        recv(client_socket, (char*)poly1305_key, sizeof(poly1305_key), 0);
        wcscat(displayMessage, L"Poly1305 Key:\r\n");
        for (int i = 0; i < 32; i++) {
            wchar_t temp[4];
            wsprintf(temp, L"%02X ", poly1305_key[i]);
            wcscat(displayMessage, temp);
            if ((i + 1) % 16 == 0) wcscat(displayMessage, L"\r\n");
        }
        wcscat(displayMessage, L"\r\n");

        BYTE decrypted[BUFFER_SIZE] = {0};
        expand_key((char*)key_bytes, key); // 키 확장
        chacha20_encrypt(ciphertext, decrypted, plainTextLen, key, counter, nonce);

        // Decrypted data 출력
        wcscat(displayMessage, L"Decrypted Data (Hex):\r\n");
        for (int i = 0; i < plainTextLen; i++) {
            wchar_t temp[4];
            wsprintf(temp, L"%02X ", decrypted[i]);
            wcscat(displayMessage, temp);
            if ((i + 1) % 16 == 0) wcscat(displayMessage, L"\r\n");
        }
        wcscat(displayMessage, L"\r\n");

        // 16진수 데이터의 텍스트로 변환해서 출력
        wcscat(displayMessage, L"Decrypted Data (Text):\r\n");

        // 텍스트로 변환
        char decrypted_text[BUFFER_SIZE] = {0};
        for (int i = 0; i < plainTextLen; i++) {
            decrypted_text[i] = decrypted[i];  // 바이트 배열을 텍스트 배열로 변환
        }

        // UTF-8로 변환된 텍스트를 출력
        wchar_t utf16Buffer[BUFFER_SIZE] = {0};
        MultiByteToWideChar(CP_UTF8, 0, decrypted_text, -1, utf16Buffer, BUFFER_SIZE);
        wcscat(displayMessage, utf16Buffer);

        
        SetWindowText(hEditOutput, displayMessage);
    }

    closesocket(client_socket);
    closesocket(server_socket);
    WSACleanup();
    return 0;
}



int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE hPrevInst, LPWSTR args, int ncmdshow) {
    WNDCLASS wc = {0};
    wc.hbrBackground = (HBRUSH)COLOR_WINDOW;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hInstance = hInst;
    wc.lpszClassName = L"ServerWindowClass";
    wc.lpfnWndProc = WindowProcedure;

    if (!RegisterClass(&wc))
        return -1;

    HWND hwnd = CreateWindow(L"ServerWindowClass", L"WinAPI 서버",
                             WS_OVERLAPPEDWINDOW | WS_VISIBLE, 100, 100, 500, 300,
                             NULL, NULL, hInst, NULL);

    CreateThread(NULL, 0, ServerThread, NULL, 0, NULL);

    MSG msg = {0};
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return 0;
}

LRESULT CALLBACK WindowProcedure(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
        case WM_CREATE:
            hEditOutput = CreateWindow(L"EDIT", L"", 
                WS_VISIBLE | WS_CHILD | WS_BORDER | ES_MULTILINE | WS_VSCROLL | ES_AUTOVSCROLL | ES_READONLY,
                20, 20, 440, 200, hwnd, NULL, NULL, NULL);
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
