#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include "../encryption/ChaCha20.h" // ChaCha20 알고리즘 포함

#pragma comment(lib, "ws2_32.lib")

#define PORT 8080
#define WM_SOCKET (WM_USER + 1)

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
void ConnectToServer(HWND hwnd);

SOCKET clientSocket;
HWND hEditOut, hEditIn;

// ChaCha20 암호화를 위한 키와 nonce
UINT key[8];
UINT nonce[3] = {0, 0, 0};

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow) {
    const wchar_t CLASS_NAME[] = L"WinAPISocketClient";

    char input_key[33] = "your_32_character_secret_key_here";
    expand_key(input_key, key);
    generate_nonce(nonce);

    WNDCLASS wc = {0};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;

    RegisterClass(&wc);

    HWND hwnd = CreateWindowExW(0, CLASS_NAME, L"WinAPI 소켓 클라이언트 (UTF-16)",
                                WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 400, 300,
                                NULL, NULL, hInstance, NULL);

    ShowWindow(hwnd, nCmdShow);
    ConnectToServer(hwnd);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    closesocket(clientSocket);
    WSACleanup();

    return 0;
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_CREATE:
            hEditOut = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_READONLY | ES_MULTILINE,
                                     10, 10, 360, 180, hwnd, NULL, NULL, NULL);
            hEditIn = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_MULTILINE,
                                    10, 200, 360, 50, hwnd, NULL, NULL, NULL);
            break;

        case WM_SOCKET:
            if (WSAGETSELECTEVENT(lParam) == FD_READ) {
                BYTE encrypted_message[1024];
                BYTE decrypted_message[1024];
                int bytesReceived = recv(clientSocket, (char*)encrypted_message, sizeof(encrypted_message), 0);
                if (bytesReceived > 0) {
                    chacha20_encrypt(encrypted_message, decrypted_message, bytesReceived, key, 1, nonce);

                    wchar_t wbuffer[512];
                    MultiByteToWideChar(CP_UTF8, 0, (char*)decrypted_message, -1, wbuffer, 512);

                    int len = GetWindowTextLengthW(hEditOut);
                    SendMessageW(hEditOut, EM_SETSEL, (WPARAM)len, (LPARAM)len);
                    SendMessageW(hEditOut, EM_REPLACESEL, 0, (LPARAM)wbuffer);
                }
            }
            break;

        case WM_COMMAND:
            if (HIWORD(wParam) == EN_CHANGE && (HWND)lParam == hEditIn) {
                if (GetAsyncKeyState(VK_RETURN) & 0x8000) {
                    wchar_t wbuffer[512];
                    BYTE plaintext[1024];
                    BYTE ciphertext[1024];

                    GetWindowTextW(hEditIn, wbuffer, 512);
                    int len = WideCharToMultiByte(CP_UTF8, 0, wbuffer, -1, (char*)plaintext, 1024, NULL, NULL);
                    chacha20_encrypt(plaintext, ciphertext, len, key, 1, nonce);

                    send(clientSocket, (char*)ciphertext, len, 0);
                    SetWindowTextW(hEditIn, L"");
                }
            }
            break;

        case WM_DESTROY:
            PostQuitMessage(0);
            break;
    }
    return DefWindowProcW(hwnd, uMsg, wParam, lParam);
}

void ConnectToServer(HWND hwnd) {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    
    struct sockaddr_in serverAddr = {0};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    serverAddr.sin_port = htons(PORT);

    connect(clientSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr));

    WSAAsyncSelect(clientSocket, hwnd, WM_SOCKET, FD_READ | FD_CLOSE);
}
