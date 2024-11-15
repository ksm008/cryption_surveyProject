#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include "../encryption/ChaCha20.h"  // 암호화 헤더 파일

#pragma comment(lib, "ws2_32.lib")
#define PORT 8084
#define BUFFER_SIZE 1024

#define WINDOW_WIDTH 800
#define WINDOW_HEIGHT 1000

HWND hEditOutput;
HFONT hFont; 
SOCKET server_socket, client_socket;
UINT key[8];

LRESULT CALLBACK WindowProcedure(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp);

const wchar_t* fontName = L"-윤고딕320";  
int fontSize = 16;  

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
        BYTE mac_2[16];
        UINT nonce[3];
        BYTE poly1305_key[32];
        UINT counter = 1;

        recv(client_socket, (char*)key, sizeof(key), 0);
    
        wcscpy(displayMessage, L"BLAKE3로 생성된 키:\r\n");
        for (int i = 0; i < 8; i++) {
            wchar_t temp[16];
            wsprintf(temp, L"%08X ", key[i]);
            wcscat(displayMessage, temp);
            if ((i + 1) % 4 == 0) wcscat(displayMessage, L"\r\n");
        }

        // 데이터 길이 수신 (plainTextLen)
        int len = recv(client_socket, (char*)&plainTextLen, sizeof(plainTextLen), 0);
        if (len <= 0) break;

        // 암호문 (ciphertext) 수신
        recv(client_socket, (char*)ciphertext, plainTextLen, 0);
        wcscat(displayMessage, L"암호문:\r\n");
        for (int i = 0; i < plainTextLen; i++) {
            wchar_t temp[4];
            wsprintf(temp, L"%02X ", ciphertext[i]);
            wcscat(displayMessage, temp);
            if ((i + 1) % 16 == 0) wcscat(displayMessage, L"\r\n");
        }
        wcscat(displayMessage, L"\r\n");

        // MAC 수신
        recv(client_socket, (char*)mac, sizeof(mac), 0);
        
        // Nonce 수신
        recv(client_socket, (char*)nonce, sizeof(nonce), 0);
        wcscat(displayMessage, L"Nonce:\r\n");
        for (int i = 0; i < 3; i++) {
            wchar_t temp[16];
            wsprintf(temp, L"%08X ", nonce[i]);
            wcscat(displayMessage, temp);
        }
        wcscat(displayMessage, L"\r\n");

        // Poly1305 Key 수신
        recv(client_socket, (char*)poly1305_key, sizeof(poly1305_key), 0);
        wcscat(displayMessage, L"Poly1305 키:\r\n");
        for (int i = 0; i < 32; i++) {
            wchar_t temp[4];
            wsprintf(temp, L"%02X ", poly1305_key[i]);
            wcscat(displayMessage, temp);
            if ((i + 1) % 16 == 0) wcscat(displayMessage, L"\r\n");
        }

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
                if ((i + 1) % 16 == 0) wcscat(displayMessage, L"\r\n");
            }

            // 16진수 데이터의 텍스트로 변환해서 출력
            wcscat(displayMessage, L"\r\n복호화된 결과:");

            // 텍스트로 변환
            char decrypted_text[BUFFER_SIZE] = {0};
            for (int i = 0; i < plainTextLen; i++) {
                decrypted_text[i] = decrypted[i];  // 바이트 배열을 텍스트 배열로 변환
            }

            // UTF-8로 변환된 텍스트를 출력
            wchar_t utf16Buffer[BUFFER_SIZE] = {0};
            MultiByteToWideChar(CP_UTF8, 0, decrypted_text, -1, utf16Buffer, BUFFER_SIZE);
            
            // 구분자 '|'을 기준으로 문자열 분할
            wchar_t* token = wcstok(utf16Buffer, L"|");
            int fieldIndex = 0;

            // 각 필드를 항목 제목과 함께 출력
            while (token != NULL) {
                switch (fieldIndex) {
                    case 0:
                        wcscat(displayMessage, L"\r\n제출자 이름: ");
                        break;
                    case 1:
                        wcscat(displayMessage, L"\r\n제출일자: ");
                        break;
                    case 2:
                        wcscat(displayMessage, L"\r\n1. 현대암호학은 어떤 과목이라고 생각합니까?\r\n- ");
                        break;
                    case 3:
                        wcscat(displayMessage, L"\r\n2. 현대암호학의 강의 난이도는 어떻습니까?\r\n- ");
                        break;
                    case 4:
                        wcscat(displayMessage, L"\r\n3. 난이도에 대한 이유는 무엇입니까?\r\n- ");
                        break;
                    case 5:
                        wcscat(displayMessage, L"\r\n4. 현재 알고 있는 암호화 방식을 알려주세요.\r\n- ");
                        break;
                    case 6:
                        wcscat(displayMessage, L"\r\n5. 암호학에 관하여 더 알고 싶은 것들이 있습니까?\r\n- ");
                        break;
                    case 7:
                        wcscat(displayMessage, L"\r\n6. 본 강의를 들으면서 바라는 점이 있다면 적어주세요.\r\n- ");
                        break;
                    default:
                        break;
                }

                wcscat(displayMessage, token);
                fieldIndex++;
                token = wcstok(NULL, L"|");
            }
            

        } else {
            wcscat(displayMessage,L"MAC 인증에 실패하였습니다.\r\n");
        }
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
            hEditOutput = CreateWindow(L"EDIT", L"", 
                WS_VISIBLE | WS_CHILD | WS_BORDER | ES_MULTILINE | WS_VSCROLL | ES_AUTOVSCROLL | ES_READONLY,
                20, 20, WINDOW_WIDTH - 40, WINDOW_HEIGHT - 80, hwnd, NULL, NULL, NULL);
            SendMessage(hEditOutput, WM_SETFONT, (WPARAM)hFont, TRUE);
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


