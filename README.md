# cryption_surveyProject
WinAPI를 사용하여 설문조사 서버와 클라이언트를 구현할 계획입니다. 
설문조사 클라이언트에서 정보를 보낼 때 ChaCha20-Poly1305 알고리즘으로 암호문, Nonce, Poly1305 Key, MAC을 보냅니다.
서버에서는 받은 정보들을 토대로 복호화 및 무결성 인증을 진행하여 받은 정보를 보게 됩니다.

코드는 VSCode로 작업했습니다. tasks.json 파일은 받아서 쓰시거나 직접 고치셔도 됩니다.

## tasks.json
```
            <!-- gcc 매개변수 -->
            "args": [
                ...
                "${workspaceFolder}\\survey_project\\encryption\\ChaCha20.c", // 사용자 환경에 따라 달라질 수 있음
                "-lws2_32",
                "-mwindows",
                "-municode"
            ],
```
헤더 파일을 읽기 위해 ChaCha20.c는 각자 경로에 맞게 추가시켜주세요.
