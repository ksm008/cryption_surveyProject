# 암호 알고리즘을 적용한 설문조사 클라이언트, 서버 구현
소켓 통신과 WinAPI를 사용하여 설문조사 서버와 클라이언트를 구현하였습니다. 클라이언트에 미리 작성되어 있는 설문조사를 참여하면, 그 답변이 암호화되어 서버로 넘어가게 됩니다. 

## 암호화 과정
클라이언트에서 설문조사를 진행하고, 답변을 하나의 문자열로 저장합니다. 이 때 | 문자를 중간에 넣어 문항 별 답변을 구분합니다. 구분 문자까지 추가된 문자열을 사용하여 ChaCha20의 비밀 키를 생성하는데, 키는 BLAKE3 해시 함수를 사용하여 설문조사 결과로부터 파생하게 됩니다.

암호화 과정에서 생성되는 데이터들은 다음과 같습니다.

- ChaCha20 비밀 키 (비대칭 키에 의해 암호화됨)
- 암호문
- Nonce
- Poly1305 키  (비대칭 키에 의해 암호화됨)
- Poly1305 MAC

여기서 ChaCha20의 비밀 키와  Poly1305 키는 둘 다 비대칭 키 암호화 방식인 ECC로 암호화되어 서버에서 가지고 있는 개인 키로 복호화하게 됩니다. 이후 서버에서는 복호화된 두 개의 키와 나머지 데이터를 사용하여 암호화된 답변을 복호화하고, Poly1305 MAC을 재생성하여 무결성 인증을 진행합니다. 무결성 인증에 성공하면 설문조사 결과를 출력합니다.

GUI 내 폰트는 윤고딕320을 사용했으므로 따로 설치해주세요.

코드는 VSCode로 작업했습니다. tasks.json 파일은 받아서 쓰시거나 직접 고치셔도 됩니다. 
## tasks.json
```
            <!-- gcc 매개변수 -->
            "args": [

                ...

                "${workspaceFolder}\\encryption\\ChaCha20.c", 
                "${workspaceFolder}\\encryption\\ECC.c",
                "-I${workspaceFolder}\\encryption\\blake3.c",
                "-I${workspaceFolder}\\encryption\\include\\",
                "-I${workspaceFolder}\\encryption\\",
                "-L${workspaceFolder}\\encryption\\lib\\",
                "-L.",  
                "-lcrypto",                       
                "-lws2_32",                
                "-mwindows",
                "-municode",
                "-lblake3"
            ],
```

