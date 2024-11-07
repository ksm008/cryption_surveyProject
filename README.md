# cryption_surveyProject

VSCode로 작업했습니다. 

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
