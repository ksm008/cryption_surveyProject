# 암호 알고리즘을 적용한 설문조사 클라이언트, 서버 구현
소켓 통신과 WinAPI를 사용하여 설문조사 서버와 클라이언트를 구현하였습니다. 클라이언트에 미리 작성되어 있는 설문조사를 참여하면, 그 답변이 암호화되어 서버로 넘어가게 됩니다. 

## 간단한 암호화 과정
클라이언트에서 설문조사를 진행하고, 답변을 하나의 문자열로 저장합니다. 이 때 | 문자를 중간에 넣어 문항 별 답변을 구분합니다. 구분 문자까지 추가된 문자열을 사용하여 ChaCha20의 비밀 키를 생성하는데, 키는 BLAKE3 해시 함수를 사용하여 설문조사 결과로부터 파생하게 됩니다.

암호화 과정에서 생성되는 데이터들은 다음과 같습니다.

- ChaCha20 비밀 키 (ECC 공개 키로 암호화됨)
- 암호문
- Nonce
- Poly1305 키  (ECC 공개 키로 암호화됨)
- Poly1305 MAC

여기서 ChaCha20의 비밀 키와  Poly1305 키는 둘 다 비대칭 키 암호화 방식인 ECC의 공개 키로 암호화되어 서버에서 가지고 있는 개인 키로 복호화하게 됩니다. 이후 서버에서는 복호화된 두 개의 키와 나머지 데이터를 사용하여 암호화된 답변을 복호화하고, Poly1305 MAC을 재생성하여 무결성 인증을 진행합니다. 무결성 인증에 성공하면 설문조사 결과를 출력합니다.

GUI 내 폰트는 윤고딕320을 사용했으므로 따로 설치해주세요.

코드는 VSCode로 작업했습니다. tasks.json 파일은 받아서 쓰시거나 직접 고치셔도 됩니다. 

## 사용한 알고리즘
ChaCha20-Poly1305는 연산 난이도가 높지 않아 직접 구현하였고, BLAKE3와 ECC는 수학적 연산이 중요한 라이브러리이기 때문에 각각 공식 라이브러리와 OpenSSL을 사용하여 구현하였습니다. 
### 1. BLAKE3
BLAKE3는 SHA-256, 3보다 훨신 빠른 암호화 해시 함수입니다. 여러 블록으로 나누어 입력 데이터를 처리하는 Merkle 트리 구조와 Blake2s 기반의 압축 함수를 사용해 빠른병렬 처리가 가능한 것이 특징입니다. 
처리 과정을 간단하게 설명하면 아래와 같습니다.

1. 입력된 데이터를 청크라는 작은 조각으로 나누고 트리를 구성합니다.
2. 각 청크는 이전 버전인 Blake2s를 기반으로 하는 F 함수를 거쳐 정제됩니다.
3. 정제된 청크들을 하나씩 조합하여 더 큰 부모 노드를 계산합니다. 이 과정은 트리 위로 올라가며 계속해서 반복됩니다.
4. 모든 청크를 하나로 합쳐서 하나의 해시 값이 만들어집니다.

해당 예제에서는 BLAKE3의 입력 데이터를 기반으로 키를 생성하고 있지만, 원래 메시지를 사용하여 키를 파생하는 것은 무차별 공격에 취약하기 때문에 조심스러운 부분입니다. 이걸 해결하기 위해 보내는 메시지 안에 Nonce 역할을 해주는 타임스탬프가 들어가기 때문에 매 전송마다 키 값이 달라지도록 하였습니다. 여기에 더해 보안을 강화하기 위해서 키의 용도를 구분하기 위한 컨텍스트나 입력 데이터의 다양성을 추가하기 위한 소금 값을 추가할 수도 있습니다.

BLAKE3는 해시 값 말고도 여러 곳에서 사용이 가능합니다. MAC이나, 의사 난수 생성기, 키 파생 함수 등에서 사용이 가능합니다. 해당 예제에서는 클라이언트에서 보낸 답변을 사용하여 ChaCha20의 키를 파생하는 키 파생 함수로 사용하였습니다. 또한 BLAKE3의 기본 출력 크기는 256비트, 즉 32바이트이기 때문에 ChaCha20의 키로 사용하기에 적합하였습니다.

### 2. ChaCha20-Poly1305
ChaCha20는 기존 Salsa20 알고리즘을 수정하여 보안성을 강화한 대칭 키 스트림 암호화 방식입니다. 단독으로 쓰이기 보다는 데이터의 무결성을 보장하기 위해 주로 Poly1305와 결합하여 많이 쓰입니다. 

해당 알고리즘의 장점 중 하나는 소프트웨어 단독 실행 환경에서 효율적이기 때문입니다. AES의 경우 S-BOX와 행렬 변환을 포함하기 때문에 연산이 무거운데, ChaCha20의 경우 비트 이동이나 XOR 같은 단순 연산만 포함하기 때문에 연산 속도가 빠릅니다. 

ChaCha20-Poly1305의 연산이 끝나게 되면, 총 5개의 데이터가 생성됩니다. ChaCha20 대칭 키, 암호문, Nonce, Poly1305 키, Poly1305 MAC이 생성되는데 여기서 ChaCha20 대칭 키와 Poly1305의 키는 암호화하지 않고 전송했을 때 그 정보가 유출된다면 보안에 문제가 생길 수 있으므로, 비대칭 키 암호화인 ECC로 다시 한번 암호화하게 됩니다.

ChaCha20의 암호화 과정을 간단하게 설명하면 아래와 같습니다.
1. 초기 단계를 설정합니다. 초기 단계에는 256비트의 상수 값, 256비트의 대칭 키, 96비트의 Nonce, 32비트의 카운터로 설정됩니다.
	- 상수 값: expand 32-byte k 라는 문자열을 아스키 코드로 변환한 4개의 32비트 상수입니다. 
	- Nonce: 난수 생성기를 통해 만들어지는 무작위 값입니다. 한번만 사용되는 고유한 값이고, 동일한 키를 사용하더라도 다른 결과가 나오게 하는 역할을 합니다.
	- 카운터: 메세지가 길어 여러 블록으로 나뉠때, 각 블록마다 증가하는 값입니다. 
2. 20 라운드의 쿼터 라운드를 수행합니다. 각 라운드는 열 라운드와 대각선 라운드로 구성되며, 열 라운드 연산이 끝나면 대각선 라운드 연산을 진행하는 방식으로 비트 단위가 섞입니다.
3. 20 라운드의 연산이 끝나면, 최종 배열에 초기 단계를 XOR 해주면서 키 스트림을 생성합니다. 그리고 키 스트림을 평문과 XOR 해주게 되면 ChaCha20의 암호화 과정이 끝나게 됩니다.

앞에서 말했듯, ChaCha20은 Poly1305와 조합하여 사용하는 것이 일반적입니다. Poly1305의 무결성 인증 과정을 간단하게 설명하면 아래와 같습니다.

1. ChaCha20의 키 스트림 생성 이후 첫 32바이트를 가져와 Poly1305의 키로 사용합니다. 그리고 그 값을 각각 r, s로 나누어 16비트의 MAC 값을 연산하는데 사용합니다.
2. ChaCha20으로 만들어진 암호문을 각 16바이트 블록으로 나눕니다. 그리고 각 블록에 대해 모듈러 연산을 진행합니다. 
3. 모든 모듈러 연산이 끝나게 되면 마지막에 s 값을 더해 16바이트 MAC을 생성합니다.

연산 과정이 끝나면 송신자 측에서 위에서 생성된 데이터를 수신자에게 전달합니다. 이후 수신자 측에서 자신이 받은 MAC 값과 받은 데이터를 토대로 재생성된 MAC 값의 일치 여부를 확인합니다. 일치한다면 무결성 인증에 성공한 것이고, 일치하지 않으면 중간에 데이터가 위/변조되었음을 알려줍니다.
### 3. ECC
ECC는 수학적 타원 곡선을 기반으로 한 암호화 방식이며, 곡선 위의 점들을 이용하여 데이터를 암호화하게 됩니다. 널리 알려진 비대칭키 방식인 RSA와의 주요 차이점으로는 키의 길이가 짧다는 것입니다. RSA의 경우 2048비트의 키가 필요하지만, ECC는 256비트의 키로 거의 동일한 수준의 보안 강도를 제공합니다.

비대칭 키 암호화이기 때문에 공개 키와 개인 키, 총 2개의 키를 생성하게 됩니다. 여기서 각 키는 타원 곡선위의 수학 연산을 통해 서로 연결되어 있습니다. 특징으로는 개인 키에서 공개 키를 계산하기에는 쉽지만, 반대로 역의 계산은 어렵다는 것입니다.

해당 예제에서는 블록체인에서 사용하는 32바이트 타원 곡선인 secp256k1을 사용하였습니다. 

ECC의 연산 과정을 간단하게 설명하면 아래와 같습니다.
1. 타원 곡선 위의 두 점 P, Q를 더하여 새로운 점 R을 만듭니다.
2. 점 P에 스칼라 곱을 통해 kP라는 점을 만듭니다. 이 부분에서 개인 키는 k 값이 되고, 공개 키는 W = k x G 값이 되는데, 여기서 G 값을 기준점이라고 합니다. 기준점은 무작위 점이 아닌 특정 타원 곡선 방정식을 만족해야 하며, 암호 표준에서 검증된 값이어야 하는 등 조건을 만족해야 합니다.
3. 송신자 측에서 무작위 X 값을 정하여 공개 키 W와 곱하여 공유 비밀을 생성하고,  다시 메시지와 XOR 연산을 하여 수신자 측으로 보내면, 수신자 측은 개인 키로 공유 비밀을 재생성하며 메시지를 복호화하게 됩니다.
## GUI 설명
먼저 서버를 실행시킨 후, 클라이언트를 실행시켜야 연결 됩니다. 서버를 먼저 실행시키면, 클라이언트가 연결될 때까지 기다립니다. 클라이언트가 연결되면, 서버에서 ECC 연산에 필요한 공개 키를 클라이언트로 전송합니다. 

클라이언트가 실행되면, 설문조사에 참여할 수 있습니다. 가장 위에 자신의 이름을 적고, 설문조사 문항에 답변을 작성 후 제출 버튼을 누르게 되면 

```
참여자이름|답변전송시간|1번문항답변|2번문항답변|...|6번문항답변
```

위 형식으로 | 문자를 구분자로 삼은 답변 문자열이 만들어지게 됩니다. 이 문자열은 위에서 설명했던 알고리즘들을 바탕으로 암호화되고, 복호화에 필요한 데이터들과 함께 서버로 전송됩니다. 정상적으로 전송이 되었다면 클라이언트 아래 디스플레이에 전송한 데이터들의 목록과 내용을 나열합니다.

서버가 정상적으로 데이터를 받았다면, 받은 데이터를 사용하여 복호화하고 무결성 인증을 진행한 뒤 성공하면 결과를 출력합니다. 상단 디스플레이에는 받은 데이터들과 무결성 인증 여부, 복호화 내용을 출력하고, 하단 디스플레이에는 복호화된 문자열을 사용하여 설문조사 결과를 출력합니다.
