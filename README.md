# eth_header_dissector

### 1. 캡처한 파일을 capture.pcap로 저장한다.
---
**※ 주의사항**

	* .pcapang 파일로 저장할 경우 실행되지 않음.

### 2. key.txt파일을 생성한다. (기존 파일이 있다면 내용을 지우고 자신의 key를 입력해둔다)
---
**※ 입력할 명령어**

	1. sudo docker exec -it ethereum-node geth attach
	2. admin.nodeInfo.id


---
**※ 자신의 key 찾는법**


	* 터미널에 sudo docker exec -it ethereum-node geth attach 입력: geth console에 접속하는 명령어 
	( 설치한 방식에 따라 다를 수 있음 )

	* geth console에 admin.nodeInfo.id를 입력해 노드id를 찾는다.

	* 노드 id는 [:16]만큼 잘라서 key로 사용한다.

### 3. ethereum_dissector.cpp를 g++를 이용해 컴파일 후 실행하기	
---
**※ 입력할 명령어**


	1. g++ ethereum_dissector.cpp -lpcap -lssl -lcrypto -o dissector
	2. ./dissector 
---

**※ 옵션에 대한 간단한 설명**


	* -lpcap: pcap파일을 읽기 위해 추가한 옵션
	* -lssl, -lcrypto: AES-CTR로 암호화된 패킷을 해석하기 위해 추가한 옵션



### 4. Wireshark Lua 해석기 파일 위치 지정
---

**※ Wireshark init.lua 파일 맨 하단에 ethereum.lua 파일 위치를 입력한다.**


	
	* 운영체제 별 init.lua 파일 위치 
		Linux: /usr/share/wireshark
		Window: C:\Program Files\Wireshark

	* Linux의 경우 sudo su 하고 나서, Window는 Visual Studio Code를 관리자 모드로 열어서 수정해야 함.
		- Wireshark 프로그램 폴더에 넣었을 경우, 위치 입력 방법
		Linux, Window:
		dofile(DATA_DIR.."ethereum.lua")

	* 다른 곳에 넣어야 할 경우 폴더명이 영어인 곳에 넣을 것. 아래와 같이 입력하면 됨.
		Linux: dofile("usr/share/wireshark/ethereum.lua")
		window: dofile("C:\\Program Files\\vscode\\ethereum.lua")


### 5. Wiresahrk에 해석기 적용하기 
---
**※ 실행과정**

	1. Wireshark 실행
	2. 메뉴 바에서 Analyze >> Enabled Protocols 클릭
	3. ethereum 검색하면 내가 넣은 해석기 있음
	4. 체크 후 확인버튼 클릭


### 6. Wireshark로 해석된 파일을 열어서 확인하기
---
**※ 실행과정**

	* decode.pcap파일을 Wireshark를 통해 보면 해석이 된 결과를 볼 수 있다.


# < 사전 설치 필요 패키지 - 리눅스 기준 >

**※ 입력할 명령어**

	1. sudo apt-get install libpcap-dev
	2. sudo apt-get install libss-dev

### 참고한 사이트
---
Ethereum devp2p github - https://github.com/ethereum/devp2p/blob/master/discv5/discv5.md
