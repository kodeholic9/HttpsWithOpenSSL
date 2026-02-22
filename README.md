HttpsWithOpenSSL: High-Availability Native TLS Engine
1. 개요 (Overview)
본 프로젝트는 안드로이드 시스템 네트워크 스택의 제약을 극복하고, L4(TCP)와 L7(Application) 사이의 보안 계층을 독자적으로 통제하기 위해 설계된 범용 TLS 통신 엔진입니다. 표준 TLS 1.3에서 지원하지 않는 국산 암호화 표준(ARIA) 등을 수용하며, JNI 환경의 고질적인 문제인 네트워크 행(Hang)과 메모리 오염을 원천 차단하는 **'무정지 보안 스택'**을 지향합니다.

2. 핵심 설계 아키텍처 (Core Architecture)
2.1. 정적 슬롯 기반 자원 관리 (Static Slot Management)
JNI 환경에서 동적 메모리 할당과 포인터 노출은 시스템 불안정의 주범입니다. 이를 해결하기 위해 본 엔진은 결정적 자원 관리(Deterministic Resource Management) 시스템을 구축했습니다.

정적 풀(Static Pool) 할당: MAX_TLS_CONN_NUM(64)개의 세션 슬롯을 전역 메모리에 미리 확보하여 런타임 중 빈번한 할당/해제로 인한 메모리 파편화를 방지하고 성능을 극대화합니다.

인덱스 기반 핸들링: Java 계층에는 실제 메모리 주소가 아닌 0~63 사이의 인덱스(tlsconn_id)만을 핸들로 전달합니다.

유효성 검증 레이어: 모든 네이티브 진입점에서 인덱스 범위 확인 및 occupied 플래그 체크를 수행하여, 잘못된 호출이 시스템 세그멘테이션 폴트(SIGSEGV)로 이어지는 것을 원천 차단합니다.

2.2. 하이브리드 I/O 상태 머신 (Hybrid I/O State Machine)
TLS 프로토콜의 단계별 특성에 맞춘 최적화된 I/O 모델을 적용하여 연결 안정성과 데이터 처리 효율을 동시에 확보했습니다.

Handshake Phase (Select-based): 소켓을 논블로킹(O_NONBLOCK)으로 설정한 뒤, SSL_connect()와 select()를 조합하여 상태 머신을 제어합니다. 이를 통해 핸드셰이크 과정에서 발생하는 WANT_READ/WRITE 상태를 정교하게 추적합니다.

Data Phase (Memory BIO Swap): 핸드셰이크 완료 후 소켓과 SSL 객체 사이에 **메모리 BIO(rbio, wbio)**를 물리적으로 배치합니다. 소켓에서 읽은 암호화 패킷을 네이티브 버퍼 레벨에서 직접 핸들링함으로써 커스텀 사이퍼슈트 환경에서도 데이터 무결성을 보장합니다.

2.3. IPC 시그널 기반 중단 메커니즘 (Pipe-Signal Interrupt)
네트워크 지연이나 서버 무응답 상황에서 네이티브 루프가 무한 대기에 빠져 앱이 응답하지 않는(ANR) 상황을 방지하기 위한 비상 탈출 장치입니다.

제어용 파이프(pipefd) 운용: 각 커넥션 슬롯마다 독립적인 시그널 파이프를 생성하여 select() 루프에서 소켓과 함께 감시합니다.

강제 깨우기 (Instant Wake-up): Java 단에서 tlsShutdown() 호출 시 파이프에 즉각 시그널(1Byte)을 기록합니다.

안전한 자원 회수: 시그널을 감지한 네이티브 루프는 즉시 제어권을 반납하고 점유 중인 자원을 해제하여 시스템 가용성을 유지합니다.

3. 보안 및 확장성 (Security & Extensibility)
Custom OpenSSL Patch: TLS 1.3 표준에서 지원하지 않는 국산 암호화 알고리즘 ARIA 지원을 위해 직접 패치된 OpenSSL 정적 라이브러리(libssl.a, libcrypto.a)를 링킹합니다.

범용 L4/L7 추상화: TLSNativeIF는 Java 표준 InputStream/OutputStream을 상속받아 구현되어, HTTP뿐 아니라 모든 TCP 기반 커스텀 프로토콜에 즉시 적용 가능합니다.

인증서 보안: tls_init_x509_store를 통해 앱 내부의 신뢰할 수 있는 인증서만 사용하여 중간자 공격(MITM)을 방어합니다.

4. 운영 및 안정성 정책 (Stability Policy)
이중 뮤텍스 전략: 전역 관리용 뮤텍스와 개별 세션용 뮤텍스를 분리하여 멀티스레드 환경의 경합을 최소화했습니다.

Zero-Leak 보장: 모든 자원은 SSL, CTX, Socket, Pipe 순으로 정해진 역순서에 따라 100% 명시적으로 해제됩니다.
