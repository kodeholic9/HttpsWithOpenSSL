# HttpsWithOpenSSL: High-Availability Native TLS Engine

## 1. 개요 (Overview)
본 프로젝트는 Android OS의 네트워크 스택 파편화 문제를 해결하고, 표준 TLS에서 지원하지 않는 **국산 암호화 표준(ARIA)** 등의 특수 요구사항을 수용하기 위해 설계된 **Native 기반 범용 TLS 통신 엔진**입니다.

단순한 HTTP 클라이언트를 넘어, L4(TCP)와 L7(Application) 사이의 보안 계층을 독자적으로 통제합니다. 특히 JNI 환경에서 발생할 수 있는 네트워크 행(Hang)과 메모리 오염을 원천 차단하는 **'무정지(Zero-Downtime) 보안 스택'** 구현을 최우선 과제로 삼았습니다.

---

## 2. 핵심 아키텍처 설계 (Architectural Core)

### 2.1. 결정적 자원 관리: 64-Slot 정적 풀 (Static Slot Management)
JNI 환경에서 동적 메모리 할당(`malloc`)과 포인터의 Java 계층 노출은 시스템 불안정의 근본 원인입니다. 본 엔진은 이를 해결하기 위해 **'예측 가능한 메모리 모델'**을 채택했습니다.

* **정적 슬롯 예비 할당**: `MAX_TLS_CONN_NUM(64)`개의 세션 구조체(`tlsconn_t`)를 전역 메모리 영역에 미리 확보합니다. 이는 빈번한 할당/해제로 인한 메모리 파편화를 방지하고, 시스템이 사용하는 최대 메모리 점유율을 고정하여 OOM(Out of Memory) 위험을 최소화합니다.
* **Opaque Handle (인덱스 기반 인터페이스)**: Java 계층에는 실제 메모리 주소(Pointer)를 절대 노출하지 않습니다. 오직 0~63 사이의 **슬롯 인덱스(`tlsconn_id`)**만을 핸들로 사용하여, 무효한 포인터 접근으로 인한 시스템 세그멘테이션 폴트(SIGSEGV)를 논리적으로 차단합니다.
* **Occupied Flag 검증**: 모든 네이티브 진입점에서 인덱스 범위 확인과 슬롯 점유 상태를 실시간 검증함으로써, 이미 닫힌 세션에 대한 오동작을 원천 방어합니다.

### 2.2. 하이브리드 I/O 상태 머신 (Hybrid I/O State Machine)
TLS 프로토콜의 단계별 동작 특성(Handshake vs Data Stream) 차이를 극복하기 위해 정교한 I/O 모델을 적용했습니다.

* **Handshake Phase (Select-based)**: 연결 초기 단계에서는 소켓을 논블로킹(`O_NONBLOCK`)으로 설정한 뒤, `SSL_connect()`와 `select()`를 조합하여 상태 머신을 제어합니다. 이를 통해 핸드셰이크 과정에서 발생하는 `WANT_READ/WRITE` 상태를 소켓 레벨에서 완벽하게 추적하며 안정성을 보장합니다.
* **Data Phase (Memory BIO Swap)**: 핸드셰이크 완료 후 소켓과 SSL 객체 사이에 **메모리 BIO(`rbio`, `wbio`)**를 물리적으로 배치합니다. 네트워크 패킷을 네이티브 버퍼 레벨에서 직접 핸들링함으로써, ARIA 패치와 같은 커스텀 사이퍼슈트 환경에서도 데이터 무결성을 100% 유지합니다.

### 2.3. IPC 파이프 기반 인터럽트 시스템 (Pipe-Signal Interrupt)
모바일 네트워크의 불확실성과 서버 무응답(Hang) 상황에서 네이티브 루프가 무한 대기에 빠져 앱이 응답하지 않는(ANR) 현상을 방지합니다.

* **제어용 파이프(`pipefd`) 운용**: 모든 세션 슬롯은 자신만의 시그널 전송용 파이프를 가집니다. 네이티브 `select()` 루프는 실제 소켓뿐만 아니라 이 제어용 파이프를 동시에 감시합니다.
* **Instant Wake-up (비상 탈출)**: Java 단에서 중단 요청(`tls_signal`)이 들어오면 파이프에 즉각 시그널(1바이트)을 기록합니다. `select()` 루프는 네트워크 패킷이 없더라도 시그널을 감지하여 즉각 깨어나며, 자원을 안전하게 회수하고 제어권을 Java 계층으로 즉시 반환합니다.

---

## 3. 범용 보안 인터페이스 (Universal Security Layer)

본 프로젝트는 특정 애플리케이션 프로토콜에 종속되지 않는 유연성을 제공합니다.

* **ARIA Custom Patch**: TLS 1.3에서 공식 지원하지 않는 국산 암호화 표준 **ARIA**를 지원하기 위해 직접 패치된 OpenSSL 정적 라이브러리(`libssl.a`, `libcrypto.a`)를 링킹합니다.
* **Standard I/O Abstraction**: `TLSNativeIF`는 Java 표준 `InputStream`/`OutputStream`을 상속받아 구현되었습니다. 이는 HTTP/HTTPS뿐만 아니라 커스텀 TCP 프로토콜(채팅, 바이너리 전송 등) 환경에서 보안 계층만 즉시 교체하여 사용할 수 있는 범용성을 제공합니다.
* **인증서 보안**: `tls_init_x509_store`를 통해 앱 내부에 포함된 신뢰할 수 있는 인증서만을 사용하여 중간자 공격(MITM)을 원천 봉쇄합니다.

---

## 4. 운영 및 안정성 정책 (Stability Policy)

* **이중 뮤텍스 전략**: 전역 자원 관리를 위한 `Oz.mutex`와 개별 세션의 원자성을 보장하는 `connlock`을 분리하여 멀티스레드 환경의 경합을 최소화합니다.
* **Deterministic Cleanup**: 모든 자원은 `SSL`, `SSL_CTX`, `Socket`, `Pipe` 순으로 정해진 역순서에 따라 100% 명시적으로 해제됨을 보장하며, 단 1바이트의 메모리 누수도 허용하지 않습니다.

---
**Author**: kodeholic
