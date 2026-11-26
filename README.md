# 유레카 비대면 융합프로젝트 1조

## Snac (Share Network Allocation & Commerce)

![헤더 (2)](https://github.com/user-attachments/assets/78461da4-dee7-4be4-882e-df732ee39129)

## 기획

### 남는 통신 데이터를 쉽고 안전하게 사고파는 실시간 데이터 거래 플랫폼, Snac!

Snac은 이런 서비스예요.

실시간 거래: 판매자와 구매자가 즉시 연결되어, 남는 데이터를 빠르고 쉽게 거래할 수 있습니다.
거래 안전성과 익명성: 개인정보 노출 없이, 안심하고 거래할 수 있도록 익명 매칭과 안전 결제 시스템을 도입했습니다.
시장 데이터 약 300건을 조사하여 불편함을 느낀 20명 중 18명이 빠른 응답을, 2명이 익명성 보장을 가장 중요한 가치로 꼽았습니다.

# 🔐 인증 도메인 고도화

> 팀 프로젝트 종료 후, 직접 담당했던 **인증/인가(auth)** 도메인을 개인적으로 리팩토링하고 보안 취약점을 보완했습니다.
> 거래/결제/정산 등 다른 팀원의 담당 영역은 변경하지 않았습니다.

## 한눈에 보기

| 문제 | 해결 | 검증 |
| --- | --- | --- |
| 인증코드 검증의 `조회 → 비교 → 삭제` 가 분리되어 동시 요청 시 같은 코드가 여러 번 통과 가능 | Redis Lua 스크립트로 검증과 상태 전이를 원자적으로 처리 | 같은 정답 100건 동시 검증 → 성공 **1건** |
| 6자리 코드(100만 가지)에 시도 횟수 제한이 없어 무차별 대입 가능 | 실패 횟수 누적을 검증 스크립트에 통합, 5회 오답 시 코드 폐기 | 서로 다른 오답 200건 동시 대입 → 코드와 비교된 요청 **정확히 5건** |
| 발송 API 제한이 없어 SMS 반복 발송 비용 공격(SMS pumping)에 노출 | 재발송 대기(1분) + 일일 발송 한도(10회)를 MQ 발행 전에 원자적으로 예약, 발행 실패 시 예약 해제 | 발송 요청 50건 동시 → 예약 **1건** |
| 인증 완료 상태가 사용 후에도 10분간 남아 비밀번호 재설정 등에 재사용 가능 | 사용 시점에 1회성으로 소비, 회원가입은 휴대폰+이메일을 한꺼번에 소비 | 같은 인증 상태 50건 동시 사용 → 성공 **1건** |
| 12시간 유효한 소셜 로그인 교환 토큰이 URL·로그에 남아 재사용 가능 | 토큰 ID(jti)를 등록하고 교환 시 소비하는 1회용 토큰으로 전환, 유효시간 5분 | 같은 토큰 50건 동시 교환 → 성공 **1건** |
| 위조/형식 오류 JWT 가 예외로 새어 나가 500 응답, 카테고리 누락 시 NPE | 파싱을 한 곳으로 모으고 예외를 401 로 매핑, 웹소켓/OAuth 연동 경로도 토큰 종류 검증 | 필터/재발급/소셜 로그인 단위 테스트 |

## 1. 인증코드 검증 — 원자성과 무차별 대입 방어

```
[검증 요청] ──▶ Lua (단일 원자 실행)
                 ├─ 코드 없음/이미 인증됨  → -1 (만료)
                 ├─ 불일치 → 실패 횟수 +1 ─┬─ 5회 미만 → 0 (불일치)
                 │                        └─ 5회 도달 → 코드 폐기, -2 (시도 초과)
                 └─ 일치   → 코드 키를 VERIFIED 마커로 전이, 1 (성공)
```

- **왜 Lua 인가**: 인증코드 검증은 단일 대상의 Redis 키 몇 개만 다루는 작업이라, 분산락보다 서버 측 스크립트가 단순하고 오버헤드가 낮습니다. 애플리케이션 레벨 락이나 DB 트랜잭션은 Redis 키 소비의 원자성을 직접 보장하지 못합니다.
- **실패 횟수를 같은 스크립트에 넣은 이유**: 카운터를 별도 요청으로 올리면 `비교`와 `증가` 사이에 동시 요청이 끼어들어 제한 횟수를 넘는 대입이 가능합니다. 같은 스크립트 안에서 처리해, 어떤 동시성 상황에서도 코드 1개당 무차별 대입 성공 확률 상한을 **5 / 1,000,000** 으로 고정했습니다.
- 실패 횟수 키의 TTL 은 코드의 남은 TTL 로 맞춰 코드보다 오래 남지 않고, 새 코드 발급 시 함께 초기화됩니다.
- 키에는 대상 값 대신 **정규화한 대상 값의 SHA-256 해시를 해시태그**로 넣습니다. 같은 대상의 키가 Redis Cluster 에서도 항상 한 슬롯에 놓이고(`}` 가 섞인 주소로 태그가 깨지는 경우 포함), 키 이름에 이메일/휴대폰 번호가 남지 않습니다.

## 2. 발송 제한 — 비용이 발생하기 전에 거절

- 컨트롤러에서 RabbitMQ 로 발행하기 **전에** `재발송 대기 확인 → 일일 횟수 확인 → 증가 → 대기 키 설정`을 하나의 스크립트로 수행합니다.
- 한도에 걸린 요청은 429 로 즉시 응답하고, 일일 횟수에 포함하지 않습니다.
- MQ 발행 자체가 실패하면 예약을 되돌려(대기 키 삭제 + 횟수 1 감소) 장애 때문에 사용자가 최대 24시간 막히지 않도록 했습니다. 예약마다 식별자를 두고 **대기 키가 아직 자기 예약일 때만** 되돌려서, 발행이 지연되는 사이 생긴 새 예약을 잘못 풀지 않습니다.
- 이메일 도메인 대소문자, 휴대폰 번호 `+8210…` / `010…` 형식 차이로 한도를 우회하거나 인증 상태가 어긋나지 않도록 대상 값을 정규화합니다.

## 3. 인증 완료 상태 1회성 소비

- 회원가입, 휴대폰 번호 변경, 이메일 찾기, 비밀번호 재설정에서 인증 완료 상태를 `확인 후 삭제` 하는 스크립트로 소비합니다.
- 회원가입은 휴대폰과 이메일이 **모두** 인증 완료일 때만 한꺼번에 소비하고, 하나라도 아니면 아무것도 소비하지 않습니다.
- 이메일/닉네임 중복 검사를 먼저 통과한 뒤 소비해서, 중복 때문에 실패한 사용자가 인증을 다시 받지 않도록 했습니다.

## 4. 토큰 처리

- **소셜 로그인 교환 토큰 1회용화**: OAuth 성공 후 리다이렉트 URL 로 전달되는 토큰에 jti 를 부여해 Redis 에 등록하고, `/api/social-login` 교환 시 `DEL` 로 소비합니다. `DEL` 은 단일 명령이라 별도 스크립트 없이 원자적입니다.
- **JWT 파싱 일원화**: 클레임마다 서명을 다시 검증하던 구조를 `JWTUtil.parse` 한 번으로 바꾸고, `ExpiredJwtException` 외의 `JwtException` 을 401 로 매핑했습니다.
- **토큰 종류 검증**: refresh/social 토큰으로 API, 웹소켓(STOMP CONNECT), OAuth 계정 연동을 시도할 수 없도록 access 토큰만 허용합니다.
- **민감 정보 로그 제거**: SMS 인증번호, social 토큰이 포함된 URL, 소셜 제공자 AccessToken 이 로그에 남지 않도록 했습니다.

## 5. 구조 리팩토링

- 토큰 발급(`TokenIssuer`)과 쿠키 생성/만료(`AuthCookieService`)를 한 곳으로 모아 로그인·소셜 로그인·재발급의 중복 제거
- 비대했던 `CustomOAuth2UserService` 를 프로필 해석 / 계정 연동 / 소셜 토큰 저장 / 플로우 판별로 분리
- 이메일·SMS 인증을 공통 코어(`VerificationCodeService`)와 채널별 전략(`VerificationPolicy`, `VerificationTokenGenerator`)으로 통합해, 채널 추가나 정책 변경 시 코어를 건드리지 않도록 구성

## 테스트

Lua 스크립트의 원자성은 Mock 으로 검증할 수 없어서 **Testcontainers 로 실제 Redis 를 띄워** 동시 요청을 재현했습니다. (Docker 필요)

```bash
./gradlew test --tests 'com.ureca.snac.auth.*' --tests 'com.ureca.snac.member.service.JoinServiceImplTest'
```

| 테스트 | 내용 |
| --- | --- |
| `VerificationCodeServiceTest` | 동시 검증, 무차별 대입, 시도 횟수 초기화/TTL, 발송 제한/해제, 대상 정규화, 키 슬롯, 인증 상태 소비 (24건) |
| `EmailServiceImplTest` | 발행 실패 시 예약 해제, 한도 초과 시 미발행 (4건) |
| `SocialLoginTokenRegistryTest` | 1회용 토큰 소비, 동시 교환 (4건) |
| `JWTFilterTest` · `ReissueServiceImplTest` · `SocialLoginServiceImplTest` | 만료/위조/형식 오류/토큰 종류별 응답 (19건) |
| `JoinServiceImplTest` | 인증 상태 소비 순서와 경쟁 상황 (4건) |

## 알려진 한계

- **인증 완료 상태가 요청자에 묶여 있지 않음**: 인증 완료 상태는 휴대폰 번호/이메일 기준으로 저장되어, 인증 직후 같은 번호를 아는 제3자가 먼저 사용할 수 있는 창이 남아 있습니다. 1회성 소비로 재사용은 막았지만, 근본적으로는 검증 성공 시 일회용 증명 토큰을 내려주고 이후 요청에서 함께 받도록 API 계약을 바꿔야 해서 프론트엔드와 함께 진행할 과제로 남겼습니다.
- **OAuth 계정 연동 state**: 연동 시 액세스 토큰을 OAuth `state` 로 전달하는 기존 구조를 유지하고 있습니다. 토큰 종류 검증은 추가했지만, 짧은 수명의 연동 전용 토큰으로 바꾸는 것도 프론트엔드 변경이 필요합니다.
- **refresh 토큰 동시 재발급**: 같은 refresh 토큰으로 동시에 재발급하면 둘 다 성공하고 마지막 토큰만 유효해집니다. 보안상 위험은 없어 범위에서 제외했습니다.

# 디렉토리 구조

```
com.ureca.snac
├── asset          # 자산 내역 (스낵 머니 / 포인트) 
├── auth           # 인증/인가 (로그인, 회원가입, 소셜 연동 등)
├── board          # 게시글 관련 (카드 등록, 상태 등)
├── common         # 공통 유틸, 예외 처리, 응답 구조 등
├── config         # 전역 설정 (Swagger, S3, Jpa, RabbitMQ)
├── dev            # 비밀통로 (작업 단축 API)
├── favorite       # 단골 (CRUD)
├── finance        # 계좌, 은행 도메인
├── infra          # Toss payments Api
├── member         # 사용자 도메인
├── money          # 머니 충전 요청 (주문서)
├── mypage         # 마이페이지 관련 기능
├── notification   # 알림 기능 (WebSocket,  RabbitMQ 등)
├── payment        # 결제 처리 (결제 승인 및 취소, 누락)
├── settlement     # 정산 (판매 대금 정산)
├── swagger        # Swagger 관련 설정 및 문서화
├── trade          # 거래 처리 (구매/판매 흐름, 상태 전환 등)
└── wallet         # 지갑 및 잔액 기록
```

# ERD

<img width="2101" height="1157" alt="Image" src="https://github.com/user-attachments/assets/bead419f-1e1b-428e-8a8e-f354a9942de0" />

# 기술 스택

## 백엔드

![BE](https://github.com/user-attachments/assets/21e6a9fb-7fe4-4bbb-9bcd-3ff51b621c40)

## 인프라

![Infra](https://github.com/user-attachments/assets/c2f28915-222a-4fef-91ad-4f4fa29275f5)

# 인프라 아키텍쳐

![Image](https://github.com/user-attachments/assets/972b9bb2-0cf0-4ff8-960a-91d705505468)

# 팀원

***
<table>
  <tbody>
    <tr>
      <td align="center"><a href="https://github.com/iju42829"><img src="https://avatars.githubusercontent.com/u/116072376?v=4" width="120px;" alt=""/><br /><b>이재윤</b></a><br /></td>
      <td align="center"><a href="https://github.com/Iamcalmdown"><img src="https://avatars.githubusercontent.com/u/144317474?v=4" width="120px;" alt=""/><br /><b>정동현</b></a><br /></td>
      <td align="center"><a href="https://github.com/mike7643"><img src="https://avatars.githubusercontent.com/u/121170730?v=4" width="120px;" alt=""/><br /><b>정유민</b></a><br /></td>
      <td align="center"><a href="https://github.com/seokjuun"><img src="https://avatars.githubusercontent.com/u/45346977?v=4" width="120px;" alt=""/><br /><b>홍석준</b></a><br /></td>
    </tr>
  </tbody>
</table>

## ⌛ Developed Period

### 2025.6.30 ~ 2025.8.8 (39 days)
