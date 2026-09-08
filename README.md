# 소개 페이지 + 패스키(WebAuthn) 잠금

1번 과제에서 만든 공개 소개 페이지는 그대로 두고, 그 아래에 **나만 보는 자리**를 하나 만들어
**패스키로만** 열리게 한 것입니다. 비밀번호는 만들지 않았습니다.

- 공개 영역: 누구나, 아무것도 등록하지 않고 볼 수 있습니다.
- 비공개 영역: 패스키로 확인된 뒤에만 서버가 내용을 내려보냅니다.
- 비공개 영역 내용은 전부 **만들어 넣은 가상 데이터**입니다. 실제 연락처나 신분증 번호는 없습니다.

---

## 1. 폴더 구조

```
├─ public/                 공개 소개 페이지 (여기에는 비공개 내용이 없다)
│   ├─ index.html          공개 영역 + 비공개 영역의 '잠긴 껍데기'
│   ├─ app.js              등록·로그인·로그아웃·비공개 조회를 부르는 브라우저 코드
│   └─ styles.css
├─ src/
│   ├─ app.js              서버 본체 — 모든 API가 여기 있다
│   ├─ store.js            질문(challenge)·공개키·세션 저장소
│   └─ data.js             두 계정의 비공개 내용(가상 데이터)
├─ api/index.js            Vercel 서버리스 진입점
├─ server.js               로컬 실행 진입점
├─ test/
│   ├─ passkey-e2e.mjs     자동 검사 — evidence/검사기록.md 를 만든다
│   ├─ soft-authenticator.mjs  검사용 소프트웨어 인증기
│   ├─ browser-smoke.mjs   실제 크롬 + 가상 인증기로 화면 동작 확인
│   └─ screenshots.mjs     제출용 화면 캡처 생성
├─ evidence/               검사 기록과 캡처
└─ docs/제출문.md           인증 구현 설명서 여섯 항목 등 제출 문서
```

## 2. 네 흐름이 지나는 자리

| 흐름 | 브라우저 | 서버 |
|---|---|---|
| 등록 | `public/app.js` → `registerPasskey()` | `src/app.js` → `POST /api/register/options` (127행), `POST /api/register/verify` (174행) |
| 로그인 | `public/app.js` → `loginWithPasskey()` | `src/app.js` → `POST /api/login/options` (240행), `POST /api/login/verify` (260행) |
| 로그아웃 | `public/app.js` → `#btn-logout` 처리 | `src/app.js` → `POST /api/logout` (334행) |
| 비공개 조회 | `public/app.js` → `showUnlocked()` | `src/app.js` → `GET /api/private/notes` (357행), `GET /api/private/notes/:userId` (373행) |

## 3. 로컬에서 실행하기

```bash
npm install
npm start        # → http://localhost:3000
```

패스키는 https에서만 동작하지만 **localhost는 예외**로 허용됩니다.
저장소 환경변수가 없으면 임시 파일에 저장하므로 설정 없이 바로 돌아갑니다.

## 4. 검사 돌리기

```bash
npm run test:e2e            # 요청·응답 기록을 evidence/검사기록.md 로 저장
node test/browser-smoke.mjs # 실제 크롬 + 가상 인증기로 화면 동작 확인
node test/screenshots.mjs   # 제출용 캡처 생성
```

## 5. Vercel에 올리기

1. 이 폴더를 GitHub 저장소로 올립니다(공개 저장소여야 심사자가 볼 수 있습니다).
2. [vercel.com](https://vercel.com) → **Add New… → Project** → 그 저장소를 고릅니다.
   Framework Preset은 **Other**, 나머지는 기본값 그대로 둡니다.
3. **Storage** 탭에서 **Upstash for Redis**를 만들어 이 프로젝트에 연결합니다.
   `KV_REST_API_URL` / `KV_REST_API_TOKEN` 환경변수가 자동으로 들어옵니다.
   - 연결하지 않아도 화면은 뜨지만, 서버리스 인스턴스가 바뀌면 등록한 패스키가 사라집니다.
     **반드시 연결하세요.**
4. 배포된 주소(`https://…vercel.app`)로 접속합니다. 첫 화면은 공개 소개 페이지입니다.
5. 직접 만든 도메인을 붙였다면 환경변수 `ALLOWED_ORIGINS`에 그 주소를 넣어 주세요.
   (예: `ALLOWED_ORIGINS=https://jang.example.com`)

> 패스키는 도메인에 묶입니다. `*.vercel.app`에서 등록한 패스키는 다른 도메인에서 쓸 수 없습니다.
> 도메인을 바꾸면 패스키를 다시 등록해야 합니다.

## 6. 개인정보·비밀값

- 이 저장소에는 API 키, 토큰, 비밀번호가 들어 있지 않습니다. 저장소 접속 정보는 배포 환경변수로만 넣습니다.
- 비공개 영역 내용(`src/data.js`)은 전부 과제용으로 지어낸 것입니다.
- 기록에 남는 세션 값은 앞 네 글자만 남기고 가립니다.

배포: https://jang-portfolio-passkey.vercel.app
