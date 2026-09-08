// 로컬 실행용 진입점: node server.js → http://localhost:3000
// (WebAuthn은 https가 원칙이지만 localhost는 예외로 허용된다.)
import { createApp } from './src/app.js';

const port = process.env.PORT || 3000;
createApp().listen(port, () => {
  console.log(`▶ http://localhost:${port}`);
});
