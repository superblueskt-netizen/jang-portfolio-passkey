// Vercel 서버리스 진입점. vercel.json의 rewrite가 모든 /api/* 요청을 이리로 보낸다.
import { createApp } from '../src/app.js';

export default createApp();
