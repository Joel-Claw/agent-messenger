// Agent Messenger Load Test v4
// Focused test: auth + conversation + messaging pipeline
// Rate-limited server means we test at realistic traffic levels
//
// Usage: k6 run load-test.js

import http from 'k6/http';
import { check, sleep } from 'k6';

const BASE = __ENV.AM_TEST_HOST || 'http://localhost:18901';
const AGENT_SECRET = __ENV.AGENT_SECRET || 'dev-agent-secret-change-me';

// Shared state for pre-registered users (setup function)
const users = {};

export const options = {
  stages: [
    { duration: '10s', target: 5 },    // gentle ramp
    { duration: '30s', target: 15 },    // moderate load
    { duration: '20s', target: 15 },    // hold
    { duration: '10s', target: 0 },    // ramp down
  ],
  thresholds: {
    http_req_duration: ['p(95)<2000'],   // 95% under 2s
    http_req_failed: ['rate<0.3'],        // under 30% (rate limiting expected)
  },
};

export default function () {
  const vuId = __VU;
  const username = `k6_${vuId}`;
  const password = 'testpass123456';

  // ── Register user (409 = already exists, that's fine) ─────────
  http.post(`${BASE}/auth/user`, {
    username: username,
    password: password,
  });

  // ── Login ──────────────────────────────────────────────────────
  const loginRes = http.post(`${BASE}/auth/login`, {
    username: username,
    password: password,
  });

  if (!check(loginRes, { 'login succeeded': (r) => r.status === 200 })) {
    sleep(2);
    return;
  }

  const token = loginRes.json('token');

  // ── Register agent (once per VU) ──────────────────────────────
  const agentId = `agent_k6_${vuId}`;
  http.post(`${BASE}/auth/agent`, {
    agent_id: agentId,
    name: `Load Agent ${vuId}`,
    model: 'test-model',
    personality: 'helpful',
    specialty: 'load testing',
    agent_secret: AGENT_SECRET,
  });

  // ── Create conversation ────────────────────────────────────────
  const convRes = http.post(`${BASE}/conversations/create`, {
    agent_id: agentId,
    title: `Conv ${vuId}-${__ITER}`,
  }, {
    headers: { 'Authorization': `Bearer ${token}` },
  });
  check(convRes, { 'conversation created': (r) => r.status === 200 });

  // ── List conversations (main read path) ─────────────────────────
  const listRes = http.get(`${BASE}/conversations/list?limit=20`, {
    headers: { 'Authorization': `Bearer ${token}` },
  });
  check(listRes, { 'list conversations': (r) => r.status === 200 });

  // ── Health check (no auth needed, no rate limit) ────────────────
  const healthRes = http.get(`${BASE}/health`);
  check(healthRes, { 'health ok': (r) => r.status === 200 && r.json('status') === 'ok' });

  // Longer sleep to stay within rate limits
  sleep(1);
}