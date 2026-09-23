/**
 * gate.test.mjs — 授权闸门（**本件唯一真正新增的机制**）的离线验收。
 *
 * 对应设计稿 §7 的 A8 / A9 / A10：
 * - A8：五类坏样本全 deny，且 reason 与裁决表逐条一致；
 * - A9：闸门**先于副作用**（deny 时零网络零子进程）——结构判据 + 运行时判据；
 * - A10：范围匹配带 `.` 边界（`evil-example.com` 不匹配 `example.com`）。
 *
 * 纪律：恒放行或恒拒绝的实现必须让这些用例**失败**（否则判据没有分辨力）。
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, mkdtempSync, rmSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { decideGate, matchesScopeEntry, normalizeTarget, gateDeniedLine } from '../lib/gate.js'
import { apply } from '../lib/index.js'

const NOW = Date.parse('2026-09-23T12:00:00+08:00')

function eng(over = {}) {
  return {
    id: 'eng-test',
    title: 't',
    authorization: { source: 'lab-charter', ref: 'doc://charter' },
    scope: { targets: ['example.com'], exclude: [], allowActiveAuth: false },
    window: { notBefore: '2026-09-23T10:00:00+08:00', notAfter: '2026-09-23T18:00:00+08:00' },
    status: 'active',
    ...over,
  }
}

test('A8 坏样本 ①：无交战 ⇒ deny gate/no-engagement（fail-closed）', () => {
  const v = decideGate({ engagement: null, actionClass: 'active', target: 'example.com', nowMs: NOW })
  assert.deepEqual(v, { verdict: 'deny', reason: 'gate/no-engagement' })
})

test('A8 坏样本 ②：空授权 ref ⇒ deny gate/no-authorization', () => {
  const v = decideGate({ engagement: eng({ authorization: { source: 'owner-directive', ref: '   ' } }), actionClass: 'active', target: 'example.com', nowMs: NOW })
  assert.deepEqual(v, { verdict: 'deny', reason: 'gate/no-authorization' })
})

test('A8 坏样本 ③：越界 host ⇒ deny gate/out-of-scope', () => {
  const v = decideGate({ engagement: eng(), actionClass: 'active', target: 'evil.org', nowMs: NOW })
  assert.deepEqual(v, { verdict: 'deny', reason: 'gate/out-of-scope' })
})

test('A8 坏样本 ④：过期窗口 ⇒ deny gate/out-of-window（passive 亦受窗口约束）', () => {
  const late = Date.parse('2026-09-23T20:00:00+08:00')
  assert.deepEqual(decideGate({ engagement: eng(), actionClass: 'active', target: 'example.com', nowMs: late }), { verdict: 'deny', reason: 'gate/out-of-window' })
  assert.deepEqual(decideGate({ engagement: eng(), actionClass: 'intel', nowMs: late }), { verdict: 'deny', reason: 'gate/out-of-window' })
})

test('A8 坏样本 ⑤：allowActiveAuth=false 下的 auth-attempt ⇒ deny gate/auth-not-enabled', () => {
  const v = decideGate({ engagement: eng(), actionClass: 'active-auth', target: 'example.com', nowMs: NOW })
  assert.deepEqual(v, { verdict: 'deny', reason: 'gate/auth-not-enabled' })
  // 对照组：开了开关就放行（证明这条判据有分辨力，不是恒 deny）
  const on = eng({ scope: { targets: ['example.com'], exclude: [], allowActiveAuth: true } })
  assert.deepEqual(decideGate({ engagement: on, actionClass: 'active-auth', target: 'example.com', nowMs: NOW }), { verdict: 'allow' })
})

test('A8 补充：closed 交战 ⇒ deny gate/closed；exclude 命中 ⇒ deny gate/excluded', () => {
  assert.deepEqual(decideGate({ engagement: eng({ status: 'closed' }), actionClass: 'passive', nowMs: NOW }), { verdict: 'deny', reason: 'gate/closed' })
  const ex = eng({ scope: { targets: ['example.com'], exclude: ['api.example.com'], allowActiveAuth: false } })
  assert.deepEqual(decideGate({ engagement: ex, actionClass: 'active', target: 'api.example.com', nowMs: NOW }), { verdict: 'deny', reason: 'gate/excluded' })
})

test('A8 正样本：passive 恒放行；intel 不要求 scope 命中；active 在范围内放行', () => {
  assert.deepEqual(decideGate({ engagement: eng(), actionClass: 'passive', nowMs: NOW }), { verdict: 'allow' })
  assert.deepEqual(decideGate({ engagement: eng(), actionClass: 'intel', nowMs: NOW }), { verdict: 'allow' })
  assert.deepEqual(decideGate({ engagement: eng(), actionClass: 'active', target: 'a.example.com', nowMs: NOW }), { verdict: 'allow' })
})

test('A10 范围匹配带 `.` 边界：子域命中、同名后缀不命中、大小写与尾点归一化', () => {
  assert.equal(matchesScopeEntry('a.example.com', 'example.com'), true)
  assert.equal(matchesScopeEntry('evil-example.com', 'example.com'), false)
  assert.equal(matchesScopeEntry('EXAMPLE.com.', 'example.com'), true)
  assert.equal(matchesScopeEntry('example.com:443', 'example.com'), true)
  assert.equal(matchesScopeEntry('https://user@example.com/x?y=1', 'example.com'), true)
  assert.equal(matchesScopeEntry('example.com.evil.org', 'example.com'), false)
})

test('normalizeTarget：去 scheme / userinfo / 路径 / 端口 / 尾点，转小写', () => {
  assert.equal(normalizeTarget('HTTPS://User@Example.COM:8443/a/b?c=1'), 'example.com')
  assert.equal(normalizeTarget('example.com...'), 'example.com')
  assert.equal(normalizeTarget(''), '')
})

test('A9 结构判据：注册切面在 deny 分支**先返回**，不触碰 spec.run（闸门先于副作用）', () => {
  const src = readFileSync(join(import.meta.dirname, '..', 'src', 'index.ts'), 'utf8')
  const denyBlock = /if \(verdict\.verdict === 'deny'\) \{[\s\S]*?return \{ text: `⛔[\s\S]*?\}\n/.exec(src)
  assert.ok(denyBlock !== null, '找不到 deny 分支')
  assert.ok(!denyBlock[0].includes('spec.run'), 'deny 分支里出现了 spec.run —— 闸门不再先于副作用')
  // 副作用只能经 spec.run 发生（通道都在各工具的 run 体内）
  assert.ok(src.includes('const text = await spec.run(args, { eng, paths })'))
})

test('A9 运行时判据：deny 时工具返回拒绝文案，且**不产生证据**（证据只在 run 成功后写）', async () => {
  const root = mkdtempSync(join(tmpdir(), 'eng-gate-'))
  try {
    const registered = []
    const ctx = {
      tools: { register: (spec) => { registered.push(spec); return () => {} } },
      on: () => () => {},
      effect: () => () => {},
      logger: () => ({ info: () => {}, warn: () => {}, debug: () => {}, error: () => {} }),
    }
    apply(ctx, { enabled: true, root, timeoutMs: 1000, limit: 5, reportDir: '' })
    assert.equal(registered.length, 12, '工具面不是 12')
    const recon = registered.find((t) => t.name === 'eng_recon_host')
    assert.ok(recon !== undefined)
    const out = await recon.execute({ engagementId: 'eng-nonexistent', host: 'example.com', ports: '80' })
    assert.ok(out.text.includes('闸门拒绝'), '未返回拒绝文案：' + out.text)
    assert.ok(out.text.includes('gate/no-engagement'))
    // deny 只落 timeline（设计允许的那一处），**不落证据**
    const dir = join(root, 'eng-nonexistent')
    assert.ok(existsSync(join(dir, 'timeline.jsonl')), '拒绝未留痕（I4）')
    assert.ok(!existsSync(join(dir, 'evidence.jsonl')), 'deny 竟产生了证据')
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('I4 拒绝留痕行形状：phase=gate/denied + reason + 目标', () => {
  const line = gateDeniedLine({ atMs: NOW, engagementId: 'eng-1', tool: 'eng_recon_host', actionClass: 'active', target: 'evil.org', reason: 'gate/out-of-scope' })
  const v = JSON.parse(line)
  assert.equal(v.phase, 'gate/denied')
  assert.equal(v.reason, 'gate/out-of-scope')
  assert.equal(v.target, 'evil.org')
  assert.equal(v.outcome, 'denied')
})
