/**
 * live-path.test.mjs — **正路径**测试：工具真的能跑通，不只是「坏样本被拦住」。
 *
 * 为什么要单独一个文件（2026-09-23 实测事故）：坏样本测试全绿 + 加载冒烟全绿 + `tsc` 全绿，
 * 但**第一个真实调用就发现 `eng_open` 被自己的闸门挡住**——整件不可用。原因是闸门裁决表
 * 把「无交战 ⇒ deny」排在「passive ⇒ allow」之前，而 `eng_open` 正是**创建**交战的工具。
 *
 * ⇒ 教训：**只测拒绝路径的防线，等于只测了一半**。本文件补上「开得起来、读得回来」的那一半。
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { existsSync, mkdtempSync, rmSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { decideGate } from '../lib/gate.js'
import { apply } from '../lib/index.js'

function registry(root) {
  const registered = []
  const ctx = {
    tools: { register: (spec) => { registered.push(spec); return () => {} } },
    on: () => () => {},
    effect: () => () => {},
    logger: () => ({ info: () => {}, warn: () => {}, debug: () => {}, error: () => {} }),
  }
  apply(ctx, { enabled: true, root, timeoutMs: 1000, limit: 5, reportDir: '' })
  const find = (n) => {
    const t = registered.find((x) => x.name === n)
    assert.ok(t !== undefined, `未注册工具 ${n}`)
    return t
  }
  return find
}

test('闸门：meta 类别在**无交战**时也放行（先于交战存在的管理动作）', () => {
  assert.deepEqual(decideGate({ engagement: null, actionClass: 'meta', nowMs: Date.now() }), { verdict: 'allow' })
})

test('正路径：eng_open 能真的开出一次交战（不再被自己的闸门挡住）', async () => {
  const root = mkdtempSync(join(tmpdir(), 'eng-open-'))
  try {
    const find = registry(root)
    const out = await find('eng_open').execute({
      title: '正路径冒烟',
      purpose: '验证开得起来',
      authorizationSource: 'lab-charter',
      authorizationRef: 'test://live-path',
      targets: ['example.com'],
      notAfter: '2030-01-01T00:00:00+08:00',
    })
    assert.ok(!out.text.includes('闸门拒绝'), 'eng_open 仍被闸门挡住：' + out.text)
    assert.ok(out.text.includes('交战已开启'), '未返回开启文案：' + out.text)
    const id = /交战已开启：(\S+)/.exec(out.text)[1]
    assert.ok(existsSync(join(root, id, 'engagement.json')), '交战文件未落盘')
    const eng = JSON.parse(readFileSync(join(root, id, 'engagement.json'), 'utf8'))
    assert.equal(eng.status, 'active')
    assert.deepEqual(eng.scope.targets, ['example.com'])
    assert.equal(eng.authorization.source, 'lab-charter')
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('正路径：eng_status 无 id 时列出全部交战；带 id 时读出全貌', async () => {
  const root = mkdtempSync(join(tmpdir(), 'eng-status-'))
  try {
    const find = registry(root)
    const opened = await find('eng_open').execute({
      title: 't', authorizationSource: 'owner-directive', authorizationRef: 'msg://1',
      targets: ['10.0.0.0/28'], notAfter: '2030-01-01T00:00:00+08:00',
    })
    const id = /交战已开启：(\S+)/.exec(opened.text)[1]

    const list = await find('eng_status').execute({})
    assert.ok(list.text.includes(id), '清单里没有刚开的交战：' + list.text)

    const one = await find('eng_status').execute({ engagementId: id })
    assert.ok(one.text.includes('10.0.0.0/28'), '全貌缺范围：' + one.text)
    assert.ok(one.text.includes('闸门拒绝 0'), '计数行缺失：' + one.text)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('正路径：非法授权来源被拒（闭集），不落盘', async () => {
  const root = mkdtempSync(join(tmpdir(), 'eng-open-bad-'))
  try {
    const find = registry(root)
    const out = await find('eng_open').execute({
      title: 't', authorizationSource: 'self-declared', authorizationRef: 'x',
      targets: ['example.com'], notAfter: '2030-01-01T00:00:00+08:00',
    })
    assert.ok(out.text.includes('闭集'), '非法来源未被拒：' + out.text)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('正路径：开完交战后的 active 工具在范围内放行、越界被拦（同一次会话里对照）', async () => {
  const root = mkdtempSync(join(tmpdir(), 'eng-scope-'))
  try {
    const find = registry(root)
    const opened = await find('eng_open').execute({
      title: 't', authorizationSource: 'lab-charter', authorizationRef: 'test://scope',
      targets: ['example.com'], notAfter: '2030-01-01T00:00:00+08:00',
    })
    const id = /交战已开启：(\S+)/.exec(opened.text)[1]
    // 越界：闸门在触碰通道前就拒绝（不实际发起扫描）
    const denied = await find('eng_recon_host').execute({ engagementId: id, host: 'evil.org', ports: '80' })
    assert.ok(denied.text.includes('gate/out-of-scope'), '越界未被拦：' + denied.text)
    // 范围内：允许过闸门（用 node 后端 + 一个必然无响应的端口，快速返回，不产生对外流量到真实主机）
    const allowed = await find('eng_recon_host').execute({ engagementId: id, host: 'example.com', ports: '1', backend: 'node', timeoutMs: 300 })
    assert.ok(!allowed.text.includes('闸门拒绝'), '范围内被误拦：' + allowed.text)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})
