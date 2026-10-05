/**
 * load.test.mjs — **加载冒烟**：用 stub ctx 真跑 `apply`，把 12 个工具全送进 `defineTool`。
 *
 * 为什么必须有（2026-09-23 identity-loop 事故的机器判据）：schema DSL 的错误只在 `defineTool`
 * 运行时暴露（`tsc` 查不出、`plugin_boot_status` 也报 live），若不在此拦，代价是**一次重启 + 整件未加载**。
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { apply, Config, inject, name } from '../lib/index.js'

const DESIGNED = [
  'eng_open', 'eng_status', 'eng_close',
  'eng_recon_dns', 'eng_recon_host', 'eng_recon_web',
  'eng_intel', 'eng_finding', 'eng_payload', 'eng_verify', 'eng_detect', 'eng_report',
]

function stubCtx() {
  const registered = []
  return {
    registered,
    ctx: {
      tools: { register: (spec) => { registered.push(spec); return () => {} } },
      on: () => () => {},
      effect: () => () => {},
      logger: () => ({ info: () => {}, warn: () => {}, debug: () => {}, error: () => {} }),
    },
  }
}

test('加载冒烟：apply 真跑一遍，12 个工具全部注册成功（schema DSL 校验在此暴露）', () => {
  const root = mkdtempSync(join(tmpdir(), 'eng-load-'))
  try {
    const { ctx, registered } = stubCtx()
    apply(ctx, { enabled: true, root, timeoutMs: 1000, limit: 5, reportDir: '' })
    assert.equal(registered.length, 12, '注册的工具数不是 12')
    assert.deepEqual(registered.map((t) => t.name).sort(), [...DESIGNED].sort())
    for (const t of registered) {
      assert.equal(typeof t.execute, 'function', `${t.name} 缺 execute`)
      assert.ok(t.output !== undefined, `${t.name} 缺 output`)
      assert.ok(t.parameters !== undefined, `${t.name} 缺 parameters`)
      assert.ok(t.description.length > 20, `${t.name} 描述过短`)
    }
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('工具参数里的 object 型 schema 都显式声明了 additionalProperties（本类事故的源码判据）', async () => {
  const { readFileSync } = await import('node:fs')
  const src = readFileSync(join(import.meta.dirname, '..', 'src', 'index.ts'), 'utf8')

  /** 从 `{` 起做括号配平，取出该对象字面量的文本（含花括号）。 */
  const blockAt = (text, open) => {
    let depth = 0
    for (let i = open; i < text.length; i += 1) {
      if (text[i] === '{') depth += 1
      else if (text[i] === '}') {
        depth -= 1
        if (depth === 0) return text.slice(open, i + 1)
      }
    }
    return text.slice(open)
  }
  /** 收集「未声明 additionalProperties 的 object 型 schema 块」。 */
  const offendersOf = (text) => {
    const out = []
    for (const m of text.matchAll(/type: 'object'/g)) {
      const open = text.lastIndexOf('{', m.index)
      if (open < 0) continue
      const block = blockAt(text, open)
      if (!block.includes('additionalProperties')) out.push(block.slice(0, 160))
    }
    return out
  }

  // ⚠ 尸体样本先行（判据必须先证明自己有区分力）：**两种**形态都要能拦下——
  //   数组项（`items:`，旧判据覆盖）与**普通参数**（旧判据的盲区）。2026-10-06 实测：
  //   `eng_payload` 新增的 `params` 正是从盲区逃过，直到加载冒烟才以 UNSUPPORTED_SCHEMA 暴露。
  assert.equal(offendersOf("items: { type: 'object', properties: {} }").length, 1, '尸体样本①（items 形态）未被拦下')
  assert.equal(offendersOf("params: { type: 'object', description: 'x' }").length, 1, '尸体样本②（普通参数形态）未被拦下')
  // 对照组：声明了 additionalProperties 的不得被误报
  assert.equal(offendersOf("params: { type: 'object', additionalProperties: true }").length, 0, '对照组被误报')

  const offenders = offendersOf(src)
  assert.equal(offenders.length, 0, 'object 型 schema 未显式声明 additionalProperties：\n' + offenders.join('\n---\n'))
})

test('导出形状：name / inject / Config', () => {
  assert.equal(name, 'engagement')
  assert.deepEqual([...inject], ['tools'])
  assert.equal(typeof Config, 'function')
})
