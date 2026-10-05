/**
 * normalize.ts —— 从 `index.ts:apply()` 闭包抽出的参数规范化 / 守卫 / 输出裁剪（纯函数）。
 *
 * 抽取原则（技能 `dsh-plugin-testability`）：只搬家不改语义。本套件是「搬家无行为漂移」的证据：
 * 每条正常路径都对应旧实现的逐字语义，每条退化路径都记录**真实**语义（而不是我本来以为的语义）。
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  normalizeSerializedProps, parseEcbArgs, formatJwtReport, SECRET_PREVIEW_LIMIT,
} from '../lib/xp-normalize.js'

/* ── normalizeSerializedProps ── */

test('normalizeSerializedProps: bool/number 原样保留，其余 String()', () => {
  assert.deepEqual(normalizeSerializedProps({ a: 'x', b: true, c: false, d: 3, e: 1.5 }), {
    a: 'x', b: true, c: false, d: 3, e: 1.5,
  })
})

test('normalizeSerializedProps: 退化——null/undefined 值被字符串化（PHP 侧无法还原）', () => {
  assert.deepEqual(normalizeSerializedProps({ a: null }), { a: 'null' })
  assert.deepEqual(normalizeSerializedProps({ a: undefined }), { a: 'undefined' })
  assert.deepEqual(normalizeSerializedProps({ a: { x: 1 } }), { a: '[object Object]' })
  assert.deepEqual(normalizeSerializedProps({ a: ['x'] }), { a: 'x' }, '单元素数组同样走 String()')
})

test('normalizeSerializedProps: 退化——空值输入得到空表（接线层再判「至少一个属性」）', () => {
  assert.deepEqual(normalizeSerializedProps(undefined), {})
  assert.deepEqual(normalizeSerializedProps(null), {})
  assert.deepEqual(normalizeSerializedProps({}), {})
})

test('normalizeSerializedProps: 退化——非对象标量按 Object.entries 语义展开（字符串 → 索引键）', () => {
  assert.deepEqual(normalizeSerializedProps('ab'), { 0: 'a', 1: 'b' })
  assert.deepEqual(normalizeSerializedProps(5), {})
  assert.deepEqual(normalizeSerializedProps(true), {})
})

test('normalizeSerializedProps: 退化——NaN/Infinity 保留为 number（不字符串化，PHP 侧成 d:NaN）', () => {
  const out = normalizeSerializedProps({ a: NaN, b: Infinity })
  assert.equal(typeof out.a, 'number')
  assert.ok(Number.isNaN(out.a))
  assert.equal(out.b, Infinity)
})

test('normalizeSerializedProps: 无副作用——不改动入参对象，且同输入恒同输出（幂等）', () => {
  const input = { a: 'x', b: 1 }
  const snapshot = JSON.stringify(input)
  assert.deepEqual(normalizeSerializedProps(input), normalizeSerializedProps(input))
  assert.equal(JSON.stringify(input), snapshot)
})

/* ── parseEcbArgs ── */

test('parseEcbArgs: 正常路径——数字直通，缺省项回落（16 / 反斜杠）', () => {
  const r = parseEcbArgs({ prefixLen: 38, injectOffset: 36, payload: 'X' })
  assert.equal(r.ok, true)
  assert.deepEqual(r.options, { prefixLen: 38, injectOffset: 36, payload: 'X', blockSize: 16, escapeChar: '\\' })
})

test('parseEcbArgs: 正常路径——字符串数字被 Number() 转换；blockSize/escapeChar 是**透传**', () => {
  const r = parseEcbArgs({ prefixLen: '38', injectOffset: '36', payload: 'X', blockSize: '8' })
  assert.equal(r.ok, true)
  assert.equal(r.options.prefixLen, 38)
  assert.equal(typeof r.options.prefixLen, 'number')
  // 真实语义：只有 prefixLen/injectOffset 走 Number()，blockSize/escapeChar 原样透传
  // （工具 schema 声明 blockSize 为 number，故经工具调用必为数字；直接调函数才是这般形态）
  assert.equal(r.options.blockSize, '8')
  assert.equal(typeof r.options.blockSize, 'string')
})

test('parseEcbArgs: 退化——字符串 blockSize 靠 JS 算术隐式转换仍可算出正确填充', async () => {
  const { planEcbSplice } = await import('../lib/xp-ecb.js')
  const r = parseEcbArgs({ prefixLen: 38, injectOffset: 36, payload: 'X', blockSize: '16' })
  const p = planEcbSplice(r.options)
  assert.equal(p.oracleCalls[0].input, 'A'.repeat(12)) // 36 % '16' → 4，与数字 16 同解
})

test('parseEcbArgs: 边界（2026-10-06 语义修正）——0 是合法值：prefixLen=0（无前缀）/ injectOffset=0（从开头注入）', () => {
  // ⚠ 旧语义用 `!0` 判「必填缺失」⇒ 这两个合法值被拒。修正为只拒非有限数。
  // 该缺陷由 tests/wire-contract.test.mjs 的「接线④」缺省路径对照抓出（缺省 injectOffset=0 ⇒ 必红）。
  assert.deepEqual(parseEcbArgs({ prefixLen: 0, injectOffset: 36, payload: 'X' }).options,
    { prefixLen: 0, injectOffset: 36, payload: 'X', blockSize: 16, escapeChar: '\\' })
  assert.deepEqual(parseEcbArgs({ prefixLen: 38, injectOffset: 0, payload: 'X' }).options,
    { prefixLen: 38, injectOffset: 0, payload: 'X', blockSize: 16, escapeChar: '\\' })
})

test('parseEcbArgs: 失败路径——缺失 / 非数字 / 非有限数一律拒绝，不落进块计算', () => {
  const msg = 'prefixLen/injectOffset 必填（且须为有限数字）'
  for (const bad of [
    {}, { prefixLen: 38 }, { injectOffset: 36 },
    { prefixLen: 'abc', injectOffset: 36 },
    { prefixLen: 38, injectOffset: Infinity },
  ]) {
    const r = parseEcbArgs({ ...bad, payload: 'X' })
    assert.equal(r.ok, false, `${JSON.stringify(bad)} 必须被拒`)
    assert.equal(r.error, msg)
  }
})

test('parseEcbArgs: 失败路径——payload 空串/缺失走第二道守卫（顺序在 prefixLen 之后）', () => {
  assert.deepEqual(parseEcbArgs({ prefixLen: 38, injectOffset: 36, payload: '' }),
    { ok: false, error: 'payload 必填' })
  assert.deepEqual(parseEcbArgs({ prefixLen: 38, injectOffset: 36 }),
    { ok: false, error: 'payload 必填' })
  // 两道守卫都该命中时，先报 prefixLen（顺序是契约的一部分）
  assert.deepEqual(parseEcbArgs({}), { ok: false, error: 'prefixLen/injectOffset 必填（且须为有限数字）' })
})

test('parseEcbArgs: 退化（现状锁）——负值通过校验，blockSize 不校验', () => {
  const r = parseEcbArgs({ prefixLen: -5, injectOffset: -1, payload: 'X', blockSize: 0 })
  assert.equal(r.ok, true)
  assert.equal(r.options.prefixLen, -5)
  assert.equal(r.options.blockSize, 0, '0 块大小会 NaN 化后续计算——见 tests/primitives 的锁现状用例')
})

test('parseEcbArgs: escapeChar 显式覆盖', () => {
  assert.equal(parseEcbArgs({ prefixLen: 1, injectOffset: 1, payload: 'X', escapeChar: '#' }).options.escapeChar, '#')
})

/* ── formatJwtReport ── */

test('formatJwtReport: 手动自签——密钥行 + JWT 行 + note，且不列字典', () => {
  const text = formatJwtReport({
    foundSecret: 'washington', secretSource: 'manual', token: 'h.p.s', candidates: ['washington'], note: 'N',
  })
  assert.equal(text, '密钥: washington（manual）\nJWT: h.p.s\nN')
})

test('formatJwtReport: 未指定密钥——列出候选并裁到 10 条 + 省略号', () => {
  const text = formatJwtReport({
    foundSecret: undefined, secretSource: 'none', token: 'h.p.s',
    candidates: Array.from({ length: 16 }, (_, i) => `s${i}`), note: 'N',
  })
  const last = text.split('\n').at(-1)
  assert.equal(last, `候选密钥(16): ${Array.from({ length: 10 }, (_, i) => `s${i}`).join(', ')}…`)
  assert.equal(SECRET_PREVIEW_LIMIT, 10)
})

test('formatJwtReport: 边界——恰好 10 条不加省略号；0 条不出候选行；11 条加省略号', () => {
  const mk = (n) => formatJwtReport({
    secretSource: 'none', candidates: Array.from({ length: n }, (_, i) => `s${i}`), note: 'N',
  })
  const ten = mk(10)
  assert.ok(ten.includes('候选密钥(10):'))
  assert.equal(ten.includes('…'), false)
  assert.equal(mk(0), 'N', '空候选（退化）只留 note，不出现空列表行')
  assert.ok(mk(11).endsWith('…'))
})

test('formatJwtReport: 三条件齐备才列候选——有 foundSecret 时不列（即使 secretSource=none）', () => {
  const text = formatJwtReport({
    foundSecret: 'x', secretSource: 'none', candidates: ['a', 'b'], note: 'N',
  })
  assert.equal(text, '密钥: x（none）\nN')
})

test('formatJwtReport: 退化——无 token 无候选时只剩 note（不产生空行）', () => {
  assert.equal(formatJwtReport({ secretSource: 'none', candidates: [], note: 'N' }), 'N')
})
