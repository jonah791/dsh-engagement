/**
 * PowerShell 脚本构建契约守卫（回归测试 · 尸体测试）。
 *
 * 已证实的缺陷（2026-09-14）：`src/host.ts:queryEventLog` 把调用方传入的 `logName`
 * **原样**插进 PS 单引号字面量（`LogName='${logName}'`），而同文件的 `hashFile` 做了
 * `'` → `''` 转义。`blue_event_log_query` 的 `logName` 是自由字符串参数，因此
 * `logName = "x'; <任意命令>; '"` 可逃逸出字面量执行任意 PowerShell。
 *
 * 本文件让这条缺陷不可能复发：**任何外来字符串进入 PS 单引号字面量前必须先转义**。
 * 守卫自带尸体样本（见「尸体测试」一节）——证明断言在坏产物上确实会失败。
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { queryEventLog, hashFile, auditConnections, auditAutoruns, baselineCheck } from '../lib/blue-host.js'

/** 时间注入定值：使脚本可确定性断言（2026-01-15T12:00:00.000Z） */
const FIXED_NOW = Date.UTC(2026, 0, 15, 12, 0, 0)

/** 攻击样本：单引号闭合 → 注入命令 → 再开一个引号让剩余脚本语法保持合法 */
const HOSTILE = "x'; Remove-Item -Recurse -Force C:\\Windows; '"

/**
 * 不变量断言：`build(恶意串)` 的产物里，恶意串必须以**转义形态**出现，
 * 且**不得**以原始未转义形态出现（原始形态 = 可逃逸）。
 */
function assertEscaped(build, label) {
  const script = build(HOSTILE)
  const escaped = HOSTILE.replace(/'/g, "''")
  assert.ok(
    !script.includes(`'${HOSTILE}'`),
    `${label}: 未转义宿主串原样进入 PS 字面量 → 可逃逸执行任意命令`,
  )
  assert.ok(
    script.includes(`'${escaped}'`),
    `${label}: 转义形态缺失（' 未翻倍）`,
  )
}

/* ── 尸体测试：证明守卫本身有牙齿 ── */

test('尸体测试：守卫在「未转义」坏产物上确实失败（否则本守卫是摆设）', () => {
  const badArtifact = () => `$x = '${HOSTILE}'` // 复刻修复前的 queryEventLog 形态
  assert.throws(() => assertEscaped(badArtifact, 'corpse'), /未转义/, '守卫必须拦下未转义样本')
})

test('尸体测试：守卫在「转义后」好产物上通过（排除守卫永远抛错的假阳性）', () => {
  const goodArtifact = () => `$x = '${HOSTILE.replace(/'/g, "''")}'`
  assert.doesNotThrow(() => assertEscaped(goodArtifact, 'good'))
})

/* ── 真实构建器的注入防护（S6：失败路径 = 恶意输入不得逃逸） ── */

test('queryEventLog: logName 必须转义（回归守卫 · 防御 PowerShell 注入）', () => {
  assertEscaped((h) => queryEventLog([4625], 7, h, 10, FIXED_NOW), 'queryEventLog')
})

test('hashFile: filePath 必须转义（回归守卫 · 防御 PowerShell 注入）', () => {
  assertEscaped((h) => hashFile(h), 'hashFile')
})

test('host.ts 全部构建器：正常输入下必须产出非空脚本且关闭错误噪音', () => {
  const scripts = {
    auditConnections: auditConnections(200),
    auditAutoruns: auditAutoruns(100),
    queryEventLog: queryEventLog([4625], 7, 'Security', 100, FIXED_NOW),
    baselineCheck: baselineCheck(),
    hashFile: hashFile('C:\\a.txt'),
  }
  for (const [label, s] of Object.entries(scripts)) {
    assert.ok(typeof s === 'string' && s.trim().length > 0, `${label}: 脚本不得为空`)
    assert.match(s, /\$ErrorActionPreference='SilentlyContinue'/, `${label}: 必须显式设 SilentlyContinue`)
  }
})

/* ── 限额透传：条数上限必须真的进入脚本（防「参数被吞」静默退化） ── */

test('限额透传：auditConnections/auditAutoruns 的 limit 进入 Select-Object -First', () => {
  assert.match(auditConnections(7), /Select-Object -First 7\b/)
  assert.match(auditAutoruns(3), /Select-Object -First 3\b/)
})

test('限额透传：queryEventLog 的 limit 进入 -MaxEvents，天数换算为 since 时间戳', () => {
  const s = queryEventLog([4625, 4624], 7, 'Security', 42, FIXED_NOW)
  assert.match(s, /-MaxEvents 42\b/)
  // 真实语义（预期曾写错）：eventIds 先进 $idArr 变量，过滤表里引用的是 **$idArr**（不是内联的 @(...)）
  assert.match(s, /@\(4625,4624\)/, 'id 列表必须内联进 $idArr')
  assert.match(s, /Id=\$idArr/, '过滤表必须引用 $idArr（不是内联列表）')
  // 7 天前 = FIXED_NOW - 7*86400_000
  assert.ok(s.includes(`[datetime]'${new Date(FIXED_NOW - 7 * 86400_000).toISOString()}'`), 'since 必须等于 now-days')
})

test('退化路径：limit 为 0 / 负数的真实语义（原样透传，不 clamp）', () => {
  assert.match(auditConnections(0), /Select-Object -First 0\b/)
  assert.match(auditConnections(-1), /Select-Object -First -1\b/)
})

test('失败路径：days 为 NaN 时 new Date(NaN).toISOString() 抛 RangeError（fail-loud，由 safe() 收口）', () => {
  assert.throws(() => queryEventLog([4625], Number.NaN, 'Security', 10, FIXED_NOW), RangeError)
})

/* ── 确定性：时间注入让脚本可复现 ── */

test('时间注入：同一 nowMs 产出逐字节相同的脚本（离线可复现）', () => {
  const a = queryEventLog([4625], 7, 'Security', 100, FIXED_NOW)
  const b = queryEventLog([4625], 7, 'Security', 100, FIXED_NOW)
  assert.equal(a, b)
  const c = queryEventLog([4625], 7, 'Security', 100, FIXED_NOW + 86_400_000)
  assert.notEqual(a, c, '不同 nowMs 必须产出不同 since')
})
