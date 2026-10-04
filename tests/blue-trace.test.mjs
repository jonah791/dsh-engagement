/**
 * 蓝队调用轨迹单测（跑 lib 产物）。
 *
 * 覆盖：脱敏 / 摘要 / 命中条数投影（`count` 三来源）/ 断点分类 / 路径 / 序列化 / 解析
 * + 正常与失败落盘 + **尸体测试**（不可写路径 → `false` 且不抛，且不改变返回值/异常传播）
 * + **隐私尸体测试**（敏感键参数 + **结果里的哈希原文** → 断言绝不出现在落盘行里）。
 *
 * 说明：轨迹**没有 `exitCode` 字段**——`host.ts:runPs()` 把 `execFile` 的错误折叠成字符串，
 * 数字退出码在到达工具返回值前已丢失（改它=业务行为改动，本轮不做）。断点分类 `ps-exit`
 * 表达「子进程失败」；「如何拿到真退出码」登记为语义文档 §10 U3。
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  appendTraceEntry,
  buildStamp,
  classifyBreak,
  collectSecrets,
  defaultTargetOf,
  errorOf,
  isSensitiveKey,
  mtimeOf,
  parseTraceEntries,
  readPackageVersion,
  readTraceEntries,
  resolveHome,
  safeTrace,
  scrub,
  serializeTraceEntry,
  summarizeArgs,
  summarizeResult,
  summarizeValue,
  tracePath,
  tracedExecute,
  truncate,
} from '../lib/blue-trace.js'

const tmp = mkdtempSync(join(tmpdir(), 'blue-team-trace-'))
const base = (entry) => ({
  atMs: 1_700_000_000_000,
  phase: 'end',
  action: 'blue_event_log_query',
  build: '0.1.1@42',
  pid: 777,
  durationMs: 3210,
  ok: true,
  ...entry,
})

test('resolveHome / tracePath：DSH_HOME 优先，路径锚定单一文件名', () => {
  assert.equal(resolveHome({ DSH_HOME: 'E:/alice/.dsh' }, '/home/x'), 'E:/alice/.dsh')
  assert.equal(resolveHome({ DSH_HOME: ' ' }, '/home/x'), join('/home/x', '.dsh'))
  assert.equal(tracePath('/h/.dsh'), join('/h/.dsh', 'blue-team-trace.jsonl'))
})

test('isSensitiveKey：口令/用户名/哈希等凭据键命中；调查对象键不误伤', () => {
  for (const key of ['pass', 'password', 'user', 'username', 'hash', 'hashes', 'cookie',
    'token', 'authorization', 'secret', 'credential']) {
    assert.equal(isSensitiveKey(key), true, key + ' 应判敏感')
  }
  for (const key of ['host', 'path', 'value', 'log', 'logName', 'ids', 'days', 'limit',
    'ports', 'type', 'query', 'format', 'eventId']) {
    assert.equal(isSensitiveKey(key), false, key + ' 不应判敏感')
  }
})

test('collectSecrets / scrub：数组秘密也收集；长秘密优先替换', () => {
  const secrets = collectSecrets({ hash: 'deadbeef', hashes: ['aa11', 'bb22'], host: 'h' })
  assert.ok(secrets.includes('deadbeef') && secrets.includes('aa11') && secrets.includes('bb22'))
  assert.equal(secrets.includes('h'), false)
  assert.deepEqual(collectSecrets({ pass: 'abc', hash: 'abcdef' }), ['abcdef', 'abc'])
  assert.deepEqual(collectSecrets(null), [])
  assert.deepEqual(collectSecrets('str'), [])
  assert.equal(scrub('hash=deadbeef host=h', ['deadbeef']), 'hash=[redacted] host=h')
  assert.equal(scrub('abc', ['']), 'abc')
})

test('summarizeValue / summarizeArgs：敏感键只记长度，调查对象保留（查询摘要）', () => {
  assert.equal(summarizeValue('hash', 'deadbeef'), '<8 chars>')
  assert.equal(summarizeValue('path', 'C:/x/y.txt'), 'C:/x/y.txt')
  assert.equal(summarizeValue('host', 'h.example'), 'h.example')
  assert.equal(summarizeValue('ids', [4625, 4624]), '<array 2>')
  assert.equal(summarizeValue('days', 7), '7')
  assert.equal(summarizeValue('limit', undefined), '')
  assert.equal(summarizeValue('host', 'z'.repeat(200)).length, 81)
  assert.equal(summarizeArgs({ log: 'Security', ids: [4625], days: 7, hash: 'abc' }),
    'log=Security; ids=<array 1>; days=7; hash=<3 chars>')
  assert.equal(summarizeArgs(null), '')
  assert.ok(summarizeArgs({ log: 'z'.repeat(2000) }, 100).length <= 101)
  assert.equal(truncate('abcdef', 3), 'abc…')
})

test('defaultTargetOf：按调查对象键序取首个非空；无则 undefined', () => {
  assert.equal(defaultTargetOf({ host: 'h.example', path: 'C:/x' }), 'h.example')
  assert.equal(defaultTargetOf({ path: 'C:/x/y.txt' }), 'C:/x/y.txt')
  assert.equal(defaultTargetOf({ value: '1.2.3.4' }), '1.2.3.4')
  assert.equal(defaultTargetOf({ limit: 200 }), undefined)
  assert.equal(defaultTargetOf({}), undefined)
})

test('summarizeResult：命中条数三来源（count / results / open）+ 只投影量级', () => {
  assert.equal(summarizeResult({ ok: true, results: [1, 2, 3] }).count, 3)
  assert.equal(summarizeResult({ ok: true, count: 9, results: [1] }).count, 9) // 显式 count 优先
  assert.equal(summarizeResult({ ok: true, host: 'h', scanned: 3, open: 2, results: [1, 2] }).count, 2)
  assert.equal(summarizeResult({ ok: true, scanned: 3 }).count, 3)
  assert.equal(summarizeResult({ ok: false, error: '路径必填' }).ok, false)
  assert.equal(summarizeResult({ ok: true, results: [] }).count, 0)
  assert.deepEqual(summarizeResult(null), { ok: true })
  assert.equal(errorOf({ error: 'boom' }), 'boom')
  assert.equal(errorOf(null), '')
})

test('classifyBreak：断点分类可 grep（超时/起不来/子进程失败/JSON/NOT_FOUND/参数）', () => {
  assert.equal(classifyBreak(''), 'empty')
  assert.equal(classifyBreak('Command failed: powershell.exe ...'), 'ps-exit')
  assert.equal(classifyBreak('PowerShell 执行失败: timeout'), 'ps-timeout')
  assert.equal(classifyBreak('spawn powershell.exe ENOENT'), 'ps-spawn')
  assert.equal(classifyBreak("Unexpected token '<' in JSON at position 0"), 'json')
  assert.equal(classifyBreak('NOT_FOUND'), 'not-found')
  assert.equal(classifyBreak('path 必填'), 'bad-args')
  assert.equal(classifyBreak('莫名其妙'), 'other')
})

test('serializeTraceEntry：单行 + 键序固定 + 缺省字段不污染（无 exitCode 字段）', () => {
  const line = serializeTraceEntry(base({}))
  assert.equal(line.includes('\n'), false)
  assert.deepEqual(Object.keys(JSON.parse(line)), ['atMs', 'phase', 'action', 'build', 'pid', 'durationMs', 'ok'])
  assert.equal(line.includes('exitCode'), false) // runPs 未暴露数字退出码（见文件头说明）
  const full = JSON.parse(serializeTraceEntry(base({ target: 'h', query: 'q', count: 2, resultBytes: 8, break: 'ps-exit', error: 'e' })))
  assert.deepEqual(Object.keys(full).slice(6), ['query', 'durationMs', 'ok', 'count', 'resultBytes', 'break', 'error'])
})

test('parseTraceEntries：坏行/半行/空行/null/标量跳过；readTraceEntries 缺失/目录返回空', () => {
  const good = serializeTraceEntry(base({}))
  const text = ['', good, '  ', '{"atMs":1,"phase":"end"', '{"action":"blue"}', 'null', '0', 'nope', '[]'].join('\n')
  const parsed = parseTraceEntries(text)
  assert.equal(parsed.length, 1)
  assert.equal(parsed[0].action, 'blue_event_log_query')
  assert.deepEqual(readTraceEntries(join(tmp, 'nope', 'blue-team-trace.jsonl')), [])
  assert.deepEqual(readTraceEntries(tmp), [])
})

test('appendTraceEntry：追加可回读（begin/end 两行 = 一次调用）', () => {
  const path = join(tmp, 'ok', 'blue-team-trace.jsonl')
  assert.equal(appendTraceEntry(path, base({ phase: 'begin', durationMs: 0 })), true)
  assert.equal(appendTraceEntry(path, base({})), true)
  assert.deepEqual(readTraceEntries(path).map((e) => e.phase), ['begin', 'end'])
})

test('尸体测试：父路径是普通文件 → 返回 false 且不抛（观测不反噬调用）', () => {
  const blocker = join(tmp, 'blocker')
  writeFileSync(blocker, 'not a dir', 'utf8')
  assert.doesNotThrow(() => {
    assert.equal(appendTraceEntry(join(blocker, 'blue-team-trace.jsonl'), base({})), false)
    assert.equal(safeTrace(base({}), { path: join(blocker, 'blue-team-trace.jsonl'), now: 1, pid: 1 }), false)
  })
})

test('tracedExecute 正常路径：begin/end + 注入时钟耗时 + 命中条数 + 返回值逐字不变', async () => {
  const path = join(tmp, 'wrap', 'blue-team-trace.jsonl')
  const times = [100, 100, 350, 350]
  const wrapped = tracedExecute({ action: 'blue_event_log_query', build: 'b@1', path, pid: 9, now: () => times.shift() ?? 350 },
    async (a) => ({ ok: true, eventIds: '4625', days: a.days, results: [{}, {}] }))
  const result = await wrapped({ log: 'Security', ids: [4625], days: 7 })
  assert.deepEqual(result, { ok: true, eventIds: '4625', days: 7, results: [{}, {}] })
  const lines = readTraceEntries(path)
  assert.deepEqual(lines.map((e) => e.phase), ['begin', 'end'])
  assert.equal(lines[0].durationMs, 0)
  assert.equal(lines[0].target, 'Security')
  assert.equal(lines[0].query, 'log=Security; ids=<array 1>; days=7')
  assert.equal(lines[1].durationMs, 250)
  assert.equal(lines[1].count, 2)
  assert.equal(lines[1].ok, true)
  assert.equal(lines[1].pid, 9)
})

test('失败返回值：ok=false → end 记 break=ps-exit + 分类错误文本', async () => {
  const path = join(tmp, 'wrap-err', 'blue-team-trace.jsonl')
  const wrapped = tracedExecute({ action: 'blue_process_audit', build: 'b@1', path, now: () => 1 },
    async () => ({ ok: false, error: 'PowerShell 执行失败: Command failed: powershell.exe ...' }))
  const r = await wrapped({ limit: 200 })
  assert.equal(r.ok, false)
  const lines = readTraceEntries(path)
  assert.equal(lines[0].phase, 'begin')
  assert.equal(lines[1].phase, 'end')
  assert.equal(lines[1].ok, false)
  assert.equal(lines[1].break, 'ps-exit')
})

test('异常路径：超时错误原样重抛（同一对象） + break=ps-timeout', async () => {
  const path = join(tmp, 'wrap-throw', 'blue-team-trace.jsonl')
  const boom = new Error('Command failed: powershell.exe ... ETIMEDOUT timeout 30000ms')
  const wrapped = tracedExecute({ action: 'blue_autoruns_check', build: 'b@1', path, now: () => 1 },
    async () => { throw boom })
  await assert.rejects(() => wrapped({ limit: 100 }), (e) => e === boom)
  const lines = readTraceEntries(path)
  assert.equal(lines[1].ok, false)
  assert.equal(lines[1].break, 'ps-timeout')
})

test('隐私尸体测试（一）：结果里的哈希原文/管理员名绝不出现在落盘行里', async () => {
  const path = join(tmp, 'privacy-hash', 'blue-team-trace.jsonl')
  const md5 = 'd41d8cd98f00b204e9800998ecf8427e'
  const sha256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
  const wrapped = tracedExecute({ action: 'blue_hash_lookup', build: 'b@1', path, now: () => 1 },
    async () => ({ ok: true, hash: { Path: 'C:/x/y.txt', Size: 1234, MD5: md5, SHA1: 'da39a3ee5e6b4b0d3255bfef95601890afd80709', SHA256: sha256 } }))
  await wrapped({ path: 'C:/x/y.txt' })
  const raw = readFileSync(path, 'utf8')
  for (const secret of [md5, sha256, 'da39a3ee5e6b4b0d3255bfef95601890afd80709']) {
    assert.equal(raw.includes(secret), false, '哈希原文泄漏进了轨迹！' + secret)
  }
  assert.ok(raw.includes('"resultBytes":')) // 只记量级（JSON 字段形态，不是 k=v 摘要形态）
  assert.ok(raw.includes('"target":"C:/x/y.txt"')) // 目标保留（排障要看；JSON 字段形态）
  assert.ok(raw.includes('path=C:/x/y.txt'))       // 查询摘要里的调查对象也保留
})

test('隐私尸体测试（二）：敏感键参数与错误文本里的凭据绝不出现在落盘行里', async () => {
  const path = join(tmp, 'privacy', 'blue-team-trace.jsonl')
  const args = { path: 'C:/x', hash: 'deadbeef-must-not-land', password: 'pw-must-not-land', username: 'alice-secret-user' }
  const wrapped = tracedExecute({ action: 'blue_ioc_query', build: 'b@1', path, pid: 2, now: () => 1 },
    async () => ({ ok: false, error: 'PowerShell 执行失败: hash=deadbeef-must-not-land user=alice-secret-user pass=pw-must-not-land' }))
  await wrapped(args)
  const raw = readFileSync(path, 'utf8')
  for (const secret of ['deadbeef-must-not-land', 'pw-must-not-land', 'alice-secret-user']) {
    assert.equal(raw.includes(secret), false, secret + ' 泄漏进了轨迹！')
  }
  assert.ok(raw.includes('hash=<22 chars>'))
  assert.ok(raw.includes('password=<16 chars>')) // 'pw-must-not-land' = 16 字符
  assert.ok(raw.includes('username=<17 chars>'))
  assert.ok(raw.includes('[redacted]'))
})

test('观测失败不反噬：不可写路径下返回值照常、不抛；targetOf 抛错也被吞', async () => {
  const blocker = join(tmp, 'blocker')
  const wrapped = tracedExecute({
    action: 'blue_baseline_check', build: 'b@1', path: join(blocker, 'blue-team-trace.jsonl'), now: () => 1,
    targetOf: () => { throw new Error('targetOf 崩了') },
  }, async () => ({ ok: true, results: [1] }))
  assert.deepEqual(await wrapped({}), { ok: true, results: [1] })
})

test('构建自证：buildStamp/readPackageVersion/mtimeOf', () => {
  const root = join(tmp, 'pkg')
  mkdirSync(join(root, 'lib'), { recursive: true })
  writeFileSync(join(root, 'package.json'), JSON.stringify({ version: '0.1.1' }), 'utf8')
  const self = join(root, 'lib', 'index.js')
  writeFileSync(self, '// x', 'utf8')
  assert.equal(readPackageVersion(self), '0.1.1')
  assert.ok(mtimeOf(self) > 0)
  assert.equal(buildStamp(self, '0.1.1'), '0.1.1@' + String(mtimeOf(self)))
  assert.equal(buildStamp(join(root, 'missing.js'), ''), 'unknown@0')
})

test('cleanup', () => {
  rmSync(tmp, { recursive: true, force: true })
})
