/**
 * 利用原语调用轨迹单测（跑 lib 产物）。
 *
 * 覆盖：脱敏 / 摘要 / 结果投影（count 三来源）/ 断点分类 / 路径 / 序列化 / 解析
 * + 正常与失败落盘 + **尸体测试**（不可写路径 → `false` 且不抛，且不改变返回值/异常传播）
 * + **隐私尸体测试**（JWT 密钥/JWT 本体/注册口令/用户名/command → 断言绝不出现在落盘行里）。
 *
 * 说明：本插件的工具是**纯本地生成器**（无子进程），故轨迹**没有 `exitCode` 字段**——
 * 这不是遗漏，而是「不伪造一个恒为 0 的退出码」；结果质量由 `count` / `resultBytes` 表达。
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
} from '../lib/xp-trace.js'

const tmp = mkdtempSync(join(tmpdir(), 'exploit-kit-trace-'))
const base = (entry) => ({
  atMs: 1_700_000_000_000,
  phase: 'end',
  action: 'xp_cmdi_payload',
  build: '0.1.1@42',
  pid: 777,
  durationMs: 12,
  ok: true,
  ...entry,
})

test('resolveHome / tracePath：DSH_HOME 优先，路径锚定单一文件名', () => {
  assert.equal(resolveHome({ DSH_HOME: 'E:/alice/.dsh' }, '/home/x'), 'E:/alice/.dsh')
  assert.equal(resolveHome({ DSH_HOME: ' ' }, '/home/x'), join('/home/x', '.dsh'))
  assert.equal(tracePath('/h/.dsh'), join('/h/.dsh', 'exploit-kit-trace.jsonl'))
})

test('isSensitiveKey：JWT 密钥/本体、口令、用户名、command 命中；类型键不误伤', () => {
  for (const key of ['secret', 'secrets', 'token', 'password', 'pass', 'user', 'username',
    'command', 'cookie', 'authorization', 'credential']) {
    assert.equal(isSensitiveKey(key), true, key + ' 应判敏感')
  }
  for (const key of ['kind', 'mode', 'separators', 'bypasses', 'shell', 'visibility', 'base64',
    'urlEncode', 'alg', 'blockSize', 'prefixLen', 'injectOffset', 'depth', 'gt', 'maxLen',
    'double', 'className', 'properties', 'relPath', 'file', 'word', 'text']) {
    assert.equal(isSensitiveKey(key), false, key + ' 不应判敏感')
  }
})

test('collectSecrets / scrub：数组秘密也收集；长秘密优先替换', () => {
  const secrets = collectSecrets({ secret: 'k1', secrets: ['dict-secret-1', 'dict-secret-2'], kind: 'lfi' })
  assert.ok(secrets.includes('k1') && secrets.includes('dict-secret-1') && secrets.includes('dict-secret-2'))
  assert.equal(secrets.includes('lfi'), false)
  assert.deepEqual(collectSecrets({ pass: 'abc', secret: 'abcdef' }), ['abcdef', 'abc'])
  assert.equal(scrub('sig=k1 body=secret', ['k1', 'secret']), 'sig=[redacted] body=[redacted]')
  assert.deepEqual(collectSecrets(null), [])
})

test('summarizeValue / summarizeArgs：敏感键只记长度，类型键保留（payload 类型摘要）', () => {
  assert.equal(summarizeValue('command', 'id'), '<2 chars>')
  assert.equal(summarizeValue('secret', 'jwt-key'), '<7 chars>')
  assert.equal(summarizeValue('separators', ['pipe', 'and']), '<array 2>')
  assert.equal(summarizeValue('kind', 'lfi_double'), 'lfi_double')
  assert.equal(summarizeValue('base64', true), 'true')
  assert.equal(summarizeValue('properties', { a: 1 }), '{"a":1}')
  assert.equal(summarizeValue('gt', undefined), '')
  assert.equal(summarizeArgs({ kind: 'lfi', depth: 4, secret: 'k1' }), 'kind=lfi; depth=4; secret=<2 chars>')
  assert.equal(summarizeArgs(null), '')
  assert.ok(summarizeArgs({ kind: 'z'.repeat(2000) }, 100).length <= 101)
  assert.equal(truncate('abcdef', 3), 'abc…')
})

test('summarizeResult：count 三来源（count 字段 / payloads / candidates / plan）+ resultBytes 量级', () => {
  assert.deepEqual(summarizeResult({ ok: true, payloads: [1, 2, 3], count: 3 }).count, 3)
  assert.equal(summarizeResult({ ok: true, candidates: [1, 2] }).count, 2)
  assert.equal(summarizeResult({ ok: true, plan: [1, 2, 3, 4] }).count, 4)
  assert.equal(summarizeResult({ ok: true, count: 7, payloads: [1] }).count, 7) // 显式 count 优先
  assert.equal(summarizeResult({ ok: false, error: 'command 为空' }).count, undefined)
  assert.equal(summarizeResult({ ok: false, error: 'x' }).ok, false)
  assert.equal(summarizeResult({ ok: true, kind: 'a' }).resultBytes, Buffer.byteLength('{"ok":true,"kind":"a"}', 'utf8'))
  assert.deepEqual(summarizeResult(null), { ok: true })
  assert.equal(errorOf({ error: 'boom' }), 'boom')
  assert.equal(errorOf(null), '')
})

test('classifyBreak：断点分类可 grep（range/type/uri/missing-args/empty-output/other）', () => {
  assert.equal(classifyBreak(''), 'empty')
  assert.equal(classifyBreak('Invalid count value: -1'), 'range')
  assert.equal(classifyBreak('RangeError: Invalid string length'), 'range')
  assert.equal(classifyBreak('TypeError: x is not a function'), 'type')
  assert.equal(classifyBreak('URIError: URI malformed'), 'uri')
  assert.equal(classifyBreak('className 必填'), 'missing-args')
  assert.equal(classifyBreak('参数不足：strstr_numeric 需要 needle'), 'missing-args')
  assert.equal(classifyBreak('command 为空'), 'empty-output')
  assert.equal(classifyBreak('莫名其妙'), 'other')
})

test('serializeTraceEntry：单行 + 键序固定 + 缺省字段不污染（无 exitCode 字段）', () => {
  const line = serializeTraceEntry(base({}))
  assert.equal(line.includes('\n'), false)
  assert.deepEqual(Object.keys(JSON.parse(line)), ['atMs', 'phase', 'action', 'build', 'pid', 'durationMs', 'ok'])
  assert.equal(line.includes('exitCode'), false) // 纯生成器：无子进程 ⇒ 无退出码
  const full = JSON.parse(serializeTraceEntry(base({ payload: 'p', count: 3, resultBytes: 9, error: 'e' })))
  // 真实键序：atMs phase action build pid | payload durationMs ok count resultBytes error
  assert.deepEqual(Object.keys(full).slice(6), ['durationMs', 'ok', 'count', 'resultBytes', 'error'])
})

test('parseTraceEntries：坏行/半行/空行/null/标量跳过；readTraceEntries 缺失/目录返回空', () => {
  const good = serializeTraceEntry(base({}))
  const text = ['', good, '  ', '{"atMs":1,"phase":"end"', '{"action":"xp"}', 'null', '0', 'nope', '[]'].join('\n')
  const parsed = parseTraceEntries(text)
  assert.equal(parsed.length, 1)
  assert.equal(parsed[0].action, 'xp_cmdi_payload')
  assert.deepEqual(readTraceEntries(join(tmp, 'nope', 'exploit-kit-trace.jsonl')), [])
  assert.deepEqual(readTraceEntries(tmp), [])
})

test('appendTraceEntry：追加可回读（begin/end 两行 = 一次调用）', () => {
  const path = join(tmp, 'ok', 'exploit-kit-trace.jsonl')
  assert.equal(appendTraceEntry(path, base({ phase: 'begin', durationMs: 0 })), true)
  assert.equal(appendTraceEntry(path, base({})), true)
  assert.deepEqual(readTraceEntries(path).map((e) => e.phase), ['begin', 'end'])
})

test('尸体测试：父路径是普通文件 → 返回 false 且不抛（观测不反噬调用）', () => {
  const blocker = join(tmp, 'blocker')
  writeFileSync(blocker, 'not a dir', 'utf8')
  assert.doesNotThrow(() => {
    assert.equal(appendTraceEntry(join(blocker, 'exploit-kit-trace.jsonl'), base({})), false)
    assert.equal(safeTrace(base({}), { path: join(blocker, 'exploit-kit-trace.jsonl'), now: 1, pid: 1 }), false)
  })
})

test('tracedExecute 正常路径：begin/end + 注入时钟耗时 + count/resultBytes + 返回值逐字不变', async () => {
  const path = join(tmp, 'wrap', 'exploit-kit-trace.jsonl')
  const times = [100, 100, 350, 350]
  const wrapped = tracedExecute({ action: 'xp_cmdi_payload', build: 'b@1', path, pid: 9, now: () => times.shift() ?? 350 },
    async (a) => ({ ok: true, payloads: [{ p: 1 }, { p: 2 }], count: 2, echo: a.shell }))
  const result = await wrapped({ command: 'id', shell: 'bash' })
  assert.deepEqual(result, { ok: true, payloads: [{ p: 1 }, { p: 2 }], count: 2, echo: 'bash' })
  const lines = readTraceEntries(path)
  assert.deepEqual(lines.map((e) => e.phase), ['begin', 'end'])
  assert.equal(lines[0].durationMs, 0)
  assert.equal(lines[0].payload, 'command=<2 chars>; shell=bash')
  assert.equal(lines[1].durationMs, 250)
  assert.equal(lines[1].count, 2)
  assert.equal(lines[1].ok, true)
  assert.equal(lines[1].pid, 9)
  assert.equal(lines[1].build, 'b@1')
})

test('tracedExecute 失败返回值：ok=false → end 记分类错误（不抛）', async () => {
  const path = join(tmp, 'wrap-err', 'exploit-kit-trace.jsonl')
  const wrapped = tracedExecute({ action: 'xp_serialize_php', build: 'b@1', path, now: () => 1 },
    async () => ({ ok: false, error: 'className 必填' }))
  const r = await wrapped({})
  assert.deepEqual(r, { ok: false, error: 'className 必填' })
  const lines = readTraceEntries(path)
  assert.equal(lines[1].ok, false)
  assert.match(lines[1].error, /^missing-args: /)
})

test('tracedExecute 抛错路径：RangeError（sqlTruncation 负填充缺陷形状）原样重抛 + 落 range 分类', async () => {
  const path = join(tmp, 'wrap-throw', 'exploit-kit-trace.jsonl')
  const boom = new RangeError('Invalid count value: -1')
  const wrapped = tracedExecute({ action: 'xp_php_juggling', build: 'b@1', path, now: () => 1 },
    async () => { throw boom })
  await assert.rejects(() => wrapped({ username: 'x', maxLen: 64 }), (e) => e === boom)
  const lines = readTraceEntries(path)
  assert.deepEqual(lines.map((e) => e.phase), ['begin', 'end'])
  assert.equal(lines[1].ok, false)
  assert.match(lines[1].error, /^range: /)
})

test('隐私尸体测试：JWT 密钥/本体/注册口令/用户名/command 绝不出现在落盘行里', async () => {
  const path = join(tmp, 'privacy', 'exploit-kit-trace.jsonl')
  const args = {
    mode: 'bruteforce',
    alg: 'HS256',
    token: 'eyJhbGci.token-must-not-land.sig',
    secret: 'jwt-secret-must-not-land',
    secrets: ['dict-must-not-land'],
    username: 'alice-secret-user',
    password: 'pw-must-not-land',
    command: 'mysql -p pw-must-not-land',
  }
  const wrapped = tracedExecute({ action: 'xp_jwt_forge', build: 'b@1', path, pid: 2, now: () => 1 },
    async () => ({ ok: false, error: '签名失败 secret=jwt-secret-must-not-land token=eyJhbGci.token-must-not-land.sig' }))
  await wrapped(args)
  const raw = readFileSync(path, 'utf8')
  for (const secret of ['jwt-secret-must-not-land', 'token-must-not-land', 'pw-must-not-land',
    'alice-secret-user', 'dict-must-not-land']) {
    assert.equal(raw.includes(secret), false, secret + ' 泄漏进了轨迹！')
  }
  assert.ok(raw.includes('secret=<24 chars>'))
  assert.ok(raw.includes('token=<32 chars>'))
  assert.ok(raw.includes('username=<17 chars>'))
  assert.ok(raw.includes('command=<25 chars>'))
  assert.ok(raw.includes('mode=bruteforce')) // 类型键保留（payload 类型摘要）
  assert.ok(raw.includes('alg=HS256'))
  assert.ok(raw.includes('secrets=<array 1>'))
})

test('观测失败不反噬：不可写路径下返回值照常、不抛；参数是标量也不崩', async () => {
  const blocker = join(tmp, 'blocker')
  const wrapped = tracedExecute({ action: 'xp_ecb_splice', build: 'b@1', path: join(blocker, 'exploit-kit-trace.jsonl'), now: () => 1 },
    async (a) => ({ ok: true, plan: [a] }))
  assert.deepEqual(await wrapped(null), { ok: true, plan: [null] })
  assert.deepEqual(await wrapped(undefined), { ok: true, plan: [undefined] })
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
