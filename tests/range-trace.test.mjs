/**
 * 靶场调用轨迹单测（跑 lib 产物）。
 *
 * 覆盖：脱敏/摘要/断点分类/路径/序列化/解析 + 正常与失败落盘 + **尸体测试**
 * （不可写路径 → `false` 且不抛，且**不改变返回值/异常传播**）+ **隐私尸体测试**
 * （口令/用户名/cookie/URL 内嵌凭据/远程命令 → 断言**绝不出现在落盘行里**）。
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
  isSensitiveKey,
  mtimeOf,
  parseTraceEntries,
  readPackageVersion,
  readTraceEntries,
  resolveHome,
  safeTrace,
  scrub,
  secretsOfUrl,
  serializeTraceEntry,
  summarizeArgs,
  summarizeResult,
  summarizeUrl,
  summarizeValue,
  tracePath,
  tracedExecute,
  truncate,
} from '../lib/range-trace.js'

const tmp = mkdtempSync(join(tmpdir(), 'cyber-range-trace-'))
const base = (entry) => ({
  atMs: 1_700_000_000_000,
  phase: 'end',
  action: 'request',
  build: '0.1.1@42',
  pid: 777,
  durationMs: 1234,
  ok: true,
  ...entry,
})

test('resolveHome / tracePath：DSH_HOME 优先，路径锚定单一文件名', () => {
  assert.equal(resolveHome({ DSH_HOME: 'E:/alice/.dsh' }, '/home/x'), 'E:/alice/.dsh')
  assert.equal(resolveHome({ DSH_HOME: ' ' }, '/home/x'), join('/home/x', '.dsh'))
  assert.equal(resolveHome({}, '/home/x'), join('/home/x', '.dsh'))
  assert.equal(tracePath('/h/.dsh'), join('/h/.dsh', 'cyber-range-trace.jsonl'))
})

test('isSensitiveKey：凭据/身份/命令类命中；业务键不误伤', () => {
  for (const key of ['pass', 'password', 'pwd', 'user', 'username', 'cookie', 'token',
    'authorization', 'secret', 'hash', 'hashFile', 'data', 'command', 'form']) {
    assert.equal(isSensitiveKey(key), true, key + ' 应判敏感')
  }
  for (const key of ['host', 'port', 'path', 'method', 'url', 'expr', 'template', 'injectParam',
    'charset', 'maxLen', 'condType', 'mode', 'sleepSec', 'userAgent', 'resolveIp', 'trueText']) {
    assert.equal(isSensitiveKey(key), false, key + ' 不应判敏感')
  }
})

test('secretsOfUrl：结构化取内嵌凭据（含百分号编码）；非法 URL 返回空', () => {
  // 真实语义：**不去重**（user 与 pass 字面相同则各出现一次）——去重由 collectSecrets 负责
  assert.deepEqual(secretsOfUrl('http://natas0:natas0@host/x').sort(), ['natas0', 'natas0'])
  assert.deepEqual(secretsOfUrl('http://u%20ser:p%40ss@host/x'), ['u ser', 'p@ss'])
  assert.deepEqual(secretsOfUrl('http://host/x'), [])
  assert.deepEqual(secretsOfUrl('not a url'), [])
})

test('collectSecrets：敏感键全覆盖 + 去重 + 长秘密优先（短先替换会留残余）', () => {
  const secrets = collectSecrets({ user: 'ab', pass: 'hunter2', cookie: 'c1', host: 'h', path: '/x' })
  assert.ok(secrets.includes('hunter2') && secrets.includes('ab') && secrets.includes('c1'))
  assert.equal(secrets.includes('h'), false)
  assert.equal(secrets.includes('/x'), false)
  const ordered = collectSecrets({ pass: 'abc', command: 'abcdef' })
  assert.deepEqual(ordered, ['abcdef', 'abc']) // 长的在前
  assert.deepEqual(collectSecrets(null), [])
  assert.deepEqual(collectSecrets('str'), [])
})

test('scrub：用秘密值擦除文本；空秘密值不参与', () => {
  assert.equal(scrub('u -p hunter2 x', ['hunter2']), 'u -p [redacted] x')
  assert.equal(scrub('abc', ['']), 'abc')
  assert.equal(scrub('-u alice:hunter2', ['alice', 'hunter2']), '-u [redacted]:[redacted]')
})

test('summarizeValue：敏感键只记长度；容器记形状；普通键截断', () => {
  assert.equal(summarizeValue('pass', 'hunter2'), '<7 chars>')
  assert.equal(summarizeValue('command', 'id'), '<2 chars>')
  assert.equal(summarizeValue('host', 'x'.repeat(200)).length, 81)
  assert.equal(summarizeValue('charset', 'alnum'), 'alnum')
  assert.equal(summarizeValue('charset', ['a', 'b']), '<array 2>')
  assert.equal(summarizeValue('extra', { n: 1 }), '{"n":1}')
  assert.equal(summarizeValue('port', undefined), '')
  assert.equal(summarizeValue('pass', null), '<0 chars>')
  assert.equal(truncate('abcdef', 3), 'abc…')
})

test('summarizeUrl：剥掉凭据只留 hostname+path；非法 URL 退化', () => {
  assert.equal(summarizeUrl('http://natas0:natas0@natas.labs/x.php?y=1'), 'natas.labs/x.php')
  assert.equal(summarizeUrl('nope'), '<unparsable-url>')
})

test('summarizeArgs：拼装 + 跳过 undefined + url 结构化 + 整体封顶', () => {
  const line = summarizeArgs({ host: 'h.example', pass: 'hunter2', user: 'alice', method: 'GET', path: undefined })
  assert.equal(line, 'host=h.example; pass=<7 chars>; user=<5 chars>; method=GET')
  assert.equal(summarizeArgs({ url: 'http://a:b@h/x' }), 'url=h/x')
  assert.equal(summarizeArgs(null), '')
  assert.equal(summarizeArgs('str'), '')
  assert.ok(summarizeArgs({ host: 'z'.repeat(2000) }, 100).length <= 101)
})

test('summarizeResult：ok 是通道级语义（401 也算通）；量级字段投影，不落正文', () => {
  assert.deepEqual(summarizeResult({ status: 401, body: 'abcdef', truncated: false }), { ok: true, status: 401, bodyBytes: 6 })
  assert.equal(summarizeResult({ status: 0, body: '', truncated: false, error: 'curl: (7) fail' }).ok, false)
  assert.deepEqual(summarizeResult({ ok: false, stdout: 'x', stderr: 'yy', exitCode: 255 }),
    { ok: false, exitCode: 255, stdoutBytes: 1, stderrBytes: 2 })
  assert.deepEqual(summarizeResult({ result: 'x', queries: 42, error: 'e' }), { ok: false, queries: 42 })
  assert.deepEqual(summarizeResult(null), { ok: true })
})

test('classifyBreak：断点分类可 grep（超时/起不来/连接/非零退出/空/其它）', () => {
  assert.equal(classifyBreak('timeout'), 'http-timeout')
  assert.equal(classifyBreak('spawn wsl.exe ENOENT'), 'wsl-spawn')
  assert.equal(classifyBreak('getaddrinfo ENOTFOUND x'), 'http-error')
  assert.equal(classifyBreak('curl: (7) Failed to connect'), 'wsl-exit')
  assert.equal(classifyBreak('  '), 'empty')
  assert.equal(classifyBreak('something odd'), 'other')
})

test('serializeTraceEntry：单行 + 键序固定 + 缺省字段不污染', () => {
  const line = serializeTraceEntry(base({}))
  assert.equal(line.includes('\n'), false)
  assert.deepEqual(Object.keys(JSON.parse(line)), ['atMs', 'phase', 'action', 'build', 'pid', 'durationMs', 'ok'])
  const full = JSON.parse(serializeTraceEntry(base({
    target: 'h', params: 'p', cmdShape: 'c', status: 200, exitCode: 0,
    stdoutBytes: 1, stderrBytes: 2, bodyBytes: 3, queries: 4, error: 'e',
  })))
  // 真实键序：atMs phase action build pid | target params cmdShape durationMs ok | 其余量级字段
  assert.deepEqual(Object.keys(full).slice(6), ['params', 'cmdShape', 'durationMs', 'ok', 'status',
    'exitCode', 'stdoutBytes', 'stderrBytes', 'bodyBytes', 'queries', 'error'])
})

test('parseTraceEntries：坏行/半行/空行/null/标量跳过；readTraceEntries 缺失/目录返回空', () => {
  const good = serializeTraceEntry(base({}))
  const text = ['', good, '   ', '{"atMs":1,"phase":"end"', '{"action":"request"}', 'null', '0', 'nope', '[]'].join('\n')
  const parsed = parseTraceEntries(text)
  assert.equal(parsed.length, 1)
  assert.equal(parsed[0].action, 'request')
  assert.deepEqual(readTraceEntries(join(tmp, 'nope', 'cyber-range-trace.jsonl')), [])
  assert.deepEqual(readTraceEntries(tmp), []) // 目录：读失败 → 空数组
})

test('appendTraceEntry：追加可回读（begin/end 两行 = 一次调用）', () => {
  const path = join(tmp, 'ok', 'cyber-range-trace.jsonl')
  assert.equal(appendTraceEntry(path, base({ phase: 'begin', durationMs: 0 })), true)
  assert.equal(appendTraceEntry(path, base({})), true)
  assert.deepEqual(readTraceEntries(path).map((e) => e.phase), ['begin', 'end'])
})

test('尸体测试：父路径是普通文件 → 返回 false 且不抛（观测不反噬调用）', () => {
  const blocker = join(tmp, 'blocker')
  writeFileSync(blocker, 'not a dir', 'utf8')
  assert.doesNotThrow(() => {
    assert.equal(appendTraceEntry(join(blocker, 'cyber-range-trace.jsonl'), base({})), false)
    assert.equal(safeTrace(base({}), { path: join(blocker, 'cyber-range-trace.jsonl'), now: 1, pid: 1 }), false)
  })
})

test('隐私尸体测试：凭据/用户名/cookie/URL 内嵌凭据绝不出现在落盘行里', () => {
  const path = join(tmp, 'privacy', 'cyber-range-trace.jsonl')
  const args = {
    host: 'target.example',
    user: 'alice-secret-user',
    pass: 'hunter2-must-not-land',
    cookie: 'sess-must-not-land',
    data: 'username=alice-secret-user&password=hunter2-must-not-land',
    command: 'mysql -p hunter2-must-not-land',
    url: 'http://alice-secret-user:hunter2-must-not-land@target.example/x',
    path: '/x',
  }
  const secrets = collectSecrets(args)
  const wrapped = tracedExecute(
    { action: 'ssh', build: 'b@1', path, now: () => 1, pid: 2, cmdOf: () => 'sshpass -p hunter2-must-not-land ssh alice-secret-user@target.example' },
    async (a) => ({ ok: false, error: 'sshpass failed for hunter2-must-not-land (alice-secret-user)' }),
  )
  return wrapped(args).then(() => {
    const raw = readFileSync(path, 'utf8')
    for (const secret of ['alice-secret-user', 'hunter2-must-not-land', 'sess-must-not-land']) {
      assert.equal(raw.includes(secret), false, secret + ' 泄漏进了轨迹！')
    }
    assert.ok(raw.includes('pass=<21 chars>')) // 'hunter2-must-not-land' = 21 字符
    assert.ok(raw.includes('user=<17 chars>')) // 'alice-secret-user' = 17 字符
    assert.ok(raw.includes('[redacted]'))
    assert.ok(raw.includes('host=target.example')) // 业务参数保留（排障要看）
    assert.equal(secrets.includes('hunter2-must-not-land'), true)
  })
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

test('tracedExecute 正常路径：begin/end 两行 + 耗时（注入时钟）+ 结果量级 + 返回值逐字不变', async () => {
  const path = join(tmp, 'wrap', 'cyber-range-trace.jsonl')
  const times = [100, 100, 350, 350]
  const wrapped = tracedExecute({
    action: 'request', build: 'b@1', path, pid: 9, now: () => times.shift() ?? 350,
    targetOf: (a) => String(a.host), cmdOf: () => "curl -u 'x:y' http://h/",
  }, async (args) => ({ status: 200, body: 'hello', truncated: false, echo: args.host }))
  const result = await wrapped({ host: 'h.example', pass: 'y' })
  assert.deepEqual(result, { status: 200, body: 'hello', truncated: false, echo: 'h.example' })
  const lines = readTraceEntries(path)
  assert.deepEqual(lines.map((e) => e.phase), ['begin', 'end'])
  assert.equal(lines[0].durationMs, 0)
  assert.equal(lines[0].target, 'h.example')
  assert.equal(lines[0].cmdShape, "curl -u 'x:[redacted]' http://h/")
  assert.equal(lines[1].durationMs, 250)
  assert.equal(lines[1].ok, true)
  assert.equal(lines[1].status, 200)
  assert.equal(lines[1].bodyBytes, 5)
  assert.equal(lines[1].pid, 9)
  assert.equal(lines[1].build, 'b@1')
})

test('tracedExecute 失败路径：end 记 ok=false + 断点分类，异常原样重抛', async () => {
  const path = join(tmp, 'wrap-fail', 'cyber-range-trace.jsonl')
  const boom = new Error('curl: (28) Operation timed out after 20000ms')
  const wrapped = tracedExecute(
    { action: 'blind', build: 'b@1', path, pid: 9, now: () => 1, targetOf: () => 'h' },
    async () => { throw boom },
  )
  await assert.rejects(() => wrapped({ url: 'http://h/x' }), (e) => e === boom) // 同一个对象，未被包装
  const lines = readTraceEntries(path)
  assert.deepEqual(lines.map((e) => e.phase), ['begin', 'end'])
  assert.equal(lines[1].ok, false)
  assert.match(lines[1].error, /^http-timeout: /)
})

test('tracedExecute 观测失败不反噬：不可写路径下返回值照常、不抛；摘要函数抛错也被吞', async () => {
  const blocker = join(tmp, 'blocker')
  const wrapped = tracedExecute({
    action: 'request', build: 'b@1', path: join(blocker, 'cyber-range-trace.jsonl'), now: () => 1,
    targetOf: () => { throw new Error('targetOf 崩了') },
    cmdOf: () => { throw new Error('cmdOf 崩了') },
  }, async () => ({ status: 200, body: 'ok' }))
  assert.deepEqual(await wrapped({ host: 'h' }), { status: 200, body: 'ok' })
})

test('接线守卫：会落盘的 target 必须经 redactTarget 剥离 URL 内嵌凭据（分层：裁决仍用原始值）', () => {
  // 真实缺陷（2026-09-14 在旧插件上实测发现；**2026-10-05 移植时在融合后的插件上复现**）：
  //   接线层曾把含 `user:pass@` 的 url **原样**记进 `target` ⇒ 凭据写进 timeline.jsonl。
  //   融合 5 个安全线插件时这条防线没被带过来 —— 旧测试还在，所以一移植就报红，抓出真缺陷。
  // ⚠ 修法是**分层**而不是改 targetOf：`decideGate` 用同一个值做 scope 匹配（`inList`），
  //   剥掉协议或凭据会让合法目标匹配不上 ⇒ **误拦合法动作**。⇒ 裁决用原始值、落盘用派生值。
  const src = readFileSync(new URL('../src/index.ts', import.meta.url), 'utf8')
  // ① 落盘派生值存在，且确实经 redactTarget
  assert.ok(
    /const loggedTarget = [^\n]*redactTarget\(/.test(src),
    '接线层必须为落盘构造经 redactTarget 的派生值',
  )
  // ② 防「修过头」：闸门裁决必须仍用**原始** target
  assert.ok(
    /decideGate\(\{[^\n]*target !== undefined \? \{ target \}/.test(src),
    '闸门裁决必须用原始 target —— 剥过会让合法目标匹配不上 scope ⇒ 误拦',
  )
  // ③ 尸体样本：裸 target 直接落盘的形态必须不存在（修复前的写法）
  assert.equal(
    /gateDeniedLine\(\{[^\n]*target !== undefined \? \{ target \}/.test(src),
    false,
    '闸门拒绝行仍在用裸 target 落盘 —— 凭据会进 timeline',
  )
  assert.equal(
    /appendTimeline\(paths, \{[^\n]*target !== undefined \? \{ target \}/.test(src),
    false,
    'tool/end 行仍在用裸 target 落盘 —— 凭据会进 timeline',
  )
})

test('cleanup', () => {
  rmSync(tmp, { recursive: true, force: true })
})
