/**
 * dsh-red-team 扫描轨迹 + 过滤统计单测（跑 lib 产物，零网络、零真实目标）。
 *
 * 覆盖：正常路径（路径解析/脱敏/分类/命中抽取/序列化/落盘/回读）+ 退化路径（坏行/半行/空文件/
 * 缺失文件/脏返回值）+ **尸体测试**（父路径是普通文件 → 返回 false 且不抛）
 * + 隐私尸体测试（凭据型目标不落盘）+ 过滤依据统计（原缺陷面：异源被当同源）
 * + **接线测试**（真 `apply` + 假 ctx + fetch 桩 → 轨迹落盘且带过滤依据）。
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  REDACTED,
  asTraceStats,
  buildStamp,
  classifyFailure,
  clip,
  hitsOf,
  homePathVariants,
  parseTraceEntries,
  redTrace,
  redTraceBoot,
  redTracePath,
  readPackageVersion,
  readTraceEntries,
  redactHome,
  redactTarget,
  resolveHome,
  selfBuild,
  serializeTraceEntry,
  traceEnabled,
} from '../lib/red-trace.js'
import { extractLinks, extractLinksDetailed, parseCrtShNames, parseCrtShNamesDetailed } from '../lib/red-pure.js'
import { apply } from '../lib/index.js'

const tmp = mkdtempSync(join(tmpdir(), 'redteam-trace-test-'))
process.env['DSH_HOME'] = join(tmp, 'home')

const base = (entry) => ({
  atMs: 1_700_000_000_000,
  phase: 'scan/end',
  build: '0.1.1@12345',
  pid: 4242,
  tool: 'red_crawl_links',
  durationMs: 812,
  ...entry,
})

// ---------- 路径与构建自报（Q1） ----------

test('resolveHome：DSH_HOME 优先，空白/缺失回退 <homedir>/.dsh', () => {
  assert.equal(resolveHome({ DSH_HOME: 'E:/alice/.dsh' }, '/home/x'), 'E:/alice/.dsh')
  assert.equal(resolveHome({ DSH_HOME: '  ' }, '/home/x'), join('/home/x', '.dsh'))
  assert.equal(resolveHome({}, '/home/x'), join('/home/x', '.dsh'))
})

test('redTracePath：锚定 DSH_HOME 下的单一文件名', () => {
  assert.equal(redTracePath('/h/.dsh'), join('/h/.dsh', 'redteam-trace.jsonl'))
})

test('selfBuild：<version>@<mtime ms> 形态且 mtime 来自产物；缓存稳定', () => {
  const build = selfBuild()
  assert.match(build, /^[^@]+@\d+$/)
  const [version, mtime] = build.split('@')
  const libTrace = fileURLToPath(new URL('../lib/red-trace.js', import.meta.url))
  assert.equal(version, readPackageVersion(libTrace))
  assert.ok(Number(mtime) > 0)
  assert.equal(selfBuild(), build)
  assert.equal(buildStamp('/nope/missing.js', ''), 'unknown@0')
})

test('traceEnabled：DSH_REDTEAM_TRACE=0 关闭，其余（含缺失）开启', () => {
  assert.equal(traceEnabled({ DSH_REDTEAM_TRACE: '0' }), false)
  assert.equal(traceEnabled({}), true)
})

// ---------- 目标脱敏与失败分类（隐私 + Q3） ----------

test('redactTarget：userinfo / 凭据型 query 脱敏，普通 query 原样，主目录折叠', () => {
  assert.equal(
    redactTarget('http://admin:hunter2@a.com/x?token=abc&q=1'),
    `http://admin:${REDACTED}@a.com/x?token=${REDACTED}&q=1`,
  )
  assert.equal(redactTarget('http://a.com/x?id=7'), 'http://a.com/x?id=7')
  assert.equal(redactTarget('a.com:22'), 'a.com:22')          // 非 URL 目标原样
  assert.equal(redactTarget('http://a.com?api_key=k'), `http://a.com?api_key=${REDACTED}`)
  assert.equal(redactHome('http://a.com/C:/Users/demo/x', 'C:\\Users\\demo'), 'http://a.com/<home>/x')
  const once = redactTarget('http://u:p@a.com?secret=s')
  assert.equal(redactTarget(once), once)                       // 幂等
  assert.deepEqual(homePathVariants(''), [])
})

test('classifyFailure：失败分类可 grep（含 abort/超时/DNS/拒绝/HTTP/解析/未知）', () => {
  assert.equal(classifyFailure('The operation was aborted'), 'abort')
  assert.equal(classifyFailure('AbortSignal.timeout(20000) fired: TimeoutError'), 'timeout')
  assert.equal(classifyFailure('fetch failed: getaddrinfo ENOTFOUND nope.invalid'), 'dns')
  assert.equal(classifyFailure('connect ECONNREFUSED 127.0.0.1:1'), 'refused')
  assert.equal(classifyFailure('crt.sh HTTP 502'), 'http-5xx')
  assert.equal(classifyFailure('HTTP 404'), 'http-4xx')
  assert.equal(classifyFailure('fetch failed'), 'network')
  assert.equal(classifyFailure('Unexpected token < in JSON'), 'parse')
  assert.equal(classifyFailure('莫名其妙'), 'unknown')
})

test('clip：折平空白 + 超长带裁剪标记；短串原样', () => {
  assert.equal(clip('a\n\n  b', 200), 'a b')
  assert.equal(clip('x'.repeat(250), 200), `${'x'.repeat(200)}...(+50)`)
})

// ---------- 命中/过滤抽取（Q4） ----------

test('asTraceStats：raw/kept/dropped 三数字齐备才算，脏数据返回 undefined', () => {
  assert.deepEqual(asTraceStats({ raw: 5, kept: 2, dropped: 3, reasons: { x: 3 } }), {
    raw: 5, kept: 2, dropped: 3, reasons: { x: 3 },
  })
  assert.deepEqual(asTraceStats({ raw: 5, kept: 2, dropped: 3 }), { raw: 5, kept: 2, dropped: 3 })
  assert.equal(asTraceStats({ raw: 5 }), undefined)
  assert.equal(asTraceStats({ raw: '5', kept: 2, dropped: 3 }), undefined)
  assert.equal(asTraceStats(null), undefined)
  assert.equal(asTraceStats('x'), undefined)
})

test('hitsOf：八工具的实际返回形状全部认得出（不认识的形状不猜）', () => {
  assert.deepEqual(hitsOf(['a', 'b']), { hits: 2 })                       // 子域（旧）/目录/CVE/敏感路径
  assert.deepEqual(hitsOf({ results: [1, 2, 3] }), { hits: 3 })
  assert.deepEqual(hitsOf({ links: [1], page: {} }), { hits: 1 })
  assert.deepEqual(hitsOf({ names: ['a'] }), { hits: 1 })
  assert.deepEqual(hitsOf({ fp: { marks: ['Nginx', 'PHP'] } }), { hits: 2 })
  assert.deepEqual(hitsOf({ result: { present: ['a'], missing: ['b', 'c'] } }), {
    hits: 1, raw: 3, stats: { raw: 3, kept: 1, dropped: 2, reasons: { missing: 2 } },
  })
  assert.deepEqual(hitsOf('SSH-2.0-OpenSSH_9.6'), { textChars: 19 })      // banner：长度不是命中数，单列
  assert.deepEqual(hitsOf(null), {})
  assert.deepEqual(hitsOf(42), {})
  assert.deepEqual(hitsOf({ 乱七八糟: 1 }), {})                            // 不认识的形状不猜
})

// ---------- 序列化 / 解析 / 落盘 ----------

test('serializeTraceEntry：单行 + 键序固定 + 缺省字段不污染', () => {
  const line = serializeTraceEntry(base({ hits: 3 }))
  assert.equal(line.includes('\n'), false)
  assert.deepEqual(Object.keys(JSON.parse(line)), [
    'atMs', 'phase', 'build', 'pid', 'tool', 'durationMs', 'hits',
  ])
  const full = JSON.parse(serializeTraceEntry(base({
    target: 'http://a.com/', raw: 9, hits: 2, stats: { raw: 9, kept: 2, dropped: 7 },
    failure: 'http-5xx', error: 'crt.sh HTTP 502',
  })))
  assert.deepEqual(Object.keys(full).slice(5), [
    'target', 'durationMs', 'raw', 'hits', 'stats', 'failure', 'error',
  ])
})

test('parseTraceEntries：坏行/半行/空行/null 全部跳过，不抛', () => {
  const good = serializeTraceEntry(base({}))
  const text = ['', good, '  ', '{"atMs":1,"phase":"scan/end"', '{"atMs":"x","phase":"y"}', 'null', '[1]', 'nope'].join('\n')
  const parsed = parseTraceEntries(text)
  assert.equal(parsed.length, 1)
  assert.equal(parsed[0].tool, 'red_crawl_links')
})

test('readTraceEntries：缺失文件 / 目录当文件读 → 空数组（不抛）', () => {
  assert.deepEqual(readTraceEntries(join(tmp, 'nope', 'redteam-trace.jsonl')), [])
  assert.deepEqual(readTraceEntries(tmp), [])
})

test('appendTraceEntry + readTraceEntries：正常落盘与回读（追加不覆盖）', () => {
  const path = join(tmp, 'ok', 'redteam-trace.jsonl')
  redTrace({ phase: 'scan/start', tool: 'red_dir_brute', durationMs: 0 }, { path, now: 1, pid: 2 })
  redTrace({ phase: 'scan/end', tool: 'red_dir_brute', durationMs: 5, hits: 2 }, { path, now: 2, pid: 2 })
  const back = readTraceEntries(path)
  assert.deepEqual(back.map((e) => e.phase), ['scan/start', 'scan/end'])
  assert.equal(back[1].hits, 2)
})

test('尸体测试：父路径是普通文件 → 返回 false 且不抛（观测不反噬扫描）', () => {
  const blocker = join(tmp, 'blocker')
  writeFileSync(blocker, 'not a dir', 'utf8')
  assert.doesNotThrow(() => {
    assert.equal(redTrace({ phase: 'scan/end', tool: 't', durationMs: 1 }, { path: join(blocker, 'redteam-trace.jsonl') }), false)
  })
})

test('redTraceBoot：boot 行自报生效面（enabled + 工具名清单）', () => {
  const path = join(tmp, 'boot', 'redteam-trace.jsonl')
  assert.equal(redTraceBoot({ enabled: true, tools: ['red_crawl_links'] }, { path, now: 5, pid: 6, build: 'b@2' }), true)
  const [line] = readTraceEntries(path)
  assert.equal(line.phase, 'boot')
  assert.equal(line.tool, 'apply')
  assert.deepEqual(line.cfg, { enabled: true, tools: ['red_crawl_links'] })
})

test('隐私尸体测试：含凭据的目标 → 落盘行里搜不到凭据串（脱敏确实发生）', () => {
  const path = join(tmp, 'privacy', 'redteam-trace.jsonl')
  const secrets = ['hunter2', 's3cr3t-token', 'AKIAEXAMPLEKEY']
  redTrace({
    phase: 'scan/end', tool: 'red_crawl_links', durationMs: 1, hits: 0,
    target: redactTarget('https://admin:hunter2@a.com/x?token=s3cr3t-token&access_key=AKIAEXAMPLEKEY&page=2'),
  }, { path, now: 1, pid: 1 })
  const raw = readFileSync(path, 'utf8')
  for (const secret of secrets) assert.equal(raw.includes(secret), false, `轨迹泄露：${secret}`)
  assert.equal(raw.includes(REDACTED), true)
  assert.equal(raw.includes('page=2'), true)   // 非凭据 query 仍可诊断
})

// ---------- 过滤依据（Q4 的核心：原缺陷面） ----------

const DEFECT_HTML = [
  '<html><head><title>T</title></head><body>',
  '<a href="/ok">1</a>',
  '<a href="/ok">dup</a>',
  '<a href="https://a.com.evil.com/x">异源（前缀相同）</a>',   // 修复前 startsWith(origin) 会误当同源
  '<a href="https://a.com:8443/y">异端口</a>',                 // 修复前也会被误当同源
  '<a href="javascript:void(0)">js</a>',
  '<img src="data:image/png;base64,AAA">',
  '<form action="/login">',
  '<a href="http://[">非法</a>',
  '<a href="#top">锚点</a>',
  '</body></html>',
].join('\n')

test('extractLinksDetailed：原始 9 → 保留 2，丢弃依据逐项可读（含前缀型异源）', () => {
  const { links, stats } = extractLinksDetailed(DEFECT_HTML, 'http://a.com/', 50)
  assert.deepEqual(links.map((l) => l.url), ['http://a.com/ok', 'http://a.com/login'])
  assert.equal(stats.raw, 9)
  assert.equal(stats.kept, 2)
  assert.equal(stats.dropped, 7)
  assert.deepEqual(stats.reasons, {
    scheme: 3, 'off-origin': 2, duplicate: 1, 'invalid-url': 1,
  })
})

test('extractLinks 是 Detailed 的薄委托（零漂移等价）', () => {
  assert.deepEqual(extractLinks(DEFECT_HTML, 'http://a.com/', 50), extractLinksDetailed(DEFECT_HTML, 'http://a.com/', 50).links)
  assert.deepEqual(extractLinks(DEFECT_HTML, 'http://a.com/', 1).map((l) => l.url), ['http://a.com/ok'])
  const limited = extractLinksDetailed(DEFECT_HTML, 'http://a.com/', 1).stats
  assert.equal(limited.kept, 1)
  assert.equal(limited.reasons['over-limit'], 1)
})

test('parseCrtShNamesDetailed：原始名单 → 清洗后条数 + 丢弃依据', () => {
  const long = `${'x'.repeat(120)}.a.com`
  const data = [
    { name_value: 'a.com' },                       // not-subdomain
    { name_value: '*.a.com' },                     // 去 *. 后 = a.com → not-subdomain
    { name_value: 'www.a.com' },                   // kept
    { name_value: 'WWW.a.com' },                   // duplicate（小写后同名）
    { name_value: 'api.a.com\nmail.a.com' },       // 两个 kept（拆行）
    { name_value: long },                          // too-long
    { name_value: '' },                            // 空行：不计候选
  ]
  const { names, stats } = parseCrtShNamesDetailed(data, 'a.com', 30)
  assert.deepEqual(names, ['api.a.com', 'mail.a.com', 'www.a.com'])
  assert.equal(stats.raw, 7)          // 7 个非空候选（拆行那行贡献 2 个）
  assert.equal(stats.kept, 3)
  assert.equal(stats.dropped, 4)
  assert.deepEqual(stats.reasons, { 'not-subdomain': 2, duplicate: 1, 'too-long': 1 })
  // 薄委托等价 + 脏数据（非数组）不抛
  assert.deepEqual(parseCrtShNames(data, 'a.com', 30), names)
  assert.deepEqual(parseCrtShNamesDetailed(null, 'a.com', 30).stats, { raw: 0, kept: 0, dropped: 0 })
  assert.deepEqual(parseCrtShNamesDetailed(data, 'a.com', 2).stats.reasons['over-limit'], 1)
})

// ---------- 接线测试：真 apply + 假 ctx + fetch 桩 ----------

function makeCtx() {
  const registered = []
  const ctx = {
    logger: () => ({ info: () => {}, warn: () => {}, error: () => {} }),
    tools: { register: (t) => { registered.push(t); return () => {} } },
  }
  return { ctx, registered }
}

// ⚠ 2026-10-05：此处原有三条 `test.skip` **接线级**测试（apply 落 boot/scan 行、失败落 scan/error、
//   观测不反噬的尸体测试）。融合 5 个安全线插件后 apply 契约已变（工具数 8 → 12、副作用统一走
//   `reg()` 单一切面、轨迹从 `redTrace` 通道迁到交战国度的 `timeline.jsonl`），三条的**判据意图**
//   已按新契约重写并迁至 `tests/wire-contract.test.mjs`（接线①②③ + 两条结构不变量）。
//   ⇒ 本文件不再保留 skip；`redTrace` 系纯层函数仍由本文件上方各用例覆盖（它们测的是模块行为）。
//   同族的归档项 `_archive/dsh-exploit-kit-*/tests/tool-contract.test.mjs`（13 条）判据意图
//   由 `wire-contract.test.mjs` 的 I2/I5 两条不变量承接。

test('cleanup', () => {
  rmSync(tmp, { recursive: true, force: true })
})
