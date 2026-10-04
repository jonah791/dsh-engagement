/**
 * pure.ts 纯函数套件（离线、零网络、零目标交互）。
 * 覆盖：正常路径 + 失败/退化路径（空响应、脏 JSON、缺字段、非法 URL、空字典项）。
 * 本套件**不对任何目标发起请求**（安全边界：只测本地判定逻辑）。
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  FRAMEWORK_MARKS, matchFrameworks, SEC_HEADERS, splitSecurityHeaders, SENSITIVE_PATHS,
  classifySensitivePath, DIR_DICT, buildDirPaths, isInterestingStatus,
  extractTitle, extractLinks, parseCrtShNames, mapCves,
} from '../lib/red-pure.js'

// ---------- 指纹 ----------

test('matchFrameworks: 响应头/页面特征命中（大小写不敏感）', () => {
  assert.deepEqual(matchFrameworks('Server: nginx/1.24'), ['Nginx'])
  assert.deepEqual(matchFrameworks('<link href="/wp-content/x.css">'), ['WordPress'])
  assert.ok(matchFrameworks('X-Powered-By: PHP/8.1').includes('PHP'))
  assert.ok(matchFrameworks('<div id="__NUXT__">').includes('Vue.js'))
})

test('matchFrameworks: 退化路径——空串/无特征返回空数组，不抛错', () => {
  assert.deepEqual(matchFrameworks(''), [])
  assert.deepEqual(matchFrameworks('nothing to see here'), [])
})

test('matchFrameworks: 表结构不变量（名字与正则成对，可被外部审计）', () => {
  assert.ok(FRAMEWORK_MARKS.length >= 15)
  for (const [name, re] of FRAMEWORK_MARKS) {
    assert.equal(typeof name, 'string')
    assert.ok(re instanceof RegExp && re.flags.includes('i'), `${name} 的特征必须大小写不敏感`)
  }
})

// ---------- 安全头 ----------

test('splitSecurityHeaders: 全部缺失 / 全部存在 / 部分存在', () => {
  const none = splitSecurityHeaders(() => null)
  assert.equal(none.present.length, 0)
  assert.equal(none.missing.length, SEC_HEADERS.length)
  assert.match(none.missing[0], /^strict-transport-security \(/)

  const all = splitSecurityHeaders(() => 'x')
  assert.equal(all.missing.length, 0)
  assert.equal(all.present.length, SEC_HEADERS.length)

  const some = splitSecurityHeaders((h) => (h === 'content-security-policy' ? 'default-src' : null))
  assert.deepEqual(some.present, ['content-security-policy (CSP（防 XSS/注入）)'])
  assert.equal(some.missing.length, SEC_HEADERS.length - 1)
})

test('splitSecurityHeaders: getter 可喂真实 Headers（结构性兼容）', () => {
  const h = new Headers({ 'X-Frame-Options': 'DENY' })
  const r = splitSecurityHeaders((n) => h.get(n))
  assert.equal(r.present.length, 1)
  assert.equal(r.missing.length, SEC_HEADERS.length - 1)
})

// ---------- 敏感路径 ----------

test('classifySensitivePath: 四类高风险定性 + 兜底「存在」', () => {
  assert.equal(classifySensitivePath('.git/HEAD', 'ref: refs/heads/main'), 'Git 仓库泄露!')
  assert.equal(classifySensitivePath('.env', 'DB_PASSWORD=1'), '环境变量疑似泄露!')
  assert.equal(classifySensitivePath('phpinfo.php', 'PHP Version'), 'PHPINFO 暴露!')
  assert.equal(classifySensitivePath('robots.txt', 'User-agent: *'), 'robots.txt（可能泄露路径）')
  assert.equal(classifySensitivePath('backup.zip', 'PK'), '存在')
})

test('classifySensitivePath: 记录真语义——判定按顺序覆盖，且 .git/.env 是子串判定', () => {
  // 顺序覆盖：phpinfo + .git/ref: 同时命中时，phpinfo 的 note 胜出（后写覆盖前写）
  assert.equal(classifySensitivePath('phpinfo.php', 'ref: x'), 'PHPINFO 暴露!')
  // 子串判定：名为 .git 前缀的其它文件同样会命中（记为已知语义，不是缺陷断言）
  assert.equal(classifySensitivePath('.gitlab-ci/.env', 'KEY=1'), '环境变量疑似泄露!')
  // .git 子串但 body 不以 ref: 开头 → 只落到兜底
  assert.equal(classifySensitivePath('.git/config', '[core]'), '存在')
})

test('SENSITIVE_PATHS: 清单非空且含高价值目标（只读断言）', () => {
  assert.ok(SENSITIVE_PATHS.includes('.git/HEAD'))
  assert.ok(SENSITIVE_PATHS.includes('.env'))
})

// ---------- 目录字典 ----------

test('buildDirPaths: 字典 + 追加项（去前导斜杠、去重），且不改写 DIR_DICT', () => {
  const before = DIR_DICT.length
  const out = buildDirPaths(['/secret', 'admin', 'secret'])
  assert.equal(out.length, before + 1, '追加项与字典去重后只多 1 个（secret）')
  assert.ok(out.includes('secret'))
  assert.equal(out.includes('/secret'), false, '前导 / 必须被去掉')
  assert.equal(DIR_DICT.length, before, 'DIR_DICT 不得被改写')
})

test('buildDirPaths: 退化路径——undefined / 空数组 / 全空串', () => {
  assert.deepEqual(buildDirPaths(undefined), [...DIR_DICT])
  assert.equal(buildDirPaths([]).length, DIR_DICT.length)
  assert.deepEqual(buildDirPaths(['', '']), [...DIR_DICT, ''])
})

test('isInterestingStatus: 404/0 不算存在，其余（含 3xx/5xx）算', () => {
  assert.equal(isInterestingStatus(404), false)
  assert.equal(isInterestingStatus(0), false)
  assert.equal(isInterestingStatus(200), true)
  assert.equal(isInterestingStatus(301), true)
  assert.equal(isInterestingStatus(403), true)
  assert.equal(isInterestingStatus(500), true)
})

// ---------- 页面解析 ----------

test('extractTitle: 取值并 trim；无 title/空 title 返回空串', () => {
  assert.equal(extractTitle('<html><title> Hello </title></html>'), 'Hello')
  assert.equal(extractTitle('<TITLE>x</TITLE>'), 'x')
  assert.equal(extractTitle('<html></html>'), '')
  assert.equal(extractTitle(''), '')
})

test('extractLinks: 抽取 href/src/action、相对转绝对、同源过滤、去重、截断', () => {
  const html = '<a href="/a">1</a><img src="b.png"><form action="https://evil.com/x">'
    + '<a href="/a">dup</a><a href="#frag">f</a><a href="javascript:void(0)">j</a>'
    + '<a href="data:text/plain,x">d</a>'
  const links = extractLinks(html, 'https://site.com/dir/page', 50)
  assert.deepEqual(links.map((l) => l.url), [
    'https://site.com/a', 'https://site.com/dir/b.png',
  ])
  assert.deepEqual(links.map((l) => l.source), ['href', 'src'])
})

test('extractLinks: 退化路径——空 html / 全非法 URL / maxLinks=0 / 非法 baseUrl 抛错', () => {
  assert.deepEqual(extractLinks('', 'https://a.com', 10), [])
  assert.deepEqual(extractLinks('<a href="http://other.com/x">', 'https://a.com', 10), [])
  assert.deepEqual(extractLinks('<a href="/x">', 'https://a.com', 0), [])
  assert.throws(() => extractLinks('<a href="/x">', 'not-a-url', 10))
})

test('extractLinks: 同源判定按 origin 精确比较（不同端口 / 前缀形似域均排除）', () => {
  // 2026-09-14 修复的真缺陷：原实现是字符串前缀 `startsWith(origin)`，
  // `https://a.com:8443/x` 与 `https://a.com.evil.com/x` 都会被误判为同源。
  assert.deepEqual(extractLinks('<a href="https://a.com:8443/x">', 'https://a.com/y', 10), [])
  assert.deepEqual(extractLinks('<a href="https://a.com.evil.com/x">', 'https://a.com/y', 10), [])
  assert.deepEqual(extractLinks('<a href="https://a.com:443/x">', 'https://a.com/y', 10).map((l) => l.url),
    ['https://a.com/x'], '默认端口与显式 :443 归一后同源')
})

// ---------- crt.sh 名单清洗 ----------

test('parseCrtShNames: 拆行、去 *、小写、只留目标域子域、去重排序截断', () => {
  const data = [
    { name_value: '*.Example.com\nwww.example.com' },
    { name_value: 'WWW.example.com' },
    { name_value: 'other.com' },
    { name_value: 'a.example.com' },
  ]
  // 真实语义：判定是 `n.endsWith('.example.com')`（带点）⇒ **apex 本身不算子域**，
  // `*.Example.com` 去掉 `*.` 后得到 apex 因而被丢弃。这不是缺陷，是子域枚举的正确定义。
  assert.deepEqual(parseCrtShNames(data, 'example.com', 10), ['a.example.com', 'www.example.com'])
  assert.deepEqual(parseCrtShNames(data, 'example.com', 1), ['a.example.com'])
})

test('parseCrtShNames: 失败/退化路径——非数组、缺字段、空白行、超长名一律安全跳过', () => {
  assert.deepEqual(parseCrtShNames(null, 'example.com', 5), [])
  assert.deepEqual(parseCrtShNames({}, 'example.com', 5), [])
  assert.deepEqual(parseCrtShNames([{}], 'example.com', 5), [])
  assert.deepEqual(parseCrtShNames([{ name_value: '\n  \n' }], 'example.com', 5), [])
  assert.deepEqual(parseCrtShNames([{ name_value: 'x'.repeat(120) + '.example.com' }], 'example.com', 5), [])
  assert.deepEqual(parseCrtShNames([{ name_value: 'notexample.com' }], 'example.com', 5), [], '后缀必须带点：notexample.com 不是子域')
})

// ---------- CVE 归一 ----------

test('mapCves: 取 CVSS v3.1 优先 / 回落 v2；按分数降序；字段裁剪', () => {
  const data = {
    vulnerabilities: [
      { cve: { id: 'CVE-1', metrics: { cvssMetricV31: [{ cvssData: { baseScore: 5.5, baseSeverity: 'MEDIUM' } }] }, descriptions: [{ lang: 'en', value: 'd1' }] } },
      { cve: { id: 'CVE-2', metrics: { cvssMetricV2: [{ cvssData: { baseScore: 9.8, baseSeverity: 'HIGH' } }] }, descriptions: [{ lang: 'en', value: 'd2' }], references: [{ url: 'https://github.com/poc' }] } },
    ],
  }
  const out = mapCves(data, 8)
  assert.deepEqual(out.map((c) => c.id), ['CVE-2', 'CVE-1'])
  assert.equal(out[0].cvss, 9.8)
  assert.equal(out[0].exploitRef, true)
  assert.equal(out[1].exploitRef, false)
})

test('mapCves: 退化路径——空/坏响应、缺 metrics、缺 desc 一律安全（cvss=null, severity=UNKNOWN）', () => {
  assert.deepEqual(mapCves(null, 5), [])
  assert.deepEqual(mapCves({}, 5), [])
  assert.deepEqual(mapCves({ vulnerabilities: [] }, 5), [])
  const out = mapCves({ vulnerabilities: [{ cve: { id: 'CVE-X' } }] }, 5)
  assert.deepEqual(out, [{ id: 'CVE-X', cvss: null, severity: 'UNKNOWN', description: '', exploitRef: false }])
})

test('mapCves: cvss 缺失记 0 参与排序（null 不抛错）且 limit 截断', () => {
  const data = { vulnerabilities: [{ cve: { id: 'A' } }, { cve: { id: 'B', metrics: { cvssMetricV31: [{ cvssData: { baseScore: 1 } }] } } }] }
  assert.deepEqual(mapCves(data, 5).map((c) => c.id), ['B', 'A'])
  assert.equal(mapCves(data, 1).length, 1)
  assert.equal(mapCves(data, 0).length, 0)
})
