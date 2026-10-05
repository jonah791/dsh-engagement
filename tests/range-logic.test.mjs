/**
 * logic.ts 纯函数套件（离线、无 IO、无网络、无子进程）。
 * 覆盖：正常路径 + 失败/退化路径（空值、脏类型、非法编码、越界、probe 抛错）——后者是 S6 判据。
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  shellQuote, buildCurlCmd, parseCurlOutput, buildSshCmd, buildPostBody, buildGetPath,
  basicAuthOf, normalizeCharset, charsetBounds, buildCond, bisectExtract, judgeProbe,
  defaultSleepThresholdMs,
} from '../lib/range-logic.js'

/** 与实现同源的 shell 单引号转义（测试侧独立实现，避免「用被测函数测被测函数」） */
const q = (s) => "'" + String(s).replace(/'/g, "'\\''") + "'"
/** 攻击样本：闭合单引号 → 注入命令 → 再开一个引号 */
const HOSTILE = "x'; touch /tmp/dsh-pwned; '"

/* ── shellQuote ── */

test('shellQuote: 正常路径——整体包单引号，内部单引号转义为 \'\\\'\'', () => {
  assert.equal(shellQuote('abc'), "'abc'")
  assert.equal(shellQuote("it's"), "'it'\\''s'")
  assert.equal(shellQuote(''), "''")
  assert.equal(shellQuote(22), "'22'", '数字也转成字符串再包引号')
})

test('shellQuote: 退化路径——非字符串不抛（String() 兜底）', () => {
  assert.equal(shellQuote(undefined), "'undefined'")
  assert.equal(shellQuote(null), "'null'")
})

/* ── buildCurlCmd：结构与注入防线 ── */

test('buildCurlCmd: 正常路径——最小形态（只有 host）', () => {
  assert.equal(buildCurlCmd({ host: 'natas0.natas.labs.overthewire.org' }),
    `curl -s --noproxy "*" --max-time 20 -w '\\n%{http_code}' 'http://natas0.natas.labs.overthewire.org/'`)
})

test('buildCurlCmd: 正常路径——各开关按序出现，值为真才加', () => {
  const cmd = buildCurlCmd({ host: 'h', user: 'u', pass: 'p', cookie: 'c=1', userAgent: 'UA', resolveIp: '1.2.3.4', method: 'POST', data: 'a=b' })
  assert.match(cmd, /--resolve 'h:80:1\.2\.3\.4' /)
  assert.match(cmd, /-u 'u:p' /)
  assert.match(cmd, /-b 'c=1' /)
  assert.match(cmd, /-A 'UA' /)
  assert.match(cmd, /-d 'a=b' /)
  assert.ok(!buildCurlCmd({ host: 'h', method: 'GET', data: 'a=b' }).includes('-d '), 'GET 不带 -d')
  assert.ok(!buildCurlCmd({ host: 'h', path: '/x' }).includes('--resolve'), '无 resolveIp 不加 --resolve')
})

test('buildCurlCmd: 退化路径——空串等价于缺省（不产生空 flag）', () => {
  const cmd = buildCurlCmd({ host: 'h', user: '', cookie: '', userAgent: '', data: '', resolveIp: '' })
  assert.equal(cmd, `curl -s --noproxy "*" --max-time 20 -w '\\n%{http_code}' 'http://h/'`)
  // 真实语义：`args.path ?? '/'` 只兜 null/undefined，**空串 path 会产出 http://h**（不是 http://h/）
  assert.match(buildCurlCmd({ host: 'h', path: '' }), /'http:\/\/h'$/)
})

/** 注入防线通用断言：raw 形态必须不存在、转义形态必须存在 */
function assertNoEscape(cmd, raw, label) {
  assert.ok(!cmd.includes(raw), `${label}: 未转义样本出现在命令里 → 可逃逸出引号执行任意命令`)
}

test('buildCurlCmd: 注入防线——user/pass/cookie/userAgent/data/host/path/resolveIp 全部转义', () => {
  const cmd = buildCurlCmd({
    host: HOSTILE, user: HOSTILE, pass: HOSTILE, cookie: HOSTILE, userAgent: HOSTILE,
    resolveIp: HOSTILE, method: 'POST', data: HOSTILE, path: '/p',
  })
  assertNoEscape(cmd, `-u '${HOSTILE}:`, 'user')
  assertNoEscape(cmd, `-b '${HOSTILE}'`, 'cookie')
  assertNoEscape(cmd, `-A '${HOSTILE}'`, 'userAgent')
  assertNoEscape(cmd, `-d '${HOSTILE}'`, 'data')
  assertNoEscape(cmd, `http://${HOSTILE}`, 'host')
  assertNoEscape(cmd, `--resolve ${HOSTILE}`, 'resolveIp')
  // 转义形态必须真的在位
  assert.ok(cmd.includes(q(`${HOSTILE}:${HOSTILE}`)), 'user:pass 必须以转义形态出现')
  assert.ok(cmd.includes(q(HOSTILE)), 'cookie/UA/data 必须以转义形态出现')
  assert.ok(cmd.includes(q(`http://${HOSTILE}/p`)), 'URL 必须以转义形态出现')
})

test('尸体测试：注入防线断言在「修复前形态」上确实失败（否则断言是摆设）', () => {
  const preFix = `curl -s -b '${HOSTILE}' 'http://h/'` // 复刻修复前的 `-b '${cookie}'`
  assert.throws(() => assertNoEscape(preFix, `-b '${HOSTILE}'`, 'corpse'), /未转义样本/)
})

/* ── parseCurlOutput ── */

test('parseCurlOutput: 正常路径——末行是 http_code，其余是 body', () => {
  assert.deepEqual(parseCurlOutput('hello\nworld\n200'), { status: 200, body: 'hello\nworld', truncated: false })
})

test('parseCurlOutput: 退化路径——只有一行时 status=0 且 body=整串（真实语义，不抛）', () => {
  assert.deepEqual(parseCurlOutput('just-body'), { status: 0, body: 'just-body', truncated: false })
})

test('parseCurlOutput: 失败路径——末行非数字时 status=0（Number(...)||0）', () => {
  assert.equal(parseCurlOutput('body\nnot-a-code').status, 0)
  assert.equal(parseCurlOutput('body\n').status, 0, '空末行同理')
})

test('parseCurlOutput: 边界——超长 body 截断并置 truncated；maxChars=0 时全截', () => {
  const long = 'a'.repeat(50) + '\n200'
  assert.deepEqual(parseCurlOutput(long, 10), { status: 200, body: 'a'.repeat(10), truncated: true })
  assert.deepEqual(parseCurlOutput(long, 50), { status: 200, body: 'a'.repeat(50), truncated: false })
  assert.equal(parseCurlOutput(long, 0).truncated, true)
  assert.equal(parseCurlOutput('', 10).body, '')
})

/* ── buildSshCmd ── */

test('buildSshCmd: 正常路径——sshpass + ProxyCommand + 端口 + 远程命令', () => {
  const cmd = buildSshCmd({ host: 'bandit.labs.overthewire.org', port: 2220, user: 'bandit0', pass: 'p0', command: 'ls -la', proxyHost: '127.0.0.1', proxyPort: 16888 })
  assert.equal(cmd, "sshpass -p 'p0' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=15 -o ProxyCommand='nc -X connect -x 127.0.0.1:16888 %h %p' 'bandit0@bandit.labs.overthewire.org' -p '2220' 'ls -la'")
})

test('buildSshCmd: 注入防线——pass/user/host/command 全部转义（命令由 WSL bash 执行）', () => {
  const cmd = buildSshCmd({ host: HOSTILE, port: 22, user: HOSTILE, pass: HOSTILE, command: HOSTILE, proxyHost: HOSTILE, proxyPort: 1 })
  assertNoEscape(cmd, `-p '${HOSTILE}' ssh`, 'pass')
  assertNoEscape(cmd, `${HOSTILE}@`, 'user')
  assertNoEscape(cmd, `'${HOSTILE}'`, 'command/pass 原样引号形态')
  assert.ok(cmd.includes(q(`${HOSTILE}@${HOSTILE}`)), 'user@host 必须以转义形态出现')
  assert.ok(cmd.includes(q(HOSTILE)), '远程命令必须以转义形态出现')
})

/* ── 盲注请求构造 ── */

test('buildPostBody: 正常路径——解析固定参数并覆盖注入参数', () => {
  assert.equal(buildPostBody('username=admin&password=x', 'username', 'a" OR 1=1-- '), 'username=a%22+OR+1%3D1--+&password=x')
})

test('buildPostBody: 退化路径——空 data / 无等号段 / 重复键（后者覆盖）', () => {
  assert.equal(buildPostBody('', 'p', 'v'), 'p=v')
  assert.equal(buildPostBody('k', 'p', 'v'), 'k=&p=v', '真实语义：无 = 的段以空值加入')
  assert.equal(buildPostBody('a=1&a=2', 'p', 'v'), 'a=1&a=2&p=v')
  assert.equal(buildPostBody('a=1&a=2', 'a', 'v'), 'a=v', '真实语义：append 后 set 覆盖为首个')
})

test('buildPostBody: 失败路径——非法百分号编码抛 URIError（不静默）', () => {
  assert.throws(() => buildPostBody('a=%E0%A4%A', 'p', 'v'), URIError)
})

test('buildGetPath: 正常路径——保留原 query 并覆盖注入参数', () => {
  const u = new URL('http://h/s?x=1&y=2')
  assert.equal(buildGetPath(u, 'y', 'Z z'), '/s?x=1&y=Z+z')
  assert.equal(buildGetPath(new URL('http://h/s'), 'y', 'Z'), '/s?y=Z')
})

test('basicAuthOf: 正常路径——user:pass 转 Basic 头；无凭据时不给头', () => {
  const withAuth = basicAuthOf(new URL('http://natas0:secret@h/'))
  assert.equal(withAuth.host, 'h')
  assert.equal(withAuth.authorization, 'Basic ' + Buffer.from('natas0:secret').toString('base64'))
  assert.equal(basicAuthOf(new URL('http://h/')).authorization, undefined)
})

test('basicAuthOf: 失败路径——非法百分号编码抛 URIError', () => {
  assert.throws(() => basicAuthOf(new URL('http://a%ZZ:b@h/')), URIError)
})

/* ── 字符集 / 条件 SQL ── */

test('normalizeCharset: 三种内建形态 + 自定义（均已排序）', () => {
  const alnum = normalizeCharset('alnum')
  assert.equal(alnum.length, 62)
  assert.deepEqual(alnum, [...alnum].sort())
  assert.equal(normalizeCharset('printable').length, 95)
  assert.deepEqual(normalizeCharset('zyx'), ['x', 'y', 'z'], '自定义字符集按字符拆分并排序')
})

test('normalizeCharset: 退化路径——空串得到空数组（不抛）', () => {
  assert.deepEqual(normalizeCharset(''), [])
})

test('charsetBounds: 正常路径取码点极值；退化路径（空集）回落 32/126', () => {
  assert.deepEqual(charsetBounds(['0', '9', 'A', 'z']), { csMin: 48, csMax: 122 })
  assert.deepEqual(charsetBounds([]), { csMin: 32, csMax: 126 }, '空集不得得 Infinity')
})

test('buildCond: ascii_gt / ascii_eq / like_prefix（后者真实语义等同 ascii_gt）', () => {
  assert.equal(buildCond('ascii_gt', 'password', 3, 97), 'ASCII(SUBSTRING(password,3,1)) > 97')
  assert.equal(buildCond('ascii_eq', 'password', 3, 97), 'ASCII(SUBSTRING(password,3,1)) = 97')
  assert.equal(buildCond('like_prefix', 'password', 3, 97), 'ASCII(SUBSTRING(password,3,1)) > 97')
  assert.equal(buildCond('unknown', 'pw', 1, 50), 'ASCII(SUBSTRING(pw,1,1)) > 50', '未知模式回落 ascii_gt')
})

/* ── bisectExtract（probe 注入，离线可测） ── */

/** 用「目标字符串」造一个假 probe：条件为真 ⟺ 目标位字符码 > asc（与 ascii_gt 同构） */
function fakeProbe(target) {
  return async (cond) => {
    const m = /SUBSTRING\((\w+),(\d+),1\)\) > (\d+)/.exec(cond)
    if (!m) throw new Error('bad cond: ' + cond)
    const pos = Number(m[2])
    const asc = Number(m[3])
    const ch = target[pos - 1]
    if (ch === undefined) return false // 越界：恒假 → hi 落到 csMin-1 之下 → break
    return ch.charCodeAt(0) > asc
  }
}

const CS = normalizeCharset('alnum')
const BOUNDS = charsetBounds(CS)

test('bisectExtract: 正常路径——二分提取出完整目标串（maxLen 恰为目标长度）', async () => {
  const target = 'aB3z'
  const r = await bisectExtract({ probe: fakeProbe(target), chars: CS, ...BOUNDS, maxLen: target.length, condType: 'ascii_gt', expr: 'password' })
  assert.equal(r.result, target)
  assert.equal(r.error, undefined)
})

test('bisectExtract: 已知局限——maxLen 大于目标长度时会补 `0`（尾随填充，非错误）', async () => {
  // 真实语义：调用方必须给出准确 maxLen；多给的长度会被 '0' 填满（SQL 侧 ASCII('')=0 → 收敛到 csMin）。
  // 这是设计局限而非缺陷（工具参数文档写明 maxLen=最大提取长度），已记入 §10。
  const r = await bisectExtract({ probe: fakeProbe('aB3z'), chars: CS, ...BOUNDS, maxLen: 6, condType: 'ascii_gt', expr: 'password' })
  assert.equal(r.result, 'aB3z00')
})

test('bisectExtract: 边界——超过 maxLen 即停（结果被截断为 maxLen 位）', async () => {
  const r = await bisectExtract({ probe: fakeProbe('abcdef'), chars: CS, ...BOUNDS, maxLen: 3, condType: 'ascii_gt', expr: 'p' })
  assert.equal(r.result, 'abc')
})

test('bisectExtract: 退化路径——目标耗尽后**不会自然终止**，收敛到字符集最小值并追加到 maxLen', async () => {
  // 真实语义（重要陷阱）：越界时 SQL 侧 ASCII('')=0 ⇒ 条件恒假 ⇒ 二分收敛到 csMin = '0'，
  // 而 '0' 在字符集内 ⇒ 继续追加。故**算法本身不感知字符串结尾**，终止完全依赖调用方给的 maxLen。
  const r = await bisectExtract({ probe: fakeProbe('ab'), chars: CS, ...BOUNDS, maxLen: 5, condType: 'ascii_gt', expr: 'p' })
  assert.equal(r.result, 'ab000')
})

test('bisectExtract: 失败路径——目标字符码 > csMax 时越界终止（hi > csMax → break）', async () => {
  const r = await bisectExtract({ probe: fakeProbe('ab{c'), chars: CS, ...BOUNDS, maxLen: 10, condType: 'ascii_gt', expr: 'p' })
  assert.equal(r.result, 'ab', "'{' (123) 超出 alnum 上界 122 → 立即终止")
})

test('bisectExtract: 失败路径——目标字符不在字符集内时终止（落在 alnum 的空隙 58-64/91-96）', async () => {
  const r = await bisectExtract({ probe: fakeProbe('ab<c'), chars: CS, ...BOUNDS, maxLen: 10, condType: 'ascii_gt', expr: 'p' })
  assert.equal(r.result, 'ab', "'<' (60) 在 alnum 空隙内 → 终止（不产出杂字符）")
})

test('bisectExtract: 失败路径——probe 抛错时保留已提取前缀并回传 error（不丢进度）', async () => {
  let n = 0
  const target = 'aBc'
  const probe = async (cond) => {
    if (++n > 12) throw new Error('network jitter')
    return fakeProbe(target)(cond)
  }
  const r = await bisectExtract({ probe, chars: CS, ...BOUNDS, maxLen: 10, condType: 'ascii_gt', expr: 'p' })
  assert.ok(r.error, '必须回传 error')
  assert.match(r.error, /network jitter/)
  assert.ok(target.startsWith(r.result), `已提取前缀必须是目标的真前缀：${r.result}`)
})

/* ── judgeProbe / 阈值 ── */

test('judgeProbe: time 模式取 3 样本的中位数与阈值比较（抗单次抖动）', () => {
  assert.equal(judgeProbe('time', [5000, 100, 120], [], 1000, ''), false, '排序后中位数 120 ≤ 1000 → 假')
  assert.equal(judgeProbe('time', [120, 5000, 4000], [], 1000, ''), true, '排序后中位数 4000 > 1000 → 真')
  assert.equal(judgeProbe('time', [], [], 1000, ''), false, '空样本 → (undefined ?? 0) → 假')
  assert.equal(judgeProbe('time', [3000], [], 1000, ''), false, '单样本时 [1] 为 undefined → 0 → 假（真实语义）')
})

test('judgeProbe: bool 模式看多数（≥2/3 命中 trueText）', () => {
  assert.equal(judgeProbe('bool', [], ['hit', 'hit', 'miss'], 0, 'hit'), true)
  assert.equal(judgeProbe('bool', [], ['hit', 'miss', 'miss'], 0, 'hit'), false)
  assert.equal(judgeProbe('bool', [], ['', '', ''], 0, ''), true, '真实语义：trueText 为空串时 includes("") 恒真')
})

test('defaultSleepThresholdMs: SLEEP 的 60% 与 1200ms 下界', () => {
  assert.equal(defaultSleepThresholdMs(2), 1200)
  assert.equal(defaultSleepThresholdMs(5), 3000)
  assert.equal(defaultSleepThresholdMs(0), 1200)
})
