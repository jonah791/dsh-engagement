/**
 * commands.ts 纯函数套件（离线、零网络、零 WSL）。
 * 覆盖：正常路径 + 失败/退化路径（注入尝试、类型不符、空值、非法 target/url）。
 * 安全不变量（S6 判据）：受校验参数必须被 `sq()` 包裹而无法逃逸；
 * 原样拼接参数（extra/scanType/ports/mode/service）必须过 `unsafeArg()` 闸门。
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  sq, validUrl, validTarget, validWord, hasShellMeta, unsafeArg,
  buildNmapCmd, buildMasscanCmd, buildGobusterCmd, buildSubfinderCmd, buildWhatwebCmd, buildDnsreconCmd,
  buildSqlmapCmd, buildNiktoCmd, buildHydraCmd, buildHashcatCmd, buildJohnCmd,
} from '../lib/sec-commands.js'
import { runNmap, runGobuster, runMasscan } from '../lib/sec-recon.js'
import { runHydra, runSqlmap } from '../lib/sec-attack.js'

// ---------- sq ----------

test('sq: 单引号包裹且转义内部单引号（注入不可逃逸）', () => {
  assert.equal(sq('abc'), "'abc'")
  assert.equal(sq("a'b"), "'a'\\''b'")
  assert.equal(sq(''), "''")
  assert.equal(sq('; rm -rf /'), "'; rm -rf /'")
})

test('sq: 退化路径——引号/反引号/换行全部被包在引号内，不产生新的命令边界', () => {
  for (const evil of ["'; id; '", '`id`', '$(id)', 'a\nb']) {
    const q = sq(evil)
    assert.equal(q.startsWith("'") && q.endsWith("'"), true)
    assert.equal(q.includes('\\\''), evil.includes("'"), `未正确转义单引号：${evil}`)
  }
})

// ---------- validUrl / validTarget / validWord ----------

test('validUrl: 正常 http/https 通过', () => {
  assert.equal(validUrl('http://example.com/a?b=1').ok, true)
  assert.equal(validUrl('HTTPS://example.com').ok, true)
})

test('validUrl: 失败路径——缺 scheme / 含 shell 元字符 / 空格 / 空串一律拒绝', () => {
  for (const bad of ['example.com', 'ftp://x', 'http://a b', 'http://a;id', 'http://a|id', 'http://a$(id)',
    'http://a`id`', 'http://a&b', 'http://a>b', '']) {
    const r = validUrl(bad)
    assert.equal(r.ok, false, `${JSON.stringify(bad)} 应被拒绝`)
    assert.ok(r.error.length > 0)
  }
})

test('validTarget: 域名/IP 通过；无点、前导连字符、元字符、空串拒绝', () => {
  assert.equal(validTarget('example.com'), true)
  assert.equal(validTarget('10.0.0.1'), true)
  assert.equal(validTarget('sub.a-b.co'), true)
  for (const bad of ['localhost', '-x.com', 'a;b.com', 'a b.com', '', 'a$(b).com', 'a/*.com']) {
    assert.equal(validTarget(bad), false, `${JSON.stringify(bad)} 应被拒绝`)
  }
})

test('validWord: 字母数字下划线连字符通过；其余拒绝', () => {
  assert.equal(validWord('id_1-a'), true)
  assert.equal(validWord('a b'), false)
  assert.equal(validWord('a;b'), false)
  assert.equal(validWord(''), false)
})

// ---------- hasShellMeta / unsafeArg ----------

test('hasShellMeta: 不含空格（nmap extra 合法含空格），拦元字符与换行', () => {
  assert.equal(hasShellMeta('-O -A --script=vuln'), false, '合法多参数不得被拦')
  assert.equal(hasShellMeta('1-1000'), false)
  assert.equal(hasShellMeta('dir'), false)
  assert.equal(hasShellMeta('ssh'), false)
  for (const bad of ['; id', 'a|b', 'a&b', '`id`', '$(id)', 'a>b', 'a<b', 'a{b}', 'a"b', "a'b", 'a\nb', 'a\\b']) {
    assert.equal(hasShellMeta(bad), true, `${JSON.stringify(bad)} 应被判为元字符`)
  }
})

test('unsafeArg: 放行合法值（含空格的多参数）；拒绝注入；空值不报错', () => {
  assert.equal(unsafeArg(undefined), null)
  assert.equal(unsafeArg(''), null)
  assert.equal(unsafeArg('-O -A'), null)
  assert.equal(unsafeArg('dir'), null)
  assert.match(unsafeArg('; rm -rf /'), /含 shell 元字符/)
  assert.match(unsafeArg('$(id)', 'service'), /^service 含 shell 元字符/)
  assert.match(unsafeArg(123), /类型不符/)
})

// ---------- 命令构造（正常路径） ----------

test('buildNmapCmd: 默认 -F + -sV；指定 ports/scanType/extra 时组合正确', () => {
  assert.equal(buildNmapCmd({ target: 'a.com' }), "nmap -sV -F --open 'a.com' 2>&1")
  assert.equal(buildNmapCmd({ target: 'a.com', ports: '80,443', scanType: '-sS', extra: '-O' }),
    "nmap -sS -p '80,443' -O --open 'a.com' 2>&1")
  assert.equal(buildNmapCmd({ target: 'a.com', scanType: 'sS' }), "nmap -sS -F --open 'a.com' 2>&1")
})

test('buildMasscanCmd / buildGobusterCmd / buildSubfinderCmd: 默认值与标志位', () => {
  assert.equal(buildMasscanCmd({ target: 'a.com' }), "masscan 'a.com' -p1-1000 --rate 1000 2>&1")
  assert.equal(buildMasscanCmd({ target: 'a.com', ports: '80', rate: 500 }), "masscan 'a.com' -p80 --rate 500 2>&1")
  assert.equal(buildGobusterCmd({ url: 'http://a.com' }),
    "gobuster dir -u 'http://a.com' -w '/usr/share/wordlists/dirb/common.txt' -t 20 2>&1")
  assert.equal(buildGobusterCmd({ url: 'http://a.com', mode: 'dns', wordlist: '/w.txt', extensions: 'php,html' }),
    "gobuster dns -u 'http://a.com' -w '/w.txt' -x 'php,html' -t 20 2>&1")
  assert.equal(buildSubfinderCmd({ domain: 'a.com' }), "subfinder -d 'a.com' -silent 2>&1")
  assert.equal(buildSubfinderCmd({ domain: 'a.com', recursive: true, active: true }),
    "subfinder -d 'a.com' -recursive -active -silent 2>&1")
})

test('buildWhatwebCmd / buildDnsreconCmd: 默认 a=3 / type=std', () => {
  assert.equal(buildWhatwebCmd({ url: 'http://a.com' }), "whatweb -a 3 'http://a.com' 2>&1")
  assert.equal(buildDnsreconCmd({ domain: 'a.com' }), "dnsrecon -d 'a.com' -t 'std' 2>&1")
  assert.equal(buildDnsreconCmd({ domain: 'a.com', type: 'brt' }), "dnsrecon -d 'a.com' -t 'brt' 2>&1")
})

test('buildSqlmapCmd: action 分支（dbs/current-db/tables 带库/dump 带库表/未知回落 dbs）', () => {
  assert.equal(buildSqlmapCmd({ url: 'http://a.com/?id=1' }),
    "sqlmap -u 'http://a.com/?id=1' --dbs --batch --level 1 --risk 1 2>&1")
  assert.equal(buildSqlmapCmd({ url: 'u', param: 'id' }), "sqlmap -u 'u' -p 'id' --dbs --batch --level 1 --risk 1 2>&1")
  assert.match(buildSqlmapCmd({ url: 'u', action: 'tables', db: 'd' }), /-D 'd' --tables/)
  assert.match(buildSqlmapCmd({ url: 'u', action: 'tables' }), /--tables --batch/)
  assert.match(buildSqlmapCmd({ url: 'u', action: 'dump', db: 'd', table: 't' }), /-D 'd' -T 't' --dump/)
  assert.match(buildSqlmapCmd({ url: 'u', action: 'dump' }), /--dump --batch/)
  assert.match(buildSqlmapCmd({ url: 'u', action: 'current-db' }), /--current-db/)
  const unknown = buildSqlmapCmd({ url: 'u', action: 'nope' })
  assert.match(unknown, /--dbs/, '未知 action 回落 --dbs（保守：不做破坏性动作）')
})

test('buildNiktoCmd / buildHydraCmd: 默认与凭据分支', () => {
  assert.equal(buildNiktoCmd({ url: 'http://a.com' }), "nikto -h 'http://a.com' -nointeractive 2>&1")
  assert.equal(buildNiktoCmd({ url: 'http://a.com', tune: 1 }), "nikto -h 'http://a.com' -Tuning 1 -nointeractive 2>&1")
  assert.equal(buildHydraCmd({ target: 'a.com', service: 'ssh' }), "hydra  -f 'a.com' ssh 2>&1")
  // 2026-09-14 修复的真缺陷：原实现在 user+pass 时把密码拼两遍 → `'u':'p':'p'`
  // （hydra 按首个冒号切分 ⇒ 密码成为 "p:p"，凭据永远不匹配）。本条即证伪样本，修复后为 `'u':'p'`。
  assert.equal(buildHydraCmd({ target: 'a.com', service: 'ssh', user: 'u', pass: 'p' }),
    "hydra 'u':'p' -f 'a.com' ssh 2>&1")
  assert.equal(buildHydraCmd({ target: 'a.com', service: 'ssh', user: 'u' }), "hydra 'u'  -f 'a.com' ssh 2>&1")
  assert.equal(buildHydraCmd({ target: 'a.com', service: 'ssh', userlist: '/u.txt', passlist: '/p.txt' }),
    "hydra -L '/u.txt'  -P '/p.txt' -f 'a.com' ssh 2>&1")
  assert.match(buildHydraCmd({ target: 'a.com', service: 'x', form: '/login:u=^USER^' }),
    /http-post-form '\/login:u=\^USER\^'/, 'form 存在时 service 被替换为 http-post-form 字面量')
})

test('buildHashcatCmd / buildJohnCmd: 攻击模式 3 时不带字典；john 带 --show 二次调用', () => {
  assert.equal(buildHashcatCmd({ mode: 0, hash: 'h' }),
    "hashcat -m 0 -a 0 'h' '/usr/share/wordlists/rockyou.txt' --force --show 2>&1")
  assert.equal(buildHashcatCmd({ mode: 1000, hashFile: '/h.txt', attack: 3, mask: '?d?d' }),
    "hashcat -m 1000 -a 3 '/h.txt' '?d?d' --force --show 2>&1")
  assert.equal(buildJohnCmd({ hashFile: '/h.txt' }), "john '/h.txt' 2>&1; echo '---SHOW---'; john --show '/h.txt' 2>&1")
  assert.equal(buildJohnCmd({ hashFile: '/h.txt', format: 'raw-md5', wordlist: '/w.txt' }),
    "john --format='raw-md5' --wordlist='/w.txt' '/h.txt' 2>&1; echo '---SHOW---'; john --show '/h.txt' 2>&1")
})

// ---------- 原样拼接点：证明闸门存在的理由 ----------

test('构造器本身不做闸门（记录真语义）：extra/mode/service 原样进入命令行', () => {
  // 这**不是**缺陷复现，而是「为什么 runX 必须先过 unsafeArg」的证据：
  // 构造器只负责拼串，安全判定在调用方（单一职责）。runX 的闸门测试见下方。
  assert.ok(buildNmapCmd({ target: 'a.com', extra: '; id' }).includes('; id'))
  assert.ok(buildSqlmapCmd({ url: 'u', extra: '; id' }).includes('; id'))
  assert.ok(buildGobusterCmd({ url: 'http://a', mode: 'dir; id' }).startsWith('gobuster dir; id '))
})

test('受校验参数无法逃逸：单引号包裹 + 内部引号转义', () => {
  const cmd = buildNmapCmd({ target: "a.com'; id; '" })
  assert.ok(cmd.includes("'a.com'\\''; id; '\\'''"), `target 未安全包裹：${cmd}`)
  const h = buildHydraCmd({ target: 'a.com', service: 'ssh', user: "u'", pass: 'p' })
  assert.ok(h.includes("'u'\\'''"), `user 未安全包裹：${h}`)
})

// ---------- runX 闸门（离线：闸门在 toolExists 之前 → 不触碰 WSL） ----------

test('runNmap: extra/scanType 含元字符 → 拒绝且不进入 WSL（WSL 未安装 nmap 也不会走那条分支）', async () => {
  const r = await runNmap({ target: 'example.com', extra: '; id' })
  assert.equal(r.ok, false)
  assert.match(r.error, /extra 含 shell 元字符/)
  const r2 = await runNmap({ target: 'example.com', scanType: 'sV|id' })
  assert.match(r2.error, /scanType 含 shell 元字符/)
})

test('runNmap: target 非法优先于元字符闸门（校验顺序：格式 → 闸门 → 工具存在）', async () => {
  const r = await runNmap({ target: 'bad target', extra: '; id' })
  assert.match(r.error, /target 格式无效/)
})

test('runGobuster / runMasscan / runSqlmap / runHydra: 各自的元字符闸门生效', async () => {
  assert.match((await runGobuster({ url: 'http://a.com', mode: 'dir; id' })).error, /mode 含 shell 元字符/)
  assert.match((await runMasscan({ target: 'a.com', ports: '80; id' })).error, /ports 含 shell 元字符/)
  assert.match((await runSqlmap({ url: 'http://a.com', extra: '$(id)' })).error, /extra 含 shell 元字符/)
  assert.match((await runHydra({ target: 'a.com', service: 'ssh|id' })).error, /service 含 shell 元字符/)
})

test('闸门: 合法 extra（含空格的合法多参数）不被误拦（只问闸门，不跑 I/O）', () => {
  // ⚠ 2026-10-04 移植时改写。原版是 `await runNmap({ target: 'example.com', extra: '-O -A' })`
  //    ——它会**真的执行 nmap**（本机实测 45 秒，含工具探测与网络），违反本套件开头声明的
  //    前提「离线、零网络、零 WSL」，并把整仓测试从秒级拖成分钟级。
  //    判据**意图不变**（合法的含空格多参数必须被闸门放行），改为直接问闸门本身：
  //    `unsafeArg` 返回 null = 放行，返回字符串 = 拒绝原因。I/O 层归 live-path 套件。
  assert.equal(unsafeArg('-O -A'), null)
  assert.equal(unsafeArg('-p 80,443 --script vuln'), null)
})
