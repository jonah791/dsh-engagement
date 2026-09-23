/**
 * dsh-sec-tools — 命令构造与参数校验层（纯函数，零 IO，可离线单测）
 *
 * 2026-09-14 可维护性补课：原先每个 runX 都是「校验 → 构造命令 → spawnWsl」揉在一起，
 * **命令怎么拼**这层判定无法离线验证。本次把构造与校验抽到本模块（**仅搬家**，命令逐字不变），
 * runX 只剩「校验（含安全闸）→ toolExists → spawnWsl(build…Cmd(opts))」。
 *
 * 不变量（tests/commands.test.mjs 锁住）：
 *   1. 受校验参数（target/url/wordlist/hash/format…）一律 `sq()` 单引号包裹，注入不可逃逸
 *   2. 少数「原样拼接」参数（nmap.extra / nmap.scanType / masscan.ports / gobuster.mode /
 *      sqlmap.extra / hydra.service）走 `unsafeArg()` 闸门：含 shell 元字符即拒绝（纵深防御）
 *   3. 校验函数对非法输入返回 `{ok:false,error}` / `false`，**绝不抛错**
 */

/** 参数安全：单引号包裹并转义（WSL bash 内） */
export function sq(v: string): string {
  return "'" + v.replace(/'/g, "'\\''") + "'"
}

/** URL 校验：http(s):// 开头 + 禁止 shell 特殊字符（纵深防御，不只靠 sq 包裹） */
export function validUrl(v: string): { ok: boolean; error?: string } {
  if (!/^https?:\/\//i.test(v)) return { ok: false, error: 'url 需 http(s):// 开头' }
  if (/[;|&`$(){}<>"\\\s]/.test(v)) return { ok: false, error: 'url 含特殊字符（禁止 ; | & ` $ 空格 等 shell 元字符）' }
  return { ok: true }
}

/** 校验目标 host 格式（域名/IP，防命令注入） */
export function validTarget(v: string): boolean {
  return /^[a-zA-Z0-9.-]+$/.test(v) && v.includes('.') && !v.startsWith('-')
}

/** 校验纯字母数字标识（如接口名） */
export function validWord(v: string): boolean {
  return /^[a-zA-Z0-9_-]+$/.test(v)
}

/** shell 元字符检测（不含空格：nmap `extra` 这类参数**合法含空格**，如 `-O -A`） */
export function hasShellMeta(v: string): boolean {
  return /[;|&`$(){}<>"'\\\n\r]/.test(v)
}

/**
 * 原样拼接参数的闸门：返回错误文本 = 拒绝；返回 null = 放行。
 * 用于 nmap.extra / nmap.scanType / masscan.ports / gobuster.mode / sqlmap.extra / hydra.service
 * ——这些参数在命令里**不加引号**（要保持「多参数展开」语义），因此必须自己挡元字符。
 */
export function unsafeArg(v: string | undefined, name = '参数'): string | null {
  if (v === undefined || v === '') return null
  if (typeof v !== 'string') return `${name} 类型不符（需字符串）`
  return hasShellMeta(v) ? `${name} 含 shell 元字符（禁止 ; | & \` $ ( ) { } < > 引号 换行）：${v}` : null
}

// ═══════════════ 侦察面 ═══════════════

export function buildNmapCmd(o: { target: string; ports?: string; scanType?: string; extra?: string }): string {
  const portFlag = o.ports ? `-p ${sq(o.ports)}` : '-F' // -F = 快速常见端口
  const scanFlag = o.scanType ? `-${o.scanType.replace(/^-/, '')}` : '-sV'
  const extraFlag = o.extra ? ` ${o.extra}` : ''
  return `nmap ${scanFlag} ${portFlag}${extraFlag} --open ${sq(o.target)} 2>&1`
}

export function buildMasscanCmd(o: { target: string; ports?: string; rate?: number }): string {
  const ports = o.ports ?? '1-1000'
  const rate = o.rate ?? 1000
  return `masscan ${sq(o.target)} -p${ports} --rate ${rate} 2>&1`
}

export function buildGobusterCmd(o: { url: string; mode?: string; wordlist?: string; extensions?: string }): string {
  const mode = o.mode ?? 'dir'
  const wl = o.wordlist ?? '/usr/share/wordlists/dirb/common.txt'
  const extFlag = o.extensions ? ` -x ${sq(o.extensions)}` : ''
  return `gobuster ${mode} -u ${sq(o.url)} -w ${sq(wl)}${extFlag} -t 20 2>&1`
}

export function buildSubfinderCmd(o: { domain: string; recursive?: boolean; active?: boolean }): string {
  const recFlag = o.recursive ? ' -recursive' : ''
  const activeFlag = o.active ? ' -active' : ''
  return `subfinder -d ${sq(o.domain)}${recFlag}${activeFlag} -silent 2>&1`
}

export function buildWhatwebCmd(o: { url: string; agility?: number }): string {
  const a = o.agility ?? 3
  return `whatweb -a ${a} ${sq(o.url)} 2>&1`
}

export function buildDnsreconCmd(o: { domain: string; type?: string }): string {
  const type = o.type ?? 'std'
  return `dnsrecon -d ${sq(o.domain)} -t ${sq(type)} 2>&1`
}

// ═══════════════ 利用面 ═══════════════

export function buildSqlmapCmd(o: {
  url: string; param?: string; action?: 'dbs' | 'tables' | 'dump' | 'current-db'
  db?: string; table?: string; level?: number; risk?: number; extra?: string
}): string {
  const paramFlag = o.param ? ` -p ${sq(o.param)}` : ''
  const action = o.action ?? 'dbs'
  const actionFlag = action === 'dbs' ? '--dbs'
    : action === 'current-db' ? '--current-db'
    : action === 'tables' ? (o.db ? `-D ${sq(o.db)} --tables` : '--tables')
    : action === 'dump' ? (o.db && o.table ? `-D ${sq(o.db)} -T ${sq(o.table)} --dump` : '--dump')
    : '--dbs'
  const lvl = o.level ?? 1
  const rsk = o.risk ?? 1
  const extraFlag = o.extra ? ` ${o.extra}` : ''
  return `sqlmap -u ${sq(o.url)}${paramFlag} ${actionFlag} --batch --level ${lvl} --risk ${rsk}${extraFlag} 2>&1`
}

export function buildNiktoCmd(o: { url: string; tune?: number }): string {
  const tuneFlag = o.tune ? ` -Tuning ${o.tune}` : ''
  return `nikto -h ${sq(o.url)}${tuneFlag} -nointeractive 2>&1`
}

export function buildHydraCmd(o: {
  target: string; service: string; user?: string; pass?: string
  userlist?: string; passlist?: string; port?: number; threads?: number; form?: string
}): string {
  const cred = o.user && o.pass
    ? `${sq(o.user)}:${sq(o.pass)}`
    : o.user
    ? `${sq(o.user)} `
    : o.userlist ? `-L ${sq(o.userlist)} ` : ''
  // 2026-09-14 修复：user+pass 时 cred 已含密码，原实现再拼一次 → `hydra 'u':'p':'p'`
  // （hydra 按首个冒号切分 ⇒ 密码变成 "p:p"，凭据永远错）。只在**未走 user+pass 分支**时补密码段。
  const passPart = (o.user && o.pass) ? ''
    : o.pass ? `:${sq(o.pass)}`
    : o.passlist ? ` -P ${sq(o.passlist)}` : ''
  const portFlag = o.port ? ` -s ${o.port}` : ''
  const thrFlag = o.threads ? ` -t ${o.threads}` : ''
  // 处理 http-post-form 特殊协议（service 参数含 :// 形式）
  const servicePart = o.form
    ? `http-post-form ${sq(o.form)}`
    : `${o.service}`
  return `hydra ${cred}${passPart}${portFlag}${thrFlag} -f ${sq(o.target)} ${servicePart} 2>&1`
}

// ═══════════════ 密码面 ═══════════════

export function buildHashcatCmd(o: {
  hash?: string; hashFile?: string; mode: number; attack?: number; wordlist?: string; mask?: string
}): string {
  const input = o.hashFile ? sq(o.hashFile) : sq(o.hash!)
  const attack = o.attack ?? 0
  const wl = o.wordlist ?? '/usr/share/wordlists/rockyou.txt'
  const maskPart = o.mask ? ` ${sq(o.mask)}` : ''
  const wlPart = attack === 3 ? '' : ` ${sq(wl)}`
  return `hashcat -m ${o.mode} -a ${attack} ${input}${wlPart}${maskPart} --force --show 2>&1`
}

export function buildJohnCmd(o: { hashFile: string; format?: string; wordlist?: string }): string {
  const fmtFlag = o.format ? ` --format=${sq(o.format)}` : ''
  const wlFlag = o.wordlist ? ` --wordlist=${sq(o.wordlist)}` : ''
  return `john${fmtFlag}${wlFlag} ${sq(o.hashFile)} 2>&1; echo '---SHOW---'; john --show ${sq(o.hashFile)} 2>&1`
}
