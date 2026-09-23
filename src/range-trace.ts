/**
 * 靶场调用自证轨迹（可维护性 S4 证据层 · 2026-09-14）。
 *
 * 动机：本插件的三个工具（`otw_request` / `otw_ssh` / `otw_blind`）都把命令交给 **WSL 内 bash** 执行，
 * 但除了 `ctx.logger` 的 ready 行（宿主 logger **不落盘**，AGENTS.md §5.22 规则 1）之外**没有任何落盘证据**。
 * 后果：事后无法回答「谁发起了哪一发、命令长什么样、断在哪一级、stdout 多长、花了多久」——
 * 只能靠现场写一次性脚本反解源码。语义文档 §10 U2 早已登记该缺口，本次闭环。
 *
 * 修法：每次工具调用落一行 `begin` + 一行 `end` 到
 * `<DSH_HOME>/cyber-range-trace.jsonl`（一行一阶段，`atMs` 单调，可 `tail`/`grep`）。
 *
 * 轨迹回答的五问（技能 plugin-maintainability 判据）：
 *   Q1 线上跑的是哪个构建 → `build`（`<version>@<lib/index.js mtime ms>`，进程级自报）+ `pid`
 *   Q2 谁发起了什么        → `action`（request/ssh/blind）+ `target` + `params`（脱敏摘要）
 *   Q3 断在哪一段          → `phase` 枚举 + `error`（`classifyBreak` 断点分类）
 *   Q4 结果质量            → `ok` / `status` / `exitCode` / `stdoutBytes` / `stderrBytes` / `bodyBytes` / `queries`
 *   Q5 耗时与预算          → `durationMs`（`end` 行的全程实耗）
 *
 * **隐私红线（本插件尤其重要）**：口令 / 用户名 / cookie / token / data / 远程命令
 * **一个字都不落盘**——敏感键只记 `<N chars>`；`url` 里的 `user:pass@` 结构化剥离只留 host+path；
 * 命令与错误文本落盘前再过一遍 `scrub()`（用本次参数里收集到的秘密值做替换），双保险：
 * 任何凭据都是从参数进入命令的，因此对参数秘密的替换是**完备**的。
 *
 * **观测绝不反噬主流程**（技能 C4 / 审计 S6）：全部 IO 失败吞错并返回 `false`；
 * 摘要函数自身抛错一律吞掉退化为不记录；绝不改变工具的返回值或异常传播。
 *
 * @module dsh-cyber-range/trace
 */
import { Buffer } from 'node:buffer'
import { appendFileSync, mkdirSync, readFileSync, statSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'

/** 阶段枚举（一次调用 = `begin` → `end` 两行）。 */
export type TracePhase = 'begin' | 'end'

/** 动作类型（本插件的三条出击路径）。 */
export type TraceAction = 'request' | 'ssh' | 'blind'

/** 一行调用轨迹。 */
export interface TraceEntry {
  /** 写入时刻（ms epoch）。 */
  atMs: number
  phase: TracePhase
  /** 动作类型（Q2）。 */
  action: TraceAction
  /** 构建标识 `<version>@<lib/index.js mtime ms>`（Q1）。 */
  build: string
  /** 进程 pid（web / watch 两侧都可能跑）。 */
  pid: number
  /** 目标（host 或 url 的 hostname+path；**绝不含凭据**）。 */
  target?: string
  /** 参数摘要（脱敏；敏感键只记 `<N chars>`）。 */
  params?: string
  /** 命令形态摘要（脱敏 + 截断；`otw_blind` 无 shell 命令故缺省）。 */
  cmdShape?: string
  /** 阶段耗时（`begin`=0；`end`=全程实耗）。 */
  durationMs: number
  /** 通道级成功（`end` 行）。 */
  ok?: boolean
  /** HTTP 状态码（`otw_request` 的 curl `-w` 行）。 */
  status?: number
  /** 子进程退出码（`otw_request` / `otw_ssh`）。 */
  exitCode?: number
  /** stdout 字节数（不落正文）。 */
  stdoutBytes?: number
  /** stderr 字节数（不落正文）。 */
  stderrBytes?: number
  /** HTTP body 字节数（不落正文；`otw_request` / `otw_blind`）。 */
  bodyBytes?: number
  /** 盲注查询次数（`otw_blind`）。 */
  queries?: number
  /** 断点分类（`classifyBreak`；仅在失败时出现）。 */
  error?: string
}

/** 解析 DSH_HOME：环境变量优先，缺省 `<homedir>/.dsh`（与既有插件同约定，单一真源）。 */
export function resolveHome(
  env: Record<string, string | undefined> = process.env,
  fallback = homedir(),
): string {
  const raw = env['DSH_HOME']
  return raw !== undefined && raw.trim() !== '' ? raw : join(fallback, '.dsh')
}

/** 轨迹文件路径（纯函数，便于测试与文档化）。 */
export function tracePath(home: string): string {
  return join(home, 'cyber-range-trace.jsonl')
}

/** 文件 mtime（ms；不可得为 0）。 */
export function mtimeOf(file: string): number {
  try {
    return Math.round(statSync(file).mtimeMs)
  } catch {
    return 0
  }
}

/** 从 `<file>` 所在包的 package.json 读版本（读不到返回空串——尽力而为，不抛）。 */
export function readPackageVersion(file: string): string {
  try {
    const pkg = JSON.parse(readFileSync(join(dirname(file), '..', 'package.json'), 'utf8')) as {
      version?: string
    }
    return typeof pkg.version === 'string' ? pkg.version : ''
  } catch {
    return ''
  }
}

/** 构建标识：`<version>@<模块 mtime ms>`（版本缺失退化为 `unknown@<mtime>`）。 */
export function buildStamp(file: string, version = ''): string {
  return version !== '' ? `${version}@${String(mtimeOf(file))}` : `unknown@${String(mtimeOf(file))}`
}

/* ─────────────────────────── 脱敏（隐私红线） ─────────────────────────── */

/**
 * 敏感键判定（**只记长度，绝不落值**）：
 * 口令（pass/password/pwd）、用户名（user/username）、cookie、token、authorization、secret、
 * 哈希（hash/hashFile）、POST 表单体（data，可能内嵌凭据）、远程命令（command，可能内嵌凭据，
 * 如 `mysql -p…` / `curl -u…`）。
 * 业务键（host/port/path/method/url/expr/template/charset/maxLen…）**不误伤**——排障要看它们。
 */
export function isSensitiveKey(key: string): boolean {
  return /^(pass|password|pwd|user|username|usernames|cookie|token|authorization|auth|secret|hash|hashfile|data|command|form)$/i.test(
    key,
  )
}

/** 从 URL 里结构性地取出内嵌凭据（`scheme://user:pass@host/…`）——解码后的明文，供 `scrub` 使用。 */
export function secretsOfUrl(url: string): string[] {
  const out: string[] = []
  try {
    const u = new URL(url)
    for (const raw of [u.username, u.password]) {
      if (raw === '') continue
      try {
        out.push(decodeURIComponent(raw))
      } catch {
        out.push(raw)
      }
    }
  } catch {
    return []
  }
  return out
}

/** 收集本次参数里的全部秘密值（敏感键的值 + URL 内嵌凭据），供 `scrub` 做完备替换。 */
export function collectSecrets(args: unknown): string[] {
  const out: string[] = []
  if (typeof args !== 'object' || args === null) return out
  for (const [key, value] of Object.entries(args as Record<string, unknown>)) {
    if (key === 'url' && typeof value === 'string') {
      out.push(...secretsOfUrl(value))
      continue
    }
    if (!isSensitiveKey(key)) continue
    if (typeof value === 'string' && value !== '') out.push(value)
    else if (Array.isArray(value)) {
      for (const item of value) if (typeof item === 'string' && item !== '') out.push(item)
    }
  }
  // 长秘密先替换（避免短秘密先命中把长秘密切碎后留下残余）
  return [...new Set(out)].sort((a, b) => b.length - a.length)
}

/** 用已知秘密值擦除文本（命令形态 / 错误文本落盘前的最后一道防线）。 */
export function scrub(text: string, secrets: readonly string[]): string {
  let out = text
  for (const secret of secrets) {
    if (secret === '') continue
    out = out.split(secret).join('[redacted]')
  }
  return out
}

/** 通用文本截断（超长加 `…`）。 */
export function truncate(text: string, limit: number): string {
  return text.length > limit ? text.slice(0, limit) + '…' : text
}

/** 单值摘要：敏感键只记长度；数组记形状；对象记 JSON（截断）；其余字符串化（截断）。 */
export function summarizeValue(key: string, value: unknown, limit = 80): string {
  if (value === undefined) return ''
  if (isSensitiveKey(key)) {
    if (typeof value === 'string') return `<${String(value.length)} chars>`
    if (Array.isArray(value)) return `<array ${String(value.length)}>`
    if (value === null) return '<0 chars>'
    return '<1 chars>'
  }
  if (Array.isArray(value)) return `<array ${String(value.length)}>`
  if (value !== null && typeof value === 'object') return truncate(JSON.stringify(value) ?? '{}', limit)
  return truncate(String(value), limit)
}

/**
 * `url` 的结构化呈现：**剥掉凭据**，只留 `<hostname><pathname>`（Q2「发给谁」）。
 * 非法 URL 退化为脱敏后的截断原文（不经 `scrub` 时绝不调用本函数之外的路径）。
 */
export function summarizeUrl(url: string): string {
  try {
    const u = new URL(url)
    return `${u.hostname}${u.pathname}`
  } catch {
    return '<unparsable-url>'
  }
}

/** 参数摘要：`k=v; k2=v2`，脱敏 + 逐个截断 + 整体封顶；非对象返回空串。 */
export function summarizeArgs(args: unknown, limit = 400): string {
  if (args === null || typeof args !== 'object' || Array.isArray(args)) return ''
  const parts: string[] = []
  for (const [key, value] of Object.entries(args as Record<string, unknown>)) {
    if (value === undefined) continue
    if (key === 'url' && typeof value === 'string') {
      parts.push(`url=${summarizeUrl(value)}`)
      continue
    }
    const shown = summarizeValue(key, value)
    if (shown !== '') parts.push(`${key}=${shown}`)
  }
  return truncate(parts.join('; '), limit)
}

/* ─────────────────────────── 结果投影 ─────────────────────────── */

/** 结果投影字段（从工具返回值里抽取的**量级**，绝不落正文）。 */
export interface ResultFacts {
  ok: boolean
  status?: number
  exitCode?: number
  stdoutBytes?: number
  stderrBytes?: number
  bodyBytes?: number
  queries?: number
}

const bytes = (v: unknown): number | undefined =>
  typeof v === 'string' ? Buffer.byteLength(v, 'utf8') : undefined

/**
 * 结果投影（纯函数）：从工具返回值抽取量级字段。
 * `ok` 的语义 = **通道级**成功（`ok:false` 显式失败，或 `error` 字段非空）；
 * 应用层结果（HTTP 401 也是「通道通」）由 `status` 单独记录——两者语义不同，不得互相掩盖。
 */
export function summarizeResult(result: unknown): ResultFacts {
  if (result === null || typeof result !== 'object') return { ok: true }
  const r = result as Record<string, unknown>
  const explicit = typeof r['ok'] === 'boolean' ? r['ok'] : undefined
  const hasError = r['error'] !== undefined && r['error'] !== null && r['error'] !== ''
  const out: ResultFacts = { ok: explicit === undefined ? !hasError : explicit && !hasError }
  if (typeof r['status'] === 'number') out.status = r['status']
  if (typeof r['exitCode'] === 'number') out.exitCode = r['exitCode']
  const so = bytes(r['stdout'])
  if (so !== undefined) out.stdoutBytes = so
  const se = bytes(r['stderr'])
  if (se !== undefined) out.stderrBytes = se
  const bo = bytes(r['body'])
  if (bo !== undefined) out.bodyBytes = bo
  if (typeof r['queries'] === 'number') out.queries = r['queries']
  return out
}

/**
 * 断点分类（纯函数，Q3）：把自由文本错误归到一个**可 grep 的类别**。
 * 类别：`wsl-exit`（子进程非零退出）→ `wsl-spawn`（wsl.exe 起不来）→ `http-timeout`
 * → `http-error`（连接/解析失败）→ `bisect-partial`（盲注半途而废，已保留前缀）→ `empty` → `other`。
 */
export function classifyBreak(error: string): string {
  const e = error.trim()
  if (e === '') return 'empty'
  if (/timeout|timed out|ETIMEDOUT/i.test(e)) return 'http-timeout'
  if (/spawn|ENOENT|not found/i.test(e)) return 'wsl-spawn'
  if (/ECONN|ECONNRESET|EAI_AGAIN|getaddrinfo|socket hang up|URLError/i.test(e)) return 'http-error'
  if (/^curl:/i.test(e) || /exit\s*(code)?\s*[1-9]/i.test(e)) return 'wsl-exit'
  return 'other'
}

/* ─────────────────────────── 序列化 / IO ─────────────────────────── */

/** 稳定序列化（键序固定 + 单行 JSON，便于 `tail`/`grep`）。 */
export function serializeTraceEntry(entry: TraceEntry): string {
  const ordered: TraceEntry = {
    atMs: entry.atMs,
    phase: entry.phase,
    action: entry.action,
    build: entry.build,
    pid: entry.pid,
    ...(entry.target !== undefined ? { target: entry.target } : {}),
    ...(entry.params !== undefined ? { params: entry.params } : {}),
    ...(entry.cmdShape !== undefined ? { cmdShape: entry.cmdShape } : {}),
    durationMs: entry.durationMs,
    ...(entry.ok !== undefined ? { ok: entry.ok } : {}),
    ...(entry.status !== undefined ? { status: entry.status } : {}),
    ...(entry.exitCode !== undefined ? { exitCode: entry.exitCode } : {}),
    ...(entry.stdoutBytes !== undefined ? { stdoutBytes: entry.stdoutBytes } : {}),
    ...(entry.stderrBytes !== undefined ? { stderrBytes: entry.stderrBytes } : {}),
    ...(entry.bodyBytes !== undefined ? { bodyBytes: entry.bodyBytes } : {}),
    ...(entry.queries !== undefined ? { queries: entry.queries } : {}),
    ...(entry.error !== undefined ? { error: entry.error } : {}),
  }
  return JSON.stringify(ordered)
}

/** 容错解析：坏行/半行/空行/非对象跳过，不抛（轨迹是证据，不是契约校验器）。 */
export function parseTraceEntries(text: string): TraceEntry[] {
  const out: TraceEntry[] = []
  for (const raw of text.split('\n')) {
    const line = raw.trim()
    if (line === '') continue
    try {
      const parsed = JSON.parse(line) as TraceEntry
      if (parsed !== null && typeof parsed === 'object' && typeof parsed.atMs === 'number' && typeof parsed.phase === 'string') {
        out.push(parsed)
      }
    } catch {
      continue
    }
  }
  return out
}

/** 读轨迹文件；缺失/不可读/是目录返回空数组（诊断工具的安全入口）。 */
export function readTraceEntries(path: string): TraceEntry[] {
  try {
    return parseTraceEntries(readFileSync(path, 'utf8'))
  } catch {
    return []
  }
}

/** 追加一行（失败即吞并返回 false：轨迹是观测，绝不因写不进去而影响工具结论）。 */
export function appendTraceEntry(path: string, entry: TraceEntry): boolean {
  try {
    mkdirSync(dirname(path), { recursive: true })
    appendFileSync(path, serializeTraceEntry(entry) + '\n', 'utf8')
    return true
  } catch {
    return false
  }
}

/** 记一笔轨迹（薄接线：补 atMs/pid，路径缺省 `<DSH_HOME>/cyber-range-trace.jsonl`）。 */
export function safeTrace(
  entry: Omit<TraceEntry, 'atMs' | 'pid'>,
  opts: { path?: string; home?: string; now?: number; pid?: number } = {},
): boolean {
  try {
    const path = opts.path ?? tracePath(opts.home ?? resolveHome())
    return appendTraceEntry(path, {
      atMs: opts.now ?? Date.now(),
      pid: opts.pid ?? process.pid,
      ...entry,
    })
  } catch {
    return false
  }
}

/* ─────────────────────────── 统一接线（单一切面） ─────────────────────────── */

/** 可注入的执行上下文（测试用假时钟/假 pid/临时路径）。 */
export interface TraceRuntime {
  path?: string
  home?: string
  pid?: number
  now?: () => number
}

/** 单个工具的轨迹接线选项（**全部是纯函数或常量**，绝不引入新的 IO 语义）。 */
export interface TracedToolOptions extends TraceRuntime {
  action: TraceAction
  build: string
  /** 从参数取目标（Q2「发给谁」）；抛错即视为取不到。 */
  targetOf?: (args: Record<string, unknown>) => string | undefined
  /** 从参数取命令原文（会被 `scrub` + 截断）；抛错即视为取不到。 */
  cmdOf?: (args: Record<string, unknown>) => string | undefined
}

/** 安全调用摘要函数：任何异常都退化为 `undefined`（观测绝不反噬主流程）。 */
function safely<T>(fn: (() => T | undefined) | undefined): T | undefined {
  if (fn === undefined) return undefined
  try {
    return fn()
  } catch {
    return undefined
  }
}

/**
 * 把一个工具的 `execute` 包成「落 `begin` 行 → 执行 → 落 `end` 行」。
 *
 * 三条硬约束（对应审计 S4/S6 与技能 C4）：
 *   1. **返回值与异常传播逐字不变**（失败时 `end.ok=false` + `error`，然后原样重抛）；
 *   2. **落盘失败不影响主流程**（`safeTrace` 返回 bool）；
 *   3. **摘要函数抛错不影响主流程**（`safely` 吞错）。
 */
export function tracedExecute<A, R>(
  opts: TracedToolOptions,
  run: (args: A) => Promise<R>,
): (args: A) => Promise<R> {
  const now = opts.now ?? (() => Date.now())
  return async (args: A): Promise<R> => {
    const t0 = now()
    const bag = (args ?? {}) as Record<string, unknown>
    let secrets: string[] = []
    try {
      secrets = collectSecrets(bag)
    } catch {
      secrets = []
    }
    const target = safely(() => opts.targetOf?.(bag)) ?? undefined
    const rawCmd = safely(() => opts.cmdOf?.(bag)) ?? undefined
    const cmdShape = rawCmd === undefined ? undefined : truncate(scrub(rawCmd, secrets), 240)
    const params = summarizeArgs(bag)
    const base = { action: opts.action, build: opts.build } as const
    const io = { path: opts.path, home: opts.home, pid: opts.pid, now: now() }
    safeTrace({ ...base, phase: 'begin', durationMs: 0, target, params, cmdShape }, io)

    try {
      const result = await run(args)
      const facts = summarizeResult(result)
      safeTrace(
        {
          ...base,
          phase: 'end',
          durationMs: Math.max(0, now() - t0),
          target,
          ...facts,
        },
        { ...io, now: now() },
      )
      return result
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e)
      safeTrace(
        {
          ...base,
          phase: 'end',
          durationMs: Math.max(0, now() - t0),
          target,
          ok: false,
          error: `${classifyBreak(message)}: ${truncate(scrub(message, secrets), 200)}`,
        },
        { ...io, now: now() },
      )
      throw e
    }
  }
}
