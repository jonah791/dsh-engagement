/**
 * 蓝队工具调用自证轨迹（可维护性 S4 证据层 · 2026-09-14）。
 *
 * 动机：8 个蓝队工具都经 `runPs()` 起 **PowerShell 子进程**（`host.ts:execFile('powershell.exe', …)`），
 * 但除了 `ctx.logger` 的 ready 行（宿主 logger **不落盘**，AGENTS.md §5.22 规则 1）之外**无落盘证据**。
 * 事后无法回答「查了什么、命中几条、断在哪一级、花了多久」——而蓝队工作恰恰是「审计要看证据」。
 *
 * 修法：每次工具调用落一行 `begin` + 一行 `end` 到
 * `<DSH_HOME>/blue-team-trace.jsonl`（一行一阶段，`atMs` 单调，可 `tail`/`grep`）。
 *
 * 轨迹回答的五问（技能 plugin-maintainability 判据）：
 *   Q1 线上跑的是哪个构建 → `build`（`<version>@<lib/index.js mtime ms>`）+ `pid`
 *   Q2 查了什么 / 对谁        → `action`（工具名）+ `target` + `query`（**查询摘要**，脱敏）
 *   Q3 断在哪一段             → `phase` 枚举 + `break`（`classifyBreak` 分类）+ `error`
 *   Q4 结果质量               → `ok` / `count`（**命中条数**）/ `resultBytes`
 *   Q5 耗时与预算             → `durationMs`
 *
 * **诚实声明：本插件轨迹没有 `exitCode` 字段。** `host.ts:runPs()` 把 `execFile` 的错误
 * **折叠成一个字符串**（`PowerShell 执行失败: ${err.message}`），数字退出码（`err.code`）
 * 在到达工具返回值之前就已丢失；要记录它必须改 `runPs`/`tryRun` 的返回形状 = **业务行为改动**，
 * 本轮（零行为变更）不做。轨迹以**断点分类** `ps-exit`（子进程失败）表达同一信息，
 * 并把「如何拿到真退出码」登记为未决项（见语义文档 §10 U3）。
 *
 * **隐私红线（尤其重要）**：蓝队结果里**天然含哈希原文**（`hashFile` 的 MD5/SHA1/SHA256）、
 * 管理员名、默认登录名——因此轨迹**只记量级**（`resultBytes` / `count`），**绝不落结果正文**；
 * 入参侧 `hash`/`password`/`user`/`token`/`cookie`/`secret` 等敏感键只记 `<N chars>`；
 * `error` 落盘前过 `scrub(text, secrets)`（`runPs` 的错误里会带整条 PowerShell 脚本，
 * 脚本内嵌了 `path`/`logName`，是真实的泄漏面）。
 *
 * **观测绝不反噬主流程**（技能 C4 / 审计 S6）：全部 IO 失败吞错并返回 `false`；
 * 摘要函数自身抛错一律吞掉退化为不记录；绝不改变工具的返回值或异常传播。
 *
 * @module dsh-blue-team/trace
 */
import { Buffer } from 'node:buffer'
import { appendFileSync, mkdirSync, readFileSync, statSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'

/** 阶段枚举（一次调用 = `begin` → `end` 两行）。 */
export type TracePhase = 'begin' | 'end'

/** 一行调用轨迹。 */
export interface TraceEntry {
  /** 写入时刻（ms epoch）。 */
  atMs: number
  phase: TracePhase
  /** 动作（工具名，如 `blue_event_log_query`）。 */
  action: string
  /** 构建标识 `<version>@<lib/index.js mtime ms>`（Q1）。 */
  build: string
  /** 进程 pid。 */
  pid: number
  /** 目标（host / path / value / domain…；**非凭据**）。 */
  target?: string
  /** 查询摘要（脱敏参数摘要，Q2）。 */
  query?: string
  /** 阶段耗时（`begin`=0；`end`=全程实耗，Q5）。 */
  durationMs: number
  /** 成功与否（`end` 行）。 */
  ok?: boolean
  /** 命中条数（`count` 字段优先，否则 `results`/`hits` 数组长度或 `open` 计数）——Q4。 */
  count?: number
  /** 结果 JSON 字节数（量级，**不落正文**——蓝队结果含哈希原文）。 */
  resultBytes?: number
  /** 断点分类（`classifyBreak`；仅在 `ok=false` 时出现）。 */
  break?: string
  /** 分类前缀 + **已 `scrub`** 的截断错误文本。 */
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
  return join(home, 'blue-team-trace.jsonl')
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
 * 敏感键（**只记长度**）：口令（pass/password/pwd）、用户名（user/username）、**哈希**（hash/hashes）、
 * cookie/token/authorization/secret/credential。
 * **业务键保留**（排障要看，非凭据）：`host`/`path`/`value`/`log`/`logName`/`ids`/`days`/`limit`/
 * `ports`/`type`/`query`——它们是蓝队的**调查对象**（目标资产与威胁指标），不是本机凭据。
 * 前瞻性：本白名单让未来「接收哈希/凭据入参」的新工具**无需改观测层**即自动受保护。
 */
export function isSensitiveKey(key: string): boolean {
  return /^(pass|password|pwd|user|username|hash|hashes|hashvalue|cookie|token|authorization|auth|secret|credential|passwordhash)$/i.test(
    key,
  )
}

/** 收集本次参数里的全部秘密值（供 `scrub` 做完备替换）。 */
export function collectSecrets(args: unknown): string[] {
  const out: string[] = []
  if (typeof args !== 'object' || args === null) return out
  for (const [key, value] of Object.entries(args as Record<string, unknown>)) {
    if (!isSensitiveKey(key)) continue
    if (typeof value === 'string' && value !== '') out.push(value)
    else if (Array.isArray(value)) {
      for (const item of value) if (typeof item === 'string' && item !== '') out.push(item)
    }
  }
  // 长秘密先替换（短先替换会把长秘密切碎留下残余）
  return [...new Set(out)].sort((a, b) => b.length - a.length)
}

/** 用已知秘密值擦除文本（错误文本落盘前的最后一道防线）。 */
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

/** 查询摘要 = 脱敏参数摘要：`k=v; k2=v2`，逐个截断 + 整体封顶；非对象返回空串。 */
export function summarizeArgs(args: unknown, limit = 300): string {
  if (args === null || typeof args !== 'object' || Array.isArray(args)) return ''
  const parts: string[] = []
  for (const [key, value] of Object.entries(args as Record<string, unknown>)) {
    if (value === undefined) continue
    const shown = summarizeValue(key, value)
    if (shown !== '') parts.push(`${key}=${shown}`)
  }
  return truncate(parts.join('; '), limit)
}

/** 默认目标投影（纯函数）：按蓝队的调查对象键序取第一个非空值。 */
export function defaultTargetOf(args: Record<string, unknown>): string | undefined {
  for (const key of ['host', 'path', 'value', 'domain', 'query', 'log', 'logName', 'target']) {
    const v = args[key]
    if (typeof v === 'string' && v !== '') return truncate(v, 120)
  }
  return undefined
}

/* ─────────────────────────── 结果投影 ─────────────────────────── */

/** 结果投影字段（从工具返回值抽取量级，**绝不落正文**）。 */
export interface ResultFacts {
  ok: boolean
  count?: number
  resultBytes?: number
}

const bytes = (v: unknown): number | undefined =>
  typeof v === 'string' ? Buffer.byteLength(v, 'utf8') : undefined

/**
 * 结果投影（纯函数）：`ok` 取显式的 `ok` 字段；`count` = **命中条数**
 * （`count` 字段优先，否则 `results`/`hits`/`events` 数组长度，否则 `open`/`scanned` 数值）；
 * `resultBytes` 取结果的 JSON 长度（量级）。
 * **注意**：结果正文里含哈希原文/管理员名（`hashFile`/`baselineCheck`），故**只投影量级**。
 */
export function summarizeResult(result: unknown): ResultFacts {
  if (result === null || typeof result !== 'object') return { ok: true }
  const r = result as Record<string, unknown>
  const explicit = typeof r['ok'] === 'boolean' ? r['ok'] : undefined
  const out: ResultFacts = { ok: explicit === undefined ? true : explicit }
  if (typeof r['count'] === 'number') out.count = r['count']
  else {
    for (const key of ['results', 'hits', 'events']) {
      const v = r[key]
      if (Array.isArray(v)) { out.count = v.length; break }
    }
    if (out.count === undefined) {
      for (const key of ['open', 'scanned']) {
        const v = r[key]
        if (typeof v === 'number') { out.count = v; break }
      }
    }
  }
  try {
    const json = JSON.stringify(r)
    if (typeof json === 'string') out.resultBytes = Buffer.byteLength(json, 'utf8')
  } catch {
    /* 循环引用等：不记字节数，不影响主流程 */
  }
  return out
}

/** 从工具返回值里取错误文本（供分类；不落盘原文）。 */
export function errorOf(result: unknown): string {
  if (result === null || typeof result !== 'object') return ''
  const e = (result as Record<string, unknown>)['error']
  return typeof e === 'string' ? e : ''
}

/**
 * 断点分类（纯函数，Q3）：把自由文本错误归到**可 grep 的类别**。
 * 类别：`empty` → `ps-timeout`（超时/被杀）→ `ps-spawn`（powershell.exe 起不来）→
 * `ps-exit`（子进程非零退出/Command failed）→ `json`（结果解析失败）→
 * `not-found`（`NOT_FOUND` 哨兵）→ `bad-args`（必填/无效）→ `other`。
 *
 * 说明：`runPs()` 把 `execFile` 的错误折叠成字符串、**丢弃了数字退出码**，
 * 故此处以 `ps-exit` 类表达「子进程失败」（真退出码见语义文档 §10 U3）。
 */
export function classifyBreak(error: string): string {
  const e = error.trim()
  if (e === '') return 'empty'
  if (/timeout|timed out|ETIMEDOUT|killed|maxBuffer/i.test(e)) return 'ps-timeout'
  if (/ENOENT|not recognized|is not recognized|spawn/i.test(e)) return 'ps-spawn'
  if (/PowerShell 执行失败|Command failed/i.test(e)) return 'ps-exit'
  if (/JSON|Unexpected token|parse/i.test(e)) return 'json'
  if (/NOT_FOUND|不存在/.test(e)) return 'not-found'
  if (/必填|无效|invalid|需/.test(e)) return 'bad-args'
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
    ...(entry.query !== undefined ? { query: entry.query } : {}),
    durationMs: entry.durationMs,
    ...(entry.ok !== undefined ? { ok: entry.ok } : {}),
    ...(entry.count !== undefined ? { count: entry.count } : {}),
    ...(entry.resultBytes !== undefined ? { resultBytes: entry.resultBytes } : {}),
    ...(entry.break !== undefined ? { break: entry.break } : {}),
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

/** 记一笔轨迹（薄接线：补 atMs/pid，路径缺省 `<DSH_HOME>/blue-team-trace.jsonl`）。 */
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

/** 轨迹接线选项（**全部是纯函数或常量**，绝不引入新的 IO 语义）。 */
export interface TracedToolOptions extends TraceRuntime {
  /** 动作（工具名）。 */
  action: string
  build: string
  /** 目标投影；缺省 `defaultTargetOf`（抛错即视为取不到）。 */
  targetOf?: (args: Record<string, unknown>) => string | undefined
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
 *   1. **返回值与异常传播逐字不变**（失败时落 `ok=false` + `break`/`error`，然后原样重抛）；
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
    let query: string | undefined
    let secrets: string[] = []
    try {
      query = summarizeArgs(bag)
      secrets = collectSecrets(bag)
    } catch {
      query = undefined
      secrets = []
    }
    const target = safely(() => (opts.targetOf ?? defaultTargetOf)(bag)) ?? undefined
    const io = { path: opts.path, home: opts.home, pid: opts.pid }
    safeTrace({ action: opts.action, build: opts.build, phase: 'begin', durationMs: 0, target, query }, { ...io, now: now() })

    try {
      const result = await run(args)
      const facts = summarizeResult(result)
      const kind = facts.ok ? undefined : classifyBreak(errorOf(result))
      safeTrace(
        {
          action: opts.action, build: opts.build, phase: 'end',
          durationMs: Math.max(0, now() - t0),
          target,
          ok: facts.ok,
          ...(facts.count !== undefined ? { count: facts.count } : {}),
          ...(facts.resultBytes !== undefined ? { resultBytes: facts.resultBytes } : {}),
          ...(kind !== undefined ? { break: kind } : {}),
          ...(kind !== undefined
            ? { error: `${kind}: ${truncate(scrub(errorOf(result), secrets), 200)}` }
            : {}),
        },
        { ...io, now: now() },
      )
      return result
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e)
      const kind = classifyBreak(message)
      safeTrace(
        {
          action: opts.action, build: opts.build, phase: 'end',
          durationMs: Math.max(0, now() - t0),
          target,
          ok: false,
          break: kind,
          error: `${kind}: ${truncate(scrub(message, secrets), 200)}`,
        },
        { ...io, now: now() },
      )
      throw e
    }
  }
}
