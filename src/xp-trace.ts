/**
 * 利用原语调用自证轨迹（可维护性 S4 证据层 · 2026-09-14）。
 *
 * 动机：本插件是**纯本地生成器**（`xp_*`：命令注入矩阵 / PHP 弱类型 / Web 绕过 / JWT 伪造 /
 * 反序列化 / ECB 块拼接）——不 spawn、不触网、不写文件，因此除了 `ctx.logger` 的 ready 行
 * （宿主 logger **不落盘**，AGENTS.md §5.22 规则 1）之外**无任何落盘证据**。
 * 事后无法回答「哪一发被调用、输入了什么形态、生成出几个候选、花了多久、为什么报错」。
 *
 * 修法：每次工具调用落一行 `begin` + 一行 `end` 到
 * `<DSH_HOME>/exploit-kit-trace.jsonl`（一行一阶段，`atMs` 单调，可 `tail`/`grep`）。
 *
 * 轨迹回答的五问（技能 plugin-maintainability 判据）：
 *   Q1 线上跑的是哪个构建 → `build`（`<version>@<lib/index.js mtime ms>`）+ `pid`
 *   Q2 谁发起了什么        → `action`（工具名）+ `payload`（**payload 类型摘要**：脱敏参数摘要）
 *   Q3 断在哪一段          → `phase` 枚举 + `error`（`classifyBreak` 断点分类）
 *   Q4 结果质量            → `ok` / `count`（候选数）/ `resultBytes`
 *   Q5 耗时与预算          → `durationMs`
 *
 * **本插件没有 `exitCode` 字段——这是诚实而非遗漏**：六个工具全部是纯函数计算，
 * 不产生子进程，不存在退出码。用「候选数 + 结果字节数」表达结果质量，不伪造一个恒为 0 的退出码。
 *
 * **隐私红线**：JWT 密钥（`secret`/`secrets`）、JWT 本体（`token`）、注册口令（`password`）、
 * 用户名、`command`（**命令注入模板的载荷输入**——可能内嵌字面凭据，从严处理）
 * **一个字都不落盘**——只记 `<N chars>`；`error` 落盘前再过一遍 `scrub()`。
 * `kind` / `mode` / `separators` / `bypasses` / `shell` / `visibility` / `base64` / `alg` / `blockSize`
 * 等**类型键保留**（这正是「payload 类型摘要」要回答的）。
 *
 * **观测绝不反噬主流程**（技能 C4 / 审计 S6）：全部 IO 失败吞错并返回 `false`；
 * 摘要函数自身抛错一律吞掉退化为不记录；绝不改变工具的返回值或异常传播。
 *
 * @module dsh-exploit-kit/trace
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
  /** 动作（工具名，如 `xp_cmdi_payload`）。 */
  action: string
  /** 构建标识 `<version>@<lib/index.js mtime ms>`（Q1）。 */
  build: string
  /** 进程 pid。 */
  pid: number
  /** payload 类型 / 参数摘要（脱敏，Q2）。 */
  payload?: string
  /** 阶段耗时（`begin`=0；`end`=全程实耗，Q5）。 */
  durationMs: number
  /** 成功与否（`end` 行）。 */
  ok?: boolean
  /** 生成出的候选数量（Q4：结果质量）。 */
  count?: number
  /** 结果 JSON 字节数（Q4）。 */
  resultBytes?: number
  /** 断点分类（`classifyBreak`；仅在 `ok=false` 时出现）。 */
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
  return join(home, 'exploit-kit-trace.jsonl')
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
 * 敏感键（**只记长度**）：JWT 密钥（`secret`/`secrets`）、JWT 本体（`token`）、注册口令（`password`）、
 * 用户名、`command`（命令注入模板的载荷输入，可能内嵌 `mysql -p…` 这类字面凭据，从严）。
 * 类型键（`kind`/`mode`/`separators`/`bypasses`/`shell`/`visibility`/`base64`/`urlEncode`/`alg`/
 * `blockSize`/`prefixLen`/`injectOffset`/`depth`/`gt`/`maxLen`/`double`/`className`）**不误伤**
 * ——它们正是「payload 类型摘要」的内容。
 */
export function isSensitiveKey(key: string): boolean {
  return /^(command|secret|secrets|token|tokens|password|pass|user|username|cookie|authorization|auth|credential|privatekey|private_key|key)$/i.test(
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

/** payload 类型摘要 = 脱敏参数摘要：`k=v; k2=v2`，逐个截断 + 整体封顶；非对象返回空串。 */
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

/* ─────────────────────────── 结果投影 ─────────────────────────── */

/** 结果投影字段（从工具返回值抽取量级，绝不落正文）。 */
export interface ResultFacts {
  ok: boolean
  count?: number
  resultBytes?: number
}

const bytes = (v: unknown): number | undefined =>
  typeof v === 'string' ? Buffer.byteLength(v, 'utf8') : undefined

/**
 * 结果投影（纯函数）：`ok` 取显式的 `ok` 字段；`count` 取候选数
 * （`count` 字段优先，否则 `payloads` / `candidates` / `plan` 数组长度）；
 * `resultBytes` 取结果的 JSON 长度（量级，不落正文）。
 */
export function summarizeResult(result: unknown): ResultFacts {
  if (result === null || typeof result !== 'object') return { ok: true }
  const r = result as Record<string, unknown>
  const out: ResultFacts = { ok: r['ok'] === true }
  if (typeof r['count'] === 'number') out.count = r['count']
  else {
    for (const key of ['payloads', 'candidates', 'tokens', 'plan']) {
      const v = r[key]
      if (Array.isArray(v)) { out.count = v.length; break }
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
 * 类别：`empty`（空错误）→ `range`（数值越界：`RangeError`/负填充）→
 * `type`（`TypeError`/非法类型）→ `uri`（非法百分号编码）→
 * `missing-args`（必填/参数不足）→ `empty-output`（生成结果为空）→ `other`。
 */
export function classifyBreak(error: string): string {
  const e = error.trim()
  if (e === '') return 'empty'
  if (/RangeError|Invalid count value|negative|负数|越界/i.test(e)) return 'range'
  if (/TypeError|类型|not a function|undefined is not/i.test(e)) return 'type'
  if (/URIError|URI malformed|百分号/i.test(e)) return 'uri'
  if (/必填|参数不足|需要/.test(e)) return 'missing-args'
  if (/为空|无候选|无候选（参数组合为空）/.test(e)) return 'empty-output'
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
    ...(entry.payload !== undefined ? { payload: entry.payload } : {}),
    durationMs: entry.durationMs,
    ...(entry.ok !== undefined ? { ok: entry.ok } : {}),
    ...(entry.count !== undefined ? { count: entry.count } : {}),
    ...(entry.resultBytes !== undefined ? { resultBytes: entry.resultBytes } : {}),
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

/** 记一笔轨迹（薄接线：补 atMs/pid，路径缺省 `<DSH_HOME>/exploit-kit-trace.jsonl`）。 */
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
}

/**
 * 把一个工具的 `execute` 包成「落 `begin` 行 → 执行 → 落 `end` 行」。
 *
 * 三条硬约束（对应审计 S4/S6 与技能 C4）：
 *   1. **返回值与异常传播逐字不变**（失败时落 `ok=false` + `error`，然后原样重抛）；
 *   2. **落盘失败不影响主流程**（`safeTrace` 返回 bool）；
 *   3. **摘要函数抛错不影响主流程**（全部吞错）。
 */
export function tracedExecute<A, R>(
  opts: TracedToolOptions,
  run: (args: A) => Promise<R>,
): (args: A) => Promise<R> {
  const now = opts.now ?? (() => Date.now())
  return async (args: A): Promise<R> => {
    const t0 = now()
    let payload: string | undefined
    let secrets: string[] = []
    try {
      payload = summarizeArgs(args)
      secrets = collectSecrets(args)
    } catch {
      payload = undefined
      secrets = []
    }
    const io = { path: opts.path, home: opts.home, pid: opts.pid }
    safeTrace({ action: opts.action, build: opts.build, phase: 'begin', durationMs: 0, payload }, { ...io, now: now() })

    try {
      const result = await run(args)
      const facts = summarizeResult(result)
      safeTrace(
        {
          action: opts.action, build: opts.build, phase: 'end',
          durationMs: Math.max(0, now() - t0),
          ok: facts.ok,
          ...(facts.count !== undefined ? { count: facts.count } : {}),
          ...(facts.resultBytes !== undefined ? { resultBytes: facts.resultBytes } : {}),
          ...(facts.ok ? {} : { error: `${classifyBreak(errorOf(result))}: ${truncate(scrub(errorOf(result), secrets), 200)}` }),
        },
        { ...io, now: now() },
      )
      return result
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e)
      safeTrace(
        {
          action: opts.action, build: opts.build, phase: 'end',
          durationMs: Math.max(0, now() - t0),
          ok: false,
          error: `${classifyBreak(message)}: ${truncate(scrub(message, secrets), 200)}`,
        },
        { ...io, now: now() },
      )
      throw e
    }
  }
}
