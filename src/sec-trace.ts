/**
 * 渗透工具调用自证轨迹（可维护性 S4 证据层 · 2026-09-14）。
 *
 * 动机：本插件的 12 个工具都经 **WSL bash + base64 通道**执行外部渗透工具，但除了
 * `ctx.logger` 的 ready 行（宿主 logger **不落盘**，AGENTS.md §5.22 规则 1）之外**无任何落盘证据**。
 * 事后无法回答「哪一发被 `unsafeArg()` 闸门挡下、断在哪一级、stdout 多长、花了多久」。
 *
 * 修法：每次工具调用落一行 `begin`，再落一行 `gate` **或** `end` 到
 * `<DSH_HOME>/sec-tools-trace.jsonl`（一行一阶段，`atMs` 单调，可 `tail`/`grep`）。
 *
 * **为什么单独有 `gate` 阶段**：`unsafeArg()` 闸门是**在触碰 WSL 之前**拒绝的纵深防御
 * （`nmap.extra`/`scanType`、`masscan.ports`、`gobuster.mode`、`sqlmap.extra`、`hydra.service`
 * 这 6 个「原样拼接」参数）。**「闸门拒绝了什么」是防线是否真在工作的唯一一手证据**
 * ——把它混进 `end` 里就再也不能用一条 `grep` 证明防线活着。故 `gate` 是**独立阶段**。
 *
 * 轨迹回答的五问（技能 plugin-maintainability 判据）：
 *   Q1 线上跑的是哪个构建 → `build`（`<version>@<lib/index.js mtime ms>`）+ `pid`
 *   Q2 发给谁 / 用了什么     → `tool` + `target` + `args`（脱敏摘要）+ `params`（关键参数摘要）
 *   Q3 断在哪一段            → `phase`（`gate` vs `end`）+ `break`（`classifyBreak` 分类）
 *   Q4 结果质量              → `ok` / `exitCode` / `resultBytes` / `stderrBytes`
 *   Q5 耗时与预算            → `durationMs`
 *
 * **隐私红线**：口令 / 用户名 / 哈希原文 / cookie / token / hydra `form`（可能内嵌字面凭据）
 * **一个字都不落盘**——只记 `<N chars>`；`url` 里的 `user:pass@` 结构性剥离只留 host+path；
 * `error` 落盘前再过一遍 `scrub()`（用本次参数里收集到的秘密值替换）——秘密值全部来自本次参数，
 * 故替换是**完备**的。
 *
 * **观测绝不反噬主流程**（技能 C4 / 审计 S6）：全部 IO 失败吞错并返回 `false`；
 * 摘要函数自身抛错一律吞掉退化为不记录；绝不改变工具的返回值或异常传播。
 *
 * @module dsh-sec-tools/trace
 */
import { Buffer } from 'node:buffer'
import { appendFileSync, mkdirSync, readFileSync, statSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'

/** 阶段枚举（一次调用 = `begin` →（`gate` **或** `end`））。 */
export type TracePhase = 'begin' | 'gate' | 'end'

/** 一行调用轨迹。 */
export interface TraceEntry {
  /** 写入时刻（ms epoch）。 */
  atMs: number
  phase: TracePhase
  /** 工具名（如 `sec_nmap`）。 */
  tool: string
  /** 构建标识 `<version>@<lib/index.js mtime ms>`（Q1）。 */
  build: string
  /** 进程 pid。 */
  pid: number
  /** 目标（`target` / `url` 的 host+path / `domain`）。 */
  target?: string
  /** 关键参数摘要（脱敏）。 */
  args?: string
  /** 阶段耗时（`begin`=0；其余=全程实耗）。 */
  durationMs: number
  /** 成功与否（`gate`/`end` 行）。 */
  ok?: boolean
  /** 子进程退出码。 */
  exitCode?: number
  /** 标准化结果字节数（Q4：结果质量）。 */
  resultBytes?: number
  /** stderr 字节数（不落正文）。 */
  stderrBytes?: number
  /** 断点/闸门分类（`classifyBreak`；仅在 `ok=false` 时出现）。 */
  break?: string
  /** 分类前缀 + 已 `scrub` 的截断错误文本。 */
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
  return join(home, 'sec-tools-trace.jsonl')
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
 * 敏感键（**只记长度**）：口令（pass/password/pwd）、用户名（user/username）、哈希原文（hash）、
 * cookie/token/authorization/secret、hydra `form`（解析模板**可能**内嵌字面凭据，从严处理）。
 * 业务键（target/url/domain/ports/scanType/extra/mode/wordlist/level/rate…）**不误伤**——排障要看它们。
 */
export function isSensitiveKey(key: string): boolean {
  return /^(pass|password|pwd|user|username|hash|hashfile|cookie|token|authorization|auth|secret|form|credential)$/i.test(
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

/** 收集本次参数里的全部秘密值（敏感键的值 + URL 内嵌凭据）。 */
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

/** `url` 的结构化呈现：**剥掉凭据**，只留 `<hostname><pathname>`。 */
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

/** 结果投影字段（从 `wrapExecute` 的返回值抽取量级，绝不落正文）。 */
export interface ResultFacts {
  ok: boolean
  exitCode?: number
  resultBytes?: number
  stderrBytes?: number
}

const bytes = (v: unknown): number | undefined =>
  typeof v === 'string' ? Buffer.byteLength(v, 'utf8') : undefined

/** 结果投影（纯函数）：`ok` 取工具返回值里显式的 `ok`（`wrapExecute` 已归一）。 */
export function summarizeResult(result: unknown): ResultFacts {
  if (result === null || typeof result !== 'object') return { ok: true }
  const r = result as Record<string, unknown>
  const out: ResultFacts = { ok: r['ok'] === true }
  if (typeof r['exitCode'] === 'number') out.exitCode = r['exitCode']
  const rb = bytes(r['result'])
  if (rb !== undefined) out.resultBytes = rb
  const sb = bytes(r['stderr'])
  if (sb !== undefined) out.stderrBytes = sb
  return out
}

/** 从工具返回值里取错误文本（供分类；不落盘原文）。 */
export function errorOf(result: unknown): string {
  if (result === null || typeof result !== 'object') return ''
  const e = (result as Record<string, unknown>)['error']
  return typeof e === 'string' ? e : ''
}

/**
 * 断点 / 闸门分类（纯函数，Q3）：把自由文本错误归到**可 grep 的类别**。
 *
 * **闸门类（`gate/*`，在触碰 WSL 之前拒绝）**：
 *   `gate/unsafe-arg`（`unsafeArg()` 命中 shell 元字符 / 类型不符）
 *   `gate/invalid-url`（`validUrl()`）
 *   `gate/invalid-target`（`validTarget()`）
 * **非闸门类**（已进入执行路径）：
 *   `missing-tool`（`toolExists` 为假）→ `missing-file` → `bad-args` → `tool-exit`（子进程非零）→ `other`
 *
 * 判据与 `src/commands.ts` 的错误文案同源：单测用 `unsafeArg()` / `validUrl()` 的**真实返回值**
 * 交叉验证本函数（文案漂移会让测试红，而不是让防线静默失效）。
 */
export function classifyBreak(error: string): string {
  const e = error.trim()
  if (e === '') return 'empty'
  if (/含 shell 元字符|类型不符/.test(e)) return 'gate/unsafe-arg'
  if (/url 需 http\(s\)|url 含特殊字符/.test(e)) return 'gate/invalid-url'
  if (/格式无效/.test(e)) return 'gate/invalid-target'
  if (/WSL 未安装/.test(e)) return 'missing-tool'
  if (/不存在/.test(e)) return 'missing-file'
  if (/必填|需提供/.test(e)) return 'bad-args'
  if (/执行失败/.test(e)) return 'tool-exit'
  return 'other'
}

/** 该分类是否属于「在触碰 WSL 之前被闸门拒绝」（决定落 `gate` 还是 `end`）。 */
export function isGate(breakKind: string): boolean {
  return breakKind.startsWith('gate/')
}

/* ─────────────────────────── 序列化 / IO ─────────────────────────── */

/** 稳定序列化（键序固定 + 单行 JSON，便于 `tail`/`grep`）。 */
export function serializeTraceEntry(entry: TraceEntry): string {
  const ordered: TraceEntry = {
    atMs: entry.atMs,
    phase: entry.phase,
    tool: entry.tool,
    build: entry.build,
    pid: entry.pid,
    ...(entry.target !== undefined ? { target: entry.target } : {}),
    ...(entry.args !== undefined ? { args: entry.args } : {}),
    durationMs: entry.durationMs,
    ...(entry.ok !== undefined ? { ok: entry.ok } : {}),
    ...(entry.exitCode !== undefined ? { exitCode: entry.exitCode } : {}),
    ...(entry.resultBytes !== undefined ? { resultBytes: entry.resultBytes } : {}),
    ...(entry.stderrBytes !== undefined ? { stderrBytes: entry.stderrBytes } : {}),
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

/** 记一笔轨迹（薄接线：补 atMs/pid，路径缺省 `<DSH_HOME>/sec-tools-trace.jsonl`）。 */
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
  /** 工具名（如 `sec_nmap`）。 */
  tool: string
  build: string
  /** 目标投影；缺省按 `target` / `url` / `domain` 依次取（抛错即视为取不到）。 */
  targetOf?: (args: Record<string, unknown>) => string | undefined
}

/** 默认目标投影：`target` → `url`（结构化，仅 host+path）→ `domain`。 */
export function defaultTargetOf(args: Record<string, unknown>): string | undefined {
  const t = args['target']
  if (typeof t === 'string' && t !== '') return t
  const u = args['url']
  if (typeof u === 'string' && u !== '') return summarizeUrl(u)
  const d = args['domain']
  if (typeof d === 'string' && d !== '') return d
  return undefined
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
 * 把一个工具的 `execute` 包成「落 `begin` 行 → 执行 → 落 `gate`/`end` 行」。
 *
 * 三条硬约束（对应审计 S4/S6 与技能 C4）：
 *   1. **返回值与异常传播逐字不变**（失败时落 `ok=false` + `break`/`error`，然后原样重抛）；
 *   2. **落盘失败不影响主流程**（`safeTrace` 返回 bool）；
 *   3. **摘要函数抛错不影响主流程**（`safely` 吞错）。
 *
 * `gate` 阶段的语义：`unsafeArg()`/`validUrl()`/`validTarget()` 在 **WSL 之前**拒绝
 * ⇒ 该行**同时证明两件事**：防线拦下了什么，以及「这一发没有产生任何子进程」。
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
    const target = safely(() => (opts.targetOf ?? defaultTargetOf)(bag)) ?? undefined
    const argsSum = summarizeArgs(bag)
    const io = { path: opts.path, home: opts.home, pid: opts.pid }
    safeTrace(
      { tool: opts.tool, build: opts.build, phase: 'begin', durationMs: 0, target, args: argsSum },
      { ...io, now: now() },
    )

    try {
      const result = await run(args)
      const facts = summarizeResult(result)
      const kind = facts.ok ? undefined : classifyBreak(errorOf(result))
      safeTrace(
        {
          tool: opts.tool,
          build: opts.build,
          phase: kind !== undefined && isGate(kind) ? 'gate' : 'end',
          durationMs: Math.max(0, now() - t0),
          target,
          ok: facts.ok,
          ...(facts.exitCode !== undefined ? { exitCode: facts.exitCode } : {}),
          ...(facts.resultBytes !== undefined ? { resultBytes: facts.resultBytes } : {}),
          ...(facts.stderrBytes !== undefined ? { stderrBytes: facts.stderrBytes } : {}),
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
          tool: opts.tool,
          build: opts.build,
          phase: isGate(kind) ? 'gate' : 'end',
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
