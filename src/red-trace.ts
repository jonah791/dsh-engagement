/**
 * dsh-red-team 扫描轨迹（可维护性 S4 证据层 · 2026-09-14）。
 *
 * 动机：本插件 8 个工具全是「打网络 → 过滤/去重 → 返回命中」，而**过滤掉了多少、依据什么**
 * 在插件外不可见——刚修过的那类缺陷（`href.startsWith(origin)` 前缀比较把异源当同源）
 * 正是这个可见面：修前「同源过滤」名不副实，修后也只留下一个结果条数。
 * 宿主 `ctx.logger` 不落盘（AGENTS.md §5.22 规则 1），于是排障只能反解源码。
 *
 * 修法：每次工具调用的阶段落成可 `tail`/`grep` 的 JSONL 侧车——
 * `<DSH_HOME>/redteam-trace.jsonl`（一行一阶段，`atMs` 单调）。
 * 阶段枚举：`boot` → `scan/start` → `scan/end` | `scan/error`。
 *
 * 轨迹回答的五问（技能 plugin-maintainability 判据）：
 *   Q1 线上跑的是哪个构建 → `build`（`<version>@<模块 mtime ms>`）+ `cfg`（boot 行）
 *   Q2 谁发起 / 打向谁     → `tool`（工具名）+ `target`（脱敏后的目标）+ `pid`
 *   Q3 断在哪一段         → `phase` 枚举 + `failure`（可 grep 的失败分类）+ `error`（原文裁剪）
 *   Q4 结果质量           → `hits`（过滤/去重**后**条数）+ `stats`（raw/kept/dropped/reasons：**过滤依据**）
 *   Q5 耗时与预算         → `durationMs`（每次调用实耗；配合 `cfg.timeoutMs` 判网络超时占比）
 *
 * 隐私红线：`target` 先脱敏（URL userinfo、键名像凭据的 query 参数、用户主目录前缀）；
 * 只记**目标**与**计数**，绝不记响应正文（页面/ banner 正文可能含他人数据与凭据）。
 *
 * 观测绝不反噬主流程（技能 C4）：全部 IO 失败吞错并返回 `false`，扫描行为不受影响。
 *
 * @module dsh-red-team/trace
 */
import { appendFileSync, mkdirSync, readFileSync, statSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

/** 阶段枚举（`boot` 一次装载一行；每次工具调用从 `scan/start` 到 `scan/end`|`scan/error`）。 */
export type RedTracePhase = 'boot' | 'scan/start' | 'scan/end' | 'scan/error'

/** 脱敏占位符（测试与文档共用，避免判据漂移）。 */
export const REDACTED = '<redacted>'

/** 用户主目录前缀的折叠占位符。 */
export const HOME_TOKEN = '<home>'

/**
 * 过滤统计（Q4 的「过滤掉了多少、依据什么」）——本插件过滤层（`pure.ts`）与轨迹共用同一形状。
 * `reasons` 是**可 grep 的过滤依据**（如 `off-origin`/`duplicate`/`not-subdomain`）。
 */
export interface TraceStats {
  /** 过滤前的原始候选数（原始命中条数）。 */
  raw: number
  /** 过滤/去重/截断后保留数。 */
  kept: number
  /** 丢弃总数（= raw − kept）。 */
  dropped: number
  /** 丢弃依据分布（键是可 grep 的原因枚举）。 */
  reasons?: Record<string, number>
}

/** boot 阶段自报的生效面。 */
export interface RedTraceConfig {
  enabled: boolean
  /** 注册的工具名清单（工具面自报，便于判「线上挂的是哪几个」）。 */
  tools: string[]
}

/** 一行红队轨迹。 */
export interface RedTraceEntry {
  /** 写入时刻（ms epoch）。 */
  atMs: number
  phase: RedTracePhase
  /** 本插件构建标识 `<version>@<trace 模块 mtime ms>`。 */
  build: string
  /** 进程 pid。 */
  pid: number
  /** 工具名（如 `red_crawl_links`）；boot 行为 `apply`。 */
  tool: string
  /** 目标（脱敏后：userinfo/凭据型 query/主目录前缀）。 */
  target?: string
  /** 阶段耗时（`scan/start` = 0；`scan/end`/`scan/error` = 实耗）。 */
  durationMs: number
  /** 过滤前的原始候选数（仅内层函数提供统计时才有）。 */
  raw?: number
  /** 过滤后条数（Q4 结果质量）。 */
  hits?: number
  /** 过滤依据统计（Q4；`raw/kept/dropped/reasons`）。 */
  stats?: TraceStats
  /** 文本型结果的长度（如 banner 字符数；非「命中条数」语义，单列不混用）。 */
  textChars?: number
  /** 失败分类（可 grep：`http-4xx`/`http-5xx`/`dns`/`refused`/`timeout`/`network`/`parse`/`abort`/`unknown`）。 */
  failure?: string
  /** 失败原文（裁剪到 200 字符；网络错误串不含凭据，但一律裁剪防噪声）。 */
  error?: string
  /** 仅 boot：生效配置与工具面。 */
  cfg?: RedTraceConfig
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
export function redTracePath(home: string): string {
  return join(home, 'redteam-trace.jsonl')
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

let cachedSelfBuild: string | undefined

/** 本模块自身的构建标识（Q1：进程级自报；文件不可得退化为 `unknown@0`，进程内缓存）。 */
export function selfBuild(): string {
  if (cachedSelfBuild !== undefined) return cachedSelfBuild
  try {
    const file = fileURLToPath(import.meta.url)
    cachedSelfBuild = buildStamp(file, readPackageVersion(file))
  } catch {
    cachedSelfBuild = 'unknown@0'
  }
  return cachedSelfBuild
}

/** 主目录三形态（Windows / POSIX / WSL `/mnt/<drive>`；长的优先替换）。 */
export function homePathVariants(home: string): string[] {
  const trimmed = home.replace(/[\\/]+$/, '')
  if (trimmed === '') return []
  const variants = new Set<string>([trimmed, trimmed.replace(/\\/g, '/')])
  const drive = /^([A-Za-z]):[\\/](.*)$/.exec(trimmed)
  if (drive !== null) {
    variants.add(`/mnt/${(drive[1] ?? '').toLowerCase()}/${(drive[2] ?? '').replace(/\\/g, '/')}`)
  }
  return [...variants].filter((v) => v !== '').sort((a, b) => b.length - a.length)
}

/** 折叠用户主目录前缀为 `<home>`（用户名不落盘）。 */
export function redactHome(text: string, home = homedir()): string {
  let out = text
  for (const variant of homePathVariants(home)) out = out.split(variant).join(HOME_TOKEN)
  return out
}

/** 凭据型 query 键名（命中即脱敏其值）。 */
const SECRET_QUERY_KEY = /(pass(word|wd)?|pwd|secret|token|api[-_]?key|apikey|auth|credential|private[-_]?key|access[-_]?key|signature|sig)/i

/**
 * 目标脱敏（纯函数，幂等）：URL userinfo（`scheme://user:pass@host`）→ `scheme://user:<redacted>@host`；
 * 凭据型 query 值 → `<redacted>`；主目录前缀 → `<home>`。非 URL 目标（host:port / 软件名）原样。
 */
export function redactTarget(target: string, home = homedir()): string {
  let out = target
  out = out.replace(
    /([a-zA-Z][\w+.-]*:\/\/[^\s/:@]+):[^\s/@]+@/g,
    (_match, head: string) => `${head}:${REDACTED}@`,
  )
  out = out.replace(
    /([?&])([A-Za-z0-9_.-]+)=([^&#\s]*)/g,
    (match, sep: string, key: string) =>
      SECRET_QUERY_KEY.test(key) ? `${sep}${key}=${REDACTED}` : match,
  )
  return redactHome(out, home)
}

/** 失败分类（纯函数，Q3）：把自由文本错误归到一个**可 grep 的类别**。 */
export function classifyFailure(text: string): string {
  const t = text.toLowerCase()
  if (t.includes('aborterror') || t.includes('aborted')) return 'abort'
  if (t.includes('timeout') || t.includes('timed out') || t.includes('etimedout')) return 'timeout'
  if (t.includes('enotfound') || t.includes('getaddrinfo') || t.includes('dns')) return 'dns'
  if (t.includes('econnrefused') || t.includes('econnreset') || t.includes('ehostunreach')) return 'refused'
  if (/\bhttp 5\d\d\b/.test(t)) return 'http-5xx'
  if (/\bhttp 4\d\d\b/.test(t)) return 'http-4xx'
  if (t.includes('fetch failed') || t.includes('socket') || t.includes('network')) return 'network'
  if (t.includes('json') || t.includes('parse') || t.includes('unexpected token')) return 'parse'
  return 'unknown'
}

/** 文本裁剪（落盘用；末尾标出被砍字符数）。 */
export function clip(text: string, maxLen = 200): string {
  const flat = text.replace(/\s+/g, ' ').trim()
  return flat.length <= maxLen ? flat : `${flat.slice(0, maxLen)}...(+${String(flat.length - maxLen)})`
}

/** 数组判定（脏数据不抛）。 */
function asArray(value: unknown): unknown[] | undefined {
  return Array.isArray(value) ? value : undefined
}

/** 统计形状守卫：`raw/kept/dropped` 三个数字齐备才算（脏数据不污染轨迹）。 */
export function asTraceStats(value: unknown): TraceStats | undefined {
  if (value === null || typeof value !== 'object') return undefined
  const s = value as Record<string, unknown>
  if (typeof s['raw'] !== 'number' || typeof s['kept'] !== 'number' || typeof s['dropped'] !== 'number') {
    return undefined
  }
  const out: TraceStats = { raw: s['raw'], kept: s['kept'], dropped: s['dropped'] }
  const reasons = s['reasons']
  if (reasons !== null && typeof reasons === 'object') out.reasons = reasons as Record<string, number>
  return out
}

/**
 * 从内层函数返回值抽出「命中/过滤」事实（纯函数，Q4）。
 *
 * 覆盖本插件 8 个工具的实际返回形状（**形状不认识就返回空**，绝不猜、绝不抛）：
 * 数组（子域/目录/CVE/敏感路径）｜`{links}`（爬取）｜`{marks}`（指纹）｜`{present,missing}`（安全头）｜
 * 字符串（banner → `textChars`）。`stats` 由过滤层（`extractLinksDetailed` 等）显式带出。
 */
export function hitsOf(value: unknown): { raw?: number; hits?: number; stats?: TraceStats; textChars?: number } {
  if (typeof value === 'string') return { textChars: value.length }
  if (value === null || value === undefined) return {}
  const list = asArray(value)
  if (list !== undefined) return { hits: list.length }
  if (typeof value !== 'object') return {}
  const v = value as Record<string, unknown>
  const stats = asTraceStats(v['stats'])
  const out: { raw?: number; hits?: number; stats?: TraceStats; textChars?: number } = {}
  if (stats !== undefined) {
    out.stats = stats
    out.raw = stats.raw
    out.hits = stats.kept
  }
  for (const key of ['links', 'results', 'names', 'hits'] as const) {
    const arr = asArray(v[key])
    if (arr !== undefined && out.hits === undefined) out.hits = arr.length
  }
  const fp = v['fp']
  if (fp !== null && typeof fp === 'object') {
    const marks = asArray((fp as Record<string, unknown>)['marks'])
    if (marks !== undefined && out.hits === undefined) out.hits = marks.length
  }
  const result = v['result']
  if (result !== null && typeof result === 'object') {
    const present = asArray((result as Record<string, unknown>)['present'])
    const missing = asArray((result as Record<string, unknown>)['missing'])
    if (present !== undefined && out.hits === undefined) {
      out.hits = present.length
      if (missing !== undefined) {
        out.raw = present.length + missing.length
        out.stats = {
          raw: present.length + missing.length,
          kept: present.length,
          dropped: missing.length,
          reasons: { missing: missing.length },
        }
      }
    }
  }
  const banner = v['banner']
  if (typeof banner === 'string') out.textChars = banner.length
  return out
}

/** 稳定序列化（键序固定 + 单行 JSON，便于 `tail`/`grep`）。 */
export function serializeTraceEntry(entry: RedTraceEntry): string {
  const ordered: RedTraceEntry = {
    atMs: entry.atMs,
    phase: entry.phase,
    build: entry.build,
    pid: entry.pid,
    tool: entry.tool,
    ...(entry.target !== undefined ? { target: entry.target } : {}),
    durationMs: entry.durationMs,
    ...(entry.raw !== undefined ? { raw: entry.raw } : {}),
    ...(entry.hits !== undefined ? { hits: entry.hits } : {}),
    ...(entry.stats !== undefined ? { stats: entry.stats } : {}),
    ...(entry.textChars !== undefined ? { textChars: entry.textChars } : {}),
    ...(entry.failure !== undefined ? { failure: entry.failure } : {}),
    ...(entry.error !== undefined ? { error: entry.error } : {}),
    ...(entry.cfg !== undefined ? { cfg: entry.cfg } : {}),
  }
  return JSON.stringify(ordered)
}

/** 容错解析：坏行/半行/空行跳过，不抛（轨迹是证据，不是契约校验器）。 */
export function parseTraceEntries(text: string): RedTraceEntry[] {
  const out: RedTraceEntry[] = []
  for (const raw of text.split('\n')) {
    const line = raw.trim()
    if (line === '') continue
    try {
      const parsed = JSON.parse(line) as RedTraceEntry
      if (typeof parsed.atMs === 'number' && typeof parsed.phase === 'string') out.push(parsed)
    } catch {
      continue
    }
  }
  return out
}

/** 读轨迹文件；缺失/不可读返回空数组（诊断工具的安全入口）。 */
export function readTraceEntries(path: string): RedTraceEntry[] {
  try {
    return parseTraceEntries(readFileSync(path, 'utf8'))
  } catch {
    return []
  }
}

/** 追加一行（失败即吞并返回 false：轨迹是观测，绝不因写不进去而影响扫描结果）。 */
export function appendTraceEntry(path: string, entry: RedTraceEntry): boolean {
  try {
    mkdirSync(dirname(path), { recursive: true })
    appendFileSync(path, serializeTraceEntry(entry) + '\n', 'utf8')
    return true
  } catch {
    return false
  }
}

/** 记一笔扫描轨迹（薄接线：补 atMs/pid/build，路径缺省 `<DSH_HOME>/redteam-trace.jsonl`）。 */
export function redTrace(
  entry: Omit<RedTraceEntry, 'atMs' | 'pid' | 'build'>,
  opts: { path?: string; home?: string; now?: number; pid?: number; build?: string } = {},
): boolean {
  const path = opts.path ?? redTracePath(opts.home ?? resolveHome())
  return appendTraceEntry(path, {
    atMs: opts.now ?? Date.now(),
    pid: opts.pid ?? process.pid,
    build: opts.build ?? selfBuild(),
    ...entry,
  })
}

/** 装载自报（`apply` 调用一次）：Q1 = 跑的是哪个构建 + 挂的是哪几个工具。 */
export function redTraceBoot(
  cfg: RedTraceConfig,
  opts: { path?: string; home?: string; now?: number; pid?: number; build?: string } = {},
): boolean {
  return redTrace({ phase: 'boot', tool: 'apply', durationMs: 0, cfg }, opts)
}

/** 是否启用轨迹（`DSH_REDTEAM_TRACE=0` 关闭；缺省开启——证据层是默认行为，不是可选项）。 */
export function traceEnabled(env: Record<string, string | undefined> = process.env): boolean {
  return env['DSH_REDTEAM_TRACE'] !== '0'
}
