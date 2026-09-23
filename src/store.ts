/**
 * store.ts — 交战国度（**本件是它的唯一 owner**）。
 *
 * 落点：`<DSH_HOME>/engagement/<engagementId>/`：
 * - `engagement.json`（单文件，**原子写** tmp + rename）
 * - `findings.jsonl` / `evidence.jsonl` / `timeline.jsonl`（append-only，一行一事件，可 tail/grep）
 *
 * 纪律：
 * - **读不到就 deny，不重建不猜**（fail-closed；调用方据此返回 `gate/no-engagement`）；
 * - **凭据不落盘**：evidence 的 `summary` 与 timeline 的 `detail` 写入前一律过 `redactSecrets`（I7）；
 * - 观测面（timeline）写失败**不反噬**，但返回值要显式告知；领域面（engagement.json）写失败即失败。
 */

import { appendFileSync, existsSync, mkdirSync, readFileSync, readdirSync, renameSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { scrub } from './sec-trace.js'
import type { Engagement } from './gate.js'

export interface EngagementPaths {
  readonly root: string
  readonly dir: string
  readonly engagementFile: string
  readonly findingsFile: string
  readonly evidenceFile: string
  readonly timelineFile: string
}

export function pathsOf(root: string, engagementId: string): EngagementPaths {
  const dir = join(root, engagementId)
  return {
    root,
    dir,
    engagementFile: join(dir, 'engagement.json'),
    findingsFile: join(dir, 'findings.jsonl'),
    evidenceFile: join(dir, 'evidence.jsonl'),
    timelineFile: join(dir, 'timeline.jsonl'),
  }
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

/** 形状校验：缺 id / scope / authorization / window 一律判「不可读」（不猜测、不补默认） */
export function isEngagement(v: unknown): v is Engagement {
  if (!isRecord(v)) return false
  if (typeof v['id'] !== 'string' || typeof v['status'] !== 'string') return false
  if (!isRecord(v['scope']) || !isRecord(v['authorization'])) return false
  if (!isRecord(v['window'])) return false
  return true
}

export type EngagementRead =
  | { readonly ok: true; readonly engagement: Engagement }
  | { readonly ok: false; readonly reason: 'missing' | 'corrupt'; readonly detail: string }

/** 读交战：**不存在与损坏都返回不可读**（调用方一律 deny，不重建） */
export function readEngagement(paths: EngagementPaths): EngagementRead {
  if (!existsSync(paths.engagementFile)) {
    return { ok: false, reason: 'missing', detail: `交战不存在：${paths.engagementFile}` }
  }
  let raw: string
  try {
    raw = readFileSync(paths.engagementFile, 'utf8')
  } catch (err) {
    return { ok: false, reason: 'corrupt', detail: `读取失败：${(err as Error).message}` }
  }
  try {
    const parsed = JSON.parse(raw) as unknown
    if (!isEngagement(parsed)) return { ok: false, reason: 'corrupt', detail: '形状不符（缺 id/scope/authorization/window）' }
    return { ok: true, engagement: parsed }
  } catch (err) {
    return { ok: false, reason: 'corrupt', detail: `JSON 解析失败：${(err as Error).message}` }
  }
}

export function writeEngagement(paths: EngagementPaths, engagement: Engagement): void {
  mkdirSync(paths.dir, { recursive: true })
  const tmp = paths.engagementFile + '.tmp'
  writeFileSync(tmp, JSON.stringify(engagement, null, 1), 'utf8')
  renameSync(tmp, paths.engagementFile)
}

/** 列出全部交战 id（目录名即 id；读不到目录 ⇒ 空表） */
export function listEngagements(root: string): string[] {
  if (!existsSync(root)) return []
  try {
    return readdirSync(root, { withFileTypes: true })
      .filter((e) => e.isDirectory() && e.name.startsWith('eng-'))
      .map((e) => e.name)
      .sort()
  } catch {
    return []
  }
}

function appendJsonl(file: string, value: Record<string, unknown>, secrets: readonly string[]): boolean {
  try {
    mkdirSync(join(file, '..'), { recursive: true })
    appendFileSync(file, JSON.stringify(value) + '\n', 'utf8')
    return true
  } catch {
    return false
  }
}

function readJsonl(file: string): unknown[] {
  if (!existsSync(file)) return []
  try {
    return readFileSync(file, 'utf8')
      .split('\n')
      .map((l) => l.trim())
      .filter((l) => l !== '')
      .map((l) => {
        try {
          return JSON.parse(l) as unknown
        } catch {
          return null
        }
      })
      .filter((v) => v !== null)
  } catch {
    return []
  }
}

export interface Finding {
  readonly id: string
  readonly atMs: number
  readonly target: string
  readonly phase: string
  readonly kind: string
  readonly severity: string
  readonly status: 'candidate' | 'verified' | 'refuted'
  readonly evidenceIds: readonly string[]
  readonly note: string
}

export interface Evidence {
  readonly id: string
  readonly atMs: number
  readonly sourceToolCall: string
  readonly kind: 'http' | 'dns' | 'tcp' | 'subprocess' | 'local-read'
  readonly target: string
  readonly sha256: string
  readonly bytes: number
  readonly summary: string
}

export interface TimelineEntry {
  readonly atMs: number
  readonly phase: string
  readonly tool: string
  readonly engagementId: string
  readonly target?: string
  readonly outcome: string
  readonly reason?: string
}

/** 写发现（I5：必须挂 ≥1 个证据，否则拒绝） */
export function appendFinding(paths: EngagementPaths, f: Finding, secrets: readonly string[] = []): { ok: boolean; reason?: string } {
  if (f.evidenceIds.length === 0) return { ok: false, reason: 'finding/no-evidence' }
  const redacted = scrub(f.note, secrets)
  return appendJsonl(paths.findingsFile, { ...f, note: redacted }, secrets)
    ? { ok: true }
    : { ok: false, reason: 'finding/write-failed' }
}

export function appendEvidence(paths: EngagementPaths, e: Evidence, secrets: readonly string[] = []): { ok: boolean; reason?: string } {
  const redacted = scrub(e.summary, secrets)
  return appendJsonl(paths.evidenceFile, { ...e, summary: redacted }, secrets)
    ? { ok: true }
    : { ok: false, reason: 'evidence/write-failed' }
}

/** 时间线（含 `gate/denied`；观测面写失败只回报，不抛） */
export function appendTimeline(paths: EngagementPaths, line: Record<string, unknown>): boolean {
  return appendJsonl(paths.timelineFile, line, [])
}

export function readFindings(paths: EngagementPaths): unknown[] {
  return readJsonl(paths.findingsFile)
}

export function readEvidence(paths: EngagementPaths): unknown[] {
  return readJsonl(paths.evidenceFile)
}

export function readTimeline(paths: EngagementPaths): unknown[] {
  return readJsonl(paths.timelineFile)
}

/** 拒绝计数（`gate/denied` 行数——「防线真在拦」的读数） */
export function deniedCount(paths: EngagementPaths): number {
  return readTimeline(paths).filter((e) => isRecord(e) && e['phase'] === 'gate/denied').length
}
