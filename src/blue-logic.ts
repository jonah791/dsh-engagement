/** 纯逻辑层：参数规范化 / PowerShell 输出解析 / 脚本字面量转义。
 *
 *  从 `src/index.ts` 的 apply() 闭包与 `src/host.ts` 抽出——**行为与抽出前完全一致**（重构只是搬家）。
 *  本模块**无 IO、无时间依赖**（时间由调用方注入），因此可离线单测：`tests/logic.test.mjs`。
 */

import { parsePorts, DEFAULT_PORTS } from './blue-net.js'

/** 事件日志默认查询 ID（与 `blue_event_log_query` 工具描述一致） */
export const DEFAULT_EVENT_IDS = [4625, 4624, 4672, 4720, 7045, 1102] as const

/** 端口规格解析：空规格（'' / undefined / null / 0）回落默认常见端口表；
 *  非法规格得到空数组——由调用方判空并显式报错（`端口规格无效`）。 */
export function resolvePorts(spec: unknown): number[] {
  return spec ? parsePorts(String(spec)) : DEFAULT_PORTS
}

/** 事件 ID 规格解析："4625,4624" → [4625,4624]；空规格回落默认；非数字项被丢弃。
 *  注意真实语义：空串项被 `Number('')` 解析为 **0**（不是 NaN，故不会被过滤）——
 *  `'4625,,4711'` → `[4625, 0, 4711]`；两侧空白被容忍（`' 4625 '` → `4625`）。 */
export function parseEventIds(spec: unknown): number[] {
  const raw = String(spec ?? DEFAULT_EVENT_IDS.join(','))
  return raw.split(',').map(Number).filter((n) => !Number.isNaN(n))
}

/** PowerShell JSON 输出归一化：空输出 → `[]`；单对象 → `[对象]`；数组原样。
 *  非法 JSON **照旧抛出**（由调用方的 `safe()` 收口为 `{ok:false,error}`）——不静默吞错。 */
export function psJsonRows(out: string | null | undefined): any[] {
  if (!out) return []
  const parsed = JSON.parse(out)
  return Array.isArray(parsed) ? parsed : [parsed]
}

/** 哈希工具输出判定：`NOT_FOUND` 哨兵 → `null`（文件不存在）；否则解析 JSON。
 *  空串照旧抛出（保持原 `JSON.parse('')` 的失败语义，由 `safe()` 收口）。 */
export function psHashOutcome(out: string | null | undefined): any | null {
  if (out === 'NOT_FOUND') return null
  return JSON.parse(out as string)
}

/** PowerShell 单引号字面量转义：`'` → `''`。
 *  **不变量**：任何进入 PS 脚本的外来字符串都必须先过本函数，否则可逃逸出字面量执行任意命令。 */
export function psQuote(s: unknown): string {
  return String(s).replace(/'/g, "''")
}
