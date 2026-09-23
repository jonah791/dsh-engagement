/**
 * 工具参数的规范化 / 校验 / 输出裁剪（纯函数，无 IO、无时间、不触网）。
 *
 * 抽取动机（技能 `dsh-plugin-testability`）：这些判定原本困在 `index.ts` 的 `apply()` 闭包内
 * （依赖 `ctx`），无法离线单测。抽出后 `apply()` 只做接线，行为**逐字不变**：
 *   - `normalizeSerializedProps` ← xp_serialize_php 的 properties 强制转换
 *   - `parseEcbArgs`            ← xp_ecb_splice 的 Number 转换 + 两道守卫
 *   - `formatJwtReport`         ← xp_jwt_forge 的 render 正文（含候选密钥裁剪）
 */

import type { JwtResult } from './xp-jwt.js'
import type { EcbSpliceOptions } from './xp-ecb.js'

/** PHP 序列化可接受的值形态（其余一律 String()） */
export type SerializeValue = string | number | boolean

/**
 * 把工具入参 `properties` 规范化为 PHP 序列化友好形态：
 * boolean/number 原样保留，其余一律 `String(v)`。
 *
 * 退化语义（与 `Object.entries(raw ?? {})` 逐字一致）：
 *   - `undefined`/`null` → `{}`（空表；接线层再判「至少一个属性」）
 *   - 非对象标量 → 按 Object.entries 的 ToObject 语义展开（字符串 → 逐字符索引键）
 *   - `null` 值 → 字符串 `'null'`；对象值 → `'[object Object]'`（PHP 侧无法还原结构，属已知缺口）
 */
export function normalizeSerializedProps(raw: unknown): Record<string, SerializeValue> {
  const out: Record<string, SerializeValue> = {}
  for (const [k, val] of Object.entries((raw ?? {}) as Record<string, unknown>)) {
    out[k] = typeof val === 'boolean' || typeof val === 'number' ? val : String(val)
  }
  return out
}

/** xp_ecb_splice 的入参形态（工具 schema 之外的兜底：直接用函数时可能拿到任意类型） */
export interface EcbArgsInput {
  prefixLen?: unknown
  injectOffset?: unknown
  payload?: unknown
  blockSize?: unknown
  escapeChar?: unknown
}

export type EcbArgsParse = { ok: true; options: EcbSpliceOptions } | { ok: false; error: string }

/**
 * 解析并校验 xp_ecb_splice 入参。
 *
 * 守卫语义（保持原样，**不新增校验**）：
 *   - `Number(undefined)` = NaN → 被 `!prefixLen` 拦下（报「必填」而不是「类型错」）
 *   - `0` 被拒（`!0` 为真）——`prefixLen=0` 的合法场景（无前缀）因而无法表达
 *   - **负值通过**；`blockSize` 不校验（0 会让块计算 NaN 化，见 tests/primitives）
 *   - 两道守卫有先后：先 prefixLen/injectOffset，再 payload
 */
export function parseEcbArgs(raw: EcbArgsInput): EcbArgsParse {
  const prefixLen = Number(raw.prefixLen)
  const injectOffset = Number(raw.injectOffset)
  const payload = String(raw.payload ?? '')
  if (!prefixLen || !injectOffset) return { ok: false, error: 'prefixLen/injectOffset 必填' }
  if (!payload) return { ok: false, error: 'payload 必填' }
  const blockSize = (raw.blockSize ?? 16) as number
  const escapeChar = (raw.escapeChar ?? '\\') as string
  return { ok: true, options: { prefixLen, injectOffset, payload, blockSize, escapeChar } }
}

/** 候选密钥预览条数（超出部分以 `…` 结尾，避免结论被字典长列表淹没） */
export const SECRET_PREVIEW_LIMIT = 10

/**
 * xp_jwt_forge 的渲染正文。
 *
 * 裁剪判定（保持原样）：只有当
 *   ① `candidates` 非空 ② `secretSource === 'none'` ③ 没有 `foundSecret`
 * 三者同时成立时，才追加「候选密钥」行；列表截到 `SECRET_PREVIEW_LIMIT` 条并加 `…`。
 * 即：**爆破命中 / 手动自签时不列字典**，未指定密钥时才把字典亮出来给模型逐个试。
 */
export function formatJwtReport(result: JwtResult): string {
  const lines: string[] = []
  if (result.foundSecret) lines.push(`密钥: ${result.foundSecret}（${result.secretSource}）`)
  if (result.token) lines.push(`JWT: ${result.token}`)
  lines.push(result.note)
  if ((result.candidates?.length ?? 0) > 0 && result.secretSource === 'none' && !result.foundSecret) {
    const shown = result.candidates.slice(0, SECRET_PREVIEW_LIMIT).join(', ')
    const more = result.candidates.length > SECRET_PREVIEW_LIMIT ? '…' : ''
    lines.push(`候选密钥(${result.candidates.length}): ${shown}${more}`)
  }
  return lines.join('\n')
}
