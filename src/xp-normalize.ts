/**
 * 工具参数的规范化 / 校验 / 输出裁剪（纯函数，无 IO、无时间、不触网）。
 *
 * 抽取动机（技能 `dsh-plugin-testability`）：这些判定原本困在 `index.ts` 的 `apply()` 闭包内
 * （依赖 `ctx`），无法离线单测。抽出后 `apply()` 只做接线：
 *   - `normalizeSerializedProps` ← `eng_payload(serialize)` 的 `params.properties` 收口 —— **已接线**
 *   - `parseEcbArgs`            ← `eng_payload(ecb)` 的 `params.{prefixLen,injectOffset,payload,…}` —— **已接线**
 *   - `formatJwtReport`         ← `xp_jwt_forge` 的 render 正文（候选密钥裁剪到 10 条）—— **尚未接线**
 *
 * ⚠ 接线史（2026-10-06 · 任务 `t-dd3c6faa`）：本模块自 2026-09 抽出后**长期无人调用**
 * （`apply()` 里 serialize 写死 `properties: {}`、ecb 写死 `prefixLen:16 / injectOffset:0`），
 * 即「抽出来、忘了接回去」——直到判据工具 `scripts/scan-dead-modules.mjs` 把它判成
 * 「生产零调用 · 仅测试引用」才浮出水面。前两个函数已接回，并**由此抓出一个真缺陷**：
 * `parseEcbArgs` 的 `!0` 守卫把 `injectOffset=0`（从开头注入）当「必填缺失」拒掉，而缺省路径
 * 恰好传 0 ⇒ 接回当天即被 `tests/wire-contract.test.mjs` 的缺省对照抓红（详见该函数 JSDoc）。
 * `formatJwtReport` 因**统一 JSON 渲染已取代逐工具 render**而暂未接线，状态登记在语义文档 §10。
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
 * 守卫语义（**2026-10-06 修正**，原为「保持原样、不新增校验」的搬家语义）：
 *   - 必填判据是**非有限数**（NaN/Infinity）⇒ 缺失 / 非数字被拦（报「必填」而不是「类型错」）
 *   - **`0` 合法**：`prefixLen=0`（无前缀）与 `injectOffset=0`（从开头注入）都是真实场景。
 *     ⚠ 原实现写 `!prefixLen || !injectOffset`，而 `!0` 为真 ⇒ 这两个合法值被拒。该缺陷在旧件里
 *     从未暴露（调用方总传非 0 偏移），**接回 `eng_payload` 当天即被缺省路径对照抓出**
 *     （缺省 `injectOffset=0` ⇒ 不传 params 的正常调用直接失败）。
 *   - **负值通过**；`blockSize` 不校验（0 会让块计算 NaN 化，见 tests/primitives）
 *   - 两道守卫有先后：先 prefixLen/injectOffset，再 payload
 */
export function parseEcbArgs(raw: EcbArgsInput): EcbArgsParse {
  const prefixLen = Number(raw.prefixLen)
  const injectOffset = Number(raw.injectOffset)
  const payload = String(raw.payload ?? '')
  if (!Number.isFinite(prefixLen) || !Number.isFinite(injectOffset)) {
    return { ok: false, error: 'prefixLen/injectOffset 必填（且须为有限数字）' }
  }
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
