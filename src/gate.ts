/**
 * gate.ts — 授权闸门（**纯函数，可离线单测**）。
 *
 * 这是本件相对旧五件**唯一真正新增的机制**：五份散文式免责声明换成一道**可判定**的闸门——
 * 有结构化输入、有闭集 reason、能被坏样本证伪、拒绝会落盘留痕。
 *
 * 纪律：
 * - **fail-closed**：读不到交战 / 状态不明 / 函数自身抛错 ⇒ 一律 deny（异常即拒绝）。
 * - **主动是可判定的**：`actionClass` 是每个工具**注册时的常量声明**，不在运行时猜。
 * - **范围匹配带 `.` 边界**：`example.com` 不匹配 `evil-example.com`（I6）。
 */

export type ActionClass = 'meta' | 'passive' | 'active' | 'active-auth' | 'intel'

/**
 * `meta` 是 2026-09-23 实现时补的**第五类**，起因是一次真实调用：
 *
 * 设计稿的裁决表第一行（`engagement === null ⇒ deny`）压过了第九行（`passive ⇒ allow`），
 * 结果是 **`eng_open` 被自己的闸门挡住**——它正是用来**创建**交战的工具 ⇒ 整件不可用。
 * 根因是裁决表没有枚举「**先于交战存在**的管理动作」这一格：开交战、列交战清单都不需要
 * 一个已存在的交战，且零外部副作用（`eng_open` 的唯一副作用就是创建那份交战本身）。
 */

export type GateReason =
  | 'gate/no-engagement'
  | 'gate/closed'
  | 'gate/no-authorization'
  | 'gate/out-of-scope'
  | 'gate/excluded'
  | 'gate/out-of-window'
  | 'gate/auth-not-enabled'

export interface EngagementScope {
  readonly targets: readonly string[]
  readonly exclude?: readonly string[]
  readonly ports?: string
  readonly protocols?: readonly string[]
  readonly allowActiveAuth?: boolean
}

export interface EngagementAuthorization {
  readonly source: 'owner-directive' | 'lab-charter' | 'written-scope'
  readonly ref: string
}

export interface Engagement {
  readonly id: string
  readonly title?: string
  readonly purpose?: string
  readonly authorization: EngagementAuthorization
  readonly scope: EngagementScope
  readonly window: { readonly notBefore?: string; readonly notAfter?: string }
  readonly status: 'active' | 'closed'
}

export interface GateInput {
  readonly engagement: Engagement | null
  readonly actionClass: ActionClass
  readonly target?: string
  readonly nowMs: number
}

export type GateVerdict =
  | { readonly verdict: 'allow' }
  | { readonly verdict: 'deny'; readonly reason: GateReason }

/**
 * 归一化主机/目标：小写、去尾点、去端口、去 userinfo、去 scheme 与路径。
 * 归一化是**边界判定**的前提——不归一化就做后缀匹配，`EXAMPLE.com.:443` 会绕过。
 */
export function normalizeTarget(raw: string): string {
  let s = raw.trim().toLowerCase()
  if (s === '') return ''
  s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//, '') // scheme
  const at = s.lastIndexOf('@')
  if (at >= 0) s = s.slice(at + 1) // userinfo
  const slash = s.search(/[/?#]/)
  if (slash >= 0) s = s.slice(0, slash) // path/query/fragment
  s = s.replace(/:\d+$/, '') // 端口
  s = s.replace(/\.+$/, '') // 尾点
  return s
}

/** 目标是否命中某个范围条目（同值 / 子域，且子域必须落在 `.` 边界上） */
export function matchesScopeEntry(target: string, entry: string): boolean {
  const t = normalizeTarget(target)
  const e = normalizeTarget(entry)
  if (t === '' || e === '') return false
  if (t === e) return true
  return t.endsWith('.' + e)
}

function inList(target: string, list: readonly string[] | undefined): boolean {
  if (list === undefined) return false
  return list.some((entry) => matchesScopeEntry(target, entry))
}

function inWindow(eng: Engagement, nowMs: number): boolean {
  const { notBefore, notAfter } = eng.window
  if (notBefore !== undefined && notBefore !== '') {
    const t = Date.parse(notBefore)
    if (!Number.isNaN(t) && nowMs < t) return false
  }
  if (notAfter !== undefined && notAfter !== '') {
    const t = Date.parse(notAfter)
    if (!Number.isNaN(t) && nowMs > t) return false
  }
  return true
}

/**
 * 裁决表（逐条可穷举喂样本）：
 *
 * | 输入状态 | 裁决 | reason |
 * |---|---|---|
 * | `engagement === null` | deny | `gate/no-engagement` |
 * | `status !== 'active'` | deny | `gate/closed` |
 * | 授权 source 缺失或 ref 为空 | deny | `gate/no-authorization` |
 * | `active` 且目标不在 targets | deny | `gate/out-of-scope` |
 * | `active` 且目标命中 exclude | deny | `gate/excluded` |
 * | nowMs 在窗口外 | deny | `gate/out-of-window` |
 * | `active-auth` 且未开 allowActiveAuth | deny | `gate/auth-not-enabled` |
 * | `intel`（交战存在且 active） | allow | — |
 * | `passive` | allow | — |
 * | 其余（active 且目标在范围内） | allow | — |
 */
export function decideGate(input: GateInput): GateVerdict {
  const deny = (reason: GateReason): GateVerdict => ({ verdict: 'deny', reason })
  // ⚠ `meta` 必须排在 null 检查**之前**：开交战的工具自己不需要一个已存在的交战
  // （2026-09-23 实测事故：这一行漏了 ⇒ `eng_open` 被自己的闸门挡住，整件不可用）。
  if (input.actionClass === 'meta') return { verdict: 'allow' }
  const eng = input.engagement
  if (eng === null) return deny('gate/no-engagement')
  if (eng.status !== 'active') return deny('gate/closed')
  const auth = eng.authorization
  if (auth === undefined || auth === null || typeof auth.ref !== 'string' || auth.ref.trim() === '') {
    return deny('gate/no-authorization')
  }
  // passive 与 intel 不参与 scope 命中判定（前者零副作用，后者对象是公共情报源而非交战目标），
  // 但**都要过窗口**：窗口过期即 deny（一致优先——「交战已结束还在用它的名义」不成立）。
  if (input.actionClass === 'passive') return { verdict: 'allow' }
  if (input.actionClass === 'intel') {
    return inWindow(eng, input.nowMs) ? { verdict: 'allow' } : deny('gate/out-of-window')
  }
  if (!inWindow(eng, input.nowMs)) return deny('gate/out-of-window')
  const target = input.target ?? ''
  if (inList(target, eng.scope.exclude)) return deny('gate/excluded')
  if (!inList(target, eng.scope.targets)) return deny('gate/out-of-scope')
  if (input.actionClass === 'active-auth' && eng.scope.allowActiveAuth !== true) {
    return deny('gate/auth-not-enabled')
  }
  return { verdict: 'allow' }
}

/** 闸门拒绝时的落盘行（`gate/denied` 是「防线真在拦」的一手证据，不是日志噪音） */
export function gateDeniedLine(input: {
  atMs: number
  engagementId: string | null
  tool: string
  actionClass: ActionClass
  target?: string
  reason: GateReason
}): string {
  const out: Record<string, unknown> = {
    atMs: input.atMs,
    iso: new Date(input.atMs).toISOString(),
    phase: 'gate/denied',
    tool: input.tool,
    engagementId: input.engagementId,
    actionClass: input.actionClass,
    outcome: 'denied',
    reason: input.reason,
  }
  if (input.target !== undefined && input.target !== '') out['target'] = input.target
  return JSON.stringify(out)
}
