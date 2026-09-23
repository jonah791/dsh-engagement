/**
 * AES-ECB block splicing（块拼接）原语（cyber-range 经验固化）
 *
 * 经验来源（natas28 最难关，先误判 CBC 做 padding oracle 失败的教训）：
 *  - ECB 判定：32 个相同字符输入的密文块 16-31 == 32-47（无 CBC 链，相同明文块 = 相同密文块）
 *  - ECB 无 CBC 链 → 块可拼接：C1=encrypt('A'*10) 取块0-2 + C2=encrypt('A'*9+payload) 取块3+
 *  - 关键坑：单引号在 offset 36（block2 偏移 6），addslashes 转义 '  → \'；payload 必须把 \ 留在前块尾、' 落在新块头
 *  - `#` 注释优于 `-- `；UNION 列数匹配 select 列数；jokes 1 列匹配 UNION 1 列
 *
 * 设计：给定前缀长度/注入点偏移 + 目标 payload，输出拼接方案（哪块来自哪次加密），纯本地计算。
 */

export interface EcbSpliceOptions {
  /** 固定前缀长度（如 natas28 明文 SELECT...LIKE '% 前缀 38 字节） */
  prefixLen: number
  /** 注入点相对前缀的偏移（如 natas28 单引号在 offset 36 → 注入点 36） */
  injectOffset: number
  /** 块大小（默认 16） */
  blockSize?: number
  /** 目标 payload（如 ' UNION ALL SELECT password FROM users;#） */
  payload: string
  /** 转义字符（addslashes 是反斜杠） */
  escapeChar?: string
}

export interface EcbSplicePlan {
  /** ECB 判定方法 */
  detect: string
  /** 拼接方案说明 */
  plan: string
  /** 需要的加密 oracle 调用 */
  oracleCalls: { label: string; input: string; blocks: string; purpose: string }[]
  /** 最终密文拼接（块索引） */
  splice: string
  /** 关键坑提醒 */
  pitfalls: string[]
  /** 需要 oracle 提供的密文（占位，实际执行由模型经 otw_request/盲注补全） */
  notes: string
}

export function planEcbSplice(opts: EcbSpliceOptions): EcbSplicePlan {
  const bs = opts.blockSize ?? 16
  const esc = opts.escapeChar ?? '\\'
  const prefixLen = opts.prefixLen
  const off = opts.injectOffset

  // 判定方法
  const detect = `提交 32 个 'A' 的查询，若密文块 16-31 == 32-47 → ECB（相同明文块=相同密文块）。若不等 → CBC，本方案不适用。`

  // 拼接计算：目标让 payload 的首字节落在某个块头（使转义符留在前块尾）
  // 取 payload 前加若干填充，使 payload[0] 对齐块边界：需要 (off + fill) % bs == 0
  const fillNeeded = (bs - (off % bs)) % bs
  const filler = 'A'.repeat(fillNeeded)
  const oracleCalls: EcbSplicePlan['oracleCalls'] = []
  oracleCalls.push({
    label: 'C1（取前段块）',
    input: filler,
    blocks: `块 0..${Math.floor((off + fillNeeded) / bs) - 1}`,
    purpose: '把注入点之前的明文（含前缀）对齐加密，取前缀+填充所在的完整块',
  })
  oracleCalls.push({
    label: 'C2（取 payload 块）',
    input: filler + opts.payload,
    blocks: `从第 ${Math.floor((off + fillNeeded) / bs)} 块起`,
    purpose: `填充 ${fillNeeded} 字节后 payload 对齐块边界，${esc} 与 payload 首字节分处不同块，` +
      `取 payload 所在的后续块（首个转义符 ${esc} 若落在前块尾，则由 C1 段承载）`,
  })
  const splice = `C1[0..${Math.floor((off + fillNeeded) / bs) - 1}] + C2[${Math.floor((off + fillNeeded) / bs)}..]`
  const pitfalls = [
    `注入点偏移 ${off} 是「单引号/双引号」所在字节，不是注入参数起点——先确认引号类型（natas28 是单引号在 offset 36）`,
    `addslashes 只转义 ' → ${esc}'，${esc} 落在前块尾、' 落在新块头，block splicing 才能消掉转义符`,
    `ECB 判定必须先行：提交 32 个相同字符看密文块是否重复；误判 CBC 做 padding oracle 是 natas28 的最大弯路`,
    `UNION 列数必须匹配 select 的列数（jokes 1 列 → UNION SELECT 1 列）；# 注释优于 -- （避免尾空格）`,
  ]
  const notes = `工具已给出拼接方案与 oracle 输入；实际密文块需经 otw_request 加密 oracle 获取后按 splice 拼接提交。`

  return {
    detect,
    plan: `前缀 ${prefixLen}B、注入点 ${off}、块 ${bs}B → 需要填充 ${fillNeeded} 字节使 payload 对齐块边界。` +
      `用两次 oracle 调用分别取前缀段与 payload 段密文，再拼接。`,
    oracleCalls,
    splice,
    pitfalls,
    notes,
  }
}
