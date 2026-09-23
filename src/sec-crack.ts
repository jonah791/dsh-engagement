/**
 * 密码面工具封装：hashcat / john
 *
 * 用途：哈希破解（自有数据的密码恢复 / 靶场取证）。
 * 注意：仅限自有/授权数据；hashcat 需要 GPU（本机 WSL 可能无 CUDA，会 fallback CPU 很慢）。
 */

import { spawnWsl, toolExists, type WslResult } from './sec-wsl.js'
import { sq, fileExists } from './sec-recon.js'
import { buildHashcatCmd, buildJohnCmd } from './sec-commands.js'

// ═══════════════ hashcat ═══════════════

export interface HashcatOptions {
  /** 哈希值（单个） */
  hash?: string
  /** 哈希文件路径（WSL 内） */
  hashFile?: string
  /** hashcat 模式编号：0=MD5 1000=NTLM 3200=bcrypt 100=sha1 1400=sha256 等 */
  mode: number
  /** 攻击模式：0=字典 3=掩码 6=字典+掩码 */
  attack?: number
  /** 字典路径 */
  wordlist?: string
  /** 掩码（如 ?d?d?d?d） */
  mask?: string
  timeoutMs?: number
}

export async function runHashcat(opts: HashcatOptions): Promise<{ ok: boolean; error?: string; result?: string; exitCode?: number; stderr?: string }> {
  if (!opts.hash && !opts.hashFile) return { ok: false, error: '需提供 hash 或 hashFile' }
  if (!(await toolExists('hashcat'))) return { ok: false, error: 'WSL 未安装 hashcat' }
  const cmd = buildHashcatCmd(opts)
  const r: WslResult = await spawnWsl(cmd, opts.timeoutMs ?? 600_000)
  if (!r.ok && !r.stdout) return { ok: false, error: `hashcat 执行失败: ${r.stderr.slice(0, 400)}`, exitCode: r.exitCode }
  return { ok: true, result: r.stdout, exitCode: r.exitCode }
}

// ═══════════════ john ═══════════════

export interface JohnOptions {
  /** 哈希文件路径（WSL 内，john 格式） */
  hashFile: string
  /** 格式（如 raw-md5 / nt / sha256crypt，缺省自动检测） */
  format?: string
  /** 字典路径 */
  wordlist?: string
  timeoutMs?: number
}

export async function runJohn(opts: JohnOptions): Promise<{ ok: boolean; error?: string; result?: string; exitCode?: number; stderr?: string }> {
  if (!opts.hashFile) return { ok: false, error: 'hashFile 必填（WSL 内路径）' }
  if (!(await toolExists('john'))) return { ok: false, error: 'WSL 未安装 john' }
  if (!(await fileExists(opts.hashFile))) return { ok: false, error: `哈希文件不存在（WSL 路径）: ${opts.hashFile}` }
  const cmd = buildJohnCmd(opts)
  const r = await spawnWsl(cmd, opts.timeoutMs ?? 600_000)
  if (!r.ok && !r.stdout) return { ok: false, error: `john 执行失败: ${r.stderr.slice(0, 400)}`, exitCode: r.exitCode }
  return { ok: true, result: r.stdout, exitCode: r.exitCode }
}
