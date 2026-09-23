/**
 * 利用面工具封装：sqlmap / nikto / hydra
 *
 * 注意：这些是「授权测试」工具，仅限自有/授权/靶场环境。
 * 命令构造用单引号包裹参数防注入；危险参数（--os-shell 等）不默认开启。
 */

import { spawnWsl, toolExists, type WslResult } from './sec-wsl.js'
import { sq, validTarget, validUrl } from './sec-recon.js'
import { unsafeArg, buildSqlmapCmd, buildNiktoCmd, buildHydraCmd } from './sec-commands.js'

// ═══════════════ sqlmap ═══════════════

export interface SqlmapOptions {
  url: string
  /** 注入参数（如 id，缺省自动检测） */
  param?: string
  /** 数据：dbs 枚举库 / tables 枚举表 / dump 提取 / current-db 当前库 */
  action?: 'dbs' | 'tables' | 'dump' | 'current-db'
  /** 指定数据库名（tables/dump 时） */
  db?: string
  /** 指定表名（dump 时） */
  table?: string
  /** 风险/级别：--level 1-5 --risk 1-3 */
  level?: number
  risk?: number
  /** 额外参数（谨慎：不默认 os-shell） */
  extra?: string
  timeoutMs?: number
}

export async function runSqlmap(opts: SqlmapOptions): Promise<{ ok: boolean; error?: string; result?: string; exitCode?: number; stderr?: string }> {
  const u = validUrl(opts.url)
  if (!u.ok) return { ok: false, error: u.error }
  const bad = unsafeArg(opts.extra, 'extra')
  if (bad) return { ok: false, error: bad }
  if (!(await toolExists('sqlmap'))) return { ok: false, error: 'WSL 未安装 sqlmap' }
  const cmd = buildSqlmapCmd(opts)
  const r: WslResult = await spawnWsl(cmd, opts.timeoutMs ?? 600_000)
  if (!r.ok && !r.stdout) return { ok: false, error: `sqlmap 执行失败: ${r.stderr.slice(0, 400)}`, exitCode: r.exitCode }
  return { ok: true, result: r.stdout, exitCode: r.exitCode }
}

// ═══════════════ nikto ═══════════════

export interface NiktoOptions {
  url: string
  /** 扫描调优：0(全)/1(感兴趣)/2(配置文件误报)… */
  tune?: number
  timeoutMs?: number
}

export async function runNikto(opts: NiktoOptions): Promise<{ ok: boolean; error?: string; result?: string; exitCode?: number; stderr?: string }> {
  const u = validUrl(opts.url)
  if (!u.ok) return { ok: false, error: u.error }
  if (!(await toolExists('nikto'))) return { ok: false, error: 'WSL 未安装 nikto' }
  const cmd = buildNiktoCmd(opts)
  const r = await spawnWsl(cmd, opts.timeoutMs ?? 600_000)
  if (!r.ok && !r.stdout) return { ok: false, error: `nikto 执行失败: ${r.stderr.slice(0, 400)}`, exitCode: r.exitCode }
  return { ok: true, result: r.stdout, exitCode: r.exitCode }
}

// ═══════════════ hydra ═══════════════

export interface HydraOptions {
  target: string
  /** 协议：ssh/ftp/http-post-form/rdp/mysql 等 */
  service: string
  /** 用户名（缺省用 userlist） */
  user?: string
  /** 密码（缺省用 passlist） */
  pass?: string
  /** 用户字典路径 */
  userlist?: string
  /** 密码字典路径 */
  passlist?: string
  /** 服务端口（缺省协议默认） */
  port?: number
  /** 线程数 */
  threads?: number
  /** http-post-form 的特殊格式（如 "/login.php:user=^USER^&pass=^PASS^:Invalid"） */
  form?: string
  timeoutMs?: number
}

export async function runHydra(opts: HydraOptions): Promise<{ ok: boolean; error?: string; result?: string; exitCode?: number; stderr?: string }> {
  if (!validTarget(opts.target)) return { ok: false, error: 'target 格式无效' }
  const bad = unsafeArg(opts.service, 'service')
  if (bad) return { ok: false, error: bad }
  if (!(await toolExists('hydra'))) return { ok: false, error: 'WSL 未安装 hydra' }
  const cmd = buildHydraCmd(opts)
  const r = await spawnWsl(cmd, opts.timeoutMs ?? 300_000)
  if (!r.ok && !r.stdout) return { ok: false, error: `hydra 执行失败: ${r.stderr.slice(0, 400)}`, exitCode: r.exitCode }
  return { ok: true, result: r.stdout, exitCode: r.exitCode }
}
