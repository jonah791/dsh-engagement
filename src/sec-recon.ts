/**
 * 侦察面工具封装：nmap / masscan / gobuster / subfinder / whatweb / dnsrecon
 *
 * 每个工具：参数校验 → 构造命令 → spawnWsl 执行 → 输出解析为结构化结果。
 * 命令构造必须用引号包裹参数（防注入），路径/主机名校验。
 */

import { spawnWsl, toolExists, type WslResult } from './sec-wsl.js'
import {
  sq, validUrl, validTarget, unsafeArg,
  buildNmapCmd, buildMasscanCmd, buildGobusterCmd, buildSubfinderCmd, buildWhatwebCmd, buildDnsreconCmd,
} from './sec-commands.js'

// 校验与引号原语已迁 src/commands.ts（纯层，可离线单测）；此处按既有导入路径转出，行为不变。
export { sq, validUrl, validTarget, validWord, hasShellMeta, unsafeArg } from './sec-commands.js'

/** WSL 内文件存在性检查 */
export async function fileExists(path: string): Promise<boolean> {
  const r = await spawnWsl(`test -f ${sq(path)} && echo YES || echo NO`, 10000)
  return r.ok && r.stdout.trim() === 'YES'
}

// ═══════════════ nmap ═══════════════

export interface NmapOptions {
  target: string
  /** 端口规格：如 "80,443" / "1-1000" / 缺省 -p-（全端口太慢，默认常见端口） */
  ports?: string
  /** 扫描类型：-sS(syn)/-sT(connect)/-sV(版本) 组合 */
  scanType?: string
  /** 额外参数（如 -O 系统探测 / -A 全面） */
  extra?: string
  timeoutMs?: number
}

export async function runNmap(opts: NmapOptions): Promise<{ ok: boolean; error?: string; result?: string; exitCode?: number; stderr?: string }> {
  if (!validTarget(opts.target)) return { ok: false, error: 'target 格式无效（需 域名/IP，无特殊字符）' }
  const bad = unsafeArg(opts.extra, 'extra') ?? unsafeArg(opts.scanType, 'scanType')
  if (bad) return { ok: false, error: bad }
  if (!(await toolExists('nmap'))) return { ok: false, error: 'WSL 未安装 nmap' }
  const cmd = buildNmapCmd(opts)
  const r: WslResult = await spawnWsl(cmd, opts.timeoutMs ?? 120_000)
  if (!r.ok && !r.stdout) return { ok: false, error: `nmap 执行失败: ${r.stderr.slice(0, 400)}`, exitCode: r.exitCode, stderr: r.stderr }
  return { ok: true, result: r.stdout, exitCode: r.exitCode, stderr: r.stderr }
}

// ═══════════════ masscan ═══════════════

export interface MasscanOptions {
  target: string
  /** 端口范围（默认 1-1000） */
  ports?: string
  /** 速率 pps（默认 1000，太高易被检测） */
  rate?: number
  timeoutMs?: number
}

export async function runMasscan(opts: MasscanOptions): Promise<{ ok: boolean; error?: string; result?: string; exitCode?: number; stderr?: string }> {
  if (!validTarget(opts.target)) return { ok: false, error: 'target 格式无效' }
  const bad = unsafeArg(opts.ports, 'ports')
  if (bad) return { ok: false, error: bad }
  if (!(await toolExists('masscan'))) return { ok: false, error: 'WSL 未安装 masscan' }
  const cmd = buildMasscanCmd(opts)
  const r = await spawnWsl(cmd, opts.timeoutMs ?? 120_000)
  if (!r.ok && !r.stdout) return { ok: false, error: `masscan 执行失败: ${r.stderr.slice(0, 400)}`, exitCode: r.exitCode }
  return { ok: true, result: r.stdout, exitCode: r.exitCode }
}

// ═══════════════ gobuster ═══════════════

export interface GobusterOptions {
  url: string
  /** 模式：dir（目录）/ dns（子域）/ vhost */
  mode?: string
  /** wordlist 路径（缺省用内置常见字典） */
  wordlist?: string
  /** 扩展名（如 php,html，目录爆破时） */
  extensions?: string
  timeoutMs?: number
}

export async function runGobuster(opts: GobusterOptions): Promise<{ ok: boolean; error?: string; result?: string; exitCode?: number; stderr?: string }> {
  const u = validUrl(opts.url)
  if (!u.ok) return { ok: false, error: u.error }
  const bad = unsafeArg(opts.mode, 'mode')
  if (bad) return { ok: false, error: bad }
  if (!(await toolExists('gobuster'))) return { ok: false, error: 'WSL 未安装 gobuster' }
  const cmd = buildGobusterCmd(opts)
  const r = await spawnWsl(cmd, opts.timeoutMs ?? 120_000)
  if (!r.ok && !r.stdout) return { ok: false, error: `gobuster 执行失败: ${r.stderr.slice(0, 400)}`, exitCode: r.exitCode }
  return { ok: true, result: r.stdout, exitCode: r.exitCode }
}

// ═══════════════ subfinder ═══════════════

export interface SubfinderOptions {
  domain: string
  /** 是否递归（默认 false） */
  recursive?: boolean
  /** 是否做主动（含 API 探测，默认 passive 仅证书日志） */
  active?: boolean
  timeoutMs?: number
}

export async function runSubfinder(opts: SubfinderOptions): Promise<{ ok: boolean; error?: string; result?: string; exitCode?: number; stderr?: string }> {
  if (!validTarget(opts.domain)) return { ok: false, error: 'domain 格式无效' }
  if (!(await toolExists('subfinder'))) return { ok: false, error: 'WSL 未安装 subfinder' }
  const cmd = buildSubfinderCmd(opts)
  const r = await spawnWsl(cmd, opts.timeoutMs ?? 120_000)
  if (!r.ok && !r.stdout) return { ok: false, error: `subfinder 执行失败: ${r.stderr.slice(0, 400)}`, exitCode: r.exitCode }
  return { ok: true, result: r.stdout, exitCode: r.exitCode }
}

// ═══════════════ whatweb ═══════════════

export interface WhatwebOptions {
  url: string
  /** 聚合模式（-a 3，默认） */
  agility?: number
  timeoutMs?: number
}

export async function runWhatweb(opts: WhatwebOptions): Promise<{ ok: boolean; error?: string; result?: string; exitCode?: number; stderr?: string }> {
  const u = validUrl(opts.url)
  if (!u.ok) return { ok: false, error: u.error }
  if (!(await toolExists('whatweb'))) return { ok: false, error: 'WSL 未安装 whatweb' }
  const cmd = buildWhatwebCmd(opts)
  const r = await spawnWsl(cmd, opts.timeoutMs ?? 120_000)
  if (!r.ok && !r.stdout) return { ok: false, error: `whatweb 执行失败: ${r.stderr.slice(0, 400)}`, exitCode: r.exitCode }
  return { ok: true, result: r.stdout, exitCode: r.exitCode }
}

// ═══════════════ dnsrecon ═══════════════

export interface DnsreconOptions {
  domain: string
  /** 枚举类型：std(标准)/brt(爆破)/srv(服务记录) */
  type?: string
  timeoutMs?: number
}

export async function runDnsrecon(opts: DnsreconOptions): Promise<{ ok: boolean; error?: string; result?: string; exitCode?: number; stderr?: string }> {
  if (!validTarget(opts.domain)) return { ok: false, error: 'domain 格式无效' }
  if (!(await toolExists('dnsrecon'))) return { ok: false, error: 'WSL 未安装 dnsrecon' }
  const cmd = buildDnsreconCmd(opts)
  const r = await spawnWsl(cmd, opts.timeoutMs ?? 120_000)
  if (!r.ok && !r.stdout) return { ok: false, error: `dnsrecon 执行失败: ${r.stderr.slice(0, 400)}`, exitCode: r.exitCode }
  return { ok: true, result: r.stdout, exitCode: r.exitCode }
}
