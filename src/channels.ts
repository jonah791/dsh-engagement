/**
 * channels.ts — 通道层（**不是工具**：触达目标的执行路径）。
 *
 * 三条通道：WSL `curl` / WSL `ssh` / Node `http`。纪律：
 * - **单一引号出口**：所有经 shell 的参数一律过 `shellQuote`（`range-logic.ts` 的实现），
 *   并先过 `hasShellMeta` 元字符闸门——旧 `cyber-range` 出过一次「半吊子防线」事故
 *   （`user`/`pass`/`cookie`/`host`/`path` 曾未经转义直接内插，闭合引号即可执行任意命令）。
 * - **凭据只以引用形式进入**：口令不进工具参数、不进交战国度、不进轨迹；需要时由执行层注入环境变量。
 * - **不提供出口选择参数**（承 §5.26 G6）。
 */

import { spawn } from 'node:child_process'
import { hasShellMeta } from './sec-commands.js'
import { shellQuote } from './range-logic.js'
import { spawnWsl } from './sec-wsl.js'

export type Channel = 'wsl-curl' | 'wsl-ssh' | 'node-http'

export interface ChannelRun {
  readonly code: number | null
  readonly stdout: string
  readonly stderr: string
  readonly timedOut: boolean
}

/** 参数安全性：含 shell 元字符一律拒绝（不做「尽力转义」——那是猜测） */
export function assertShellSafe(args: readonly string[], what: string): void {
  for (const a of args) {
    if (hasShellMeta(a)) throw new Error(`${what} 含 shell 元字符，拒绝构造命令：${a.slice(0, 40)}`)
  }
}

/** 构造一条 WSL bash 命令：每个参数都经 `shellQuote`（**唯一引号出口**） */
export function buildWslCommand(program: string, args: readonly string[]): string {
  assertShellSafe([program], 'program')
  assertShellSafe(args, '参数')
  return [program, ...args].map((a) => shellQuote(a)).join(' ')
}

/**
 * 跑一条 WSL bash 命令（经 `sec-wsl` 的 `spawnWsl`，继承其 base64 传参通道与超时）。
 *
 * ⚠ 边界诚实：`WslResult` 只有 `ok/stdout/stderr/exitCode/durationMs`，**不区分超时与启动失败**
 * （两者都可能是 `exitCode: -1`）⇒ 本函数不假装能区分，`timedOut` 恒为 false，由调用方按
 * `ok === false` + `exitCode` 自行判断。
 */
export async function runWsl(command: string, timeoutMs = 120_000): Promise<ChannelRun> {
  const r = await spawnWsl(command, timeoutMs)
  return { code: r.exitCode, stdout: r.stdout, stderr: r.stderr, timedOut: false }
}

/** Node 原生 HTTP 抓取（不依赖外部工具；用于 `aspects` 里的轻量探测） */
export async function runNodeHttp(
  url: string,
  init: { method?: string; headers?: Record<string, string>; body?: string; timeoutMs?: number } = {},
): Promise<{ status: number; headers: Record<string, string>; body: string }> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), init.timeoutMs ?? 20_000)
  try {
    const res = await fetch(url, {
      method: init.method ?? 'GET',
      ...(init.headers !== undefined ? { headers: init.headers } : {}),
      ...(init.body !== undefined ? { body: init.body } : {}),
      signal: controller.signal,
      redirect: 'follow',
    })
    const headers: Record<string, string> = {}
    res.headers.forEach((v, k) => {
      headers[k] = v
    })
    const body = await res.text()
    return { status: res.status, headers, body }
  } finally {
    clearTimeout(timer)
  }
}

/** 通用子进程（用于调用本机工具，不经 shell——args 数组直传，天然免转义） */
export function runProgram(program: string, args: readonly string[], timeoutMs: number, cwd?: string): Promise<ChannelRun> {
  return new Promise<ChannelRun>((resolve) => {
    const child = spawn(program, [...args], {
      ...(cwd !== undefined ? { cwd } : {}),
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    let stdout = ''
    let stderr = ''
    let settled = false
    const timer = setTimeout(() => {
      if (settled) return
      settled = true
      try {
        child.kill()
      } catch {
        /* 已退出 */
      }
      resolve({ code: null, stdout, stderr, timedOut: true })
    }, timeoutMs)
    child.stdout.on('data', (d: Buffer) => {
      stdout += d.toString('utf8')
    })
    child.stderr.on('data', (d: Buffer) => {
      stderr += d.toString('utf8')
    })
    child.on('error', (err: Error) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      resolve({ code: null, stdout, stderr: stderr + err.message, timedOut: false })
    })
    child.on('close', (code: number | null) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      resolve({ code, stdout, stderr, timedOut: false })
    })
  })
}
