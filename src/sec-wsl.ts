/**
 * WSL 子进程执行基础设施（dsh-sec-tools）
 *
 * 关键设计（来自 dsh-tool-wsl v0.2 教训 + dsh-cyber-range 验证）：
 *  - wsl.exe 传参破坏 bug：`--` 后 argv 被重 join，`$`/引号/多行会被破坏
 *    → 必须用 base64 通道：echo <b64> | base64 -d | bash，任意复杂命令可靠传递
 *  - web 进程网络受限，WSL 子进程不受限（dsh-cyber-range 已验证）
 *  - 超时控制：工具可能长时间运行（nmap 全端口/hashcat 爆破），timeoutMs 必须可配
 */
import { spawn } from 'node:child_process'

export interface WslResult {
  ok: boolean
  stdout: string
  stderr: string
  exitCode: number
  /** 命令实际耗时 ms */
  durationMs: number
}

/** 经 wsl.exe 执行 bash 命令（base64 通道，规避传参破坏） */
export function spawnWsl(cmd: string, timeoutMs: number): Promise<WslResult> {
  return new Promise((resolve) => {
    const b64 = Buffer.from(cmd, 'utf8').toString('base64')
    const wrapper = `echo ${b64} | base64 -d | bash`
    const t0 = Date.now()
    const child = spawn('wsl.exe', ['-d', 'Ubuntu', '--', 'bash', '-c', wrapper], {
      timeout: timeoutMs,
      windowsHide: true,
    })
    let stdout = ''
    let stderr = ''
    child.stdout.on('data', (d: Buffer) => { stdout += d.toString() })
    child.stderr.on('data', (d: Buffer) => { stderr += d.toString() })
    child.on('close', (code) => resolve({
      ok: code === 0, stdout, stderr, exitCode: code ?? -1, durationMs: Date.now() - t0,
    }))
    child.on('error', (e: Error) => resolve({
      ok: false, stdout, stderr: stderr + '\n' + e.message, exitCode: -1, durationMs: Date.now() - t0,
    }))
  })
}

/** 命令存在性检查（工具调用前可预检） */
export async function toolExists(tool: string): Promise<boolean> {
  const r = await spawnWsl(`command -v ${tool} >/dev/null 2>&1 && echo YES || echo NO`, 10000)
  return r.ok && r.stdout.trim() === 'YES'
}

/** 便捷：超时默认值 */
export const DEFAULT_TIMEOUT = 120_000
export const LONG_TIMEOUT = 600_000
