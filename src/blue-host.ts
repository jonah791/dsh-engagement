/** 主机安全工具：进程/连接审计、自启动审计、事件日志、加固基线——本地 PowerShell 执行 */

import { execFile } from 'node:child_process'
import { psQuote } from './blue-logic.js'

/** 执行 PowerShell 脚本并返回 stdout（UTF-8）。本机只有 PowerShell 5.1（无 pwsh 7），用 powershell.exe */
export function runPs(script: string, timeoutMs = 30000): Promise<string> {
  const full = `[Console]::OutputEncoding=[Text.Encoding]::UTF8; $OutputEncoding=[Text.Encoding]::UTF8; ${script}`
  return new Promise((resolve, reject) => {
    execFile('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', full], {
      timeout: timeoutMs,
      maxBuffer: 20 * 1024 * 1024,
      windowsHide: true,
      encoding: 'utf8',
    }, (err, stdout) => {
      if (err) reject(new Error(`PowerShell 执行失败: ${err.message}`))
      else resolve(stdout.trim())
    })
  })
}

/** 进程 + 网络连接审计：监听端口 + 外部连接（进程映射） */
export function auditConnections(scriptLimit = 200): string {
  return `
$ErrorActionPreference='SilentlyContinue'
$conns = Get-NetTCPConnection | Where-Object { $_.State -eq 'Listen' -or $_.State -eq 'Established' }
$procs = @{}
Get-Process | ForEach-Object { $procs[$_.Id] = $_.ProcessName }
$out = foreach ($c in $conns) {
  $name = $procs[$c.OwningProcess]
  if (-not $name) { $name = "PID:$($c.OwningProcess)" }
  [PSCustomObject]@{
    State=$c.State.ToString(); Local=$c.LocalAddress+':'+$c.LocalPort
    Remote=$(if($c.RemoteAddress -and $c.RemoteAddress -ne '0.0.0.0' -and $c.RemoteAddress -ne '::'){"$($c.RemoteAddress):$($c.RemotePort)"}else{'-'})
    Proc=$name; PID=$c.OwningProcess
  }
}
$out | Select-Object -First ${scriptLimit} | Sort-Object Local | ConvertTo-Json -Compress
`
}

/** 自启动审计：Run 键 + 计划任务 + 自启动服务 */
export function auditAutoruns(scriptLimit = 100): string {
  return `
$ErrorActionPreference='SilentlyContinue'
$result = @()
$runKeys = 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
           'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
           'HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run',
           'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
           'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce'
foreach ($k in $runKeys) {
  if (Test-Path $k) {
    (Get-ItemProperty $k).PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
      $result += [PSCustomObject]@{ Type='RunKey'; Name=$_.Name; Command=[string]$_.Value; Source=$k }
    }
  }
}
Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } | Select-Object -First 40 | ForEach-Object {
  $cmd = $_.Actions | Select-Object -First 1
  $result += [PSCustomObject]@{ Type='Task'; Name=$_.TaskName; Command=[string]$cmd.Execute; Source=$_.TaskPath }
}
Get-CimInstance Win32_Service | Where-Object { $_.StartMode -eq 'Auto' -and $_.State -eq 'Running' -and $_.PathName -notmatch 'System32|Windows\\\\' } | Select-Object -First 30 | ForEach-Object {
  $result += [PSCustomObject]@{ Type='Service'; Name=$_.Name; Command=[string]$_.PathName; Source='AutoStart' }
}
$result | Select-Object -First ${scriptLimit} | ConvertTo-Json -Depth 3 -Compress
`
}

/** 事件日志查询：按事件 ID 过滤（经典安全事件）
 *  `nowMs` 为时间注入点（缺省 `Date.now()`）——使脚本可离线确定性单测。 */
export function queryEventLog(eventIds: number[], days: number, logName: string, limit = 100, nowMs: number = Date.now()): string {
  const since = new Date(nowMs - days * 86400_000).toISOString()
  const idList = eventIds.join(',')
  return `
$ErrorActionPreference='SilentlyContinue'
$idArr = @(${idList})
$since = [datetime]'${since}'
$events = Get-WinEvent -FilterHashtable @{ LogName='${psQuote(logName)}'; Id=$idArr; StartTime=$since } -MaxEvents ${limit}
$out = foreach ($e in $events) {
  $msg = ($e.Message -split "\\r?\\n" | Select-Object -First 2) -join ' '
  [PSCustomObject]@{ Time=$e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'); Id=$e.Id; Level=$e.LevelDisplayName; Machine=$e.MachineName; Msg=[string]$msg }
}
if (-not $out) { Write-Output '[]' } else { $out | ConvertTo-Json -Compress }
`
}

/** 安全基线快检：防火墙/共享/RDP/管理员/自动登录 */
export function baselineCheck(): string {
  return `
$ErrorActionPreference='SilentlyContinue'
$checks = @()
$fw = Get-NetFirewallProfile
foreach ($p in $fw) {
  $checks += [PSCustomObject]@{ Check="Firewall_$($p.Name)"; Status=$(if($p.Enabled){'PASS'}else{'FAIL'}); Detail="Inbound=$($p.DefaultInboundAction)" }
}
$shares = Get-SmbShare | Where-Object { $_.Name -notmatch '^\\$' }
$checks += [PSCustomObject]@{ Check='SMB_NonDefaultShares'; Status=$(if($shares){'WARN'}else{'PASS'}); Detail=($shares.Name -join ',') }
$rdp = (Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections).fDenyTSConnections
$checks += [PSCustomObject]@{ Check='RDP_Enabled'; Status=$(if($rdp -eq 0){'WARN'}else{'PASS'}); Detail="fDenyTSConnections=$rdp" }
$admins = Get-LocalGroupMember -Group 'Administrators' | Select-Object -ExpandProperty Name
$checks += [PSCustomObject]@{ Check='AdminGroup'; Status='INFO'; Detail=($admins -join ',') }
$auto = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -Name DefaultUserName).DefaultUserName
$checks += [PSCustomObject]@{ Check='AutoLogon'; Status=$(if($auto){'WARN'}else{'PASS'}); Detail="DefaultUserName=$auto" }
$checks | ConvertTo-Json -Compress
`
}

/** 文件哈希计算（多算法） */
export function hashFile(filePath: string): string {
  return `
$ErrorActionPreference='SilentlyContinue'
$p = '${psQuote(filePath)}'
if (-not (Test-Path -LiteralPath $p)) { Write-Output 'NOT_FOUND'; exit }
$md5 = (Get-FileHash -LiteralPath $p -Algorithm MD5).Hash
$sha1 = (Get-FileHash -LiteralPath $p -Algorithm SHA1).Hash
$sha256 = (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash
$size = (Get-Item -LiteralPath $p).Length
[PSCustomObject]@{ Path=$p; Size=$size; MD5=$md5; SHA1=$sha1; SHA256=$sha256 } | ConvertTo-Json -Compress
`
}
