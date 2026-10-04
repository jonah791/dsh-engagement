/**
 * 命令拼装契约守卫（回归测试 · 尸体测试）。
 *
 * 已证实的缺陷（2026-09-14）：`otw_request` 的 curl 命令与 `otw_ssh` 的 ssh 命令由**模板字符串**拼成，
 * 其中 `userAgent`/`data` 做了 `'` → `'\''` 转义，而 `user`/`pass`/`cookie`/`host`/`path`/`resolveIp`/`command`
 * **原样内插**——半吊子防线。命令最终交给 **WSL 内的 `bash -c`** 执行，
 * 因此 `cookie = "x'; <任意命令>; '"` 即等于在本机 WSL 内执行任意命令。
 *
 * 本文件让这条缺陷不可能复发：
 *  ① 命令拼装只允许出现在 `src/range-logic.ts`（接线层不得再出现裸命令文本）；
 *  ② 命令模板里每个 `${…}` 必须是 `shellQuote(...)` 或**已知的已转义别名**。
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const srcDir = join(root, 'src')

/** 命令文本指纹：出现在接线层即违规（命令拼装必须集中在 range-logic.ts） */
const COMMAND_MARKERS = [/sshpass/, /curl -s/, /ProxyCommand/, /StrictHostKeyChecking/]

/** 允许「原样内插」的局部别名（它们在别处已整体 shellQuote；见 buildSshCmd） */
const ALLOWED_RAW_ALIASES = new Set(['proxyCmd'])

/** 已知的「已转义 flag」局部变量（其定义处已对值做 shellQuote） */
const ALLOWED_FLAG_VARS = /^(resolveFlag|authFlag|cookieFlag|uaFlag|dataFlag)$/

/** 深度感知地取出一个模板行里的所有最外层 `${…}` 内容 */
function interpolationsOf(line) {
  const out = []
  for (let i = 0; i < line.length - 1; i++) {
    if (line[i] !== '$' || line[i + 1] !== '{') continue
    let depth = 1
    let j = i + 2
    let buf = ''
    while (j < line.length && depth > 0) {
      const c = line[j]
      if (c === '{') depth++
      else if (c === '}') { depth--; if (depth === 0) break }
      buf += c
      j++
    }
    out.push(buf)
    i = j
  }
  return out
}

/** 扫描 `{文件名: 源码}`，返回违规清单 */
export function scanCommandContract(sources) {
  const offenders = []
  for (const [file, src] of Object.entries(sources)) {
    const lines = src.split('\n')
    const isLogic = /logic\.ts$/.test(file)
    lines.forEach((line, i) => {
      const t = line.trim()
      const isComment = t.startsWith('//') || t.startsWith('*') || t.startsWith('/*')
      if (!isComment) {
        // ① 命令文本只允许出现在 range-logic.ts
        if (!isLogic) {
          for (const re of COMMAND_MARKERS) {
            if (re.test(line)) offenders.push(`${file}:${i + 1}: 命令文本出现在接线层（应集中在 range-logic.ts 并过 shellQuote）：${t}`)
          }
        }
        // ② 命令模板里每个 ${…} 必须已转义
        const isCommandTemplate = /`curl /.test(line) || /sshpass -p/.test(line)
        if (isCommandTemplate) {
          for (const expr of interpolationsOf(line)) {
            const ok = /^shellQuote\(/.test(expr) || ALLOWED_FLAG_VARS.test(expr) || ALLOWED_RAW_ALIASES.has(expr)
            if (!ok) offenders.push(`${file}:${i + 1}: 未转义内插 \${${expr}} → 可逃逸出引号执行任意命令`)
          }
        }
      }
    })
  }
  return offenders
}

function readSources() {
  const out = {}
  for (const f of readdirSync(srcDir)) {
    if (f.endsWith('.ts')) out[f] = readFileSync(join(srcDir, f), 'utf8')
  }
  return out
}

/* ── 尸体测试：证明守卫有牙齿 ── */

test('尸体测试：守卫在「修复前形态」上确实报错（裸变量内插）', () => {
  const bad = {
    'range-logic.ts': 'const curlCmd = `curl -s --noproxy "*" -b \'${cookie}\' -u \'${user}:${pass}\' \'http://${host}${path}\'`',
  }
  const offenders = scanCommandContract(bad)
  assert.equal(offenders.length, 5, `必须拦下 5 处裸内插（cookie/user/pass/host/path），实际：${offenders}`)
  assert.ok(offenders.every((o) => /未转义内插/.test(o)))
})

test('尸体测试：守卫在合规形态上零误报（含 flag 别名与 shellQuote）', () => {
  const good = {
    'range-logic.ts': [
      'const cookieFlag = `-b ${shellQuote(args.cookie)} `',
      'const resolveFlag = `--resolve ${shellQuote(`${args.host}:80:${args.resolveIp}`)} `',
      'const curlCmd = `curl -s --noproxy "*" ${resolveFlag}${cookieFlag}-w \'\\n%{http_code}\' ${shellQuote(`http://${args.host}`)}`',
      'const proxyCmd = `nc -X connect -x ${opts.proxyHost}:${opts.proxyPort} %h %p`',
      'return `sshpass -p ${shellQuote(opts.pass)} ssh -o ProxyCommand=${shellQuote(proxyCmd)}`',
    ].join('\n'),
  }
  assert.deepEqual(scanCommandContract(good), [])
})

test('尸体测试：接线层出现命令文本必须被拦（命令拼装不得散落）', () => {
  const bad = { 'index.ts': "const cmd = `sshpass -p '${pass}' ssh ${user}@${host}`" }
  assert.ok(scanCommandContract(bad).some((o) => /命令文本出现在接线层/.test(o)))
})

/* ── 真实源码守卫 ── */

test('真实源码：命令模板内插已全部转义，且命令文本只在 range-logic.ts', () => {
  const offenders = scanCommandContract(readSources())
  assert.deepEqual(offenders, [], `命令拼装契约违规：\n${offenders.join('\n')}`)
})

test('前提守卫：本插件确实在用 WSL bash 执行命令（否则本守卫不适用）', () => {
  const chan = readFileSync(join(srcDir, 'channels.ts'), 'utf8')
  assert.match(chan, /spawnWsl/, 'eng_* 经 WSL bash 执行命令（经 sec-wsl 的 spawnWsl）——这正是注入逃逸的后果面')
})

test('真实源码：range-logic.ts 保持纯逻辑（命令拼装不引入子进程/网络）', () => {
  const logic = readFileSync(join(srcDir, 'range-logic.ts'), 'utf8')
  assert.ok(!/child_process/.test(logic), 'range-logic.ts 不得引入 child_process')
  assert.ok(!/\bhttpRequest\b|\bfetch\s*\(/.test(logic), 'range-logic.ts 不得发起网络请求')
})
