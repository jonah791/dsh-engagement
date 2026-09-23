/**
 * dsh-engagement — 安全交战闭环。
 *
 * 一次交战（engagement）的完整闭环：**定范围与授权 → 侦察 → 发现 → 验证/利用 → 检测侧校验 → 证据与报告**。
 * 替换 `dsh-red-team` + `dsh-blue-team` + `dsh-exploit-kit` + `dsh-cyber-range` + `dsh-sec-tools`（36 工具 → 12）。
 * 设计依据：`docs/plans/插件融合设计_安全交战_2026-09-23.md`；权威契约见 `docs/semantic.md`。
 *
 * 本件相对旧五件**唯一真正新增的机制**是 `src/gate.ts` 的**可判定授权闸门**：五份散文式免责声明
 * 换成结构化四元组裁决 + 闭集 reason + 坏样本可证伪 + 拒绝落盘留痕。
 *
 * 不变量：I1 单一 owner（交战国度只由本件写）· I2 显式携带 `engagementId`（无隐式「最近一次」）·
 * I3 闸门先于副作用 · I4 拒绝留痕 · I5 发现必挂证据 · I6 范围判定带 `.` 边界 · I7 凭据不落盘 ·
 * I8 一次交战一个窗口 · I9 检测侧同受闸门。
 *
 * @module dsh-engagement
 */

import { createHash, randomUUID } from 'node:crypto'
import { join } from 'node:path'
import type { Context } from '@deepseek-ai/cordis'
import z from '@deepseek-ai/schemastery'
import { defineTool } from '@deepseek-ai/dsh-tools'
import { decideGate, gateDeniedLine, type ActionClass, type Engagement } from './gate.js'
import {
  appendEvidence,
  appendFinding,
  appendTimeline,
  deniedCount,
  listEngagements,
  pathsOf,
  readEngagement,
  readEvidence,
  readFindings,
  readTimeline,
  writeEngagement,
  type EngagementPaths,
  type Evidence,
  type Finding,
} from './store.js'
import { runProgram } from './channels.js'
import { crawlLinks, dirBrute, enumSubdomains } from './red-enum.js'
import { checkSecurityHeaders, grabBanner, matchCve, probeSensitivePaths, techFingerprint } from './red-finger.js'
import { extractLinks, matchFrameworks, parseCrtShNames } from './red-pure.js'
import { generateCmdi } from './xp-cmdi.js'
import { generateJuggling } from './xp-php.js'
import { generateBypass } from './xp-webbypass.js'
import { forgeJwt } from './xp-jwt.js'
import { generateSerialize } from './xp-serialize.js'
import { planEcbSplice } from './xp-ecb.js'
import { runDnsrecon, runGobuster, runMasscan, runNmap, runSubfinder, runWhatweb } from './sec-recon.js'
import { runHydra, runNikto, runSqlmap } from './sec-attack.js'
import { searchCveNvd, queryUrlhaus, queryUrlscan } from './blue-intel.js'
import { auditAutoruns, auditConnections, baselineCheck, queryEventLog } from './blue-host.js'
import { parsePorts, scanPorts } from './blue-net.js'
import { bisectExtract, buildCurlCmd, buildSshCmd, parseCurlOutput } from './range-logic.js'
import { scrub } from './sec-trace.js'

export const name = 'engagement'

export const inject = ['tools'] as const

export interface Config {
  enabled: boolean
  /** 交战国度根目录（空 ⇒ `<DSH_HOME>/engagement`） */
  root: string
  /** 单次子进程默认超时 */
  timeoutMs: number
  /** 侦察默认条数上限 */
  limit: number
  /** 报告落点（空 ⇒ 交战国度内） */
  reportDir: string
}

export const Config = z.object({
  enabled: z.boolean().default(true),
  root: z.string().default(''),
  timeoutMs: z.number().default(120_000),
  limit: z.number().default(50),
  reportDir: z.string().default(''),
})

const textOut = {
  schema: { type: 'object', additionalProperties: false, properties: { text: { type: 'string', required: true } } },
  render: (_a: unknown, v: { text: string }) => [{ type: 'text', text: v.text }],
} as const

const tool = (spec: unknown): never => defineTool(spec as never) as never

function resolveRoot(config: Config, env: NodeJS.ProcessEnv = process.env): string {
  if (config.root.trim() !== '') return config.root.trim()
  const home = env['DSH_HOME'] ?? 'E:/alice/.dsh'
  return join(home, 'engagement')
}

function sha256(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex')
}

export function apply(ctx: Context, config: Config): void {
  if (!config.enabled) return
  const root = resolveRoot(config)
  const logger = ctx.logger('dsh-engagement')

  /** 读交战（fail-closed：读不到 ⇒ null，由闸门判 deny，**不重建不猜**） */
  function load(engagementId: string): { eng: Engagement | null; paths: EngagementPaths } {
    const paths = pathsOf(root, engagementId)
    const read = readEngagement(paths)
    return { eng: read.ok ? read.engagement : null, paths }
  }

  interface RegSpec {
    readonly name: string
    readonly description: string
    readonly parameters: Record<string, unknown>
    readonly actionClass: ActionClass
    /** 从参数里取目标（用于 scope 判定） */
    readonly targetOf?: (args: Record<string, unknown>) => string | undefined
    readonly run: (args: Record<string, unknown>, c: { eng: Engagement | null; paths: EngagementPaths }) => Promise<string>
  }

  /**
   * **单一注册切面**：所有工具经此处注册，闸门与证据/时间线写入**只在这里发生**。
   *
   * 这样做的理由（I3）：闸门先于副作用的判据不是「每处记得调」，而是「没有别的路径能触发副作用」——
   * 12 个工具只有一个入口，漏掉一处写调用的可能性在结构上被消掉。
   */
  function reg(spec: RegSpec): void {
    ctx.tools.register(tool({
      name: spec.name,
      description: spec.description,
      parameters: spec.parameters,
      output: textOut,
      async execute(args: Record<string, unknown>) {
        const engagementId = typeof args['engagementId'] === 'string' ? args['engagementId'] : ''
        const now = Date.now()
        const { eng, paths } = load(engagementId)
        const target = spec.targetOf?.(args)
        const verdict = decideGate({ engagement: eng, actionClass: spec.actionClass, ...(target !== undefined ? { target } : {}), nowMs: now })

        if (verdict.verdict === 'deny') {
          // I4 拒绝留痕：deny 是「防线真在拦」的一手证据，不是日志噪音
          const line = gateDeniedLine({ atMs: now, engagementId: engagementId === '' ? null : engagementId, tool: spec.name, actionClass: spec.actionClass, ...(target !== undefined ? { target } : {}), reason: verdict.reason })
          appendTimeline(paths, JSON.parse(line) as Record<string, unknown>)
          return { text: `⛔ 闸门拒绝（${verdict.reason}）——未执行任何动作。\n工具=${spec.name} · actionClass=${spec.actionClass}${target !== undefined ? ` · 目标=${target}` : ''}\n拒绝已落 timeline.jsonl（gate/denied）。` }
        }
        if (eng === null && spec.actionClass !== 'meta') {
          return { text: '⛔ 交战不可读且未被闸门拦截——这是内部不一致，请报告。' }
        }

        try {
          const text = await spec.run(args, { eng, paths })
          appendTimeline(paths, { atMs: Date.now(), iso: new Date().toISOString(), phase: 'tool/end', tool: spec.name, engagementId: eng?.id ?? engagementId, ...(target !== undefined ? { target } : {}), outcome: 'ok' })
          return { text }
        } catch (err) {
          appendTimeline(paths, { atMs: Date.now(), iso: new Date().toISOString(), phase: 'tool/end', tool: spec.name, engagementId: eng?.id ?? engagementId, ...(target !== undefined ? { target } : {}), outcome: 'error', reason: String((err as Error).message).slice(0, 200) })
          return { text: `✗ ${spec.name} 失败：${String((err as Error).message)}` }
        }
      },
    }))
  }

  /** 记录证据（自动：单一切面，不逐工具写） */
  function recordEvidence(paths: EngagementPaths, kind: Evidence['kind'], target: string, body: string, sourceToolCall: string): string {
    const id = 'ev-' + randomUUID().slice(0, 8)
    const ev: Evidence = {
      id, atMs: Date.now(), sourceToolCall, kind, target,
      sha256: sha256(body), bytes: Buffer.byteLength(body, 'utf8'),
      summary: scrub(body.slice(0, 300), []),
    }
    const res = appendEvidence(paths, ev, [])
    if (!res.ok) throw new Error('证据写入失败（' + String(res.reason) + '）——不静默降级为「无证据成功」')
    return id
  }

  // ── 1. eng_open（定范围与授权） ──────────────────────────────────────────
  reg({
    name: 'eng_open',
    description: '开一次交战并落 engagement.json（授权来源 + 范围 + 时间窗）。**何时不该调**：只为跑一次扫描而开长期窗口（窗口该短就短）。'
      + '授权来源只承认三类闭集：owner-directive（主人直接指令）/ lab-charter（靶场或教学环境公开章程）/ written-scope（书面范围声明），且必须给可核对的 ref。',
    parameters: {
      title: { type: 'string', required: true, description: '交战标题' },
      purpose: { type: 'string', description: '目的（内部记录）' },
      authorizationSource: { type: 'string', required: true, description: 'owner-directive | lab-charter | written-scope' },
      authorizationRef: { type: 'string', required: true, description: '可核对凭据的定位符（会话 id / 文档路径 / 消息 id）' },
      targets: { type: 'array', items: { type: 'string' }, required: true, description: '范围目标（域名 / IP / CIDR）' },
      exclude: { type: 'array', items: { type: 'string' }, description: '排除项' },
      ports: { type: 'string', description: '端口约束（如 1-1024）' },
      allowActiveAuth: { type: 'boolean', description: '是否允许主动认证动作（默认 false）' },
      notBefore: { type: 'string', description: '窗口起点 ISO（可省）' },
      notAfter: { type: 'string', required: true, description: '窗口终点 ISO' },
    },
    actionClass: 'meta',
    async run(args) {
      const now = new Date()
      const id = 'eng-' + now.toISOString().slice(0, 10).replace(/-/g, '') + '-' + randomUUID().slice(0, 6)
      const src = String(args['authorizationSource'] ?? '')
      if (!['owner-directive', 'lab-charter', 'written-scope'].includes(src)) {
        throw new Error('授权来源必须是 owner-directive | lab-charter | written-scope 三者之一（闭集）')
      }
      const targets = Array.isArray(args['targets']) ? (args['targets'] as string[]) : []
      if (targets.length === 0) throw new Error('targets 不能为空——未声明目标的交战没有意义')
      const eng: Engagement = {
        id,
        title: String(args['title'] ?? ''),
        purpose: String(args['purpose'] ?? ''),
        authorization: { source: src as 'owner-directive' | 'lab-charter' | 'written-scope', ref: String(args['authorizationRef'] ?? '') },
        scope: {
          targets,
          exclude: Array.isArray(args['exclude']) ? (args['exclude'] as string[]) : [],
          ...(typeof args['ports'] === 'string' ? { ports: args['ports'] } : {}),
          allowActiveAuth: args['allowActiveAuth'] === true,
        },
        window: {
          ...(typeof args['notBefore'] === 'string' ? { notBefore: args['notBefore'] } : {}),
          notAfter: String(args['notAfter'] ?? ''),
        },
        status: 'active',
      }
      const paths = pathsOf(root, id)
      writeEngagement(paths, eng)
      return `交战已开启：${id}\n标题：${eng.title}\n授权：${eng.authorization.source}（ref=${eng.authorization.ref}）\n范围：${targets.join(', ')}${eng.scope.exclude !== undefined && eng.scope.exclude.length > 0 ? `（排除 ${eng.scope.exclude.join(', ')}）` : ''}\n窗口：${eng.window.notBefore ?? '(即刻)'} → ${eng.window.notAfter}\n主动认证：${eng.scope.allowActiveAuth === true ? '允许' : '禁止（默认）'}\n范围摘要：${sha256(JSON.stringify(eng.scope)).slice(0, 16)}`
    },
  })

  // ── 2. eng_status（读） ─────────────────────────────────────────────────
  reg({
    name: 'eng_status',
    description: '读回交战全貌：范围 / 授权 / 窗口 / 发现计数 / 证据计数 / 闸门拒绝计数。**何时该调**：任何动作之前的现状核对（防用旧快照当当下前提）。',
    parameters: {
      engagementId: { type: 'string', description: '交战 id（缺省列出全部交战）' },
      view: { type: 'string', description: 'summary（缺省）| findings | evidence | timeline' },
    },
    actionClass: 'meta',
    async run(args) {
      const id = String(args['engagementId'] ?? '')
      if (id === '') {
        const all = listEngagements(root)
        return all.length === 0 ? `（暂无交战；根目录 ${root}）` : `交战清单（${all.length}）：\n` + all.map((e) => '  ' + e).join('\n')
      }
      const paths = pathsOf(root, id)
      const read = readEngagement(paths)
      if (!read.ok) throw new Error(`交战不可读（${read.reason}）：${read.detail}`)
      const eng = read.engagement
      const findings = readFindings(paths)
      const evidence = readEvidence(paths)
      const timeline = readTimeline(paths)
      const view = String(args['view'] ?? 'summary')
      const head = [
        `交战 ${eng.id} · ${eng.status}`,
        `标题：${eng.title ?? '(无)'}`,
        `授权：${eng.authorization.source}（ref=${eng.authorization.ref}）`,
        `范围：${eng.scope.targets.join(', ')}${(eng.scope.exclude ?? []).length > 0 ? `（排除 ${(eng.scope.exclude ?? []).join(', ')}）` : ''}`,
        `窗口：${eng.window.notBefore ?? '(即刻)'} → ${eng.window.notAfter}`,
        `主动认证：${eng.scope.allowActiveAuth === true ? '允许' : '禁止'}`,
        `计数：发现 ${findings.length} · 证据 ${evidence.length} · 时间线 ${timeline.length} · 闸门拒绝 ${deniedCount(paths)}`,
      ].join('\n')
      if (view === 'summary') return head
      const rows = view === 'findings' ? findings : view === 'evidence' ? evidence : timeline
      return head + `\n\n${view}（${rows.length}）：\n` + rows.map((r) => '  ' + JSON.stringify(r)).join('\n')
    },
  })

  // ── 3. eng_close（结案） ────────────────────────────────────────────────
  reg({
    name: 'eng_close',
    description: '结案：状态置 closed 并写结案摘要。**何时不该调**：还有未裁决的发现时（先 eng_finding 裁决）。',
    parameters: {
      engagementId: { type: 'string', required: true, description: '交战 id' },
      summary: { type: 'string', required: true, description: '结案摘要' },
    },
    actionClass: 'passive',
    async run(args, c) {
      const eng = c.eng
      if (eng === null) throw new Error('eng_close 需要一个可读的交战')
      const closed: Engagement = { ...eng, status: 'closed' }
      writeEngagement(c.paths, closed)
      appendTimeline(c.paths, { atMs: Date.now(), iso: new Date().toISOString(), phase: 'engagement/closed', tool: 'eng_close', engagementId: eng.id, outcome: 'ok', reason: String(args['summary'] ?? '').slice(0, 200) })
      const findings = readFindings(c.paths)
      return `交战 ${eng.id} 已结案。\n摘要：${String(args['summary'] ?? '')}\n发现 ${findings.length} 条 · 证据 ${readEvidence(c.paths).length} 条 · 闸门拒绝 ${deniedCount(c.paths)} 次\n（结案后所有 active 动作将被闸门判 deny：gate/closed）`
    },
  })

  // ── 4. eng_recon_dns（侦察 · 域层） ─────────────────────────────────────
  reg({
    name: 'eng_recon_dns',
    description: '域层资产面：子域、DNS 记录、区域传送测试。后端可选（证书透明日志 crtsh / WSL subfinder / WSL dnsrecon）。**主动动作**，目标须在 scope 内。',
    parameters: {
      engagementId: { type: 'string', required: true, description: '交战 id' },
      domain: { type: 'string', required: true, description: '目标域名' },
      backend: { type: 'string', description: 'crtsh（缺省，公开情报）| subfinder | dnsrecon' },
      limit: { type: 'number', description: '条数上限' },
    },
    actionClass: 'active',
    targetOf: (a) => (typeof a['domain'] === 'string' ? a['domain'] : undefined),
    async run(args, c) {
      const domain = String(args['domain'])
      const backend = String(args['backend'] ?? 'crtsh')
      const limit = typeof args['limit'] === 'number' ? args['limit'] : config.limit
      if (backend === 'subfinder') {
        const r = await runSubfinder({ domain, timeoutMs: config.timeoutMs })
        if (!r.ok) throw new Error(r.error ?? 'subfinder 失败')
        const id = recordEvidence(c.paths, 'dns', domain, r.result ?? '', 'eng_recon_dns')
        return `subfinder 结果（evidence ${id}）：\n${(r.result ?? '').slice(0, 4000)}`
      }
      if (backend === 'dnsrecon') {
        const r = await runDnsrecon({ domain, timeoutMs: config.timeoutMs })
        if (!r.ok) throw new Error(r.error ?? 'dnsrecon 失败')
        const id = recordEvidence(c.paths, 'dns', domain, r.result ?? '', 'eng_recon_dns')
        return `dnsrecon 结果（evidence ${id}）：\n${(r.result ?? '').slice(0, 4000)}`
      }
      const names = await enumSubdomains(domain, limit)
      const id = recordEvidence(c.paths, 'dns', domain, JSON.stringify(names), 'eng_recon_dns')
      const list = Array.isArray(names) ? names : []
      return `证书透明日志子域（${list.length}，evidence ${id}）：\n` + list.map((n) => '  ' + String(n)).join('\n')
    },
  })

  // ── 5. eng_recon_host（侦察 · 主机层） ──────────────────────────────────
  reg({
    name: 'eng_recon_host',
    description: '主机层资产面：端口、服务版本、banner。后端可选（node 并发 connect / WSL nmap / WSL masscan）。**主动动作**，目标须在 scope 内。',
    parameters: {
      engagementId: { type: 'string', required: true, description: '交战 id' },
      host: { type: 'string', required: true, description: '目标主机（域名 / IP）' },
      ports: { type: 'string', description: '端口规格（如 80,443 / 1-1000）' },
      backend: { type: 'string', description: 'node（缺省，内置 connect）| nmap | masscan' },
      timeoutMs: { type: 'number', description: '单端口超时（node 后端）' },
    },
    actionClass: 'active',
    targetOf: (a) => (typeof a['host'] === 'string' ? a['host'] : undefined),
    async run(args, c) {
      const host = String(args['host'])
      const ports = String(args['ports'] ?? '21,22,25,53,80,110,143,443,445,993,995,1433,3306,3389,5432,6379,8080,8443,27017')
      const backend = String(args['backend'] ?? 'node')
      if (backend === 'nmap' || backend === 'masscan') {
        const r = backend === 'nmap'
          ? await runNmap({ target: host, ports, timeoutMs: config.timeoutMs })
          : await runMasscan({ target: host, ports, timeoutMs: config.timeoutMs })
        if (!r.ok) throw new Error(r.error ?? `${backend} 失败`)
        const id = recordEvidence(c.paths, 'tcp', host, r.result ?? '', 'eng_recon_host')
        return `${backend} 结果（evidence ${id}）：\n${(r.result ?? '').slice(0, 6000)}`
      }
      const open = await scanPorts(host, parsePorts(ports), typeof args['timeoutMs'] === 'number' ? args['timeoutMs'] : 1200)
      const id = recordEvidence(c.paths, 'tcp', host, JSON.stringify(open), 'eng_recon_host')
      // `scanPorts` 只返回**开放**端口（closed 不进结果）⇒ 输出如实标注口径，不把「未列出」读成「关闭」
      return `端口扫描（开放 ${open.length} 个，evidence ${id}）：\n`
        + (open.length === 0 ? '  (无开放端口)' : open.map((p) => `  ${p.port}${p.service !== undefined ? ' ' + p.service : ''}`).join('\n'))
        + `\n口径：仅列出 connect 成功的端口；探测规格 ${ports}`
    },
  })

  // ── 6. eng_recon_web（侦察 · Web 层） ───────────────────────────────────
  reg({
    name: 'eng_recon_web',
    description: 'Web 层攻击面：指纹 / 安全头 / 敏感路径 / 目录 / 链接 / 漏洞扫描。aspects 可多选（fingerprint,headers,paths,dirs,links,vuln-scan）。**主动动作**，目标须在 scope 内。',
    parameters: {
      engagementId: { type: 'string', required: true, description: '交战 id' },
      url: { type: 'string', required: true, description: '目标 URL' },
      aspects: { type: 'array', items: { type: 'string' }, description: '缺省 fingerprint,headers,paths' },
      extraPaths: { type: 'array', items: { type: 'string' }, description: '额外路径' },
    },
    actionClass: 'active',
    targetOf: (a) => (typeof a['url'] === 'string' ? a['url'] : undefined),
    async run(args, c) {
      const url = String(args['url'])
      const aspects = Array.isArray(args['aspects']) && (args['aspects'] as string[]).length > 0
        ? (args['aspects'] as string[])
        : ['fingerprint', 'headers', 'paths']
      const out: string[] = []
      let body = ''
      if (aspects.includes('fingerprint')) {
        const fp = await techFingerprint(url)
        out.push(`指纹：${JSON.stringify(fp)}`)
        body += JSON.stringify(fp)
      }
      if (aspects.includes('headers')) {
        const h = await checkSecurityHeaders(url)
        out.push(`安全头：${JSON.stringify(h)}`)
        body += JSON.stringify(h)
      }
      if (aspects.includes('paths')) {
        const p = await probeSensitivePaths(url)
        out.push(`敏感路径（${p.length}）：\n` + p.map((x) => `  ${x.status} ${x.path} ${x.note}`).join('\n'))
        body += JSON.stringify(p)
      }
      if (aspects.includes('dirs')) {
        const d = await dirBrute(url, Array.isArray(args['extraPaths']) ? (args['extraPaths'] as string[]) : undefined)
        out.push(`目录爆破：${JSON.stringify(d).slice(0, 2000)}`)
        body += JSON.stringify(d)
      }
      if (aspects.includes('links')) {
        const l = await crawlLinks(url, config.limit)
        out.push(`链接：${JSON.stringify(l).slice(0, 2000)}`)
        body += JSON.stringify(l)
      }
      if (aspects.includes('vuln-scan')) {
        const r = await runNikto({ url, timeoutMs: config.timeoutMs })
        if (r.ok) {
          out.push(`nikto（前 2000 字）：\n${(r.result ?? '').slice(0, 2000)}`)
          body += r.result ?? ''
        } else out.push(`nikto 未执行：${r.error ?? '未知'}`)
      }
      const id = recordEvidence(c.paths, 'http', url, body, 'eng_recon_web')
      return `Web 面侦察（evidence ${id}）：\n` + out.join('\n')
    },
  })

  // ── 7. eng_intel（外部情报核对） ────────────────────────────────────────
  reg({
    name: 'eng_intel',
    description: '外部情报核对：版本→CVE、IOC 查证、公开扫描档案。**何时不该调**：把情报源当目标扫（它不是 scope 的一部分）。'
      + '情报动作需要交战存在但**不要求 scope 命中**（情报源不是交战目标），仍受窗口约束。',
    parameters: {
      engagementId: { type: 'string', required: true, description: '交战 id' },
      kind: { type: 'string', required: true, description: 'cve | ioc' },
      value: { type: 'string', required: true, description: 'cve：软件名；ioc：域名/IP/URL' },
      version: { type: 'string', description: 'cve：版本号' },
      limit: { type: 'number', description: '条数上限' },
    },
    actionClass: 'intel',
    async run(args) {
      const kind = String(args['kind'])
      const value = String(args['value'])
      const limit = typeof args['limit'] === 'number' ? args['limit'] : 8
      if (kind === 'cve') {
        const version = typeof args['version'] === 'string' ? args['version'] : ''
        const rows = version !== '' ? await matchCve(value, version, limit) : await searchCveNvd(value, limit)
        return `CVE 核对（${value}${version !== '' ? ' ' + version : ''}）：\n` + (rows.length === 0 ? '  (无命中)' : rows.map((r) => '  ' + JSON.stringify(r)).join('\n'))
      }
      const urlhaus = await queryUrlhaus(value)
      const urlscan = await queryUrlscan(value)
      return `IOC 核对（${value}）：\n  urlhaus: ${JSON.stringify(urlhaus)}\n  urlscan: ${JSON.stringify(urlscan)}`
    },
  })

  // ── 8. eng_finding（发现台账） ──────────────────────────────────────────
  reg({
    name: 'eng_finding',
    description: '登记或裁决一条发现（我的判断落盘处）。**何时不该调**：拿它当笔记——无证据的登记会被拒（I5：必须挂 ≥1 个 evidenceId）。',
    parameters: {
      engagementId: { type: 'string', required: true, description: '交战 id' },
      target: { type: 'string', required: true, description: '目标' },
      kind: { type: 'string', required: true, description: '类别（如 xss / sqli / misconfig / exposure）' },
      severity: { type: 'string', required: true, description: 'info | low | medium | high | critical' },
      status: { type: 'string', required: true, description: 'candidate | verified | refuted' },
      evidenceIds: { type: 'array', items: { type: 'string' }, required: true, description: '证据 id 列表（≥1）' },
      note: { type: 'string', description: '说明' },
      findingId: { type: 'string', description: '裁决既有发现时给 id（缺省新建）' },
    },
    actionClass: 'passive',
    async run(args, c) {
      const f: Finding = {
        id: typeof args['findingId'] === 'string' && args['findingId'] !== '' ? args['findingId'] : 'f-' + randomUUID().slice(0, 8),
        atMs: Date.now(),
        target: String(args['target']),
        phase: 'assessment',
        kind: String(args['kind']),
        severity: String(args['severity']),
        status: String(args['status']) as Finding['status'],
        evidenceIds: Array.isArray(args['evidenceIds']) ? (args['evidenceIds'] as string[]) : [],
        note: String(args['note'] ?? ''),
      }
      const res = appendFinding(c.paths, f, [])
      if (!res.ok) throw new Error(`登记被拒（${String(res.reason)}）——发现必须挂 ≥1 个证据（I5）`)
      return `发现已登记：${f.id}（${f.severity} · ${f.status} · 证据 ${f.evidenceIds.length} 条）`
    },
  })

  // ── 9. eng_payload（验证/利用 · 构造，纯本地） ──────────────────────────
  reg({
    name: 'eng_payload',
    description: '为**一条已登记的发现**构造可提交载荷；primitive 选维度（cmdi / php_juggling / web_bypass / jwt / serialize / ecb）。'
      + '**纯本地计算，零网络零子进程**；必填 findingId 就是为了堵「脱离发现凭空生成」。',
    parameters: {
      engagementId: { type: 'string', required: true, description: '交战 id' },
      findingId: { type: 'string', required: true, description: '已登记的发现 id' },
      primitive: { type: 'string', required: true, description: 'cmdi | php_juggling | web_bypass | jwt | serialize | ecb' },
      value: { type: 'string', description: 'primitive 的主输入（命令 / 密码 / 路径 / JWT / 序列化串）' },
      hint: { type: 'string', description: '辅助输入（如 PHP 松散比较的提示）' },
    },
    actionClass: 'passive',
    async run(args, c) {
      const findingId = String(args['findingId'])
      const known = readFindings(c.paths).some((f) => typeof f === 'object' && f !== null && (f as { id?: string }).id === findingId)
      if (!known) throw new Error(`发现不存在：${findingId}——先 eng_finding 登记（防脱离发现凭空生成）`)
      const primitive = String(args['primitive'])
      const value = String(args['value'] ?? '')
      const hint = String(args['hint'] ?? '')
      let candidates: unknown
      if (primitive === 'cmdi') candidates = generateCmdi({ command: value })
      else if (primitive === 'php_juggling') candidates = generateJuggling({ needle: hint !== '' ? hint : value })
      else if (primitive === 'web_bypass') candidates = generateBypass({ base: value })
      else if (primitive === 'jwt') candidates = forgeJwt({ secret: value })
      else if (primitive === 'serialize') candidates = generateSerialize({ className: value, properties: {} })
      else if (primitive === 'ecb') candidates = planEcbSplice({ prefixLen: 16, injectOffset: 0, payload: value })
      else throw new Error(`未知 primitive：${primitive}`)
      return `载荷候选（finding ${findingId} · primitive ${primitive}）：\n` + JSON.stringify(candidates, null, 1).slice(0, 4000)
    },
  })

  // ── 10. eng_verify（验证/利用 · 执行） ──────────────────────────────────
  reg({
    name: 'eng_verify',
    description: '执行验证：把候选变成「verified / refuted + 证据」。primitive 含 blind-extract（盲注提取）/ echo-confirm / remote-exec / auth-attempt（弱口令，**需 allowActiveAuth**）。'
      + '**主动动作**，目标须在 scope 内；`auth-attempt` 属 active-auth。',
    parameters: {
      engagementId: { type: 'string', required: true, description: '交战 id' },
      findingId: { type: 'string', required: true, description: '发现 id' },
      primitive: { type: 'string', required: true, description: 'blind-extract | echo-confirm | remote-exec | auth-attempt' },
      target: { type: 'string', required: true, description: '目标（URL / 主机）' },
      command: { type: 'string', description: 'remote-exec / echo-confirm 的命令' },
      service: { type: 'string', description: 'auth-attempt 的服务（ssh/ftp/http-post-form…）' },
      user: { type: 'string', description: 'auth-attempt 用户名' },
      passlist: { type: 'string', description: 'auth-attempt 密码字典路径（**不接明文口令**）' },
    },
    actionClass: 'active',
    targetOf: (a) => (typeof a['target'] === 'string' ? a['target'] : undefined),
    async run(args, c) {
      const primitive = String(args['primitive'])
      const target = String(args['target'])
      if (primitive === 'auth-attempt') {
        const r = await runHydra({
          target,
          service: String(args['service'] ?? 'ssh'),
          ...(typeof args['user'] === 'string' ? { user: args['user'] } : {}),
          ...(typeof args['passlist'] === 'string' ? { passlist: args['passlist'] } : {}),
          timeoutMs: config.timeoutMs,
        })
        if (!r.ok) throw new Error(r.error ?? 'hydra 失败')
        const id = recordEvidence(c.paths, 'subprocess', target, r.result ?? '', 'eng_verify')
        return `auth-attempt（evidence ${id}）：\n${(r.result ?? '').slice(0, 3000)}`
      }
      if (primitive === 'blind-extract') {
        // 诚实边界：二分提取需要一个 probe 回调（盲注判定接线），本件尚未接线。
        // 不假装能跑——返回明确原因，而不是给一个恒空的「结果」。
        throw new Error('blind-extract 需要 probe 回调（盲注判定接线），本件尚未接线——见 docs/semantic.md 未决问题')
      }
      if (primitive === 'remote-exec') {
        // 诚实边界 + 纪律：`buildSshCmd` 需要**明文口令**，而本件纪律是「凭据只以引用形式进入」
        // （旧 `dsh-cyber-range` 用 `sshpass -p '<口令>'` 把口令同时放进工具参数与子进程命令行——本件不复制它）。
        throw new Error('remote-exec 需要凭据，而本件只接受凭据引用（不经明文参数）——该接线尚未实现')
      }
      // echo-confirm：构造 curl 并经 WSL 执行（host/path 由目标 URL 解析，参数一律经 shellQuote）
      const u = new URL(target)
      const built = buildCurlCmd({ host: u.host, path: u.pathname + u.search, method: 'GET' })
      const r = await runProgram('wsl.exe', ['-d', 'Ubuntu', '--', 'bash', '-c', built], config.timeoutMs)
      const parsed = parseCurlOutput(r.stdout)
      const id = recordEvidence(c.paths, 'http', target, r.stdout, 'eng_verify')
      return `echo-confirm（evidence ${id}）：exit=${String(r.code)} status=${parsed.status} truncated=${parsed.truncated}\n${scrub(parsed.body, []).slice(0, 3000)}`
    },
  })

  // ── 11. eng_detect（检测侧校验） ────────────────────────────────────────
  reg({
    name: 'eng_detect',
    description: '检测面反推：本机遥测（连接/监听、自启动、安全日志）+「这类动作会留下什么可观测信号」。'
      + '**I9：本机端点也必须先在 scope 声明**（未声明 127.0.0.1 时调用会被判 gate/out-of-scope）。',
    parameters: {
      engagementId: { type: 'string', required: true, description: '交战 id' },
      aspects: { type: 'array', items: { type: 'string' }, description: 'connections | autoruns | eventlog | signal-map' },
      host: { type: 'string', description: '检测面宿主（缺省 127.0.0.1）' },
      days: { type: 'number', description: 'eventlog 天数（缺省 7）' },
    },
    actionClass: 'active',
    targetOf: (a) => (typeof a['host'] === 'string' ? a['host'] : '127.0.0.1'),
    async run(args, c) {
      const aspects = Array.isArray(args['aspects']) && (args['aspects'] as string[]).length > 0
        ? (args['aspects'] as string[])
        : ['connections', 'signal-map']
      const out: string[] = []
      if (aspects.includes('connections')) out.push('本机连接/监听：\n' + auditConnections(200).slice(0, 2500))
      if (aspects.includes('autoruns')) out.push('自启动项：\n' + auditAutoruns(100).slice(0, 2500))
      if (aspects.includes('eventlog')) {
        const days = typeof args['days'] === 'number' ? args['days'] : 7
        out.push(`安全日志（近 ${days} 天）：\n` + queryEventLog([4624, 4625, 4688], days, 'Security', 100).slice(0, 2500))
      }
      if (aspects.includes('signal-map')) {
        out.push([
          '动作 → 可观测信号映射（检测面视角）：',
          '  · 端口扫描     → 目标侧连接日志/防火墙丢包计数；本机侧出站连接突发',
          '  · 目录爆破     → Web 访问日志 404 率骤升；WAF/IPS 规则命中',
          '  · 命令注入     → 子进程创建（4688）+ 父进程异常（w3wp/httpd）',
          '  · 弱口令       → 认证失败事件（4625）批量 + 源 IP 聚集',
          '  · 远程执行     → 服务端 sshd 登录日志 + 本机 ssh 出站',
          '  · 载荷构造     → **零信号**（纯本地计算）',
        ].join('\n'))
      }
      const id = recordEvidence(c.paths, 'local-read', String(args['host'] ?? '127.0.0.1'), out.join('\n'), 'eng_detect')
      return `检测面取证（evidence ${id}）：\n` + out.join('\n\n')
    },
  })

  // ── 12. eng_report（证据与报告） ────────────────────────────────────────
  reg({
    name: 'eng_report',
    description: '出交战报告：发现 / 证据 / 时间线 / 闸门拒绝，含证据校验和。**何时不该调**：交战未收尾时出「最终报告」。',
    parameters: {
      engagementId: { type: 'string', required: true, description: '交战 id' },
      format: { type: 'string', description: 'md（缺省）| json' },
      includeTimeline: { type: 'boolean', description: '是否含时间线（缺省 true）' },
    },
    actionClass: 'passive',
    async run(args, c) {
      const eng = c.eng
      if (eng === null) throw new Error('eng_report 需要一个可读的交战')
      const findings = readFindings(c.paths)
      const evidence = readEvidence(c.paths)
      const timeline = readTimeline(c.paths)
      const denied = deniedCount(c.paths)
      const digest = sha256(JSON.stringify({ findings, evidence })).slice(0, 32)
      if (String(args['format'] ?? 'md') === 'json') {
        return JSON.stringify({ engagement: eng, counts: { findings: findings.length, evidence: evidence.length, denied }, digest, findings, evidence }, null, 1)
      }
      const lines = [
        `# 交战报告 · ${eng.id}`,
        '',
        `- 标题：${eng.title ?? '(无)'}`,
        `- 状态：${eng.status}`,
        `- 授权：${eng.authorization.source}（ref=${eng.authorization.ref}）`,
        `- 范围：${eng.scope.targets.join(', ')}`,
        `- 窗口：${eng.window.notBefore ?? '(即刻)'} → ${eng.window.notAfter}`,
        `- 计数：发现 ${findings.length} · 证据 ${evidence.length} · 闸门拒绝 ${denied}`,
        `- 证据校验和：${digest}`,
        '',
        '## 发现',
        ...(findings.length === 0 ? ['（无）'] : findings.map((f) => `- ${JSON.stringify(f)}`)),
        '',
        '## 证据',
        ...(evidence.length === 0 ? ['（无）'] : evidence.map((e) => `- ${JSON.stringify(e)}`)),
      ]
      if (args['includeTimeline'] !== false) {
        lines.push('', '## 时间线（含闸门拒绝）', ...(timeline.length === 0 ? ['（无）'] : timeline.map((t) => `- ${JSON.stringify(t)}`)))
      }
      return lines.join('\n')
    },
  })

  logger.info(`ready（交战国度根=${root}，工具面 12）`)
}
