/**
 * dsh-red-team — 解析 / 判定层（纯函数，零 IO，可离线单测）
 *
 * 2026-09-14 可维护性补课：指纹匹配、安全头判定、敏感路径定性、目录字典、链接抽取、
 * crt.sh 名单清洗、CVE 归一——这些判定原先都藏在 fetch 函数体里，**无法离线验证脏数据会怎样**。
 * 本次**仅搬家**（逻辑逐字不变），IO（fetch/connect）留在 enum.ts / finger.ts。
 *
 * 边界声明：本模块只做**本地字符串/结构判定**，不发任何网络请求、不做任何攻击动作。
 *
 * 不变量（tests/pure.test.mjs 锁住）：
 *   1. 一切清洗/判定对脏数据**保守返回**（跳过/空数组），绝不抛错
 *   2. 目录字典与敏感路径清单**只读且不可被调用方改写**（每次返回新数组）
 *   3. CVE 归一按 CVSS 降序、缺失 CVSS 记 0；严重度缺失记 `UNKNOWN`
 *
 * 2026-09-14 S4 证据层：两个「过滤」函数各有一个 `*Detailed` 变体，额外返回 `stats`
 * （`raw/kept/dropped/reasons` = **原始条数 / 过滤依据 / 过滤后条数**），供轨迹落盘；
 * 原名函数是它们的薄委托（行为逐字一致）。`TraceStats` 是**类型导入**，不引入任何 IO。
 */

import type { TraceStats } from './red-trace.js'

// ═══════════════ 指纹 ═══════════════

/** 技术栈指纹特征表（响应头 + 页面特征） */
export const FRAMEWORK_MARKS: [string, RegExp][] = [
  ['WordPress', /wp-content|wp-includes|wordpress/i],
  ['Drupal', /drupal|sites\/default/i],
  ['Joomla', /joomla|com_content/i],
  ['Laravel', /laravel|XSRF-TOKEN/i],
  ['Django', /django|csrftoken|__admin/i],
  ['Spring', /spring|JSESSIONID/i],
  ['ASP.NET', /asp\.net|__VIEWSTATE|X-AspNet-Version/i],
  ['PHP', /php|PHPSESSID|X-Powered-By:\s*PHP/i],
  ['Node.js/Express', /express|connect\.sid|x-recruiting|access-control-allow-origin:\s*\*/i],
  ['OWASP Juice Shop', /x-recruiting|owasp juice shop|juice-shop/i],
  ['Ruby on Rails', /rails|_rails_session/i],
  ['React', /react|_next\/static/i],
  ['Vue.js', /vue|__NUXT__/i],
  ['Nginx', /nginx/i],
  ['Apache', /apache/i],
  ['IIS', /microsoft-iis/i],
  ['Tomcat', /tomcat|JSESSIONID/i],
  ['GitLab', /gitlab/i],
  ['Jenkins', /jenkins/i],
]

/** 命中的技术栈名（顺序 = 特征表顺序，可重复出现同名只报一次） */
export function matchFrameworks(haystack: string): string[] {
  return FRAMEWORK_MARKS.filter(([, re]) => re.test(haystack)).map(([n]) => n)
}

// ═══════════════ 安全头 ═══════════════

/** 应存在而未存在的安全响应头 = Web 攻击面 */
export const SEC_HEADERS = [
  ['strict-transport-security', 'HSTS（防降级）'],
  ['content-security-policy', 'CSP（防 XSS/注入）'],
  ['x-frame-options', '点击劫持防护'],
  ['x-content-type-options', 'MIME 嗅探防护'],
  ['x-xss-protection', 'XSS 过滤器'],
  ['referrer-policy', 'Referrer 泄露防护'],
  ['permissions-policy', '权限策略'],
] as const

/** 按「该头是否存在」拆分 present/missing（getter 注入：可喂真实 Headers，也可喂桩） */
export function splitSecurityHeaders(has: (name: string) => unknown): { present: string[]; missing: string[] } {
  const present: string[] = []
  const missing: string[] = []
  for (const [h, why] of SEC_HEADERS) {
    if (has(h)) present.push(`${h} (${why})`)
    else missing.push(`${h} (${why})`)
  }
  return { present, missing }
}

// ═══════════════ 敏感路径 ═══════════════

/** 配置文件/版本控制/管理后台泄露探测清单 */
export const SENSITIVE_PATHS = [
  '.git/HEAD', '.git/config', '.env', '.env.local', 'config.php', 'web.config',
  '.htaccess', 'backup.zip', 'backup.sql', 'db.sql', 'dump.sql', 'admin.php',
  'phpinfo.php', 'server-status', 'robots.txt', 'sitemap.xml', 'wp-config.php.bak',
]

/**
 * 敏感路径命中后的定性（只在 status===200 时调用）。
 * 2026-09-14 记录真语义：判定按**顺序覆盖**（后面的 if 会覆盖前面的 note），
 * 且 `p.includes('.git')` 这类是**子串**判定（`.gitlab-ci.yml` 也会命中）。
 */
export function classifySensitivePath(p: string, body: string): string {
  let note = '存在'
  if (p.includes('.git') && body.startsWith('ref:')) note = 'Git 仓库泄露!'
  if (p.includes('.env') && /KEY|SECRET|PASS|TOKEN/i.test(body)) note = '环境变量疑似泄露!'
  if (p.includes('phpinfo')) note = 'PHPINFO 暴露!'
  if (p === 'robots.txt') note = 'robots.txt（可能泄露路径）'
  return note
}

// ═══════════════ 目录枚举 ═══════════════

/** 目录枚举字典（常见 Web 目录/文件） */
export const DIR_DICT = [
  'admin', 'administrator', 'api', 'app', 'backup', 'bak', 'bin', 'cache', 'cgi-bin',
  'config', 'console', 'css', 'data', 'db', 'debug', 'dev', 'doc', 'docs', 'download',
  'env', 'error', 'etc', 'files', 'git', 'graphql', 'health', 'images', 'img', 'include',
  'index.php', 'js', 'json', 'lib', 'login', 'logs', 'media', 'old', 'panel', 'phpmyadmin',
  'plugins', 'portal', 'private', 'public', 'robots.txt', 'sitemap.xml', 'sql', 'src',
  'static', 'status', 'storage', 'swagger', 'temp', 'test', 'tmp', 'upload', 'uploads',
  'user', 'users', 'vendor', 'web', 'web.config', 'www', 'xml',
]

/** 字典 + 追加项（去前导 `/`、整体去重；返回新数组，不改写 DIR_DICT） */
export function buildDirPaths(extra?: string[]): string[] {
  return [...new Set([...DIR_DICT, ...(extra ?? []).map((p) => p.replace(/^\//, ''))])]
}

/** 「非 404 也非 0」才视为存在（0 = 网络层失败占位） */
export function isInterestingStatus(status: number): boolean {
  return status !== 404 && status !== 0
}

// ═══════════════ 页面解析 ═══════════════

/** 页面标题（取不到返回空串） */
export function extractTitle(html: string): string {
  return (html.match(/<title[^>]*>([^<]*)<\/title>/i)?.[1] ?? '').trim()
}

export interface LinkResult {
  url: string
  source: 'href' | 'src' | 'action'
}

/**
 * 抽取页面链接：相对地址按 baseUrl 解析，只留**同源**、去重、按 maxLinks 截断。
 *
 * 2026-09-14 修复：原实现用 `u.startsWith(base.origin)` 做同源判定——那是**字符串前缀**，
 * 会把 `https://a.com:8443/x`、以及 `https://a.com.evil.com/x`（前缀相同、源不同）都当成同源，
 * 「同源过滤」名不副实。现按 URL `origin` 精确比较（只返回被过滤掉的那部分差异）。
 */
export function extractLinks(html: string, targetUrl: string, maxLinks: number): LinkResult[] {
  return extractLinksDetailed(html, targetUrl, maxLinks).links
}

/**
 * 同上，但把**过滤依据**一并带出（2026-09-14 S4 证据层）：`stats.reasons` 的键是可 grep 的
 * 丢弃原因——`scheme`（javascript:/#/data:）｜`off-origin`（异源，含此前误判为同源的前缀型）｜
 * `duplicate`（重复 URL）｜`invalid-url`（解析失败）｜`over-limit`（超 maxLinks 截断）。
 * `extractLinks` 是本函数的薄委托（行为逐字一致，仅返回值取 `.links`）。
 */
export function extractLinksDetailed(
  html: string,
  targetUrl: string,
  maxLinks: number,
): { links: LinkResult[]; stats: TraceStats } {
  const base = new URL(targetUrl)
  const links: LinkResult[] = []
  const seen = new Set<string>()
  const reasons: Record<string, number> = {}
  const drop = (why: string) => { reasons[why] = (reasons[why] ?? 0) + 1 }
  let raw = 0
  const collect = (attr: string, source: LinkResult['source']) => {
    const re = new RegExp(`${attr}=["']([^"'\\s>]+)["']`, 'gi')
    let m: RegExpExecArray | null
    while ((m = re.exec(html)) !== null) {
      raw++
      const rawUrl = m[1] ?? ''
      if (!rawUrl || rawUrl.startsWith('javascript:') || rawUrl.startsWith('#') || rawUrl.startsWith('data:')) {
        drop('scheme')
        continue
      }
      try {
        const parsed = new URL(rawUrl, base)
        if (parsed.origin !== base.origin) {
          drop('off-origin')
          continue
        }
        const u = parsed.href
        if (!seen.has(u)) {
          seen.add(u)
          links.push({ url: u, source })
        } else {
          drop('duplicate')
        }
      } catch { drop('invalid-url') /* 跳过非法 URL */ }
    }
  }
  collect('href', 'href')
  collect('src', 'src')
  collect('action', 'action')
  const kept = links.slice(0, maxLinks)
  if (links.length > kept.length) reasons['over-limit'] = links.length - kept.length
  return {
    links: kept,
    stats: {
      raw,
      kept: kept.length,
      dropped: raw - kept.length,
      ...(Object.keys(reasons).length > 0 ? { reasons } : {}),
    },
  }
}

// ═══════════════ 子域名（crt.sh） ═══════════════

/** crt.sh 名单清洗：拆行、去 `*.`、小写、只留目标域子域、去重、排序、截断 */
export function parseCrtShNames(data: unknown, domain: string, limit: number): string[] {
  return parseCrtShNamesDetailed(data, domain, limit).names
}

/**
 * 同上，但把**过滤依据**一并带出（2026-09-14 S4 证据层）：`reasons` 键为
 * `not-subdomain`（不属于目标域）｜`too-long`（长度 ≥ 100）｜`duplicate`（重复名）｜`over-limit`（截断）。
 * `parseCrtShNames` 是本函数的薄委托（行为逐字一致，仅返回值取 `.names`）。
 */
export function parseCrtShNamesDetailed(
  data: unknown,
  domain: string,
  limit: number,
): { names: string[]; stats: TraceStats } {
  const seen = new Set<string>()
  const reasons: Record<string, number> = {}
  const drop = (why: string) => { reasons[why] = (reasons[why] ?? 0) + 1 }
  let raw = 0
  if (!Array.isArray(data)) return { names: [], stats: { raw: 0, kept: 0, dropped: 0 } }
  for (const row of data) {
    for (const name of String((row as { name_value?: unknown })?.name_value ?? '').split('\n')) {
      const trimmed = name.trim()
      if (trimmed === '') continue
      raw++
      const n = trimmed.toLowerCase().replace(/\*\./, '')
      if (!n.endsWith(`.${domain}`)) drop('not-subdomain')
      else if (n.length >= 100) drop('too-long')
      else if (seen.has(n)) drop('duplicate')
      else seen.add(n)
    }
  }
  const names = [...seen].sort()
  const kept = names.slice(0, limit)
  if (names.length > kept.length) reasons['over-limit'] = names.length - kept.length
  return {
    names: kept,
    stats: {
      raw,
      kept: kept.length,
      dropped: raw - kept.length,
      ...(Object.keys(reasons).length > 0 ? { reasons } : {}),
    },
  }
}

// ═══════════════ CVE ═══════════════

export interface CveRow {
  id: string
  cvss: number | null
  severity: string
  description: string
  exploitRef: boolean
}

/** NVD 响应 → CVE 行（CVSS 取 v3.1 优先、回落 v2；按 CVSS 降序；缺失记 0） */
export function mapCves(data: unknown, limit: number): CveRow[] {
  const vulns = (data as { vulnerabilities?: { cve: any }[] })?.vulnerabilities ?? []
  const cves = vulns.map((v) => {
    const c = v.cve
    const cvss = c.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore ?? c.metrics?.cvssMetricV2?.[0]?.cvssData?.baseScore ?? null
    const severity = c.metrics?.cvssMetricV31?.[0]?.cvssData?.baseSeverity ?? c.metrics?.cvssMetricV2?.[0]?.cvssData?.baseSeverity ?? 'UNKNOWN'
    const desc = c.descriptions?.find((d: any) => d.lang === 'en')?.value ?? ''
    const exploitRef = (c.references ?? []).some((r: any) => /exploit|metasploit|github|poc/i.test(r.url ?? ''))
    return {
      id: c.id,
      cvss,
      severity,
      description: desc.slice(0, 250),
      exploitRef,
    }
  })
  return cves.sort((a, b) => (b.cvss ?? 0) - (a.cvss ?? 0)).slice(0, limit)
}
