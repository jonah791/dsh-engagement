/** 红队侦察：子域枚举（crt.sh）、目录枚举、链接爬取——仅限授权测试 */

import { buildDirPaths, isInterestingStatus, extractTitle, extractLinksDetailed, parseCrtShNamesDetailed } from './red-pure.js'
import type { TraceStats } from './red-trace.js'

export type { LinkResult } from './red-pure.js'

/** 子域名枚举：crt.sh 证书透明日志 + DNS 验证（过滤无效子域） */
export async function enumSubdomains(
  domain: string,
  limit = 30,
): Promise<{ names: string[]; stats: TraceStats }> {
  const url = `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`
  // crt.sh 偶发 502（服务端临时故障），重试 2 次
  let res: Response | null = null
  for (let i = 0; i < 3; i++) {
    try {
      res = await fetch(url, { signal: AbortSignal.timeout(20000) })
      if (res.ok) break
    } catch { /* 超时重试 */ }
    await new Promise((r) => setTimeout(r, 1500 * (i + 1)))
  }
  if (!res || !res.ok) throw new Error(`crt.sh HTTP ${res?.status ?? 'timeout'}`)
  const data = await res.json() as { name_value?: string }[]
  // 名单清洗（拆行/去 */小写/去重/排序/截断）在 pure.parseCrtShNamesDetailed
  return parseCrtShNamesDetailed(data, domain, limit)
}

export interface DirResult {
  path: string
  status: number
  size: number
}

/** 目录/文件枚举：GET 探测常见路径，非 404 视为存在 */
export async function dirBrute(
  baseUrl: string,
  extra?: string[],
  timeoutMs = 8000,
  concurrency = 10,
): Promise<{ results: DirResult[]; stats: TraceStats }> {
  const base = baseUrl.replace(/\/+$/, '')
  const paths = buildDirPaths(extra)
  const results: DirResult[] = []
  let idx = 0
  const worker = async () => {
    while (idx < paths.length) {
      const p = paths[idx]!
      idx++
      try {
        const ctrl = new AbortController()
        const timer = setTimeout(() => ctrl.abort(), timeoutMs)
        const res = await fetch(`${base}/${p}`, {
          redirect: 'manual',
          signal: ctrl.signal,
          headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' },
        })
        clearTimeout(timer)
        if (isInterestingStatus(res.status)) {
          const len = Number(res.headers.get('content-length') ?? 0)
          results.push({ path: p, status: res.status, size: len })
        }
      } catch { /* 超时/网络错误跳过 */ }
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, paths.length) }, () => worker()))
  results.sort((a, b) => a.path.localeCompare(b.path))
  // 统计（S4 证据层）：raw = 探测过的路径数，kept = 非 404 命中数，reasons = 网络层失败/404
  return {
    results,
    stats: { raw: paths.length, kept: results.length, dropped: paths.length - results.length, reasons: { 'not-found-or-error': paths.length - results.length } },
  }
}

/** 链接爬取：提取页面内 URL（含绝对/相对解析），供发现隐藏端点 */
export async function crawlLinks(targetUrl: string, maxLinks = 50): Promise<{
  links: import('./red-pure.js').LinkResult[]
  page: { title: string; url: string; status: number }
  stats: TraceStats
}> {
  const res = await fetch(targetUrl, {
    headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' },
    signal: AbortSignal.timeout(15000),
  })
  const html = await res.text()
  // 标题与链接抽取（同源过滤/去重/截断）在 pure.extractTitle / pure.extractLinksDetailed
  const extracted = extractLinksDetailed(html, targetUrl, maxLinks)
  return {
    links: extracted.links,
    page: { title: extractTitle(html), url: targetUrl, status: res.status },
    stats: extracted.stats,
  }
}
