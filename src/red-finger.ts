/** 红队指纹/探测：技术栈指纹、banner 抓取、安全头检测、敏感路径探测、CVE 匹配——仅限授权测试 */

import { connect } from 'node:net'
import { matchFrameworks, splitSecurityHeaders, classifySensitivePath, SENSITIVE_PATHS, mapCves, type CveRow } from './red-pure.js'

export async function techFingerprint(targetUrl: string): Promise<{
  url: string; status: number; headers: Record<string, string>; marks: string[]; server: string; poweredBy: string
}> {
  const res = await fetch(targetUrl, {
    redirect: 'follow',
    headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' },
    signal: AbortSignal.timeout(15000),
  })
  const html = (await res.text()).slice(0, 50000)
  const headers: Record<string, string> = {}
  res.headers.forEach((v, k) => { headers[k] = v })
  const server = headers['server'] ?? ''
  const poweredBy = headers['x-powered-by'] ?? ''
  // 特征匹配表与判定在 pure.matchFrameworks（零 IO，可离线单测）
  const marks = matchFrameworks(`${headers['x-powered-by'] ?? ''} ${headers['server'] ?? ''} ${html.slice(0, 20000)}`)
  return { url: res.url || targetUrl, status: res.status, headers, marks, server, poweredBy }
}

/** Banner 抓取：TCP 连接读取服务 banner（端口服务版本识别） */
export async function grabBanner(host: string, port: number, timeoutMs = 5000): Promise<string> {
  return new Promise((resolve, reject) => {
    const sock = connect({ host, port, timeout: timeoutMs })
    const chunks: Buffer[] = []
    const done = (err?: Error) => {
      sock.destroy()
      if (err) reject(err)
      else resolve(Buffer.concat(chunks).toString('utf8').replace(/[\r\n]+$/, '').slice(0, 300))
    }
    sock.setTimeout(timeoutMs)
    sock.once('connect', () => {
      // 发送常见探测
      try { sock.write('HEAD / HTTP/1.0\r\n\r\n') } catch { /* ignore */ }
    })
    sock.on('data', (d) => { chunks.push(d) })
    sock.once('timeout', () => done())
    sock.once('error', (e) => done(e))
    sock.once('close', () => done())
  })
}

/** 安全头检查：缺失的安全响应头 = Web 攻击面（应存在的头清单在 pure.SEC_HEADERS） */
export async function checkSecurityHeaders(targetUrl: string): Promise<{
  url: string; present: string[]; missing: string[]
}> {
  const res = await fetch(targetUrl, {
    redirect: 'follow',
    headers: { 'User-Agent': 'Mozilla/5.0' },
    signal: AbortSignal.timeout(15000),
  })
  const { present, missing } = splitSecurityHeaders((h) => res.headers.get(h))
  return { url: res.url || targetUrl, present, missing }
}

/** 敏感路径探测：配置文件/版本控制/管理后台泄露（清单在 pure.SENSITIVE_PATHS） */
export async function probeSensitivePaths(baseUrl: string): Promise<{ path: string; status: number; note: string }[]> {
  const base = baseUrl.replace(/\/+$/, '')
  const results: { path: string; status: number; note: string }[] = []
  for (const p of SENSITIVE_PATHS) {
    try {
      const ctrl = new AbortController()
      const timer = setTimeout(() => ctrl.abort(), 8000)
      const res = await fetch(`${base}/${p}`, {
        redirect: 'manual',
        signal: ctrl.signal,
        headers: { 'User-Agent': 'Mozilla/5.0' },
      })
      clearTimeout(timer)
      if (res.status === 200) {
        const body = (await res.text()).slice(0, 200)
        results.push({ path: p, status: res.status, note: classifySensitivePath(p, body) })
      }
    } catch { /* 跳过超时 */ }
  }
  return results
}

/** CVE 匹配：软件+版本精确匹配（攻击面视角，标注可利用风险） */
export async function matchCve(software: string, version: string, limit = 8): Promise<CveRow[]> {
  const kw = version ? `${software} ${version}` : software
  const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(kw)}&resultsPerPage=${Math.min(limit, 20)}`
  const res = await fetch(url, { signal: AbortSignal.timeout(20000) })
  if (!res.ok) throw new Error(`NVD API HTTP ${res.status}`)
  const data = await res.json() as { vulnerabilities?: { cve: any }[] }
  // 归一 + CVSS 降序排序在 pure.mapCves（零 IO，可离线单测）
  return mapCves(data, limit)
}
