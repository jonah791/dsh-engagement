/** 威胁情报：CVE 查询（NVD API v2）、文件哈希、IOC 查证（URLhaus 免费源） */

/** CVE 查询：NVD API v2（免费无 key，限速 ~5 req/30s） */
export async function searchCveNvd(keyword: string, limit = 10): Promise<CveResult[]> {
  const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(keyword)}&resultsPerPage=${Math.min(limit, 20)}`
  const res = await fetch(url, { signal: AbortSignal.timeout(20000) })
  if (!res.ok) throw new Error(`NVD API HTTP ${res.status}`)
  const data = await res.json() as { vulnerabilities?: { cve: NvdCve }[] }
  return (data.vulnerabilities ?? []).map((v) => {
    const c = v.cve
    const desc = c.descriptions?.find((d) => d.lang === 'en')?.value ?? ''
    const cvss = c.metrics?.cvssMetricV31?.[0]?.cvssData
    const cvssV2 = c.metrics?.cvssMetricV2?.[0]?.cvssData
    const severity = c.metrics?.cvssMetricV31?.[0]?.cvssData?.baseSeverity
      ?? c.metrics?.cvssMetricV2?.[0]?.baseSeverity
    return {
      id: c.id,
      published: c.published?.slice(0, 10) ?? '',
      cvss: cvss?.baseScore ?? cvssV2?.baseScore ?? null,
      severity: severity ?? 'UNKNOWN',
      description: desc.slice(0, 400),
      references: (c.references ?? []).slice(0, 3).map((r) => r.url),
      cpe: (c.configurations ?? []).flatMap((cfg) =>
        (cfg.nodes ?? []).flatMap((n) => (n.cpeMatch ?? []).map((m) => m.criteria ?? '')).slice(0, 4),
      ).slice(0, 4),
    }
  })
}

interface NvdCve {
  id: string
  published?: string
  descriptions?: { lang: string; value: string }[]
  metrics?: {
    cvssMetricV31?: { cvssData?: { baseScore?: number; baseSeverity?: string } }[]
    cvssMetricV2?: { cvssData?: { baseScore?: number }; baseSeverity?: string }[]
  }
  references?: { url: string }[]
  configurations?: { nodes?: { cpeMatch?: { criteria?: string }[] }[] }[]
}

export interface CveResult {
  id: string
  published: string
  cvss: number | null
  severity: string
  description: string
  references: string[]
  cpe: string[]
}

/** URLhaus 查证（免费无 key）：host / url / hash */
export async function queryUrlhaus(value: string): Promise<UrlhausResult> {
  const body = new URLSearchParams()
  const v = value.trim()
  if (/^[0-9a-f]{64}$/i.test(v)) {
    body.set('hash', v)
  } else if (/^[0-9a-f]{32}$/i.test(v) || /^[0-9a-f]{40}$/i.test(v)) {
    body.set('hash', v)
  } else if (v.startsWith('http')) {
    body.set('url', v)
  } else {
    body.set('host', v)
  }
  const res = await fetch('https://urlhaus.abuse.ch/api/', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
    signal: AbortSignal.timeout(15000),
  })
  if (!res.ok) throw new Error(`URLhaus API HTTP ${res.status}`)
  const data = await res.json() as { query_status?: string; urlhaus_reference?: string; url_status?: string; blacklists?: Record<string, string>; firstseen?: string; lastseen?: string; threat?: string; tags?: string[] }
  return {
    queryStatus: data.query_status ?? 'unknown',
    reference: data.urlhaus_reference ?? '',
    urlStatus: data.url_status ?? '',
    blacklists: data.blacklists ?? {},
    firstSeen: data.firstseen ?? '',
    lastSeen: data.lastseen ?? '',
    threat: data.threat ?? '',
    tags: data.tags ?? [],
  }
}

/** urlscan.io 查证（免费无 key）：域名/URL 扫描记录 + 恶意标记 */
export async function queryUrlscan(value: string): Promise<UrlscanResult> {
  const v = value.trim().replace(/^https?:\/\//i, '').replace(/\/.*$/, '')
  const url = `https://urlscan.io/api/v1/search/?q=domain:${encodeURIComponent(v)}`
  const res = await fetch(url, {
    headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' },
    signal: AbortSignal.timeout(15000),
  })
  if (!res.ok) throw new Error(`urlscan.io HTTP ${res.status}`)
  const data = await res.json() as { results?: any[]; total?: number }
  const results = (data.results ?? []).slice(0, 5).map((r) => ({
    url: String(r.page?.url ?? ''),
    domain: String(r.page?.domain ?? ''),
    time: String(r.task?.time ?? ''),
    malicious: Boolean(r.verdicts?.overall?.malicious),
    score: r.verdicts?.overall?.score ?? null,
  }))
  return { total: Number(data.total ?? 0), results }
}

export interface UrlscanResult {
  total: number
  results: { url: string; domain: string; time: string; malicious: boolean; score: number | null }[]
}

export interface UrlhausResult {
  queryStatus: string
  reference: string
  urlStatus: string
  blacklists: Record<string, string>
  firstSeen: string
  lastSeen: string
  threat: string
  tags: string[]
}
