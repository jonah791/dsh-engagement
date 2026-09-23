/** 资产发现：端口扫描（Node 原生并发 TCP connect）——仅限自有/授权资产 */

import { connect } from 'node:net'

export interface PortResult {
  port: number
  service?: string
}

const COMMON_PORTS: Record<number, string> = {
  21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP',
  110: 'POP3', 111: 'RPC', 135: 'MS-RPC', 139: 'NetBIOS', 143: 'IMAP',
  443: 'HTTPS', 445: 'SMB', 465: 'SMTPS', 514: 'Syslog', 587: 'SMTP-Sub',
  636: 'LDAPS', 993: 'IMAPS', 995: 'POP3S', 1080: 'SOCKS', 1433: 'MSSQL',
  1521: 'Oracle', 1723: 'PPTP', 2049: 'NFS', 2375: 'Docker', 3000: 'HTTP-Alt',
  3306: 'MySQL', 3389: 'RDP', 4369: 'Erlang', 5000: 'HTTP-Alt', 5432: 'PostgreSQL',
  5900: 'VNC', 5985: 'WinRM-HTTP', 5986: 'WinRM-HTTPS', 6379: 'Redis',
  6443: 'K8s-API', 7001: 'WebLogic', 8000: 'HTTP-Alt', 8080: 'HTTP-Proxy',
  8081: 'HTTP-Alt', 8443: 'HTTPS-Alt', 8888: 'HTTP-Alt', 9000: 'HTTP-Alt',
  9092: 'Kafka', 9200: 'Elasticsearch', 9300: 'ES-Transport', 11211: 'Memcached',
  27017: 'MongoDB', 50000: 'SAP', 50070: 'HDFS',
}

const DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 587, 636, 993, 995, 1080, 1433, 1521, 1723, 2049, 2375, 3000, 3306, 3389, 5432, 5900, 5985, 5986, 6379, 6443, 7001, 8000, 8080, 8081, 8443, 8888, 9000, 9092, 9200, 11211, 27017, 50000]

function testPort(host: string, port: number, timeoutMs: number): Promise<boolean> {
  return new Promise((resolve) => {
    const sock = connect({ host, port, timeout: timeoutMs })
    sock.once('connect', () => { sock.destroy(); resolve(true) })
    sock.once('timeout', () => { sock.destroy(); resolve(false) })
    sock.once('error', () => { sock.destroy(); resolve(false) })
  })
}

/** 并发端口扫描：返回开放端口列表 */
export async function scanPorts(host: string, ports: number[], timeoutMs = 1000, concurrency = 200): Promise<PortResult[]> {
  const results: PortResult[] = []
  let idx = 0
  const worker = async () => {
    while (idx < ports.length) {
      const port = ports[idx]!
      idx++
      if (await testPort(host, port, timeoutMs)) {
        results.push({ port, service: COMMON_PORTS[port] })
      }
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, Math.max(ports.length, 1)) }, () => worker()))
  results.sort((a, b) => a.port - b.port)
  return results
}

/** 解析端口规格："22,80,443" / "1-1000" / "8000-9000,8080" */
export function parsePorts(spec: string): number[] {
  const set = new Set<number>()
  for (const part of spec.split(',')) {
    const t = part.trim()
    if (!t) continue
    if (t.includes('-')) {
      const parts = t.split('-').map(Number)
      const a = parts[0] ?? 0
      const b = parts[1] ?? 0
      if (a >= 1 && b >= a && b <= 65535) {
        for (let p = a; p <= b; p++) set.add(p)
      }
    } else {
      const p = Number(t)
      if (p >= 1 && p <= 65535) set.add(p)
    }
  }
  return [...set].sort((a, b) => a - b)
}

export { DEFAULT_PORTS }
