#!/usr/bin/env node
/**
 * scan-dead-modules.mjs —— 生产零调用者模块扫描器（2026-10-06 · t-dd3c6faa 的判据工具）
 *
 * 判据：对 `src/` 下每个 `.ts` 模块，回答「**生产代码**（`src/`）里有没有值调用者」——
 *   · **值导入**（`import { x } from './m.js'` / `export { x } from './m.js'`）⇒ 运行时会加载 ⇒ 非死代码
 *   · **类型导入**（`import type { T } from './m.js'`）⇒ 仅编译期 ⇒ 不算生产者（删模块需同步改引用方）
 *   · **仅测试引用**（只有 `tests/` 引用它）⇒ 生产零调用 ⇒ **测试在测死代码**（单列一档，不混报）
 *   · **零引用**（任何地方都没有）⇒ 死代码候选
 *   · **入口**（`index.ts` 或 `package.json` 的 main/module/types 指向）⇒ 由宿主加载，
 *     不经 `src/` 内部 import ⇒ **不参与判定**（对它恒报死代码是假阳性）
 *
 * 为什么不用一次 `grep`：实测临时 grep（`trace.js|trace'`）会漏掉无扩展名/多行写法，
 * 且无法区分值导入与类型导入 ⇒ 判据必须严格到「能接闸门」。
 *
 * ⚠ 三个已修缺陷（2026-10-06，**全部由真实语料抓到，不是想出来的**）：
 *   ① **多行 import 恒漏检**：原正则 `[^\n]*` 要求 `import` 与 `from` 同行，而本仓的主流写法是多行
 *      ⇒ 四个**确实被引用**的模块被误报成「零引用」（假阴性 ⇒ 误报死代码；`red-trace.ts` 因此被
 *      任务原判误列为死代码）。修法：`[\s\S]*?`（跨行非贪婪）。对照实测：多行样本 旧=false 新=true。
 *   ② **src / tests 口径不分**：原实现把两者混为一谈，而本判据问的是「**生产**有没有调用者」——
 *      测试引用它恰恰是「测试在测死代码」的症状，不是「它还活着」的证据。修法：单列 `TEST-ONLY` 档。
 *   ③ **入口未豁免**：`index.ts` 由宿主加载、不经 src 内部 import ⇒ 曾被列为「仅测试引用」。
 *      修法：`entryNamesOf()` 纯函数判入口。
 *   ⇒ 教训：**判据工具自己必须有尸体样本**。`--selftest` 覆盖语句形态八式 + 入口解析三例，
 *      其中「多行值导入」正是缺陷①的尸体样本（原实现在它上面必错）。
 *
 * 已知缺口（**显式标注，不假装完备**）：不识别动态 `import('./m.js')` 与副作用 `import './m.js'`
 * —— 本仓语料中零出现，故未实现；若将来出现，本判据会把「只被这两种写法引用的模块」误报为死代码。
 *
 * 用法：
 *   node scripts/scan-dead-modules.mjs [--root <插件目录>] [--json <out>]
 *   node scripts/scan-dead-modules.mjs --selftest          # 判据自检（纯文本样本，不读盘）
 * 退出码：0 = 生产无零调用模块；1 = 存在（可作闸门）；2 = 找不到 src/；3 = 自检失败
 */
import fs from 'node:fs'
import path from 'node:path'
import process from 'node:process'

const argv = process.argv.slice(2)
const has = (name) => argv.includes(name)
const opt = (name, dflt = null) => {
  const i = argv.indexOf(name)
  return i >= 0 && argv[i + 1] !== undefined ? argv[i + 1] : dflt
}

const ROOT = path.resolve(opt('--root', process.cwd()))
const JSON_OUT = opt('--json')
const SRC = path.join(ROOT, 'src')

/**
 * 判断某个模块 basename 在一段文本里的引用档位。
 *
 * **纯函数**——主流程与 `--selftest` 共用这一份判据（单一真源：自检不能测另一套逻辑，
 * 否则「自检通过」只证明另一套逻辑没坏）。
 *
 * @param {string} text 文件正文
 * @param {string} base 模块 basename（不含 `.ts`）
 * @returns {'USE'|'REEXPORT'|'TYPE'|'NONE'}
 */
function refKindOf(text, base) {
  const mod = '(?:^|\\.{1,2}/)[^\'"]*' + base + '(?:\\.js)?'
  // 子句（`import`/`export` 与 `from` 之间）允许跨行，但**不得含 `from`**。
  // 这一条约束同时给出两个性质：
  //   ① 多行 import 可识别（缺陷①的修法）；
  //   ② 不会跨过**相邻的下一条** import 去配它的 `from`（缺陷④：`[\s\S]*?` 会把上一行的
  //      `import` 与下一行的 `from` 配成一对 ⇒ 类型导入被误判成值导入，实测 `red-enum.ts` 中招）。
  const clause = '(?:(?!\\bfrom\\b)[\\s\\S])*?'
  const reImport = new RegExp('^[ \\t]*import\\s+(?!type\\s)' + clause + 'from\\s+[\'"]' + mod + '[\'"]', 'm')
  if (reImport.test(text)) return 'USE'
  const reReexport = new RegExp('^[ \\t]*export\\s+(?!type\\s)' + clause + 'from\\s+[\'"]' + mod + '[\'"]', 'm')
  if (reReexport.test(text)) return 'REEXPORT'
  const reType = new RegExp('^[ \\t]*(?:import|export)\\s+type\\s+' + clause + 'from\\s+[\'"]' + mod + '[\'"]', 'm')
  if (reType.test(text)) return 'TYPE'
  return 'NONE'
}

/**
 * 入口模块名集合。
 *
 * **纯函数**：入口由宿主（cordis）加载，不经 `src/` 内部 import ⇒ 对它恒报「生产零调用者」
 * 是假阳性。只认 `index.ts` 约定名 + `package.json` 的 main/module/types/typings 四键
 * （Node 的 `exports` 形态多，未解析——见头部「已知缺口」）。
 *
 * @param {unknown} pkg package.json 解析结果（可为 null）
 * @param {readonly string[]} srcFileNames `src/` 下的 `.ts` 文件名
 * @returns {Set<string>}
 */
function entryNamesOf(pkg, srcFileNames) {
  const names = new Set(['index.ts'])
  if (pkg !== null && typeof pkg === 'object') {
    for (const key of ['main', 'module', 'types', 'typings']) {
      const v = pkg[key]
      if (typeof v !== 'string' || v === '') continue
      const b = path.basename(v).replace(/\.d\.ts$/, '.ts').replace(/\.(js|cjs|mjs|ts)$/, '.ts')
      if (srcFileNames.includes(b)) names.add(b)
    }
  }
  return names
}

/**
 * 由引用计数定「档」。
 *
 * **纯函数**（自检与主流程共用）。优先级：
 * **入口 > 生产值导入 > 仅再导出 > 仅测试引用 > 仅类型引用 > 零引用**。
 *
 * ⚠ 生产侧的加载证据（`reexport`）**优先于**测试侧的（`tests` 值导入）：前者意味着模块在
 * 生产组合里会被加载，后者只说明有个测试在测它。2026-10-06 实测：把 TEST-ONLY 排在前面会让
 * 「仅被再导出」档**整档消失**（`red-trace.ts` 同时具备两者，症状是那一节显示「（无）」）。
 *
 * @param {boolean} isEntry 是否入口模块
 * @param {{use:number, reexport:number, testUse:number, typeUse:number}} c 各档引用计数
 * @returns {'ENTRY'|'USE'|'REEXPORT-ONLY'|'TEST-ONLY'|'TYPE-ONLY'|'NONE'}
 */
function gradeOf(isEntry, c) {
  if (isEntry) return 'ENTRY'
  if (c.use > 0) return 'USE'
  if (c.reexport > 0) return 'REEXPORT-ONLY'
  if (c.testUse > 0) return 'TEST-ONLY'
  if (c.typeUse > 0) return 'TYPE-ONLY'
  return 'NONE'
}

/* ─────────────────────────── 判据自检（尸体样本） ─────────────────────────── */

function selfTest() {
  const base = 'mod'
  const cases = [
    ['单行值导入', "import { a, b } from './mod.js'", 'USE'],
    ['多行值导入（缺陷①尸体样本）', "import {\n  a,\n  b,\n} from './mod.js'", 'USE'],
    ['多行 + 中间夹注释', "import {\n  // 说明\n  a,\n} from '../src/mod.js'", 'USE'],
    ['再导出', "export { a } from './mod.js'", 'REEXPORT'],
    ['类型导入', "import type { T } from './mod.js'", 'TYPE'],
    ['类型再导出', "export type { T } from './mod.js'", 'TYPE'],
    ['无关模块（须判否）', "import { z } from './other.js'", 'NONE'],
    ['前缀相同但不同名（须判否）', "import { z } from './mod-extra.js'", 'NONE'],
    ['相邻 import 不得串线（缺陷④尸体样本）', "import { a } from './other.js'\nimport type { T } from './mod.js'", 'TYPE'],
    ['相邻 import 反向（值导入在后）', "import { a } from './other.js'\nimport { b } from './mod.js'", 'USE'],
    ['三段相邻（只认自己那段）', "import type { A } from './a.js'\nimport { b } from './mod.js'\nimport { c } from './c.js'", 'USE'],
  ]
  let bad = 0
  for (const [name, text, want] of cases) {
    const got = refKindOf(text, base)
    const ok = got === want
    if (!ok) bad += 1
    console.log((ok ? '  PASS  ' : '  FAIL  ') + name + '  期望=' + want + ' 实得=' + got)
  }

  // 入口解析（缺陷③）的尸体样本：约定名兜底 + package.json 指认 + 不指认的不得混入
  const files = ['index.ts', 'other.ts', 'gate.ts']
  const entryCases = [
    ['约定名 index.ts（无 package.json）', entryNamesOf(null, files).has('index.ts'), true],
    ['package.json main 指认', entryNamesOf({ main: 'lib/other.js' }, files).has('other.ts'), true],
    ['main 指向 src 外（不混入）', entryNamesOf({ main: 'lib/index.js' }, files).size, 1],
  ]
  for (const [name, got, want] of entryCases) {
    const ok = got === want
    if (!ok) bad += 1
    console.log((ok ? '  PASS  ' : '  FAIL  ') + name + '  期望=' + String(want) + ' 实得=' + String(got))
  }

  // 档位判定的尸体样本（缺陷⑤：优先级错会让「仅再导出」整档消失）
  const gradeCases = [
    ['入口优先于一切', gradeOf(true, { use: 1, reexport: 1, testUse: 1, typeUse: 1 }), 'ENTRY'],
    ['生产值导入优先于其它', gradeOf(false, { use: 1, reexport: 1, testUse: 1, typeUse: 1 }), 'USE'],
    ['再导出优先于仅测试引用（缺陷⑤尸体样本）', gradeOf(false, { use: 0, reexport: 1, testUse: 1, typeUse: 0 }), 'REEXPORT-ONLY'],
    ['仅测试引用', gradeOf(false, { use: 0, reexport: 0, testUse: 2, typeUse: 0 }), 'TEST-ONLY'],
    ['仅类型引用', gradeOf(false, { use: 0, reexport: 0, testUse: 0, typeUse: 1 }), 'TYPE-ONLY'],
    ['零引用', gradeOf(false, { use: 0, reexport: 0, testUse: 0, typeUse: 0 }), 'NONE'],
  ]
  for (const [name, got, want] of gradeCases) {
    const ok = got === want
    if (!ok) bad += 1
    console.log((ok ? '  PASS  ' : '  FAIL  ') + name + '  期望=' + want + ' 实得=' + got)
  }

  const total = cases.length + entryCases.length + gradeCases.length
  console.log('')
  console.log(bad === 0
    ? '[selftest] ' + String(total) + '/' + String(total) + ' 全过 —— 判据在语句形态与入口解析上有区分力'
    : '[selftest] ' + String(bad) + '/' + String(total) + ' 失败 —— 判据不可用于裁决')
  return bad === 0 ? 0 : 3
}

if (has('--selftest')) process.exit(selfTest())

/* ─────────────────────────── 主流程 ─────────────────────────── */

if (!fs.existsSync(SRC)) {
  console.error('[scan-dead-modules] 找不到 src/：' + SRC)
  process.exit(2)
}

/** 递归收集 .ts / .mjs / .js（跳过 node_modules / lib / dist / 隐藏目录） */
function collect(dir, out = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (e.name === 'node_modules' || e.name === 'lib' || e.name === 'dist' || e.name.startsWith('.')) continue
    const p = path.join(dir, e.name)
    if (e.isDirectory()) collect(p, out)
    else if (/\.(ts|mjs|js)$/.test(e.name)) out.push(p)
  }
  return out
}

const srcFiles = fs
  .readdirSync(SRC, { withFileTypes: true })
  .filter((e) => e.isFile() && e.name.endsWith('.ts'))
  .map((e) => e.name)

let pkg = null
try {
  pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'))
} catch {
  /* 读不到 package.json：入口退回约定名 index.ts（不静默当「无入口」） */
}
const entryNames = entryNamesOf(pkg, srcFiles)

const SCAN_DIRS = [SRC, path.join(ROOT, 'tests')].filter((d) => fs.existsSync(d))
const allFiles = SCAN_DIRS.flatMap((d) => collect(d))

// 预读所有文件内容（一次性，避免 O(n²) IO）
const contents = new Map()
for (const f of allFiles) {
  try {
    contents.set(f, fs.readFileSync(f, 'utf8'))
  } catch {
    /* 读不了就跳过，不静默当空 */
  }
}

const SRC_PREFIX = path.resolve(SRC) + path.sep

/**
 * 收集某模块的引用者，**按 src / tests 分档**。
 *
 * 分档理由：本判据问的是「**生产**零调用者」——`src` 内的值导入才算生产者；
 * `tests` 的引用单独成档，因为它表达的是「测试在测这个模块」，与「模块被生产使用」是两件事。
 * 2026-10-06 实测：混为一谈会让「测试在测死代码」这一症状**看不见**。
 */
function refsOf(modName) {
  const base = modName.replace(/\.ts$/, '')
  const self = path.join(SRC, modName)
  const use = []
  const testUse = []
  const reexport = []
  const typeUse = []
  for (const [f, text] of contents) {
    if (f === self) continue // 自己不算调用者
    const rel = path.relative(ROOT, f).replace(/\\/g, '/')
    const isTest = !path.resolve(f).startsWith(SRC_PREFIX)
    const kind = refKindOf(text, base)
    if (kind === 'USE') (isTest ? testUse : use).push(rel)
    else if (kind === 'REEXPORT') reexport.push(rel)
    else if (kind === 'TYPE') typeUse.push(rel)
  }
  return { use, testUse, reexport, typeUse }
}

const rows = srcFiles.map((m) => {
  const r = refsOf(m)
  const isEntry = entryNames.has(m)
  const kind = gradeOf(isEntry, {
    use: r.use.length,
    reexport: r.reexport.length,
    testUse: r.testUse.length,
    typeUse: r.typeUse.length,
  })
  return { module: m, kind, entry: isEntry, ...r }
})

// 生产零调用者 = 仅测试引用 + 任何地方都无引用（两档都「死」，但症状不同，分开报）
const testOnly = rows.filter((r) => r.kind === 'TEST-ONLY')
const none = rows.filter((r) => r.kind === 'NONE')
const dead = [...testOnly, ...none]
const reexportOnly = rows.filter((r) => r.kind === 'REEXPORT-ONLY')
const typeOnly = rows.filter((r) => r.kind === 'TYPE-ONLY')

console.log('# 生产零调用者扫描 · ' + path.basename(ROOT))
console.log('# 扫描 ' + String(srcFiles.length) + ' 个 src/*.ts · 引用面 ' + String(allFiles.length) + ' 个文件')
console.log('# 入口（豁免）：' + [...entryNames].join(', '))
console.log('')

console.log('## 死代码 · 仅测试引用（生产零调用，其测试在测死代码）')
if (!testOnly.length) console.log('  （无）')
for (const r of testOnly) console.log('  ✗ ' + r.module + '  ← 仅 ' + r.testUse.join(', '))

console.log('')
console.log('## 死代码 · 零引用（任何地方都没有）')
if (!none.length) console.log('  （无）')
for (const r of none) console.log('  ✗ ' + r.module)

console.log('')
console.log('## 仅被再导出（模块会被加载，但符号或无人调用 —— 判死需看语义）')
if (!reexportOnly.length) console.log('  （无）')
for (const r of reexportOnly) console.log('  ⇢ ' + r.module + '  ← ' + r.reexport.join(', '))

console.log('')
console.log('## 仅类型引用（删模块需同步改引用方；不构成生产调用）')
if (!typeOnly.length) console.log('  （无）')
for (const r of typeOnly) console.log('  ◐ ' + r.module + '  ← ' + r.typeUse.join(', '))

console.log('')
console.log('## 入口（由宿主加载，不经 src 内部 import —— 不参与判定）')
for (const r of rows.filter((x) => x.kind === 'ENTRY')) console.log('  ⊙ ' + r.module)

console.log('')
console.log('## 有生产调用者（健康）')
for (const r of rows.filter((x) => x.kind === 'USE')) {
  console.log('  ✓ ' + r.module + '  ← ' + r.use.join(', ') + (r.testUse.length ? '  [测试亦引用]' : ''))
}

if (JSON_OUT) {
  fs.writeFileSync(JSON_OUT, JSON.stringify({ root: ROOT, scanned: srcFiles.length, entries: [...entryNames], rows }, null, 2), 'utf8')
  console.log('\n# JSON 已写: ' + JSON_OUT)
}

process.exit(dead.length ? 1 : 0)
