/**
 * 接线级契约守卫（2026-10-05 重写 · 任务 t-4d733b3c）。
 *
 * 来源：融合 5 个安全线插件（xp / red / blue / range / sec）→ `dsh-engagement` 后，`apply` 的注册
 * 契约变了（工具数 8 → **12**、副作用统一走 `reg()` 单一切面），旧的三条接线测试因此在移植时 skip。
 * 本文件按**新契约**重写它们的**判据意图**（不照搬旧文件名/工具名——`red_crawl_links` 等旧名只存在于归档侧）：
 *   ① 接线留痕：apply 注册全部工具，且一次工具调用落 timeline 的 `tool/end`
 *   ② 失败留痕：闸门拒绝落 `gate/denied`（可 grep、可计数——「防线真在拦」的一手证据）
 *   ③ 尸体样本（观测不反噬）：国度落点不可写时工具**照常返回**而不抛
 * 外加两条不相干的结构不变量（I2 单一切面、I5 工具数指纹）。
 *
 * ⚠ 与旧版的关键差异（**新契约的事实，不是取舍**）：旧 red 线的 `redTrace` 通道
 *   （`boot` / `scan/start` / `scan/end` / `scan/error`）在现役接线层**已无调用者**——
 *   全库核实：`redTrace`/`redTraceBoot`/`redTracePath` 仅被 `tests/red-trace.test.mjs` 引用，
 *   `src/` 接线层零调用（`red-pure.ts` / `red-enum.ts` 只 `import type`）。
 *   轨迹已统一到交战国度的 `timeline.jsonl`（`reg` 注释：I3「没有别的路径能触发副作用」）。
 *   故本文件断言 timeline，**不复活旧通道**。
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { apply } from '../lib/index.js'
import { pathsOf, readTimeline } from '../lib/store.js'

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..')
const tmp = mkdtempSync(join(tmpdir(), 'eng-wire-test-'))

function makeCtx() {
  const registered = []
  const ctx = {
    logger: () => ({ info: () => {}, warn: () => {}, error: () => {} }),
    tools: { register: (t) => { registered.push(t); return () => {} } },
  }
  return { ctx, registered }
}

const cfg = (root) => ({ enabled: true, root, timeoutMs: 5_000, limit: 10, reportDir: '' })

const ENG_TOOLS = [
  'eng_close', 'eng_detect', 'eng_finding', 'eng_intel', 'eng_open', 'eng_payload',
  'eng_recon_dns', 'eng_recon_host', 'eng_recon_web', 'eng_report', 'eng_status', 'eng_verify',
]

test('接线①：apply 注册 12 个 eng_* 工具；开交战后一次调用落 timeline 的 tool/end', async () => {
  const root = join(tmp, 'wired')
  const { ctx, registered } = makeCtx()
  apply(ctx, cfg(root))

  assert.equal(registered.length, 12, '新契约：工具面恰 12')
  assert.deepEqual(registered.map((t) => t.name).sort(), ENG_TOOLS)

  const open = registered.find((t) => t.name === 'eng_open')
  const o = await open.execute({
    title: '接线验收', authorizationSource: 'lab-charter',
    authorizationRef: 'tests/wire-contract.test.mjs', targets: ['127.0.0.1'],
    notAfter: '2030-01-01T00:00:00Z',
  })
  const id = /交战已开启：(\S+)/.exec(o.text)?.[1]
  assert.ok(id, 'eng_open 必须回报可复制的交战 id')

  const st = registered.find((t) => t.name === 'eng_status')
  const s = await st.execute({ engagementId: id })
  assert.match(s.text, /计数：发现 \d+ · 证据 \d+ · 时间线 \d+ · 闸门拒绝 \d+/)

  // eng_open 的 promote 发生在交战存在之前 ⇒ 其轨迹落**根目录** timeline（新契约的一个真实语义）
  const rootLines = readTimeline(pathsOf(root, ''))
  assert.equal(rootLines.filter((l) => l.tool === 'eng_open').length, 1, 'eng_open 落根 timeline')

  // 交战已存在后的调用 ⇒ 落**交战目录** timeline
  const engLines = readTimeline(pathsOf(root, id))
  const ends = engLines.filter((l) => l.phase === 'tool/end')
  assert.equal(ends.length, 1, `交战 timeline 应恰 1 行 tool/end，实为 ${engLines.length} 行`)
  assert.equal(ends[0].tool, 'eng_status')
  assert.equal(ends[0].outcome, 'ok')
  assert.equal(ends[0].engagementId, id)
  assert.equal(typeof ends[0].atMs, 'number')
  assert.equal(typeof ends[0].iso, 'string')
})

test('接线②：闸门拒绝落 gate/denied（可 grep、可计数），工具返回拒绝文本', async () => {
  const root = join(tmp, 'wired-deny')
  const { ctx, registered } = makeCtx()
  apply(ctx, cfg(root))

  const web = registered.find((t) => t.name === 'eng_recon_web')
  const out = await web.execute({ engagementId: 'nosuch', url: 'http://127.0.0.1/' })
  assert.match(out.text, /闸门拒绝/, '拒绝必须响亮（不是静默跳过）')
  assert.match(out.text, /gate\/denied/, '必须告知拒绝已留痕')

  const lines = readTimeline(pathsOf(root, 'nosuch'))
  const denied = lines.filter((l) => l.phase === 'gate/denied')
  assert.equal(denied.length, 1, '拒绝恰一行（I4：拒绝留痕，不是日志噪音）')
  assert.equal(denied[0].tool, 'eng_recon_web')
  assert.equal(denied[0].actionClass, 'active')
  assert.equal(denied[0].target, 'http://127.0.0.1/')
  assert.ok(typeof denied[0].reason === 'string' && denied[0].reason.length > 0, '拒绝必须带可读原因')
})

test('尸体测试（接线级）：国度落点不可写时工具照常返回（观测不反噬 · §5.22-3）', async () => {
  // 父路径是普通文件 ⇒ 其下任何 mkdir/write 都失败
  const blocker = join(tmp, 'blocker-wire')
  writeFileSync(blocker, 'not a dir', 'utf8')
  const badRoot = join(blocker, 'nope')

  const { ctx, registered } = makeCtx()
  apply(ctx, cfg(badRoot)) // ① apply 本身不得抛

  const st = registered.find((t) => t.name === 'eng_status')
  const out = await st.execute({}) // ② 调用不得抛，且要有可读回报
  assert.match(out.text, /暂无交战|交战清单/)
})

test('不变量 I2：副作用与留痕只在**单一注册切面**发生（接线层不得出现第二处 register）', () => {
  const src = readFileSync(join(repoRoot, 'src', 'index.ts'), 'utf8')
  const calls = [...src.matchAll(/ctx\.tools\.register\(/g)]
  assert.equal(calls.length, 1, '必须恰一处 register（reg 内部）——多一处即闸门可被绕过')
})

test('不变量 I5：工具数指纹（apply 的输出 schema 与注册数一致）', async () => {
  const root = join(tmp, 'wired-count')
  const { ctx, registered } = makeCtx()
  apply(ctx, cfg(root))
  for (const t of registered) {
    assert.equal(typeof t.name, 'string')
    assert.ok(t.output?.schema !== undefined, `${t.name} 缺 output.schema`)
  }
})

test('接线③：落盘 target 保真 —— 保留协议/端口/非凭据 query，且凭据仍打码（防修过头）', async () => {
  const root = join(tmp, 'wired-fidelity')
  const { ctx, registered } = makeCtx()
  apply(ctx, cfg(root))

  const web = registered.find((t) => t.name === 'eng_recon_web')
  const url = 'http://admin:hunter2@127.0.0.1:8080/x?id=7&token=abc'
  await web.execute({ engagementId: 'nosuch', url }) // deny ⇒ 仍留痕（拒绝也要可取证）

  const lines = readTimeline(pathsOf(root, 'nosuch'))
  const d = lines.find((l) => l.phase === 'gate/denied')
  assert.ok(d, '拒绝必须留痕')

  // 保真面：协议 / 端口 / 非凭据 query 是取证信息，不得被脱敏顺手抹掉
  assert.match(d.target, /^http:\/\//, '协议必须保留（http 与 https 是安全评级的实质区别）')
  assert.match(d.target, /:8080/, '端口必须保留（非标准端口是攻击面识别信息）')
  assert.match(d.target, /id=7/, '非凭据 query 必须保留')
  // 防修过头：脱敏的本职不能丢
  assert.doesNotMatch(d.target, /hunter2/, '密码不得落盘')
  assert.doesNotMatch(d.target, /token=abc/, '凭据型 query 必须打码')
  assert.match(d.target, /<redacted>/, '脱敏标记应在场（证明真的过了一遍）')
})

test('不变量 I1：交战数据的 fs 出口唯一 —— 接线层不得直接 import node:fs', () => {
  const src = readFileSync(join(repoRoot, 'src', 'index.ts'), 'utf8')
  assert.doesNotMatch(src, /from 'node:(fs|child_process|net)'/, '接线层不得直接碰 fs/进程/网络——一律经 store / 专用模块')
  // 交战国度的 owner 必须自述（store.ts 首行注释声明它自己是唯一 owner）
  const store = readFileSync(join(repoRoot, 'src', 'store.ts'), 'utf8')
  assert.match(store, /唯一 owner/, 'store.ts 必须自述 owner 身份（可审计的单一出口）')
})

test('不变量 I5b：每个工具的模型可见面完整（description / parameters / output.render）', async () => {
  const root = join(tmp, 'wired-face')
  const { ctx, registered } = makeCtx()
  apply(ctx, cfg(root))
  for (const t of registered) {
    assert.ok(typeof t.description === 'string' && t.description.length > 10, `${t.name} 描述过短`)
    assert.ok(t.parameters !== undefined, `${t.name} 缺 parameters`)
    assert.equal(typeof t.output?.render, 'function', `${t.name} 缺 output.render（模型看不到结果）`)
  }
})

test('契约：config.enabled=false ⇒ 零注册且不抛（开关只影响注册，不影响进程）', () => {
  const { ctx, registered } = makeCtx()
  apply(ctx, { ...cfg(join(tmp, 'wired-off')), enabled: false })
  assert.equal(registered.length, 0)
})

test('幂等：多次挂载互不串味（每次 apply 各自独立注册一套）', () => {
  const a = makeCtx()
  const b = makeCtx()
  apply(a.ctx, cfg(join(tmp, 'wired-m1')))
  apply(b.ctx, cfg(join(tmp, 'wired-m2')))
  assert.equal(a.registered.length, 12)
  assert.equal(b.registered.length, 12)
  assert.notEqual(a.registered[0], b.registered[0], '两次挂载必须是不同对象（无共享可变状态）')
})

test('cleanup', () => {
  rmSync(tmp, { recursive: true, force: true })
})
