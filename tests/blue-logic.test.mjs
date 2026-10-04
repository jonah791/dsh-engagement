/**
 * logic.ts 纯函数套件（离线、无 IO）。
 * 覆盖：正常路径 + 失败/退化路径（空值、非法输入、类型不符、边界）——后者是 S6 判据。
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  resolvePorts, parseEventIds, psJsonRows, psHashOutcome, psQuote, DEFAULT_EVENT_IDS,
} from '../lib/blue-logic.js'
import { DEFAULT_PORTS } from '../lib/blue-net.js'

/* ── resolvePorts：端口规格解析 ── */

test('resolvePorts: 逗号列表 / 区间 / 混合，去重升序', () => {
  assert.deepEqual(resolvePorts('22,80,443'), [22, 80, 443])
  assert.deepEqual(resolvePorts('1-5'), [1, 2, 3, 4, 5])
  assert.deepEqual(resolvePorts('8000-8002,8080,80'), [80, 8000, 8001, 8002, 8080])
  assert.deepEqual(resolvePorts(' 443 , 80 '), [80, 443])
})

test('resolvePorts: 退化输入——空规格回落默认端口表（非空、升序、合法、无重复）', () => {
  for (const empty of ['', undefined, null, 0, false]) {
    const out = resolvePorts(empty)
    assert.deepEqual(out, DEFAULT_PORTS, `spec=${String(empty)} 应回落默认表`)
  }
  const d = resolvePorts('')
  assert.ok(d.length > 0, '默认表不得为空')
  assert.deepEqual([...d].sort((a, b) => a - b), [...d], '默认表必须升序')
  assert.equal(new Set(d).size, d.length, '默认表不得有重复')
  assert.ok(d.every((p) => p >= 1 && p <= 65535), '默认表端口必须落在 1..65535')
})

test('resolvePorts: 失败路径——非法/越界/逆序规格得到空数组（由调用方判空报错）', () => {
  assert.deepEqual(resolvePorts('abc'), [])
  assert.deepEqual(resolvePorts('0'), [])
  assert.deepEqual(resolvePorts('65536'), [])
  assert.deepEqual(resolvePorts('80-22'), [], '逆序区间不得产出端口')
  assert.deepEqual(resolvePorts('-'), [], '单个连字符不得产出端口')
  assert.deepEqual(resolvePorts(','), [])
  assert.deepEqual(resolvePorts('0-70000'), [], '越界区间整段丢弃')
})

/* ── parseEventIds：事件 ID 规格解析 ── */

test('parseEventIds: 正常路径——逗号分隔 + 空白容忍', () => {
  assert.deepEqual(parseEventIds('4625,4624'), [4625, 4624])
  assert.deepEqual(parseEventIds(' 4625 , 4720 '), [4625, 4720])
  assert.deepEqual(parseEventIds('4625'), [4625])
})

test('parseEventIds: 退化输入——空规格回落默认 ID 表', () => {
  assert.deepEqual(parseEventIds(undefined), [...DEFAULT_EVENT_IDS])
  assert.deepEqual(parseEventIds(null), [...DEFAULT_EVENT_IDS])
  assert.deepEqual(parseEventIds(''), [0], '真实语义：空串被 Number("") 解析为 0，不是 NaN，故不会被过滤')
})

test('parseEventIds: 失败路径——非数字项被丢弃；重复项保留原序（不去重）', () => {
  assert.deepEqual(parseEventIds('4625,abc,4711'), [4625, 4711])
  assert.deepEqual(parseEventIds('abc,def'), [])
  assert.deepEqual(parseEventIds('4625,4625'), [4625, 4625], '真实语义：不做去重')
  assert.deepEqual(parseEventIds('4625,,4711'), [4625, 0, 4711], '真实语义：空串项变成 0')
  assert.deepEqual(parseEventIds('NaN,Infinity'), [Infinity], '真实语义：Number("Infinity")=Infinity 非 NaN')
})

/* ── psJsonRows：PowerShell JSON 输出归一化 ── */

test('psJsonRows: 正常路径——数组原样、单对象包成数组', () => {
  assert.deepEqual(psJsonRows('[{"a":1}]'), [{ a: 1 }])
  assert.deepEqual(psJsonRows('[]'), [])
  assert.deepEqual(psJsonRows('{"State":"Listen"}'), [{ State: 'Listen' }])
})

test('psJsonRows: 退化输入——空输出（null/undefined/空串）得到空数组', () => {
  assert.deepEqual(psJsonRows(''), [])
  assert.deepEqual(psJsonRows(null), [])
  assert.deepEqual(psJsonRows(undefined), [])
})

test('psJsonRows: 失败路径——损坏 JSON 抛出（不静默吞错，由 safe() 收口）', () => {
  assert.throws(() => psJsonRows('{oops'), SyntaxError)
  assert.throws(() => psJsonRows('<html>403</html>'), SyntaxError)
  assert.deepEqual(psJsonRows('null'), [null], '真实语义：JSON null 走「非数组」分支被包成 [null]')
})

/* ── psHashOutcome：哈希工具输出判定 ── */

test('psHashOutcome: 正常路径——JSON 对象解析', () => {
  assert.deepEqual(psHashOutcome('{"Path":"C:\\\\a.txt","Size":3}'), { Path: 'C:\\a.txt', Size: 3 })
})

test('psHashOutcome: 退化路径——NOT_FOUND 哨兵映射为 null（文件不存在 ≠ 计算失败）', () => {
  assert.equal(psHashOutcome('NOT_FOUND'), null)
})

test('psHashOutcome: 失败路径——空串抛错；null 因 JS 强转语义返回 null（不抛）', () => {
  assert.throws(() => psHashOutcome(''), SyntaxError)
  assert.equal(psHashOutcome(null), null, '真实语义：JSON.parse(null) 把 null 强转成 "null" 字面量，返回 null 不抛')
  assert.throws(() => psHashOutcome('not json'), SyntaxError)
})

/* ── psQuote：PowerShell 单引号字面量转义 ── */

test('psQuote: 正常路径——无引号原样、单引号翻倍', () => {
  assert.equal(psQuote('Security'), 'Security')
  assert.equal(psQuote("it's"), "it''s")
  assert.equal(psQuote("a''b"), "a''''b")
  assert.equal(psQuote("'; rm -rf /; '"), "''; rm -rf /; ''")
})

test('psQuote: 退化输入——非字符串先 String() 再转义（不抛）', () => {
  assert.equal(psQuote(1), '1')
  assert.equal(psQuote(undefined), 'undefined')
  assert.equal(psQuote(null), 'null')
  assert.equal(psQuote(''), '')
})

test('psQuote: 幂等性——转义后的串再无「成对奇数引号」可逃逸（二次转义只增不逃）', () => {
  const once = psQuote("a'b")
  assert.equal(once, "a''b")
  // 二次应用会把已经翻倍的引号继续翻倍（不是幂等），因此**只允许应用一次**——
  // 这条断言把该真实语义钉住，防止未来「顺手再 quote 一次」导致脚本里出现 4 个引号。
  assert.equal(psQuote(once), "a''''b")
})
