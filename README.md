# dsh-engagement — 安全交战闭环

一次交战（engagement）的完整闭环：**定范围与授权 → 侦察 → 发现 → 验证/利用 → 检测侧校验 → 证据与报告**。

替换 `dsh-red-team` + `dsh-blue-team` + `dsh-exploit-kit` + `dsh-cyber-range` + `dsh-sec-tools`（**36 工具 → 12**）。设计依据：`docs/plans/插件融合设计_安全交战_2026-09-23.md`；权威契约见 [docs/semantic.md](docs/semantic.md)。

## 为什么需要新件

旧五件各带一份散文式免责声明（「仅限授权测试」），合计 **36 个工具**、**零份范围判定代码**、五份互不相干的侧车轨迹——**没有任何一处知道「这次交战的目标是谁、授权来自哪」**。五份声明不等于一道闸门；合并只会把差异原样塞进新壳，**替换**才能立起唯一状态持有者。

## 唯一真正新增的机制：可判定授权闸门

`src/gate.ts` 的 `decideGate` 是**纯函数**：输入结构化四元组 `(engagement, actionClass, target, nowMs)`，输出 `allow` 或 `deny` + **闭集 reason**：

| 输入状态 | reason |
|---|---|
| 无交战 / 读不到 / 形状不符 | `gate/no-engagement` |
| 状态非 active | `gate/closed` |
| 授权 source 缺失或 ref 为空 | `gate/no-authorization` |
| active 且目标不在 targets | `gate/out-of-scope` |
| active 且命中 exclude | `gate/excluded` |
| 时间窗之外（含 intel） | `gate/out-of-window` |
| `active-auth` 且未开 `allowActiveAuth` | `gate/auth-not-enabled` |

它比五份声明强在四条**逐条可验**：有对象（结构化输入）· 可喂坏样本（五类样本各有断言）· 拒绝落盘（`timeline.jsonl` 的 `gate/denied` 是一手证据）· 一份范围（分裂在结构上不可能）。

**诚实边界**：闸门防的是「误伤未授权目标」与「状态分裂」，**不防**伪造一份假授权——`authorization.ref` 是**声明**，不是密码学证明。越界需要一次**可审计的伪造**，而不是一次疏忽。

## 工具面（12，按交战阶段）

| # | 工具 | 阶段 | actionClass |
|---|---|---|---|
| 1 | `eng_open` | 定范围与授权 | passive |
| 2 | `eng_status` | 全局（读） | passive |
| 3 | `eng_close` | 结案 | passive |
| 4 | `eng_recon_dns` | 侦察 · 域层 | active |
| 5 | `eng_recon_host` | 侦察 · 主机层 | active |
| 6 | `eng_recon_web` | 侦察 · Web 层 | active |
| 7 | `eng_intel` | 外部情报核对 | intel |
| 8 | `eng_finding` | 发现台账 | passive |
| 9 | `eng_payload` | 验证/利用 · 构造 | passive |
| 10 | `eng_verify` | 验证/利用 · 执行 | active |
| 11 | `eng_detect` | 检测侧校验 | active |
| 12 | `eng_report` | 证据与报告 | passive |

**闸门与证据只在一个地方发生**：所有工具经单一 `reg()` 切面注册，deny 时在触碰任何通道**之前**返回（I3），deny 落 `gate/denied`（I4），证据由切面统一写（不逐工具写）。

## 配置

| 字段 | 缺省 | 含义 |
|---|---|---|
| `root` | 空 ⇒ `<DSH_HOME>/engagement` | 交战国度根目录 |
| `timeoutMs` | 120000 | 单次子进程默认超时 |
| `limit` | 50 | 侦察默认条数上限 |
| `reportDir` | 空 ⇒ 交战国度内 | 报告落点 |

## 交战国度

```
<root>/<engagementId>/
  engagement.json   # 单文件，原子写（tmp + rename）
  findings.jsonl    # 发现（I5：必须挂 ≥1 证据）
  evidence.jsonl    # 证据指纹（sha256 + 字节数 + 摘要；**不存正文、凭据不落盘**）
  timeline.jsonl    # 时间线（含 gate/denied 与 tool/end）
```

## 生效判据

1. **构建-进程先后**：`lib/index.js` 的 mtime 晚于 web 进程启动时间。
2. **工具可答**：`eng_status` 返回交战清单或全貌。
3. **闸门真在拦**：喂一个越界目标 ⇒ 返回拒绝文案且 `timeline.jsonl` 出现 `gate/denied`。
4. **单一 owner 取证**：`grep -rn 'engagement' self-plugins/*/src/*.ts` 只有本件写交战国度。

## 回退

`plugin_mount` 五件旧件（源码与依赖均未删除）；交战国度目录保留 ⇒ 回退无需重建。
