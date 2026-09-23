# dsh-engagement — 安全交战闭环（语义文档）

## 1 · 元信息

| 项 | 值 |
|---|---|
| 能力名 | 安全交战闭环（一次交战的唯一状态持有者与唯一执行入口） |
| 插件 | `self-plugins/dsh-engagement` |
| 状态 | implemented（12 工具 + 闸门 + 国度已落地并离线验收；组合切换与线上取证待做） |
| 替换 | `dsh-red-team`(8) + `dsh-blue-team`(8) + `dsh-exploit-kit`(6) + `dsh-cyber-range`(3) + `dsh-sec-tools`(11) = 36 → **12** |
| 设计依据 | `docs/plans/插件融合设计_安全交战_2026-09-23.md` |
| 语义注册 id | `security-engagement` |
| 最近复核 | 2026-09-23 |

## 2 · 定位与反定位

**定位**：把「定范围 → 侦察 → 发现 → 验证 → 检测侧校验 → 出报告」收成一条闭环，并让每一步读写**同一份交战上下文**。工具面按**交战阶段**重组，不按旧插件分组，也不做并集。

**反定位（不做）**：不扫描未授权目标（未声明 = 拒绝，不是警告）· 不做持续驻留（无 C2 / 无定时回连 / 无横向移动自动化 / 不写目标机持久化）· 不代为攻击真实第三方（授权只认三类闭集来源）· 不是红蓝工具袋的并集 · 不管本机加固基线（属另一个顶层目的，见 §10）· 不做离线哈希破解工作台（对象是离线工件，不参与 scope 判定）· 不暴露通用 HTTP/SSH 客户端（通道下沉为内部实现）· 不提供出口选择参数。

## 3 · 术语

| 术语 | 含义 |
|---|---|
| 交战（engagement） | 一次有起点、有范围、有授权来源、有终点的安全作业——本件的**计量单位** |
| 交战上下文 | 持久化记录（授权/范围/窗口/发现/证据/时间线）；**唯一 owner 是本件** |
| 授权来源 | 三类闭集：`owner-directive` / `lab-charter` / `written-scope` + 可核对的 `ref` |
| 主动动作（active） | 会触达 scope 内目标或在本机产生可观测副作用的动作，**必须过闸门** |
| 被动动作（passive） | 纯本地计算（载荷构造/序列化/报告渲染），零网络零子进程；不过 scope 判定，**仍受窗口约束** |
| 情报动作（intel） | 触达**公共情报源**的动作；需要交战存在，但**不要求 scope 命中**，仍受窗口约束 |
| 发现（finding） | 一条观察；**必须挂 ≥1 个证据**才准登记（I5） |
| 证据（evidence） | 动作产物的指纹：`sha256` + 字节数 + 来源工具调用 + 目标 + 类型；**存指纹与摘要，不存正文，凭据一律不落** |
| 闸门拒绝（gate/denied） | `decideGate` 判 deny 时落 `timeline.jsonl` 的一行——「防线真在拦」的**一手证据** |
| 通道（channel） | 触达目标的执行路径（WSL curl / WSL ssh / Node http）。**不是工具**，是内部后端 |

## 4 · 概念模型与不变量

```
eng_open（目标 + 授权来源 + 范围 + 时间窗）
        │
        ▼   交战国度（唯一 owner）<root>/<engagementId>/
        │   engagement.json · findings.jsonl · evidence.jsonl · timeline.jsonl
        │
  eng_recon_* / eng_intel / eng_finding / eng_verify / eng_detect
        │
        ▼   decideGate（active / intel 动作之前，同步判定 + 落盘）
        ▼   evidence.jsonl（经单一 reg() 切面自动写） ──► eng_report
```

不变量：**I1 单一 owner**（交战国度只由本件写）· **I2 显式携带**（需要交战的工具必须显式传 `engagementId`，**不存在**「最近一次交战」这类隐式状态）· **I3 闸门先于副作用**（deny 时零网络零子进程）· **I4 拒绝留痕** · **I5 发现必挂证据** · **I6 范围判定带 `.` 边界**（`evil-example.com` 不匹配 `example.com`）· **I7 凭据不落盘**（evidence/timeline 写入前过 `scrub`）· **I8 一次交战一个窗口** · **I9 检测侧同受闸门**（本机端点也要先在 scope 声明）。

## 5 · 契约

### 5.1 授权闸门（纯函数）

```ts
decideGate({ engagement, actionClass, target?, nowMs }): { verdict: 'allow' } | { verdict: 'deny'; reason: GateReason }
```

裁决表见 README 与 `src/gate.ts` 的 JSDoc（**逐条可穷举喂样本**）。`actionClass` 是每个工具**注册时的常量声明**，不在运行时猜。归一化（`normalizeTarget`）先做：小写 / 去尾点 / 去端口 / 去 userinfo / 去 scheme 与路径——不归一化就做后缀匹配，`EXAMPLE.com.:443` 会绕过。

### 5.2 交战国度

| 文件 | 一行形状 |
|---|---|
| `engagement.json` | `{id, title, purpose, authorization{source,ref}, scope{targets,exclude,ports,protocols,allowActiveAuth}, window{notBefore,notAfter}, status}`（原子写） |
| `findings.jsonl` | `{id, atMs, target, phase, kind, severity, status, evidenceIds[], note}` |
| `evidence.jsonl` | `{id, atMs, sourceToolCall, kind, target, sha256, bytes, summary}` |
| `timeline.jsonl` | `{atMs, phase, tool, engagementId, target?, outcome, reason?}`（`phase` 含 `gate/denied`、`tool/end`、`engagement/closed`） |

### 5.3 调用点清单

| 调用方 | 调用点（文件:符号） | 时机 |
|---|---|---|
| cordis 宿主 | `src/index.ts:name / inject / Config / apply` | 插件激活 |
| 宿主 agent | 12 处经**单一 `reg()` 切面**注册 | 工具调用 |
| 闸门 | `reg()` 内 `decideGate(...)`，**在 `spec.run` 之前** | 每次工具调用 |
| 证据写入 | `reg()` 的 `recordEvidence`（**单一切面**，不逐工具写） | run 成功后 |
| 拒绝留痕 | `reg()` 的 deny 分支 → `appendTimeline(gate/denied)` | deny 时 |
| 通道 | `src/channels.ts`（WSL curl/ssh、Node http）；参数一律过 `shellQuote` + 元字符闸门 | 各 run 体内 |
| **禁止** | 任何其他插件写交战国度 | 由 I1 约束 |

### 5.4 类型可见性

`ctx.tools` 的声明合并在 `@deepseek-ai/dsh-tools` 内，该包必须进编译单元 ⇒ 本件显式 import 它（`defineTool`）✓。

## 6 · 边界与信任

- **能力 ≠ 沙箱**：闸门防「误伤未授权目标」与「状态分裂」，**不防**伪造假授权——正确表述是「越界需要一次**可审计的伪造**，而不是一次疏忽」。
- **闸门不是命令注入防线**：`sec-commands` 的 `unsafeArg()` / `hasShellMeta()` 挡的是「shell 元字符进我自己拼的命令」，对象是**我的注入面**；授权闸门挡的是「这个目标是否被授权」，对象是**对方的边界**。两道闸正交，**两道都要有**。
- **不给自由命令面**：不暴露 `shell`、不暴露任意 URL/路径参数、不暴露原始凭据参数。旧 `cyber-range` 出过一次「半吊子防线」事故（`user`/`pass`/`cookie`/`host`/`path` 曾未经转义直接内插，闭合用户名即可执行任意命令）⇒ 本件通道层一律经单一 `shellQuote` 出口。
- **凭据只以引用形式进入**：口令/token/私钥不进工具参数、不进交战国度、不进轨迹。**因此 `eng_verify` 的 `remote-exec` 与 `blind-extract` 目前显式未接线**（见 §10）——不假装能跑，也不用 `sshpass -p '<明文>'` 那条旧路径。
- **不越界清单**：不装持久化 · 不做 C2/定时回连 · 不做横向移动自动化 · 不做拒绝服务类动作（不提供 `--flood` 一类参数面）· 不扫描未声明目标 · 不把情报源当目标 · 不自动提交任何表单到非 scope 目标。
- **失败面（fail-closed，不许静默）**：读交战国度失败（不存在/坏 JSON/权限）⇒ **deny** 并落 timeline，**不重建不猜** · 写证据失败 ⇒ 抛错（**不静默降级为「无证据成功」**）· 闸门函数自身抛错 ⇒ 视为 deny（异常即拒绝）· 子进程超时 ⇒ 返回已获得的输出，**不重试**（重试是调用者的决定）。

## 7 · 可证伪验收

| # | 可证伪命题 | 证据 | 状态 |
|---|---|---|---|
| A8 | 五类坏样本全 deny，reason 与裁决表逐条一致 | `node --test tests/gate.test.mjs` 的 A8 组（无交战 / 空授权 / 越界 / 过期窗口 / 未开 auth 开关） | 已实测 |
| A8b | 正样本有分辨力（passive/intel/范围内 active 放行；开开关后 auth 放行） | 同上正样本组（**对照组**：证明不是恒 deny） | 已实测 |
| A9 | 闸门先于副作用（deny 时零网络零子进程） | 同上：**结构判据**（deny 分支不含 `spec.run`）+ **运行时判据**（deny 后无 `evidence.jsonl`） | 已实测 |
| A10 | 范围匹配带 `.` 边界 | 同上 A10 组（`evil-example.com` deny / `a.example.com` allow / `EXAMPLE.com.` 归一化后 allow） | 已实测 |
| A11 | 归一化覆盖 scheme/userinfo/路径/端口/尾点 | 同上 `normalizeTarget` 组 | 已实测 |
| A12 | I4 拒绝留痕行形状正确 | 同上 `gateDeniedLine` 组 | 已实测 |
| A13 | 工具面恰为 12，且注册经单一切面 | 同上 A9 运行时组（`registered.length === 12`） | 已实测 |
| A14 | 移植的 25 个模块零改动编译通过 | `tsc -p tsconfig.json` 退出码 0 | 已实测 |
| A15 | 组合切换后旧 36 件从工具面消失、新 12 件在场 | 挂载后 `plugin_boot_status` + 工具清单 | 待验收 |
| A16 | 一次真实交战（靶场）里发现→载荷→验证三步共享同一上下文 | `eng_finding` 的 findingId 被 `eng_payload` / `eng_verify` 直接消费，`eng_report` 时间线含三步同源证据 id | 待线上验收 |

## 8 · 与实现的关系

**落点**：`src/gate.ts`（闸门，纯函数）· `src/store.ts`（交战国度）· `src/channels.ts`（通道 + 单一引号出口）· `src/index.ts`（12 工具 + 单一 `reg()` 切面）· 移植模块 25 个（`red-*` / `blue-*` / `xp-*` / `range-*` / `sec-*`，共 4,031 行，**零改动编译通过**）· `tests/gate.test.mjs`。

**生效判据**：构建 mtime 晚于进程启动 · `eng_status` 可答 · 喂越界目标 ⇒ 拒绝文案 + `gate/denied` 落盘 · 交战国度只有本件写。

**回退**：`plugin_mount` 五件旧件（源码与依赖均未删除）；交战国度目录保留 ⇒ 无需重建。

## 9 · 实践修订记录

| 日期 | 修订 |
|---|---|
| 2026-09-23 | 首版：从设计稿迁入语义文档形状；移植 25 个模块（4,031 行）**零改动编译通过**；落地闸门 + 国度 + 通道 + 12 工具（经单一 `reg()` 切面）。 |
| 2026-09-23 | 移植时用**带前缀**命名（五件各有自己的 `trace.ts`，会撞名）⇒ `red-trace.ts` / `blue-trace.ts` / …；内部相对导入按前缀重写，并修掉一处**内联类型导入**（`import('./pure.js')`，`from '...'` 的替换规则抓不到它）。 |
| 2026-09-23 | 实现中发现三处 API 与我按设计稿的猜测不同，逐条按真签名改正：`PortResult` **只返回开放端口**（不列 closed ⇒ 输出如实标注口径，不把「未列出」读成「关闭」）；`BisectOptions` 需要 **probe 回调**；`SshArgs` 需要**明文口令**。后两者 ⇒ 本件的 `blind-extract` 与 `remote-exec` **显式未接线**（见 §10）——这是纪律驱动的选择：旧 `cyber-range` 的 `sshpass -p '<明文>'` 把口令同时放进工具参数与子进程命令行，本件不复制它。 |
| 2026-09-23 | 交付闸门时补一条**结构性判据**（A9）：`deny` 分支里不得出现 `spec.run`——闸门先于副作用不靠「每处记得调」，而靠**没有别的路径能触发副作用**（12 工具只有一个注册入口）。 |

## 10 · 未决问题

1. **`blue_baseline_check` 的去向与退役顺序约束**：它是「本机加固态势」，属另一个顶层目的 ⇒ 应移交拟建的 `dsh-host-posture`。**在此之前不 unmount `dsh-blue-team`**（技能 `windows-security-hardening/SKILL.md:12` 正引用它，删除会留下悬空引用）⇒ 本次只退役其余四件。
2. **`blind-extract` / `remote-exec` 未接线**：前者需 probe 回调（盲注判定接线），后者需凭据引用通道。两者都**显式抛错说明原因**，不假装能跑。接线时须遵守「凭据只以引用形式进入」。
3. **`sec_hashcat` / `sec_john` 未纳入**：对象是离线工件（不参与 scope 判定），节奏也不同（长时 + GPU）。若要保留应另立一件（离线破解工作台）。
4. **`blue_hash_lookup` 未纳入**：计算文件哈希是通用能力，归宿是通用文件工具而非本件。
5. **侦察粒度（设计稿 U1）**：三件（域/主机/Web）vs 一件带 `aspects`——本次取三件，待真实交战实测再定。
6. **本机端点摩擦（U2）**：I9 要求本机也声明进 scope ⇒ 日常本机盘点要先开一次轻量交战。是否引入常驻「house scope」，待出现 ≥3 次「为了看本机端口而开交战」再定。
7. **旧五件侧车轨迹**：退役后保留不动（它们是历史证据）；本件写自己的 timeline，不迁移旧轨迹。
