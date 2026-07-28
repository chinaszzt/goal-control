# TASK-<id>-r<revision> · <标题>

> FOREMAN 从本模板生成每个 revision 的完整、不可变语义快照。packet 是 fresh session 唯一的 task-specific 业务上下文，但它自身不存运行时动态状态。新 revision 必须新建完整文件并在 Goal manifest 中登记 path + SHA-256；禁止原地改写或靠聊天 addendum 续写。

## Packet 身份与语义基线

- Goal：<goal-id / 目标>
- Task：<task-id>
- Packet revision：<rN>
- Supersedes：<前一 revision + hash / NONE>
- Issue：<#num 或 N/A>
- Base branch：`main`
- Frozen base HEAD：<完整 40 位 SHA，禁止符号 main>
- 前置 task：<task id / NONE>；尚未发生的前置 merge SHA 只从运行时已接受的
  `MERGED_TO_MAIN.main_merge_sha` 解析，禁止在 packet 伪造未来 SHA
- Parallel group：<group id / SERIAL>
- Peer tasks：<task ids / NONE>
- Integration order：<本组 PR 串行合并顺序>
- Goal manifest：<repo-relative path + revision>
- Protocol pack：<committed bundle manifest path + SHA-256，或每个 protocol 文件的
  repo-relative path + SHA-256>
- Host constitution/policy：<repo-relative committed path + SHA-256>
- 关联 implementation plan：<repo-relative path + 固定 commit SHA>
- P1 producer：`CAPTAIN`（仅 `P1_ACTIVE` 可写本 issue 的 plan/context/_ref）
- P1 approval mode：`EXACT_USER_REPLY` / `SCOPED_DELEGATION`
- P1 approval authority：<用户回复引用，或 committed authorization path + SHA-256>
- Manifest P1 policy：<artifact_root + authority path/hash + dependency_gate=ARCHIVED；未启用则 N/A>

> Packet SHA-256 由 manifest/runtime 在本文件外记录。本节不要写 thread、host、model、worktree、branch、PR、current HEAD、状态、cursor、profile、PID、lease 或动态 evidence link；这些都属于 launch/runtime。
> 前置 task 的实际 merge SHA 同样是动态边界：merge 被控制面接受后进入下一 task 的
> runtime/base-head 证据，不因“未来 SHA 现在已知”单独升级 packet。依赖 ID、顺序或
> merge 语义变化才属于 packet revision。
> v1 mechanical P1 只允许全 Goal 全序链：全部 task 启用 p1，首项无依赖，后继直接
> 依赖紧邻 integration-order 前项。并行/mixed 需要独立 base-refresh FSM，当前拒绝。

## 权威来源

- Constitution：<path>
- Spec：<path + Requirement IDs>
- Acceptance：<path + AC IDs>
- Change Plan / P1 Plan / Context：<paths>
- host 服务契约、其它客户端、设计源、用户裁决等一手来源：<path/ref + 固定 revision/SHA>
- 已确认外部事实证据：<generated contract/deployment wire/owner confirmation；无则写 NONE>

## 范围

### 必须实现

- ...

### 明确非目标

- ...

### 禁止触碰

- ...

## 具体实现方案

1. ...
2. ...

## 接缝契约

| Seam ID | 生产者/owner | 消费者 | 形状与字段语义 | 身份/关联键 | 顺序、幂等、生命周期 | 错误/重试/恢复 | 契约测试/证据要求 | 禁止事项 |
|---|---|---|---|---|---|---|---|---|
| SEAM-01 | ... | ... | ... | ... | ... | ... | ... | ... |

每条 seam 至少回答：owner、required/optional/空值、关联/去重键、重复/乱序/延迟/丢失、超时/结果未知、慢路径恢复真相、上下游证据和相邻 task 禁区。

## AC 所有权与证据要求

| AC ID | 用户可观察结果 | 本 task 责任 | 要求证据类型 | Final closing task | 初始状态 |
|---|---|---|---|---|---|
| AC-... | ... | `FULL` / `SEAM_PRODUCER` / `SEAM_CONSUMER` / `EVIDENCE_ONLY` / `NOT_APPLICABLE` | test/Preview/contract/PR | TASK-X | pending |

- `NOT_APPLICABLE` 必须写可验证理由，不能当逃生口；
- contribution task 只按声明责任验收，最终完整关闭责任归 `Final closing task`；
- change plan `implements`：<SPEC IDs>；
- change plan `acceptance`：<本 task AC IDs；全 Spec 时写 omitted>；
- AC audit fixed adapter：CAPTAIN 调用 `goalctl gate-ac-audit --goal <goal> --task <task> --issue <issue> --pr <PR号> --actor-capability-file <cap>`；shadow/enforce 都只生成 sealed gate evidence，不评论 GitHub；评论须走独立的外部幂等发布动作；
- audit 档位：daily-single | critical-two-rounds-plus-tiebreak。

## 并行、写集与资源需求

### 冲突矩阵

| 冲突域/预计写集 | 本 task 权限 | Single writer | Peer 权限 | 协调方式 |
|---|---|---|---|---|
| `<path / symbol / generated output / schema / data>` | write/read/no-touch | TASK-X | TASK-Y: read | owner request/provider-first |

- Frozen seams：<Seam ID + owner + contract link>
- 必须交 FOREMAN：<seam/owner/scope/AC/integration-order 变化>
- Main 前移处理：<同步点、冲突 owner、需重跑的 tests/gates>

### 资源需求（不是实际 lease）

| Resource kind | Key 规则 | Mode | Roles | 允许环境/身份 | 生命周期 |
|---|---|---|---|---|---|
| port / profile / account / external session / UI target | ... | shared-read / exclusive-write | DEV / REVIEW / RECEIPT | ... | <host-defined lifecycle> |

实际端口、profile path、account、PID和 lease token只写 launch/runtime，不回填本 packet。
manifest requirement 的 `roles` 省略表示 legacy 的全部 worker；需要 DEV 保留资源以支持
返工时，REVIEW/RECEIPT 必须使用不同排他 key，共享 fixture 才可共用 `SHARED_READ`。

恢复约束固定为：dirty predecessor 只做 sealed export；successor 使用不同 worktree/branch，
在精确 `source_observed_head` 只 materialize sealed exact paths/tree、拒绝额外内容并写
receipt；dormant DEV 再用原 capability 调用 `recovery-checkpoint-source`，从 sealed
receipt 确定性创建 single-parent checkpoint（空 snapshot 走同一 allow-empty 路径），bind
复核 parent/tree/diff；`RECOVERY_HANDOFF_BOUND`
后仅 `PREFLIGHT_ONLY`，`RECOVERY_PROMOTED` 后才 `FULL`。若本 task 触达真实
Browser/Chrome/MCP/Preview/external-session/account target，填写对应 host broker/fence 要求：
<broker + target kind + mechanical fence evidence>。

Codex handoff 的新 thread 不继承 successor identity。未 bind 的 `RECOVERY_BLOCKED`
replacement 保留最初 lost `source_predecessor` 并记录完整 `recovery_chain`；进入
`PREFLIGHT_ONLY` 后 identity 冻结，直接 replacement 都 fail-closed。唯一恢复是未
promotion、successor 零非终态 lease 时，由 active CAPTAIN+FOREMAN 双 capability 显式
废止 binding，退回 `RECOVERY_BLOCKED` 再登记 fresh attempt；旧 runtime/artifact 不迁移。

## 安全红线与停工条件

- 潜在跨 tenant/organization/user 越权或由客户端身份参数决定服务端授权 → `BLOCKED_SECURITY`；
- host contract/generated artifact/deployed wire 或 owner 口径冲突 → `BLOCKED_EXTERNAL_FACT`；
- repo/HEAD/executable/PID/profile/environment/account 不匹配 → `ENV_IDENTITY_INCIDENT`；
- <本 task 特有红线>。

上述 hold 不得降级成普通 TECH blocker或 follow-up。只有 FOREMAN携带 resolution authority/evidence 能解除。legacy task 语义改变时创建新 packet revision并重新 P1批准；mechanical P1 v1 必须冻结 fresh Goal + fresh authority，不能在原 Goal 内更新 packet。

## 准出与固定 Gate Profile

固定顺序：

1. packet/schema/AC resolver lint；
2. role registration 后、对应 `LAUNCH_*` 事件前完成 repo/runtime/environment identity preflight；
3. DEV tests、clean、`git diff --check`、Fast gate、evidence schema；
4. DEV commit/push/开 PR 后、`DEV_READY` 前对候选 HEAD 复跑 preflight；
5. CAPTAIN 对当前 PR HEAD 调用 fixed Full CI + scoped AC audit adapters；
6. REVIEW；
7. fresh RECEIPT；
8. merge precondition。

- [ ] `shared.md` 通用准出全部满足；
- [ ] <task 特有标准 1>；
- [ ] <task 特有标准 2>。

所有 verdict和 evidence必须绑定 packet SHA-256 + 完整 HEAD。HEAD或 packet变化使下游结论失效。

## 测试与证据计划

- 单元/集成测试：<commands + 可观察 bug>
- 网络/竞态：<场景>
- Fast gate：DEV fixed adapter `goalctl gate-fast`
- Full gate：CAPTAIN fixed adapter `goalctl gate-full-ci` 核验 host policy 声明的 required check
- AC audit：CAPTAIN fixed adapter `goalctl gate-ac-audit`；shadow/enforce 均不评论，评论走独立外部幂等发布动作
- Host UI/runtime：<路径、账号/安全数据获取方式、视口；不适用写 NONE>
- 错误路径：<场景>
- 日志/遥测：<host policy 声明的事件和关键 detail；不适用写 NONE>
- Evidence manifest schema/期望落点：<repo-relative docs/artifact/check location；这里只写类型和位置规则，不写运行后链接>

## 环境与数据权限

- Committed host policy：<path + SHA-256>；
- 可写 environment：<exact id + 路径/tenant/账号/数据，或 NONE>；
- 只读 environment：<exact ids + 允许的只读操作，或 NONE>；
- 测试数据：<安全引用，不写 secret/PII>；
- 候选身份验证：<build-info/HEAD/executable/profile/account 证据要求>。

portable protocol 默认不授权环境写。当前 controller schema 的 `TESTING_WRITE` lane 使用
canonical id `testing`；只有 host policy 与 packet 同时显式授权时才可使用，名称匹配本身
不构成授权。

## 已知风险与升级点

- ...

## Revision 规则

以下变化必须创建新完整 revision并 supersede旧版：scope、实现语义、AC责任、seam、环境权限、安全边界、准出/gate语义。legacy task 若旧版已 P1批准，`PACKET_UPDATED` 先回到 `P1_ACTIVE`，重新产出并核验 plan/context 后再走 `P1_READY -> P1_APPROVED -> P1_COMMITTED`，不得沿用旧批准。mechanical P1 v1 在 append 前拒绝 `PACKET_UPDATED`；必须冻结 fresh Goal + fresh authority 后从 `init` 重走，不能在原 Goal 续用任何批准或状态。

以下属于 launch/runtime，不升级 packet：thread/host/model、branch/worktree、PR号、current HEAD、cursor、checkpoint、profile/PID、实际 lease和动态 evidence link。
