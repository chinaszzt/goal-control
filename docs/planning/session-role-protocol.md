# Goal 多 Session 协议入口

> 本文件只保留兼容入口。执行 session 不再读取一份包含所有角色的长协议。Goal 的运行状态、事件、账本和资源真相见 [`goal-control.md`](goal-control.md)，聊天不再兼任状态库。

文中的 `goalctl` / `resourcectl` 是逻辑动作名；实际执行统一使用
[`goal-control-quickstart.md`](goal-control-quickstart.md#01-固定双根目录与-exact-argv-wrapper)
定义的 fixed-controller exact argv wrapper，并显式传 controlled worktree。

## 启动输入

legacy `CANARY_ONLY -> ACTIVE` 只用于创建前已知 actual cwd，或 full plan 确实无需
绑定 opaque worker branch 的 session；FOREMAN/CAPTAIN 通常满足，但不能只按 role 名
推断。对 DEV/REVIEW/RECEIPT，这条 route 还要求 manifest 未启用 worker bootstrap。
初始输入只包含 `mode=CANARY_ONLY`、role label、exact full canary plan/hash，以及
可选的 committed pre-registration canary policy path+SHA-256；不注入 role kernel、
shared、角色卡、packet、launch 或 capability。

Codex 动态创建、实际 thread/host/cwd/branch 只能事后知道的
DEV/REVIEW/RECEIPT，在 fresh manifest 显式 opt in 后必须使用
`IDENTITY_ONLY -> PREPARE_ACTUAL_WORKTREE -> CANARY_EXECUTE -> ACTIVE`。初始输入只含
`mode=IDENTITY_ONLY`、role label、controller 生成的 exact identity plan/hash 和
committed policy binding；不注入任何角色文件。worker从 actual cwd只读回报 identity。
CAPTAIN以 controller adapter将 observation 绑定到
deterministic non-base branch并 seal receipt；给该 worker的第一条 follow-up才携带
receipt-bound full canary plan/hash。两条输入共同构成 pre-registration 授权，禁止用
聊天补 cwd/branch、用父 worktree plan代替、让 worker raw `git switch/checkout`，或在
中间插入其它探针。完整命令与 prompt 见
[`goal-control-run-goal.md`](goal-control-run-goal.md#动态-devreviewreceipt-的-worker-bootstrap)。

CAPTAIN detached linked worktree 不复用上述 worker-v1 authority。fresh manifest 必须
单独声明
`captain_canary_bootstrap.protocol=goalctl-captain-canary-bootstrap-v1` 和 exact
committed policy marker；完成 receipt-bound registration 后，`START_P1` 仍会重新核对
同一 actual worktree identity。旧 marker、聊天 identity 或 detached execution 都不能
替代这条 route。

opt-in 必须同时具备
`manifest.worker_canary_bootstrap.protocol=goalctl-worker-canary-bootstrap-v1`、manifest
绑定的 policy path/hash，以及 policy 中完全相同的独立行：
`Worker-Canary-Bootstrap-Protocol: goalctl-worker-canary-bootstrap-v1`。缺任一个时
bootstrap unsupported；opaque dynamic worker 不得因为旧 manifest 未 opt in 就退化走
legacy。`identity_binding_sha256` 绑定 plan core 并内嵌于生成的 inspect template，
`identity_plan_sha256` 绑定最终 plan 并供 prompt/prepare 核验，两者不得互换。

policy 只能收窄已知外部工具 fingerprint 的判定，不得携带 packet/launch/capability、
扩张角色权限或授权业务动作；session 必须先核 exact committed bytes，未提供 policy 时
不得自行发明例外。这里的“未提供”只适用于 legacy policy 例外；opt-in dynamic worker
的 manifest-bound policy 是必填 binding。canary/identity/prepare 阶段不登记、不接收
capability/packet/launch、不运行 `goalctl resume/event`；dynamic identity/prepare另禁
gh/GitHub App/Browser/source/resource/environment。PASS 后由上级完成 registration；
worker还必须完成 lease/launch/preflight/`LAUNCH_*`，随后才发送 `ACTIVE` 输入：

Goal 一旦冻结，禁止原地编辑 manifest 或 goal-specific `*.canary-policy.md` 来启用/
修复 bootstrap；新 policy bytes 使用新 committed path/hash，并由 fresh Goal 引用。

GitHub App 的当前已知限制只认 policy 中独立 exact 行
`GitHub-App-Known-Limitation: github_app_private_repo_404-v1`。full canary plan 把
repository metadata 语义 operation、禁止的 commit/PR/file/issue substitute、App-last
顺序、同-session 补偿列表和聚合条件写入 hash；旧 policy 无该 marker 时不获得例外。
当前 v1 尚未消费结构化 probe observation receipt，因此 plan 是机械合同，不是对实际
执行顺序的机械证明；上级仍须审计 session evidence。

1. [`session-protocol/role-kernel.md`](session-protocol/role-kernel.md)；
2. [`session-protocol/shared.md`](session-protocol/shared.md)；
3. 自己的角色卡；
4. 当前完整、不可变、在 Goal manifest 中登记 SHA-256 的 task packet；
5. launch/runtime 指针；
6. 本角色的 0600 capability file 指针；
7. 一行 `mode=ACTIVE role=FOREMAN|CAPTAIN|DEV|REVIEW|RECEIPT`。

| 角色 | 角色卡 |
|---|---|
| CAPTAIN | [`session-protocol/captain.md`](session-protocol/captain.md) |
| DEV | [`session-protocol/dev.md`](session-protocol/dev.md) |
| REVIEW | [`session-protocol/review.md`](session-protocol/review.md) |
| RECEIPT | [`session-protocol/receipt.md`](session-protocol/receipt.md) |
| 工头 | [`session-protocol/foreman.md`](session-protocol/foreman.md) |

任务包从 [`session-protocol/task-packet-template.md`](session-protocol/task-packet-template.md) 生成完整 revision。禁止原地改 packet、用聊天 addendum 叠加 revision，或把 FOREMAN/CAPTAIN 历史、其它角色卡和无关日志塞给执行 session。thread、PR、HEAD、model、profile、lease等动态数据只写 launch/runtime。

FOREMAN 的 `ACTIVE` 输入接收 `role-kernel.md + shared.md + foreman.md + Goal manifest`，
不接收各 task 的长 worker 历史；激活/compact后重新运行
`goalctl status/next/doctor`。CAPTAIN/执行角色只在收到 `ACTIVE` 后、以及 compact、
`systemError`、handoff/successor 后第一步运行 `goalctl resume`。正常运行角色不读取整份
`goal-control-quickstart.md`；连续运行短路径见
[`goal-control-run-goal.md`](goal-control-run-goal.md)。只有 `goalctl event` 接受的结构化
事件迁移状态；普通 `[TAG]` 回复只供人读。

Codex handoff 会产生新 thread identity，不能用新 thread 复用旧 registration/capability。
DEV recovery 尚处 `RECOVERY_BLOCKED` 且未 bind 时，controller 可以登记 fresh dormant
replacement，但必须保留最初 lost source predecessor 并追加完整 `recovery_chain`；进入
`PREFLIGHT_ONLY` 后 identity 冻结，直接 handoff/replacement 一律 fail-closed。未
promotion 且 successor 零非终态 resource lease 时，只有 active CAPTAIN+FOREMAN 双
capability 可显式废止 binding、退回 `RECOVERY_BLOCKED` 后再登记 fresh attempt；旧
runtime/artifact 不迁移。细节见
`goal-control.md` 与角色内核。

## Goal-specific host policy

本 portable protocol 不包含任何当前 Goal、业务环境、账号、外部服务或项目生命周期裁决。
这些授权必须由受控仓内已提交、由 manifest/packet 绑定 hash 的 host policy 与 Goal
authorization 提供。缺少明确授权时，环境写、真实账号、外部 session、浏览器登录态、
业务 API 和项目专属 gate 一律 fail closed。

host policy 可以收窄本协议，不能放宽 capability、identity、append-only ledger、hard
hold、角色隔离或 archive/merge 边界。用户后续指令若改变已冻结语义，必须先提升
control epoch、reconcile，并按 packet/Goal 升级规则形成新的 durable authority；worker
不得自行改写。

## 文件职责

- `goal-control.md`：manifest、immutable packet、runtime/event/FSM/holds/leases/gate/shadow 的总契约；
- `role-kernel.md`：compact后可重新物化的最小角色不变量；
- `shared.md`：所有角色都必须知道的权威顺序、状态机、SHA、环境、事件与 gate规则；
- 角色卡：该角色唯一需要执行的步骤、消息和禁区；
- `foreman.md`：Goal/DAG/packet、跨 task仲裁、merge和归档 CAPTAIN；
- `captain.md`：单 task FSM/session/checkpoint/lease/恢复；
- `task-packet-template.md`：每个 revision 的不可变语义方案、接缝、AC责任和准出；
- 本文件：portable 索引与 host-policy 接缝，不作为当前 Goal 的裁决库。

## Shadow 迁移

现有正在飞的 legacy task 不从 session JSONL 回填历史。当前控制器未实现
`LEGACY_IMPORT`：它们只能按旧协议跑完，或保持停止并等待显式、可审计的迁移工具；
禁止手写 event/快照假装导入当前 packet/head/phase。

新控制面依次经过 simulation → shadow capture → 单 task shadow coordinated → enforced task → enforced goal。Shadow 阶段只报告 would-transition 和 divergence，不自动 spawn/send/archive，不改 GitHub状态；详见 [`goal-control.md`](goal-control.md#10-shadow-迁移)。
