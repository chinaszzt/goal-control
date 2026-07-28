# Control-plane validation roadmap

本文是独立 control plane 抽取后的验证与迭代计划。目标不是把真实业务仓搬进测试，
而是用一个匿名小仓快速证明控制器本身的状态机、身份、恢复和连续编排语义，再用真实
宿主 canary 验证 Codex、GitHub、Browser 和 Preview 等外部能力。

## 成功标准

- 在匿名临时 Git 仓中，以真实 worktree、公开 CLI 子进程和 append-only store
  分钟级验证控制面。
- 完整覆盖
  `FOREMAN → CAPTAIN → DEV → REVIEW → RECEIPT → merge → archive`。
- 一条命令连续执行 TASK-A → TASK-B → TASK-C；中途重启 supervisor 或清空上下文后，
  仍只凭 durable state 自动继续。
- FOREMAN 只消费结构化 machine summary，不承载 worker 的长对话。
- 所有异常先 fail closed，再执行 `status/next/actions` 投影出的合法恢复动作。
- 明确区分：
  - L0/L1 证明 FSM、ledger、identity、recovery 和 replay；
  - L2 证明真实 task broker、GitHub、Browser、Preview 和权限可用。

## 非目标与红线

- L1 不声称证明 Codex worker 真正继承权限，也不证明真实 GitHub 或浏览器登录态。
- 不使用 fixture secret、聊天消息、手改 ledger 或伪造身份/外部工具结果绕过控制面。
- 不因测试方便放宽 production identity、launch、lease、replay 或 append-only 不变量。
- fault adapter 只能存在于明确隔离的测试 namespace，production store 必须拒绝它。
- 早期里程碑不重排生产模块路径；先建立快速、可信的反馈环。
- 匿名 lab 不替代真实宿主 L2，也不运行任何业务项目的 Quality Gate。

## Scenario 约定

目标结构：

```text
lab/
├── runner.js
├── scenarios/
│   ├── 000-initial-eligibility.js
│   ├── 100-single-task-lifecycle.js
│   ├── 200-continuous-a-b-c.js
│   ├── 300-simultaneous-expiry-recovery.js
│   ├── 310-captain-detached-bootstrap.js
│   ├── 320-worktree-loss-recovery.js
│   └── 400-permission-contract.js
├── drivers/
│   ├── foreman.js
│   ├── captain.js
│   ├── dev.js
│   ├── review.js
│   └── receipt.js
└── contracts/
    ├── scenario-result.schema.json
    └── host-canary-receipt.schema.json
```

每个 scenario 必须遵守：

1. driver 只调用公开 CLI，不 import controller internals，不直接写 control store。
2. 每次动作前读取 `status/next/actions`，只能执行机器当时实际投影的动作。
3. 每个 durable event 后使用 fresh process 重读状态，不能依赖进程内缓存或聊天记忆。
4. 测试授权来自已提交的 fixture，不把对话中的自然语言当 durable authority。
5. 每步记录 `START/PASS/FAIL`、耗时、Goal/task、revision 和 stable operation ID。
6. 每个场景产出 JSONL timeline、最终 result、ledger/state hash、doctor、Git graph、
   活动进程和耗时摘要；所有 artifact 必须脱敏。
7. response loss 使用相同 stable ID/request exact retry；异文请求必须冲突。

## M0 — 建立快速反馈底座

对应：

- [#2 Build an observable, timeout-safe scenario runner](https://github.com/chinaszzt/goal-control/issues/2)
- [#3 Shard and instrument the full compatibility suite](https://github.com/chinaszzt/goal-control/issues/3)

先把现有 initial-eligibility lab 迁入 scenario runner，并增加 runner 自测：

- PASS、预期拒绝、CLI 非零退出；
- 子进程 hang、step/scenario timeout；
- event 已落盘但 response 丢失；
- runner 收到 SIGTERM。

准出：

- 最多 15 秒输出一次 heartbeat，失败能看到当前 scenario/step/revision。
- timeout 会终止整个子进程组；默认清理，`GOAL_CONTROL_KEEP_LAB=1` 可保留现场。
- CI 上传 JUnit、timings JSON 和脱敏诊断 artifact。
- Full 使用 checked-in suite groups 并行，保留本地串行总入口；不以 skip/retry 换速度。
- PR Full 首轮目标 wall time 为 15–20 分钟，并建立只降不升的耗时预算。

## M1 — 消除启动前的人工判断

对应：

- [#4 Ingest sealed structured probe observation receipts](https://github.com/chinaszzt/goal-control/issues/4)
- [#5 Support CAPTAIN detached-worktree bootstrap](https://github.com/chinaszzt/goal-control/issues/5)

这一阶段解决两类会让全自动流程在真正开始前停住的问题：

- canary observation 从聊天摘要变为绑定 plan、身份、probe 顺序和 TTL 的 sealed receipt；
- detached CAPTAIN worktree 通过 durable intent、CAS branch attach 和 receipt
  自动进入可执行 P1 的命名分支。

准出：

- probe 缺项、乱序、cross-identity、过期或出现交互式 Allow 时，激活前确定性拒绝。
- CAPTAIN bootstrap 的 ref 创建、receipt publish、registration response loss 均可 exact retry。
- `START_P1` 机械核对 receipt、cwd/common-dir、branch、HEAD、thread 和 host。
- 主工作树、base branch、remote refs、tree 与 index 在 bootstrap 前后保持不变。

## M2 — 单任务完整生命周期

对应：

- [#6 Run one anonymous task through the full Goal lifecycle](https://github.com/chinaszzt/goal-control/issues/6)

最小场景：

```text
REGISTER_FOREMAN
→ REGISTER_CAPTAIN
→ START_P1
→ P1_READY
→ P1_APPROVED
→ P1_COMMITTED
→ REGISTER/LAUNCH_DEV
→ DEV_READY
→ REGISTER/LAUNCH_REVIEW
→ REVIEW_PASS
→ REGISTER/LAUNCH_RECEIPT
→ RECEIPT_PASS
→ READY_FOR_MERGE
→ MERGED
→ ARCHIVED
```

DEV 实际修改 fixture；REVIEW 独立检查 diff/test；RECEIPT 独立核对 acceptance；merge
使用本地 bare origin 和真实分支。

必须注入：

- `DEV_READY`、merge 和 archive 接受后丢失 response；
- `REVIEW_REWORK → DEV_READY → fresh REVIEW attempt`；
- archive 前 dirty worktree 被拒绝，恢复 clean 后再合法继续。

准出：

- 最终 `ARCHIVED`、`pending_operations=[]`、doctor 无 error。
- role attempt、launch、evidence 和 full HEAD 全部绑定正确。
- fresh replay 后 state hash 与 allowed-actions hash 不变。
- archive 后控制树保持 byte-identical finality。
- 全程无网络、真实账号、Browser 或用户 Allow。

## M3 — 连续 TASK-A → TASK-B → TASK-C

对应：

- [#7 Run anonymous A-B-C tasks as one continuous Goal](https://github.com/chinaszzt/goal-control/issues/7)

确定性 DAG：

- A 写 deterministic JSON；
- B 只在 A merge/archive 后 eligible，并生成 checksum；
- C 只在 B merge/archive 后 eligible，并验证 checksum；
- 每个任务都完整经历 CAPTAIN/DEV/REVIEW/RECEIPT/merge/archive。

必须注入：

- A archive 后立即杀死 supervisor；fresh process 只凭 store 启动 B。
- B merge event response loss，重试不能重复 merge。
- C 开始前更换 controller process 并清空上下文。

准出：

- eligibility 严格为 `A → B → C → []`。
- 三项全部 `ARCHIVED`，main tree hash 等于固定 golden hash。
- 无悬挂 operation、lease、launch 或 worktree。
- 任意 durable checkpoint 重启都不需要聊天历史。
- 一条命令可连续跑完，不出现用户 Allow/确认。

这一里程碑还应加入已经修复事故的回归场景：

- 同时 actor expiry 的 root recovery；
- same-HEAD wrong checkout identity binding；
- worker worktree 被宿主删除后的 sealed handoff；
- runtime/decoder rotation 与旧 evidence 拒绝。

这些是防复发场景，不重新建立同名实现 issue。

## M4 — 真实宿主边界

对应：

- [#8 Add trusted fencing receipts for external-resource leases](https://github.com/chinaszzt/goal-control/issues/8)
- [#9 Model worker permission envelopes before activation](https://github.com/chinaszzt/goal-control/issues/9)
- [#10 Detect Node and pnpm toolchain drift](https://github.com/chinaszzt/goal-control/issues/10)

L1 使用 deterministic fake adapters 验证 contract；L2 才执行真实探针：

- GitHub：在专用 canary repo 做一次可回收的 branch/PR 写探针；只看登录态或
  `viewerPermission` 不足以证明可操作。
- Browser：打开本地 nonce 页面并完成一次点击和读取。
- Preview：启停临时服务，绑定 PID、端口和 HTTP nonce。
- task broker：验证 create/send/wait/archive，以及 child 的 effective permission profile。
- external resource：由可信 broker 提供 acquire/fence receipt；“没有观察到占用”不能当作
  已完成物理 fence。
- toolchain：在 candidate preflight 前检查 Node、pnpm、lockfile 和 executable binding。

任一真实探针触发交互式 Allow/auth prompt，必须以
`INTERACTIVE_APPROVAL_REQUIRED` fail closed，不能把点击请求转交用户，也不能唤醒 worker。
修复权限后必须 fresh preflight/receipt。

## M5 — 真实宿主连续试跑

对应：

- [#12 Run continuous A-B-C on a real Codex/GitHub host](https://github.com/chinaszzt/goal-control/issues/12)

在专用小 GitHub repo 和真实 Codex task broker 上复用 M3 场景：

- 一个 FOREMAN task；
- 每个业务任务一个 CAPTAIN；
- DEV/REVIEW/RECEIPT 各自是独立 task；
- 完成真实 A→B→C PR、checks、merge 和 archive。

必须覆盖：

- supervisor/Codex 异常退出后由 fresh FOREMAN 恢复；
- 中途 compact 后，新 task 只获取 role kernel、packet 和 machine state；
- worker task 被 archive 并连带移除 worktree；
- GitHub、Browser、Preview 或 task broker 权限在 Goal 中途撤销。

准出：

- 无用户点击 Allow、无人工补事件、无聊天身份伪造。
- supervisor 退出后只凭 durable evidence 恢复。
- worker 长对话不进入 FOREMAN 上下文，只提交结构化结果/evidence。
- 所有 GitHub、Browser、Preview 和 task broker 副作用都有明确 receipt 和清理结果。

M5 是 release qualification，不是 L1 实现的替代品；硬依赖 #7、#8、#9。#10 完成后，
将 toolchain drift 纳入该场景的回归矩阵。

## M6 — 规模与性能

对应：

- [#11 Make 10k-artifact source handoff linear and crash-safe](https://github.com/chinaszzt/goal-control/issues/11)

在语义和恢复路径稳定后，再优化 10,000 artifact source handoff。目标是近似线性工作量，
同时保留 canonical path、mode/hash、byte budget、cleanup manifest、append-only evidence
和每个 crash boundary 的 exact retry。

## CI 分层与预算

| Gate | 内容 | 目标预算 | 触发 |
|---|---|---:|---|
| Static | provenance、schema、TypeScript、脚本语法 | < 1 min | 每个 PR |
| Core fast | FSM/ledger/transaction；Node 22.19 + 25 | < 2 min/job | 每个 PR |
| Lab smoke | M0 + initial eligibility | < 2 min | 每个 PR |
| Lifecycle | M2、M3，按 scenario 独立 job | < 5 min/job | 每个 PR，required |
| Recovery | expiry/bootstrap/worktree/rotation 分片 | < 8 min/job | 每个 PR，required |
| Full compatibility | checked-in 4–6 shards | 15–20 min wall | 每个 PR，required；main/nightly |
| Host L2 | Codex/GitHub/Browser/Preview | 独立预算 | 见下 |

真实宿主 L2 频率：

- 每次 Goal 启动：fresh permission canary，不能复用昨晚结果。
- 每晚：真实宿主单任务全角色 happy path。
- 每周：真实 A→B→C，加一次 supervisor restart 和一次权限失败。
- identity、recovery、ledger/schema、runtime rotation、broker 或 canary 变更：
  合并前强制完整 A→B→C L2。
- release candidate：在真实业务宿主上用 fresh Goal 跑 2–3 个小任务；
  匿名 lab 不能替代这一层。

## 建议执行顺序

第一批可以并行开四个 session：

1. #2 scenario runner；
2. #3 Full sharding/observability；
3. #4 structured observation receipt；
4. #5 CAPTAIN bootstrap。

依赖主线为：

```text
#2 ─> #6 ─┐
#4 ───────┼─> #7 ─┐
#5 ───────┘        │
                   ├─> #12 real-host trial
#8 ────────────────┤
#4 ─> #9 ──────────┘

#10 可独立推进，并在完成后进入 #12 回归矩阵
#11 在语义稳定后推进
```

#2 完成后即可开 #6；#4、#5 不依赖 #2，可继续并行。#6/#4/#5 都完成后开 #7。
#8 可独立推进，#9 在 #4 后推进；#7/#8/#9 都完成后开 #12。#10 独立推进，
#11 不阻塞连续试跑。

整个计划完成的最终判据是：fresh checkout 中执行一条命令，无人工点击或聊天补丁，
三个小任务全部 archive；fresh supervisor 能在任意 durable checkpoint 恢复；最终没有
pending operation、悬挂 lease、残留 worktree，且 L1 与真实 L2 都留下可审计的结构化证据。
