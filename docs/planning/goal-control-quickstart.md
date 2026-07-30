# Goal 控制面命令参考

> 本页是按需查命令的长参考，不是 runtime 角色的接手上下文。连续运行最短路径见
> [`goal-control-run-goal.md`](./goal-control-run-goal.md)；完整约束见
> [`goal-control.md`](./goal-control.md) 和
> [`session-role-protocol.md`](./session-role-protocol.md)。

## 0. 先确认边界

当前 v1 同时支持 manifest `mode=shadow|enforce`，但省略 mode 和普通 scaffold 都默认
`shadow`；spec 明写 `enforce` 时还必须在 scaffold 命令显式传 `--allow-enforce`，否则在
写输出前 fail-closed。这个 flag 只是对本次静态包 mode 的显式确认，不会授权未建模的
spawn/send/PR/merge/archive，也不会放宽 capability、packet、HEAD、resource 或外部副作用
门禁。两种 mode 下控制面都验证 packet、身份、事件、证据和资源租约，记录“现在是什么
状态、下一步允许做什么”。`goalctl` binary 本身不调用 Codex 编排工具，也不推进未由固定
adapter 建模的 GitHub 状态；自治 FOREMAN / CAPTAIN 必须按机器投影在 Codex App 中调用
create/wait/send/archive。正常连续运行要求它们全自动闭环，不等待用户逐步点击；消息只传
`event_id + 结果短摘要`，不能把聊天标签当状态源。

> **Archive 红线（active-worktree-loss incident family）**：Codex `archive` 可能同时回收
> thread worktree。它只能用于已 merge、无 dirty/unpushed 状态且已有 archive evidence 的
> terminal thread；绝不能用 archive/unarchive 取消 approval 或中断 active turn。没有
> 显式 interrupt/cancel 能力时，保留旧 thread 并登记 fresh successor。

## 0.1 固定双根目录与 exact argv wrapper

controller 与受控仓是两个独立身份。先在一个新 shell 中把下面三个占位值替换成经过审计的
canonical 绝对路径；不要从 `PATH`、shell alias 或受控仓的 `pnpm` scripts 解析 controller：

```bash
readonly GC_NODE=/absolute/path/to/audited-node
readonly GC_CONTROLLER_ROOT=/absolute/path/to/clean-committed-goal-control

gc_goalctl() {
  local repository_worktree=$1
  shift
  "$GC_NODE" "$GC_CONTROLLER_ROOT/scripts/goalctl.js" \
    "$@" --repository-worktree "$repository_worktree"
}

gc_resourcectl() {
  local repository_worktree=$1
  shift
  "$GC_NODE" "$GC_CONTROLLER_ROOT/scripts/resourcectl.js" \
    "$@" --repository-worktree "$repository_worktree"
}
```

本文所有 `gc_goalctl <controlled-worktree> ...` /
`gc_resourcectl <controlled-worktree> ...` 都精确展开为上述 argv。第一个参数必须是该
operation 要求的 canonical controlled linked worktree；wrapper 后不得再传第二个
`--repository-worktree`。controller checkout 必须 clean、committed、与 Goal 冻结的
decoder identity 匹配。受控仓提供 committed manifest/packet/protocol/host policy 和项目
lockfile；controller 仓自己的 lockfile 只固定 controller 工具链，两者不能互换。

动态状态写入受控仓的共享 Git common-dir：

```text
$(git rev-parse --git-common-dir)/goal-control/v1/
```

它不会提交进业务 PR。示例中的 `<...>` 是必须替换的操作值；capability 参数传的是 `0600` 文件路径，不是文件内容。

## 0.5 Store protocol 异常只交 supervisor

正常运行角色不执行 store adoption、decoder rotation 或 odd-generation repair。遇到
`STORE_PROTOCOL_MIGRATION_REQUIRED`、`STORE_PROTOCOL_UNSUPPORTED`、decoder 漂移或
无法可信读取的 generation，立即停止 Goal/worker 推进并交给 supervisor。完整迁移、
轮换、双 decoder canary 与清理检查只见
[`goal-control-store-operations.md`](./goal-control-store-operations.md)。

创建和连续运行 fresh Goal 的短路径见
[`goal-control-run-goal.md`](./goal-control-run-goal.md)。FOREMAN/CAPTAIN/执行角色
运行时只读取角色内核、自己的角色卡、当前 manifest/packet 和 launch 指针；不要为正常
接手整份读取本 Quickstart。

## 1. 建 Goal 静态包

先把每个 task 的完整 packet 写成独立源文件，再准备 scaffold spec。spec 的字段和多
task 示例见
[`scaffold-spec.example.json`](./goals/example/scaffold-spec.example.json)；至少填写真实
`owner/repo`、当前选定 base commit 的完整 40 位 SHA、task DAG、每个
`packet_source` 与 `packet_revision`。

从 spec 原子生成静态包：

```bash
gc_goalctl <controlled-worktree> scaffold \
  --spec docs/planning/goals/<goal-id>.scaffold.json \
  --output-dir docs/planning/goals/<goal-id> \
  --json
```

`scaffold` 会逐字节复制 packet source、计算 hash 并生成 `manifest.json`；不会生成
capability、session、事件或 launch。目标目录不存在时才写入；相同输入重跑返回
`idempotent: true`，任何差异都报 `SCAFFOLD_CONFLICT`，不会覆盖。省略 mode 时生成
`shadow`；spec 显式写 `enforce` 时必须同时传 `--allow-enforce`，缺 flag 会在创建目标
目录前拒绝，而不是静默降级成 shadow。输出路径及其现存祖先不能是 symlink，也不能进入
Git common-dir。

按这个顺序核对生成物：

1. 每个 `packets/TASK-<id>-r<revision>.md`：范围、AC、seam、环境权限、资源、准出条件；不写 thread、当前 HEAD、PR、进度或 lease。
2. `manifest.json`：默认保持 `"mode": "shadow"`；只有用户明确授权真实
   spawn/send/PR/merge/archive 的 Goal 才使用 `"mode": "enforce"`，scaffold 时同时显式
   传 `--allow-enforce`。需要控制器执行 GitHub merge 的 fresh Goal 还必须在
   `repository` 显式冻结
   `"merge_policy": "goalctl-github-squash-v1"`；该 policy 禁止绕过 wrapper 直接提交
   raw `MERGED`。若将使用 §4 的 opaque dynamic worker bootstrap，还须在这个
   **pre-init** 阶段添加 `worker_canary_bootstrap` manifest/policy 双重 opt-in 和 exact
   marker；`scaffold` 不会推断或生成它。复核 task DAG、`integration_order`、冲突域、
   预计写集和资源需求。
3. review 并提交 manifest、packet 与其引用的协议文件。之后再 `init`。`init` 会逐文件核对当前 `HEAD` 中的普通 Git blob；未提交、工作区字节不同或 symlink/submodule 输入分别以 `GOAL_INPUT_NOT_COMMITTED` / `GOAL_INPUT_DIRTY` / `GOAL_INPUT_SYMLINK` 拒绝。
4. packet 后续变化不能原地修改后沿用旧 revision。legacy task 必须新 revision + 新
   hash，并走受控 `PACKET_UPDATED`；mechanical P1 v1 不接受 `PACKET_UPDATED`，
   语义变化必须冻结 fresh Goal + fresh authority 后重新 `init`。

可对照：

- [`goals/example/manifest.json`](./goals/example/manifest.json)
- [`goals/example/packets/TASK-example-r1.md`](./goals/example/packets/TASK-example-r1.md)
- [`goals/example/scaffold-spec.example.json`](./goals/example/scaffold-spec.example.json)
- [`goals/example/launch-input.example.json`](./goals/example/launch-input.example.json)
- [`goals/example/launch-manifest.example.json`](./goals/example/launch-manifest.example.json)

忘记参数时运行 `gc_goalctl <controlled-worktree> --help` 或
`gc_goalctl <controlled-worktree> <command> --help`；`--json` 可取机器可读帮助。

## 2. 初始化并登记 FOREMAN / CAPTAIN

manifest 配置 `preclaim.policy=supervisor-exact-whitelist-v1` 时，必须在 `init` 前、旧
controller 已按
[`goal-control-store-operations.md`](./goal-control-store-operations.md)
排空且 root protocol 已迁移后运行一次：

```bash
gc_goalctl <controlled-worktree> preclaim-issues \
  --manifest docs/planning/goals/<goal-id>/manifest.json \
  --operation-id <manifest.preclaim.operation_id> \
  --json
```

adapter 只读取已提交 manifest/authorization 中的 exact issue 白名单、expected actor 与
`status:doing`。它先在 control root seal request-bound intent 和每个 issue 的首次观察，
再幂等调用 GitHub claim/status 写入并逐项 readback，最后 seal receipt。`CLAIMED` 与当前
authorization 明确允许的 `MINE_NEED_CONFIRM` 都可 PASS；`OTHERS_REJECT` seal
`BLOCKED` receipt 后停止，不继续其它 issue。外部 mutation 前、中、后崩溃或 stdout
丢失时，只能用相同 operation ID、相同 committed manifest/authorization exact retry；
异文 request、actor、repo、白名单、status、intent/observation/receipt 一律拒绝且不覆盖。
输出只含 receipt path/hash 和去敏 issue readback，不含 token。

`init` 对配置了 preclaim 的 Goal 会在任何 Goal/capability 发布前验证 deterministic
receipt path、自 hash、request/intention lineage、manifest/authorization hash、canonical
repo/remote、actor、完整 issue 白名单与每项 PASS readback；验证通过后只消费 receipt，
不会重复 claim。

```bash
gc_goalctl <controlled-worktree> init \
  --manifest docs/planning/goals/<goal-id>/manifest.json \
  --json
```

manifest 中任一 task 启用 `p1` 时，首次 init 必须从 clean base branch 执行，且
`HEAD == refs/remotes/origin/<base_branch>`。控制器把该 commit seal 为
`goal_input_head`：root task 从它开始，后继 task 从最高 integration-order 直接依赖的
accepted `main_merge_sha` 开始。不要在尚未合并的 Goal setup 分支 init；控制器会拒绝。
v1 同时要求全部 task 都启用 `p1` 并按 integration order 形成全序直接依赖链；并行或
mixed manifest 会在 init 前 `INVALID_MANIFEST`，不能用聊天约定绕过尚未实现的 base
refresh/rebase FSM。

首次输出包含：

- `bootstrap_capability_file`：仅用于签发第一个 FOREMAN，用后失效；
- `foreman_recovery_capability_file`：普通恢复中只在 FOREMAN 已被合法标记失联后签发 successor；FOREMAN 与 CAPTAIN 同时过期时，也是原子根恢复的唯一 authority，必须单独保管。
- `init_receipt_file` / `receipt_sha256`：与 manifest、sealed Goal metadata、上述两个
  capability path/hash 一起发布的初始化收据；stdout 不含 raw capability。

`init` 先在同一父目录下创建 `0700` 临时 Goal 目录和 `0700` capabilities 目录，两个
capability 与 receipt 均为 `0600`；文件和目录 fsync 完成后才把整棵 Goal 目录 rename
到最终位置，并 fsync 父目录。调用方在第一次调用前只需持久化 committed manifest
identity；若进程在目录发布后、JSON 返回前退出或 stdout 丢失，使用**逐字相同且仍与
HEAD 一致的 manifest** 重跑同一命令。精确重试会验证 sealed receipt、metadata、目录
owner/权限和现存 capability bytes/hash，并再次返回同一 deterministic paths，不会新建
第二套 authority。不同 manifest 以 `GOAL_ALREADY_INITIALIZED` 拒绝；receipt 缺失、
篡改或权限漂移均 fail-closed。

完整 staging 树已经 fsync、但进程在最终目录 rename 前退出时也属于可恢复状态：精确
`init` 会先验证 receipt、manifest、metadata、两个 capability 的最终路径与 staged bytes，
再原子提升原树，不重新 mint authority。尚未 seal 的树只允许逐字相同的 init request 在
严格 owner/`0700`/`0600` inventory 下清理重建；foreign/lookalike、多份、未知文件或
canonical/atomic-temp 分叉一律保留并停止，禁止宽泛递归 sweep。

旧版已初始化、但尚无 receipt 的 Goal 必须先按
[`goal-control-store-operations.md`](./goal-control-store-operations.md)
完成 store protocol adoption。
之后首次精确 `init` 重跑只会在 writer lock 内执行一次 legacy receipt adoption：完整重放
Goal，验证 sealed manifest/metadata、同 UID 非 symlink 目录、`0600` recovery capability
hash；bootstrap 尚在时也验证其 bytes/hash，已消费时则要求 sealed
`bootstrap_consumed_at` 与唯一 append-only BOOTSTRAP FOREMAN lineage。通过后才把
`LOCKED_LEGACY_ADOPTION` provenance 和 source digest 写入 receipt，并在 sealed metadata
设置 receipt-required marker。目录可由旧 `0755` 收紧为 `0700`；capability 权限或 hash
异常不会自动修复。marker 一旦存在，后续 receipt 丢失不会再次静默 adoption。

若 bootstrap 已被合法消费，精确重试仍返回它的 deterministic path，并同时返回
`bootstrap_capability_consumed: true`；该文件此时可以不存在，不能再次用于签发。

只有初始 FOREMAN 已用 `CANARY_ONLY` prompt 在其实际 session/host 完成 canary PASS，
且 fresh Goal 的 preclaim/init 已闭合后，才登记该 task 的 FOREMAN；登记成功后再发送
`ACTIVE`：

若 manifest 启用 `probe_observation_receipts`，host adapter 必须先在 controller
control-root 之外生成 manifest-key-signed、private `0600` actual identity observation。
controller 不接受 caller 写 `--thread/--host/--attempt` 来准备 challenge；同一个
authenticated upstream transaction 验签 observation、从 current lineage 派生 attempt
并把 durable identity intent/challenge 作为一个 schema-v2 atomic bundle seal。每个
goal/task/role/controller-attempt/lifecycle/launch semantic slot 只有一个 original
operation；另一 event ID 在 generation 前整树零写拒绝：

```bash
gc_goalctl <controlled-worktree> prepare-probe-observation-challenge \
  --goal <goal-id> --task <task-id> --role FOREMAN \
  --event-id <stable-first-foreman-registration-id> \
  --canary-plan-sha256 <sha256> \
  --issuer-capability-file <bootstrap-capability-file> \
  --identity-receipt <absolute-private-host-signed-observation.json> \
  --identity-receipt-sha256 <sha256> --json
```

worker role 还必须在同一命令携带
`--worker-bootstrap-receipt/--worker-bootstrap-receipt-sha256/`
`--worker-bootstrap-operation-id/--worker-bootstrap-challenge/`
`--worker-bootstrap-identity-plan-sha256/--worker-worktree`。signed observation 的
`launch_id` 必须等于 controller-owned bootstrap operation ID；controller 会在发布
bundle 前重验 exact task/role/thread/host/worktree/HEAD/bootstrap binding。缺 launch
authority、任意/cross bootstrap 或另一个 caller-triggered consumer 写步骤都不成立。

```bash
gc_goalctl <frozen-goal-worktree> prepare-probe-observation-challenge \
  --goal <goal-id> --task <task-id> --role DEV \
  --event-id <stable-dev-registration-id> \
  --canary-plan-sha256 <sha256> \
  --issuer-capability-file <captain-actor-capability-file> \
  --identity-receipt <absolute-private-host-signed-observation.json> \
  --identity-receipt-sha256 <sha256> \
  --worker-bootstrap-receipt <canonical-absolute-bootstrap-receipt> \
  --worker-bootstrap-receipt-sha256 <worker-bootstrap-receipt-sha256> \
  --worker-bootstrap-operation-id <same-launch-id> \
  --worker-bootstrap-challenge <same-fresh-64-lowercase-hex> \
  --worker-bootstrap-identity-plan-sha256 <same-identity-plan-sha256> \
  --worker-worktree <canonical-absolute-worker-worktree> --json
```

只有成功后，credentialless `status/actions` 才会零写投影
`role_identity_intent`。registration 的 thread/host/attempt/session/launch 必须逐项等于
该 intent，并携带同 event 的 sealed probe receipt/plan/challenge；pending/伪造/过期
observation 不产生投影。这里没有另一个 `seal/project/register identity` consumer 写步骤。

```bash
gc_goalctl <controlled-worktree> register-role \
  --goal <goal-id> \
  --task <task-id> \
  --role FOREMAN \
  --thread <foreman-thread-id> \
  --host <actual-host-id> \
  --attempt 1 \
  --event-id <stable-first-foreman-registration-id> \
  --bootstrap-capability-file <bootstrap-capability-file> \
  --json
```

`register-role` 是带 durable intent 的写操作。调用前持久化 `--event-id`；若省略，控制器
会从 role/attempt/task/host/thread 生成 deterministic ID，但响应丢失后仍必须逐字复用
原请求、同一 ID 和原 bootstrap/authorizer/recovery 或已返回的 actor capability 做
exact retry。精确重试可能返回 session history 中的原 registration 与 capability；它只
证明原调用已接受，不证明该历史 actor 仍有当前 operational authority，随后必须重新读
`status/actions`。

新 actor capability 与 sealed registration intent 会先写入由 stable event ID、完整
registration request 和 authorizer authority 共同绑定的 deterministic private staging，
fsync 后才一起 rename 到 canonical intent。若在 rename 前退出，exact retry 提升同一
capability、nonce 与 `accepted_at`；即使原 authorizer lease 随后过期也不重做已经 seal
的授权。未 seal staging 只能由仍具 fresh authority 的同一精确请求严格清理；其它请求、
权限漂移、未知项或多份 staging 全部 fail-closed。

Goal-wide FOREMAN 只有三种操作模式：

1. **首次 bootstrap 登记**：只消费一次 bootstrap capability，建立唯一 Goal authority；
2. **后续 task projection**：用现任 FOREMAN actor capability 登记完全相同的
   thread/host/attempt/status；控制器复用同一 `actor_capability_file`，不会 mint 第二份
   FOREMAN authority；
3. **失联 replacement**：已有合法 `ROLE_LOST(FOREMAN)` 时才可用 Goal recovery
   capability 登记更高 attempt。若 Goal 有多个 current projections，禁止逐 task 替换，
   必须走下文 `recover-expired-foreman` 的 Goal-wide batch。

后续 task 的 FOREMAN projection 示例：

```bash
gc_goalctl <controlled-worktree> register-role \
  --goal <goal-id> \
  --task <later-task-id> \
  --role FOREMAN \
  --thread <same-foreman-thread-id> \
  --host <same-foreman-host-id> \
  --attempt <same-foreman-attempt> \
  --event-id <stable-foreman-projection-registration-id> \
  --authorizer-thread <same-foreman-thread-id> \
  --authorizer-capability-file <foreman-actor-capability-file> \
  --json
```

保存输出的 `actor_capability_file`。FOREMAN 查看可启动批次后，在 Codex App 以
`CANARY_ONLY` prompt **实际创建一个独立 CAPTAIN task**；等待该实际 session canary
PASS 后再登记，登记成功后才发送 `ACTIVE`：

```bash
gc_goalctl <controlled-worktree> next --goal <goal-id> --json

gc_goalctl <controlled-worktree> register-role \
  --goal <goal-id> \
  --task <task-id> \
  --role CAPTAIN \
  --thread <captain-thread-id> \
  --host <actual-captain-host-uuid> \
  --attempt 1 \
  --event-id <stable-captain-registration-id> \
  --authorizer-capability-file <foreman-actor-capability-file> \
  --json
```

同样保存 CAPTAIN 的 `actor_capability_file`，响应丢失沿用同一 registration 请求精确
重试。多 task Goal 中，bootstrap 仍只能用一次；后续 task 的 FOREMAN 只能投影既有
Goal authority，不能把“现任 FOREMAN capability 授权”理解成签发第二个独立 FOREMAN。

## 3. 每轮只做机器允许的下一步

FOREMAN / CAPTAIN 接手、被唤醒或 compact 后，先恢复短角色内核：

```bash
gc_goalctl <controlled-worktree> resume \
  --goal <goal-id> \
  --task <task-id> \
  --role CAPTAIN \
  --thread <captain-thread-id>

gc_goalctl <controlled-worktree> actions \
  --goal <goal-id> \
  --task <task-id> \
  --role CAPTAIN \
  --thread <captain-thread-id> \
  --json
```

输出里的 `actions` 是 phase/role 状态迁移；`maintenance_actions` 是不推进 phase 的维护
动作。active/idle 角色的 lease 需要续期时，控制器会明确返回
`{"type":"HEARTBEAT","actor_role":"...","lease_until":"..."}`。每次接手、compact 后或
长测试前先处理即将到期的 heartbeat，再重跑 `resume/actions`；不能因为普通 `actions`
为空就让控制身份自然过期，也不能把 heartbeat 当成源码、资源或环境权限。
同一 active identity 的普通 `active/idle` heartbeat 不会让已登记 evidence 失效；
`systemError` 或 identity/checkpoint/head/packet/control/phase 漂移仍会强制作废并进入
诊断/恢复。

`status`/`next` 的 task `launch_scope` 表示 launch/action gate；同级
`operational_scope` 只是向后兼容 alias，不是角色权限。带 role 的
`actions --json`/`resume --json` 另外返回 session
`operational_scope=RECOVERY_BLOCKED|PREFLIGHT_ONLY|FULL`，它才是该
角色的 recovery authority。四个读取面都会公开 `pending_operations`；非空时对应
`actions` 与 `maintenance_actions` 必须为空，Goal-wide registration/root recovery
pending 还会冻结整个 `next.batch`。

FOREMAN 创建 ready CAPTAIN 前先读取 `goalctl next --json` 的
`required_start_head`。fetch canonical base branch 后必须满足
`refs/remotes/origin/<base_branch> == required_start_head`，再用该 remote-tracking ref
作为 Codex worktree `startingState.branchName`。新 CAPTAIN 返回后先核实际 cwd 是专属
linked worktree、branch 不是 base branch、worktree clean 且 `HEAD` 精确等于 required
head，再 register/START_P1。若 Goal authorization 已绑定 supervisor preclaim receipt，
只读验证该 receipt，不重复运行 claim。

不要手写 revision、epoch、packet hash 和 actor sequence。按 `actions` 返回的动作生成事件模板：

```bash
gc_goalctl <controlled-worktree> event-template \
  --goal <goal-id> \
  --task <task-id> \
  --role CAPTAIN \
  --thread <captain-thread-id> \
  --type START_P1 \
  --actor-capability-file <captain-actor-capability-file> \
  --json > /tmp/<goal-id>-<task-id>-START_P1.json
```

无 payload 的动作会直接产出可提交 JSON。有业务 payload 的动作必须先准备严格 payload
文件，再生成最终事件；模板不会猜 approval、PR、evidence 或 launch：

fresh task 的 P1 由当前 CAPTAIN 兼任窄权限 producer。manifest `p1` 会让模板和事件入口
共同机械执行：START 绑定 `required_start_head`；READY 只允许本 issue 的
`plan.md`、`context.md` 与 `_ref/**` 为 dirty，并冻结普通文件 inventory 与
worktree/branch；APPROVED 使用 authority+packet+inventory 的 canonical binding；随后
CAPTAIN 只能在同一 worktree/branch 提交完全一致的 bytes，且只允许一个 parent 为
required start 的 P1 commit。CAPTAIN 不得借 P1 写业务代码/测试/Spec/Acceptance/
packet，READY 后不得改 bytes，COMMITTED 后该写权限终止。

```bash
gc_goalctl <controlled-worktree> event-template \
  --goal <goal-id> \
  --task <task-id> \
  --role CAPTAIN \
  --thread <captain-thread-id> \
  --type P1_READY \
  --actor-capability-file <captain-actor-capability-file> \
  --json > /tmp/<goal-id>-<task-id>-P1_READY.json
```

上面省略 payload 的形式只适用于 manifest 显式启用 `p1` 的 task，模板会从当前
worktree 和 sealed state 派生精确字段；legacy task 仍按原有 payload 文件调用。
`P1_APPROVED` 与 `P1_COMMITTED` 的机械字段同理不可手填覆盖。
机械 P1 v1 禁止 `PACKET_UPDATED`；输入语义变化须冻结并初始化 fresh Goal。

`P1_COMMITTED` / `DEV_READY` 会更新候选 HEAD，必须额外传当前 worktree 的完整
`--full-head <40sha>`；模板会机械核对它就是当前 `HEAD`。不要改模板自动绑定字段。
提交事件：

```bash
gc_goalctl <controlled-worktree> event \
  --goal <goal-id> \
  --file <event-json> \
  --actor-capability-file <当前角色-actor-capability-file> \
  --json
```

若 CAPTAIN 在 `P1_ACTIVE/P1_READY/P1_APPROVED` 失联且旧 worktree 已消失，先完成
`ROLE_LOST(CAPTAIN)`、登记 fresh successor 和 `ROLE_RECOVERED`。仅当
`actions --json` 返回 `P1_RESTARTED` 时，FOREMAN 准备：

```json
{
  "reason": "sealed CAPTAIN P1 worktree disappeared",
  "incident_ref": "incident:<durable-reference>"
}
```

然后用 FOREMAN identity 运行 `event-template --type P1_RESTARTED
--payload-file <上面-json>`。模板会机械补齐 recovery event、lost/successor identity 与
abandoned worktree/branch；不要手填或覆盖。事件接受后 phase 回 `QUEUED`、旧
READY/approval 作废，successor 必须在 fresh linked worktree 重新 `START_P1`。同一
recovery lineage 的第二次 restart、未失联 identity 和旧 CAPTAIN capability 都会被拒绝。
机械 task 的 `CONTROL_RECONCILED` 也回 `QUEUED` 并要求 fresh successor START。

`P1_COMMITTED` 后不要用 Codex 默认 base 创建 DEV，也不要让 DEV 复用 CAPTAIN
worktree。CAPTAIN 从 `status --json` 读取 `tasks[task].p1.commit_branch`、
`tasks[task].p1.commit_ref` 与
`tasks[task].full_head`，创建 DEV 时显式使用：

```text
target.environment = worktree
target.environment.startingState = {
  type: "branch",
  branchName: <p1.commit_branch>
}
```

`p1.commit_ref` 是 controller-owned、Goal/task/cycle-bound 的本地 durable ref，不依赖
CAPTAIN disposable branch/worktree。控制器先持久化 0600 single-commit bundle +
sealed intent，再 CAS 发布 ref，最后 append accepted event/completion；任一阶段退出都
只能用原 `P1_COMMITTED` event/request 和原 CAPTAIN capability exact retry，不能手工
`update-ref`、删除 intent/bundle 或换 event ID。frozen read 会验证 ref 仍精确指向
`p1.commit_sha`；即使 disposable worktree/branch 被删并执行 Git GC，bundle 也能恢复
对象。v1 会保留 intent/bundle/completion/ref 至少到整个 Goal 全部 `ARCHIVED`，当前
不自动清理。Codex 创建的是以该本地 ref 为 starting state 的 fresh worktree/branch。
返回后先在 DEV
实际 cwd 核对 `HEAD == task.full_head == p1.commit_sha`，再 `register-role`、
launch-template 和 preflight。若工具不支持 local branch startingState 或实际 HEAD
不一致，立即 `BLOCKED_TOOLING`；禁止退回 `origin/main` 丢掉尚未 push 的 P1 commit。

### 3.1 只在两种 durable handoff 下废止未接受的 P1 commit

`p1-abandon-commit` 不是通用的“取消 P1”按钮。只有原 `P1_COMMITTED` 尚未形成
accepted event，且控制器已持久化下列两种之一，才允许 live FOREMAN 建立 append-only
tombstone：

1. **pre-seal `ABANDON_ONLY`**：原 CAPTAIN transaction 已留下 exact unsealed staging，
   但 commit object、bundle、HEAD/branch 等 carrier 经确定性核验均不可恢复。原
   `P1_COMMITTED` event/request 和**原 CAPTAIN capability**精确重试后，控制器把
   unavailable-carrier marker、residue inventory 与原 authority 一起 seal 成
   `ABANDON_ONLY` intent，返回 `accepted:false`；
2. **sealed normal intent 的 `ABANDON_HANDOFF`**：normal intent 与 bundle 已 seal，
   但 create-only `p1.commit_ref` 已确定性指向另一个 40 位 commit。控制器绝不改写 normal
   intent、绝不覆盖 foreign ref；只有原 event/request/key 与**原 CAPTAIN
   capability**精确重试，才能额外 create-only seal `abandon-handoff.json`。该记录绑定
   request/intent、task anchor、原 CAPTAIN authority、预期 ref/commit 与实测 foreign
   commit，调用返回 `accepted:false`、`abandonment_required:true`、
   `abandon_handoff_sha256` 和 `reason_code=FOREIGN_REF_CONFLICT`。

这一步只是 CAPTAIN 把不可接受 transaction 交给 FOREMAN，并不产生
`P1_COMMITTED`。`status/next/actions/resume` 会把它投影为
`kind=P1_COMMIT_REF`、原 P1 `operation_id/request_sha256`、
`prepared_stage=ABANDON_ONLY|ABANDON_HANDOFF`、`prepared_event_id`、
`intent_sha256`、`commit_ref`、`commit_sha`、`abandonment_required=true`，且 retry 为
`command=p1-abandon-commit` /
`request=NEW_STABLE_ABANDON_ID_WITH_LIVE_FOREMAN_CAPABILITY`。这里的
`intent_sha256` 是 FOREMAN 命令的公开锚点；normal intent 的 handoff digest 已由控制器
从 retained sideband 派生并绑定进 abandonment request，不要求操作员手抄隐藏字段。

FOREMAN 先持久化一个**新的** abandonment event ID，再逐字使用投影中的 intent/ref/head：

```bash
gc_goalctl <controlled-worktree> p1-abandon-commit \
  --goal <goal-id> \
  --task <task-id> \
  --prepared-event-id <原-P1_COMMITTED-event-id> \
  --event-id <fresh-stable-abandon-event-id> \
  --expected-intent-sha256 <pending.intent_sha256> \
  --expected-commit-ref <pending.commit_ref> \
  --expected-ref-head <pending.commit_sha> \
  --thread <live-foreman-thread-id> \
  --reason <durable-reason> \
  --incident-ref <durable-incident-reference> \
  --foreman-capability-file <live-foreman-capability-file> \
  --json
```

FOREMAN capability 只能验证并消费现有 handoff，不能代 CAPTAIN 创建或改写它；CAPTAIN
capability 也不能生成 tombstone。成功回报至少包含 `abandoned:true`、原
`prepared_event_id`、新 `abandon_event_id`、`request_sha256`、`receipt_sha256`、
`commit_ref/commit_sha` 与 accepted abandonment `event_sha256`。若命令在 intent/ref/
completion/ledger 中途退出，pending 改为 `kind=P1_COMMIT_REF_ABANDON`，其 retry 要求
同一 abandonment ID、逐字相同 CLI 参数和原 FOREMAN capability，不能另起 tombstone。

两种 handoff 都是 one-way：carrier 或 expected ref 后来重新出现，原 CAPTAIN exact
retry 仍只返回 `accepted:false`，不能 revive 或 append 原 `P1_COMMITTED`。normal
handoff 下 FOREMAN tombstone 保留当初观测到的 foreign ref；若 ref 后来被改成原 expected
commit，同一 FOREMAN abandonment exact retry 会用 CAS 删除 expected commit；若变成
第三个 foreign commit 则 fail-closed。tombstone accepted 后，原 P1 event 永久以
`P1_COMMIT_ABANDONED` 拒绝，只能按正常 lost/replacement/restart 流程开始新 task cycle。

其它错误（Git/IO 瞬态错误、无法证明的 carrier 状态、非确定性 ref 失败、corrupt
sideband）都**不能**生成 handoff：已经存在 durable P1 partial/odd marker 时，writer
继续保留该 odd generation crash marker，只允许原 transaction exact retry 或显式
audited repair。odd 状态下换 event/request/key 会
`STORE_TRANSACTION_MISMATCH`，错误/替代 capability 会 `CAPABILITY_INVALID`；两者均不
改 generation、intent、handoff 或 ref。禁止删 marker、换 CAPTAIN/FOREMAN capability、
手写 handoff、强推 ref 或把任意失败解释成可 abandon。

成功后才把返回的 `event_id` 发给对方 task。随后重新运行 `status/actions`，不能凭上一条聊天继续猜：

```bash
gc_goalctl <controlled-worktree> status --goal <goal-id> --task <task-id> --json
gc_goalctl <controlled-worktree> next --goal <goal-id> --json
gc_goalctl <controlled-worktree> doctor --goal <goal-id> --json
```

`doctor` 退出 1 表示存在 finding，不是“命令坏了”；退出 2 表示 store/control 无法可信
读取，不能继续使用当前投影。hard hold、身份漂移、陈旧
epoch/HEAD/packet 或 recovery 未闭合时禁止越过控制面。若某条写操作已发布 durable
intent/prepared artifact 但尚未 seal，`doctor` 会逐条输出
`TASK_OPERATION_PENDING kind:stable-id`，`next` 会把同样的
`pending=<kind:stable-id>` 加入 task reasons 并令 `eligible=false`，其它读取面则在
`pending_operations[].retry` 返回 exact retry 身份。必须用原请求、原 capability 和同一
stable ID 做 exact retry；不得另起 ID、跳到下一 task 或先归档。
若进程早在 raw stable ID marker 落盘前退出，安全投影只能返回
`stable_id_sha256`、`stable_id_unavailable=true` 和
`request=EXACT_WITH_PERSISTED_STABLE_ID`；此时必须取调用前自行持久化的原 ID，控制器会
机械核对其 SHA-256。hash 文本本身不是可用的 stable ID。
marker 的 seal/hash 若损坏，两个只读命令也会 fail-closed，不会把未知状态误报为可执行。

若任一只读命令立即返回 `STORE_REPAIR_REQUIRED` 且报告 odd generation /
`writer_crash_marker`，表示上一个 writer 未完成，当前 state **未经验证**。保留 marker
和 stable operation ID，先用同一请求做 audited writer retry；若无法闭合，再走明确的
store repair/broker 流程。禁止删除 lock/marker、手改 generation 或把失败输出当成旧
state 继续调度。

## 4. 启动 DEV / REVIEW / RECEIPT

下面的 dynamic worker bootstrap **只在 fresh Goal 的 committed manifest 显式包含**
以下字段时启用：

```json
{
  "worker_canary_bootstrap": {
    "protocol": "goalctl-worker-canary-bootstrap-v1",
    "policy": {
      "path": "<repo-relative-goal-specific.canary-policy.md>",
      "sha256": "sha256:<64-lowercase-hex>"
    }
  }
}
```

manifest 引用的 committed policy 必须包含下面这一个完全相同的独立行（大小写、空格、
冒号和值都不能改）：

```text
Worker-Canary-Bootstrap-Protocol: goalctl-worker-canary-bootstrap-v1
```

manifest 字段与 policy marker 是双重显式 opt-in；缺任一个时 bootstrap 子命令会
fail-closed，full `canary-plan` 也不接受 bootstrap receipt。legacy
`CANARY_ONLY -> ACTIVE` 只适用于创建前已知 actual cwd，或 full plan 确实不需要绑定
opaque worker branch 的 session；对 DEV/REVIEW/RECEIPT，manifest 一旦 opt in 就始终
要求 receipt，legacy 还要求 manifest 未 opt in。不能把“manifest 没 opt-in”当成让
opaque dynamic worker 走 legacy 的理由。opt-in 必须在 `init` 前随 static package
review/commit；Goal 冻结后禁止原地修改其 manifest 或 goal-specific
`*.canary-policy.md`。需要新 protocol/policy bytes 时，使用新的 committed path/hash
和 fresh Goal。

若该 fresh Goal 需要把当前 GitHub App private-repository metadata 的 exact
`404/repo_not_found` 归类为已知 connector limitation，policy 还必须包含下面这个独立
版本化 marker：

```text
GitHub-App-Known-Limitation: github_app_private_repo_404-v1
```

没有此 marker 的旧 policy 仍可用于 bootstrap，但 `canary-plan` 会输出
`known_limitations=[]`，不会被新 decoder 追溯放宽。未知或重复 marker fail-closed。
full plan 会同时 hash repository metadata 语义 operation、App-last 顺序、补偿 probe
列表和最终聚合条件；它不接受 commit/PR/file/issue read 作为替代。

通过 `goalctl scaffold` 制作静态包时，把完整 `worker_canary_bootstrap` 放进 scaffold
spec 顶层；生成器会验证 policy path/hash/marker 并将字段纳入 deterministic、
可幂等重跑的 manifest。禁止生成后手改 manifest 补字段，否则下一次 scaffold 必然因
输出不再等于 spec 而 fail-closed。

CAPTAIN 在对应 phase：

1. 在创建 worker 前持久化 stable bootstrap operation ID 与 fresh
   64-lowercase-hex challenge，
   先确认 manifest/policy exact opt-in，再用 frozen controller 的
   `canary-bootstrap-plan` 绑定 manifest/role/task/expected HEAD/committed canary
   policy，保存 exact `identity_plan`、`identity_binding_sha256` 与
   `identity_plan_sha256`；
2. 用 Codex App 以 `IDENTITY_ONLY` initial prompt 创建 fresh worker；初始输入只允许它从
   actual cwd 原样运行 plan 的 `canary-bootstrap-inspect` template并返回 exact
   observation/hash，不给 capability/packet/launch，不允许 `resume/event`、gh/App/
   Browser、Git/source/resource/environment动作；
3. CAPTAIN 核 thread/host/cwd 与 observation hash，调用
   `canary-bootstrap-prepare`。controller 先以 durable intent + fenced loose-ref CAS
   transaction 创建 deterministic non-base worker branch。Git ≥2.50 走原生
   `git-update-ref-symref-v1`；Git 2.43–2.49 走 claim-bound
   `git-files-backend-hardlink-head-v1`，仅限 files ref backend、同 filesystem、POSIX
   hardlink/rename，并以 packed/ref/index/HEAD locks + durable completion 恢复 crash。
   receipt verifier 按 claim 中的 protocol 验证，运行中 Git 升降级不切 backend；
   两条路径都 attach exact linked worktree 后 seal 0600 receipt；
   只消费输出的 `worker_bootstrap_receipt_file/sha256` 与 `worker_branch`，不手写 path；
   同时保留 supervisor 原先持久化的 operation/challenge 和完整
   `identity_plan_sha256`。第一次调用 prepare 前，还必须持久化包含
   `expected-observation-sha256`、actual thread/host/worktree 与 Node executable 在内的
   完整 exact argv；首次调用只接受 detached HEAD + absent deterministic target ref，
   不为人工预先 attach 的 branch 回填 provenance。worker不得自行 `git switch/checkout`；
4. CAPTAIN 从该 worker actual cwd 运行 full `canary-plan`，追加 bootstrap
   receipt path/SHA-256、原始 operation/challenge/identity-plan SHA、actual thread/host
   七项原子 binding；operation/challenge/identity-plan SHA 必须复用 supervisor
   创建 worker 前持久化的值，thread/host 只认平台实际 identity，均不得从 receipt 或
   聊天重建。把 exact plan/hash作为该
   worker的**第一条 follow-up** `mode=CANARY_EXECUTE`。full plan 会把 receipt 中完整
   plan preimage 与 supervisor SHA 交叉绑定，并只读复核 claim owner/anchor、single-link
   loose ref、无 packed shadow/reflog/残留 fence、attached HEAD、唯一 branch
   occupancy、registry 与 Git locks。用 `wait_threads` 取得外部权限 canary；FAIL 就 seal 一次
   `BLOCKED_TOOLING` 并停止，不登记、不消费 lease、不换候选循环；
5. PASS 后从该 worker 的 actual process cwd 用 CAPTAIN capability 登记角色；
   DEV/REVIEW/RECEIPT 必须带唯一 `--launch-id`，opt-in route 还必须把 prepare 输出的
   receipt path/SHA 与创建前持久化的 operation/challenge/identity-plan SHA 原样带入
   registration。控制器把 actual thread/host/worktree/gitdir/common-gitdir/branch/initial
   HEAD seal 进 session；同 HEAD 的 CAPTAIN/兄弟 checkout 不能代为登记。保存返回的
   worker `actor_capability_file` 和控制面签发的 `task_nonce`；
6. 准备只含动态环境/target/lease 的
   [`launch-input.example.json`](./goals/example/launch-input.example.json)，再用
   `launch-template` 推导 task nonce、repo/worktree/branch/HEAD、Node/pnpm/lockfile 和已有
   PR binding；
7. role registration 后、提交 `LAUNCH_*` 事件前先跑 preflight；
8. preflight PASS 后才提交 `LAUNCH_*`，再向 worker 发送 `ACTIVE` 启动消息。

`register-role` 的进程 cwd、`launch-template` 与 `preflight` 都必须落在该 worker 的真实
linked worktree；不能在 CAPTAIN 自己的 worktree 里替它登记或推导
repo/branch/HEAD。`register-role --repository-worktree` 可继续指 frozen Goal worktree，
因为控制器另行捕获并核对调用进程 cwd；`launch-template`/`preflight` 的
`--repository-worktree` 则必须是 actual worker worktree。

bootstrap 的三条 controller invocation 与生成的 inspect template 如下；
`<same-...>` 必须逐字复用首次 plan 的 binding，不能从聊天重建。`inspect` 从 worker
actual cwd 运行，`plan/prepare` 的
`--repository-worktree` 始终指 frozen Goal worktree，最终 full `canary-plan` 也从 worker
actual cwd 调用：

```bash
<controller-root>/scripts/goal-control/canary-plan-launch.sh \
  [--node-executable <canonical-absolute-path>] \
  canary-bootstrap-plan \
  --repository-worktree <frozen-goal-worktree> \
  --manifest <manifest> --role <DEV|REVIEW|RECEIPT> --task <task-id> \
  --expected-head <40-sha> --operation-id <persisted-stable-id> \
  --challenge <fresh-64-lowercase-hex> \
  --canary-policy <committed-policy-path> \
  --canary-policy-sha256 <sha256> --json

# worker 的 actual process cwd：只替换两个平台 identity placeholder，
# 然后原样执行 identity_plan.identity_capture.shell_command_template。
# 不得人工重建 canary-bootstrap-inspect argv。

<controller-root>/scripts/goal-control/canary-plan-launch.sh \
  [--node-executable <same-canonical-absolute-path>] \
  canary-bootstrap-prepare \
  --repository-worktree <frozen-goal-worktree> \
  --manifest <same-manifest> --role <same-role> --task <same-task-id> \
  --expected-head <same-40-sha> --operation-id <same-stable-id> \
  --challenge <same-64-lowercase-hex> \
  --canary-policy <same-policy-path> --canary-policy-sha256 <same-sha256> \
  --expected-identity-plan-sha256 <identity-plan-sha256> \
  --expected-observation-sha256 <identity-observation-sha256> \
  --worker-thread <actual-thread-id> --worker-host <actual-host-id> \
  --worker-worktree <actual-canonical-worktree> --json

<controller-root>/scripts/goal-control/canary-plan-launch.sh \
  [--node-executable <same-canonical-absolute-path>] \
  --repository-worktree <frozen-goal-worktree> \
  --manifest <same-manifest> --role <same-role> --task <same-task-id> \
  [--browser-canary-receipt <canonical-absolute-0600-json>] \
  --worker-bootstrap-receipt <canonical-absolute-bootstrap-receipt> \
  --worker-bootstrap-receipt-sha256 <worker-bootstrap-receipt-sha256> \
  --worker-bootstrap-operation-id <same-persisted-stable-id> \
  --worker-bootstrap-challenge <same-fresh-64-lowercase-hex> \
  --worker-bootstrap-identity-plan-sha256 <same-identity-plan-sha256> \
  --worker-thread <actual-thread-id> --worker-host <actual-host-id> --json
```

`identity_binding_sha256` 是对不含生成模板/最终 plan hash 的 identity core 做 hash；
生成器再把它作为
`--expected-identity-binding-sha256 <identity_plan.identity_binding_sha256>` 烤进
`identity_capture.argv_template/shell_command_template`，因此没有“把 plan hash 写回
plan 自身”的循环。`identity_plan_sha256` 则覆盖最终完整 plan（包括 binding hash 与
template），用于核对 initial prompt、`canary-bootstrap-prepare` 的
`--expected-identity-plan-sha256`，以及 full canary 七项 external authority binding。
人工检查必须验证并执行生成的 exact template；
不得把模板参数改成 outer `identity_plan_sha256` 或手拼 launcher argv。

需要显式 Node TCB 时，三条 launcher invocation 都在 launcher path 后、subcommand/
其它 options 前使用完全相同的
`--node-executable <canonical-absolute-path>`；inspect template 已绑定生成 plan 时实际
解析出的 canonical Node executable，worker 不另选。initial
`IDENTITY_ONLY` 与第一条
`CANARY_EXECUTE` follow-up 的可复制 prompt见
[`goal-control-run-goal.md`](./goal-control-run-goal.md#动态-devreviewreceipt-的-worker-bootstrap)。
旧的“initial prompt直接放 full plan”是 legacy route，只兼容创建前已知 cwd、或 plan
无需绑定 opaque branch 的 session，不适用于 opaque dynamic worker。若旧 Goal 的
frozen manifest/policy/protocol 不支持本序列，不得原地修改（尤其不得编辑其
goal-specific `*.canary-policy.md`）；合并 controller/protocol/policy 后初始化 fresh
Goal。

登记 DEV 示例：

```bash
gc_goalctl <frozen-goal-worktree> register-role \
  --goal <goal-id> \
  --task <task-id> \
  --role DEV \
  --thread <dev-thread-id> \
  --host <actual-worker-host-uuid> \
  --attempt 1 \
  --launch-id <launch-id> \
  --event-id <stable-dev-registration-id> \
  --authorizer-capability-file <captain-actor-capability-file> \
  --worker-bootstrap-receipt <canonical-absolute-bootstrap-receipt> \
  --worker-bootstrap-receipt-sha256 <worker-bootstrap-receipt-sha256> \
  --worker-bootstrap-operation-id <same-persisted-stable-id> \
  --worker-bootstrap-challenge <same-fresh-64-lowercase-hex> \
  --worker-bootstrap-identity-plan-sha256 <same-identity-plan-sha256> \
  --json

gc_goalctl <actual-worker-worktree> launch-template \
  --goal <goal-id> \
  --task <task-id> \
  --role DEV \
  --thread <dev-thread-id> \
  --input-file /tmp/<goal-id>-<task-id>-DEV.launch-input.json \
  --actor-capability-file <dev-actor-capability-file> \
  --json > /tmp/<goal-id>-<task-id>-DEV.launch.json

gc_goalctl <actual-worker-worktree> preflight \
  --goal <goal-id> \
  --task <task-id> \
  --launch /tmp/<goal-id>-<task-id>-DEV.launch.json \
  --stage LAUNCH_DEV \
  --evidence-id <stable-launch-preflight-evidence-id> \
  --actor-capability-file <dev-actor-capability-file> \
  --json
```

REVIEW、RECEIPT 同理替换 `--role`、thread、launch 和 stage；每轮 re-review / re-receipt 都用 fresh task、不同 thread 和递增 attempt，不能继承上一轮 verdict。

这里的 `goalctl preflight` 不证明 child 权限继承、`gh`/push、GitHub App、
Browser/Chrome 或 Allow 状态；必须先按
[`goal-control-run-goal.md`](./goal-control-run-goal.md#3-权限-canary-与-goalctl-preflight-的边界)
在该实际 worker 完成独立 canary。

`launch-template` 只读登记态并输出 JSON，不保存 launch、不启动进程、不执行
preflight。只有后续 `preflight` PASS 才会 seal 该 launch runtime。launch URL 禁止
userinfo、fragment 和敏感 query key。`identity_probe.source=test-fixture` 只允许
`GOAL_CONTROL_TEST_MODE=1` 且控制仓、Git 仓都位于可信系统临时目录的隔离测试；
任意 host diagnostics/MCP caller 自行写出的 JSON，即使 hash 自洽也不能充当环境身份
证明，必须接 host broker attestation adapter。executable 必须是可执行普通文件，
browser/electron profile 必须是目录。

### 4.1 同一 worker 的本地 Preview runtime 换代

同一健康 worker session 的本地 Preview 进程已经终止、需要重启，但原 registration 的
launch identity 已经 seal 时，不得拿新 PID 覆盖旧 launch，也不得继续复用旧
`launch_id`；那会得到 `LAUNCH_ID_CONFLICT`。若事故严格落在下面的窄边界，CAPTAIN
可以用 `goalctl rotate-runtime` 把该 session 的 active launch 指针 CAS 到 fresh
successor identity：

`LAUNCH_ID_CONFLICT` 本身不授权任何恢复 lane。controller 会从 current canonical
launch、controller-sealed parent PREFLIGHT registry、deterministic candidate artifact
和 current worker session 重新计算三态分类：只改允许的 source HEAD 且 ancestry 成立是
`SOURCE_ONLY`；source 坐标完全相同、只有 runtime bytes 变化是
`RUNTIME_IDENTITY`；证据缺失/损坏、source 与 runtime 混改或无法唯一证明时是
`UNKNOWN`。只有 `RUNTIME_IDENTITY` 才可能投影 `REQUEST_RUNTIME_ROTATION`；`UNKNOWN`
时 source/runtime 两个 lane 都关闭，`doctor` 报
`LAUNCH_IDENTITY_HOLD_UNCLASSIFIED`，不得按聊天描述或 check name 猜测。

- task 只有一个 hard hold，且它是本次旧 runtime 对应的
  `ENV_IDENTITY_INCIDENT`；
- 角色 session/thread 仍健康，CAPTAIN 与 worker capability 均为 current；这不是
  `ROLE_LOST` 或 successor worker；
- execution 精确为 `environment=none`、`write_mode=NONE`，target 是
  `127.0.0.1` 本地 `PREVIEW`；
- controller 的 `LOCAL_PREVIEW_ZERO_WITNESS` 证明旧 PID、旧 web 端口和派生 proxy
  端口均未占用，并把 predecessor launch/hash、当前 session、hold 与完整 active lease
  set 绑定到同一个 CAS；
- 不涉及 Browser/Electron、profile/CDP、账号、external session、tenant identity 或真实环境。

不要从聊天里发明 stable event ID、successor launch ID 或 CAS。先读
`status/actions/resume` 中的 `REQUEST_RUNTIME_ROTATION`：controller 会投影稳定的
`operation_id`、`event_id`、`successor_launch_id`、exact CAPTAIN dispatch 和完整
`execution_plan.arguments`。heartbeat 只刷新其中的 state revision CAS，不改变语义 ID。
调用方只补 `execution_plan.capability.source=EXACT_CAPTAIN_CAPABILITY` 对应的当前 0600
capability 文件，然后逐字执行：

```bash
gc_goalctl <controlled-worktree> help rotate-runtime

gc_goalctl <frozen-goal-worktree> rotate-runtime \
  --goal <goal-id> \
  --task <task-id> \
  --role <DEV|REVIEW|RECEIPT> \
  --worker-thread <worker-thread-id> \
  --predecessor-incarnation <current-runtime-incarnation> \
  --predecessor-launch <current-launch-id> \
  --expected-predecessor-launch-sha256 <current-launch-sha256> \
  --successor-launch <fresh-launch-id> \
  --hold <env-identity-incident-hold-id> \
  --expected-state-revision <current-state-revision> \
  --expected-control-epoch <current-control-epoch> \
  --reason <reason> \
  --incident-ref <durable-incident-ref> \
  --captain-thread <captain-thread-id> \
  --event-id <stable-runtime-rotation-id> \
  --captain-capability-file <captain-actor-capability-file> \
  --json
```

命令只追加 runtime rotation 记录并切换 active launch identity：旧 launch 仍 immutable
保留；worker 的 thread、attempt、task nonce、actor capability 和 leases 都不迁移、
不释放、不重领。响应丢失只允许原 event ID、原 successor ID、原 capability 和逐字
相同请求 exact retry；不得试另一个 ID 探测。

rotation accepted 后，hard hold **仍然存在**。同一 worker 改用新的本地端口生成 fresh
launch input，逐字消费新的 `REQUEST_RUNTIME_PREFLIGHT.execution_plan`，按顺序运行
runtime broker → `launch-template` → `preflight`；该 action 同时固定 exact DEV executor、
原 lease set、旧 PID/started-at/web+proxy 端口和 successor freshness contract。这条
successor remediation lane 不能触达其它 target，也不能复用旧端口、旧 launch 文件或旧
preflight evidence。runtime successor 的 `preflight` 可省略 `--evidence-id`，controller
会按 `RUNTIME_PREFLIGHT_EVIDENCE_V1` 从完整 exact launch 自动派生稳定 ID；不同 fresh
candidate 得到不同 ID，普通 launch 仍必须显式提供。
fresh preflight PASS 后，FOREMAN 才能提交 fresh `HOLD_RESOLUTION`，并在
`RESOLVE_HOLD.payload.runtime_preflight_evidence_id` 中同时绑定该 successor 的 exact
PREFLIGHT PASS；缺失、旧 launch 或不同 incarnation 的 preflight 都不能解除 hold。然后
重新读取 `status/actions` 继续。任一步失败都保留 hold 并 fail-closed。

`rotate-runtime` 不是通用 process broker，也不是角色/源码恢复。Browser/Electron、
profile、account、external session、真实环境、资源转移或无法取得本地 zero witness 的事故，仍必须
走对应 broker/recovery；禁止用本命令“证明”它们已隔离。

若 packet 声明资源，先获取 manifest 中完全一致的 canonical resource key：

```bash
gc_resourcectl <controlled-worktree> acquire \
  --goal <goal-id> \
  --task <task-id> \
  --role <DEV|REVIEW|RECEIPT> \
  --thread <registered-thread-id> \
  --host <registered-host-id> \
  --resource <canonical-resource-key> \
  --access <EXCLUSIVE|SHARED_READ> \
  --ttl-ms <milliseconds> \
  --event-id <stable-acquire-id> \
  --actor-capability-file <actor-capability-file> \
  --json
```

`--event-id` 必填。调用方必须在第一次调用前持久化它；响应丢失后用同一个 ID
和逐字相同的 owner/resource/access/TTL 参数重试。精确重试返回该 lease 的当前 durable
状态（包括后续 renew/release 后的 revision/status），不会创建第二份 lease。把返回的
lease ID 写入 launch，再 preflight。资源 lease 到期不等于旧进程已隔离；v1 的 `reap`
在 shadow/enforce 都拒绝转手，必须等待资源专用 broker。

resource requirement 带 `roles` 时，只为其中列出的 worker acquire，并且只把当前
launch.role 对应的 leases 写入 launch；省略 `roles` 才表示 legacy 的“所有 worker
（DEV/REVIEW/RECEIPT）都需要”，不包含 CAPTAIN/FOREMAN。已经 accepted 的旧 acquire
event 或 sealed intent 只允许原 stable ID/原参数精确重放；这不授权 fresh control-role
acquire。需要支持 REVIEW_REWORK 时，DEV 资源保持 active，REVIEW/RECEIPT 使用各自
不同的排他 resource id；共享 fixture 才声明为 `SHARED_READ`。

如果 acquire intent 已 seal、但 `LEASE_ACQUIRED` 尚未 append 时原 actor 已过期或终止，
同一 stable ID 的精确重试会返回 durable `status=ABORTED`：它消费该 intent 与 fencing
token，但不创建不可释放的 phantom lease。successor 必须用自己的 fresh event ID 重新
acquire；不得把 `ABORTED` 当成资源授权。

## 5. 候选 HEAD、固定 gates 与证据

候选 HEAD 必须包含当前 DEV 的
`activated_full_head || registered_full_head`；recovered DEV 还必须包含 sealed
`recovery_handoff.import_commit`。只从 manifest 的 provenance `base_head` 或 runtime
`required_start_head` 分叉、但丢掉 P1/import/既有开发提交的 clean sibling 会在
preflight、evidence/gate 和 `DEV_READY` 三层以
`CANDIDATE_HEAD_NOT_DESCENDANT` 拒绝。

先持久化下面四个 evidence ID，再调用任何 adapter；响应丢失后必须用同一 ID 和逐字
相同的参数重试，不能临时生成新 ID：

DEV 完成实现后先提交到 clean worktree、push 并开 PR，然后：

```bash
# DEV：在候选 commit 上用同一个 input 重新生成 launch（同 runtime identity，仅刷新源码 HEAD）
gc_goalctl <controlled-worktree> launch-template \
  --goal <goal-id> \
  --task <task-id> \
  --role DEV \
  --thread <dev-thread-id> \
  --input-file /tmp/<goal-id>-<task-id>-DEV.launch-input.json \
  --actor-capability-file <dev-actor-capability-file> \
  --json > /tmp/<goal-id>-<task-id>-DEV.candidate-launch.json

# DEV：用候选完整 HEAD 的 launch 复跑
gc_goalctl <controlled-worktree> preflight \
  --goal <goal-id> \
  --task <task-id> \
  --launch /tmp/<goal-id>-<task-id>-DEV.candidate-launch.json \
  --stage DEV_CANDIDATE \
  --evidence-id <stable-candidate-preflight-evidence-id> \
  --actor-capability-file <dev-actor-capability-file> \
  --json

gc_goalctl <controlled-worktree> gate-fast \
  --goal <goal-id> \
  --task <task-id> \
  --evidence-id <stable-fast-evidence-id> \
  --actor-capability-file <dev-actor-capability-file> \
  --json

# CAPTAIN：PR 必须已 ready for review，且 Full required check 已绿
gc_goalctl <controlled-worktree> gate-full-ci \
  --goal <goal-id> \
  --task <task-id> \
  --pr <pr-number> \
  --evidence-id <stable-full-ci-evidence-id> \
  --actor-capability-file <captain-actor-capability-file> \
  --json

gc_goalctl <controlled-worktree> gate-ac-audit \
  --goal <goal-id> \
  --task <task-id> \
  --issue <issue-number> \
  --pr <pr-number> \
  --evidence-id <stable-ac-audit-evidence-id> \
  --actor-capability-file <captain-actor-capability-file> \
  --json
```

canonical launch 文件不会被候选提交覆盖。`launch-template` 会复用它的 `created_at` 和全部
runtime/session/resource 字段。按 target kind 分流：`NONE` 只允许
`repository.full_head` 前进且始终禁止 `target.build_head`；`CLI/PREVIEW` 要求
`repository.full_head` 与 `execution.target.build_head` 一起前进；
`BROWSER/ELECTRON` 不允许同-runtime checkpoint，必须走
`FRESH_RUNTIME_RECOVERY_REQUIRED` 投影的 exact `ROLE_LOST(DEV)` 与 fresh runtime/worker
恢复。candidate preflight 的 `launch_uri` 指向 evidence 专属 artifact，并以
`runtime_launch_uri/runtime_launch_sha256` 同时绑定 canonical runtime。正常 commit 后
若尚无当前 HEAD 的 PASS，`status/next/actions` 会投影
`REQUEST_CANDIDATE_PREFLIGHT`：`actor_role=CAPTAIN` 只表示协调，
`dispatch.executor` 指定 exact DEV 执行者。此时禁止 `rotate-runtime`。若 lockfile、
PID/端口、executable、nonce/incarnation、lease、worktree/branch 或其它 runtime 字段
变化，必须走对应的 fresh runtime/角色恢复路径，不能伪装成源码 checkpoint。
其中 live `pnpm-lock.yaml` hash 与 canonical launch 不同时，机器直接投影
`FRESH_RUNTIME_RECOVERY_REQUIRED` +
`ROLE_LOST(DEV, trigger=SOURCE_RUNTIME_BINDING_CHANGED)`，并删除
`REQUEST_CANDIDATE_PREFLIGHT`；CAPTAIN 必须逐字消费该 exact action，再走标准 source
recovery，禁止调用一个必然 `STALE_LAUNCH` 的 candidate `launch-template`。

若旧 decoder 已把纯 source 前进登记成唯一 `ENV_IDENTITY_INCIDENT` hard hold，新
decoder 只有在上述机械分类得到 `SOURCE_ONLY` 后才会投影
`REQUEST_CANDIDATE_HOLD_REVALIDATION`。`RUNTIME_IDENTITY` 必须走 runtime rotation；
`UNKNOWN` 两边都不放行。只有 FOREMAN 能逐字消费 source action：

```bash
gc_goalctl <controlled-worktree> revalidate-source-checkpoint-hold \
  --goal <goal-id> \
  --task <task-id> \
  --thread <foreman-thread-id> \
  --operation-id <action.operation_id> \
  --hold <action.hold_id> \
  --expected-hold-event-id <action.hold_event_id> \
  --expected-canonical-launch-sha256 <action.canonical_launch_sha256> \
  --expected-candidate-head <action.candidate_head> \
  --actor-capability-file <foreman-actor-capability-file> \
  --json
```

该命令在同一事务内重验 hold incarnation、canonical bytes、candidate ancestry 和 runtime
invariant，只登记 deterministic resolution evidence 并 `RESOLVE_HOLD`；它绝不
rotate/restart runtime。任一字段或 live HEAD 漂移都保留 hard hold，并要求按新投影
重试或对新 HEAD 另做 PREFLIGHT。

把四个 registry `evidence_id` 填入 `DEV_READY` 模板后提交。AC audit gate 在 shadow/enforce 下都不发 GitHub 评论；它只生成可安全重放的 sealed evidence。评论发布不属于门禁事务，必须由另一个具备外部幂等 receipt 的动作承担。随后 CAPTAIN 按 `actions` 依次启动 REVIEW、fresh RECEIPT；语义 verdict 先用 `goalctl evidence` 登记并 seal，状态事件只引用 evidence ID。任一 packet/HEAD 变化都必须重新生成受影响的 preflight/gate/review/receipt evidence。

每轮 REVIEW 与每次 RECEIPT 都从 DEV launch runtime 的**当前 candidate branch**创建
fresh worktree，显式传 `startingState.branchName`；新 cwd 必须先证明
`HEAD == task.full_head == PR head`，再 register/acquire/launch/preflight。不得从
`origin/main`、PR merge ref 或旧 verifier branch 开始。REVIEW_REWORK/PASS 与
RECEIPT_FAIL/PASS event 接受后，该 exact terminal attempt 用原 owner+actor capability
release 全部 leases；下一 fresh attempt 可以先 register，但 cleanup 完成前不得
acquire/launch 或复用资源，旧 owner 也不得 App archive。DEV leases 在仍可能返工时保留。

若 `status/next` 或 CAPTAIN 的 `actions` 投影出
`type=REQUEST_RESOURCE_RENEW`，说明一个 active resource lease 已进入当前租期最后
四分之一（最多提前一小时）的 `RENEWAL_WINDOW`，或在唯一 runtime-preservation hard
hold 下满足下述 `EXPIRED_PRESERVATION`。先持久化整行；控制器给出的 `event_id` 已绑定
`lease_id + expected_revision`，不可另造。兼容字段 `actor_role=CAPTAIN` 只表示由
CAPTAIN 协调，**不表示 CAPTAIN 是 `resourcectl renew` 的执行者**。机器调用方应读取
`dispatch.coordinator_role=CAPTAIN`、`dispatch.executor_binding=EXACT_RESOURCE_OWNER`
和 `dispatch.executor.{role,thread_id,host_id}`；只有该 executor 能以
`dispatch.capability_mode=EXACT_OWNER_DUAL_CAPABILITY` 执行。`owner` 保留为向后兼容的
同一身份副本。CAPTAIN 把请求发给 exact owner，由 owner 恢复 owner capability 后以
双 capability 续租：

```bash
gc_resourcectl <controlled-worktree> owner-capability \
  --lease <action.lease_id> \
  --actor-capability-file <action.owner 的 actor-capability> \
  --json

gc_resourcectl <controlled-worktree> renew \
  --lease <action.lease_id> \
  --owner-capability-file <上一步返回的-owner-capability-file> \
  --actor-capability-file <同一个 exact-owner-actor-capability> \
  --expected-revision <action.expected_revision> \
  --ttl-ms <action.ttl_ms> \
  --event-id <action.event_id> \
  --json
```

`ttl_ms` 保持上一租期长度；响应丢失只用持久化行中的原参数与原双 capability 精确
重试。重读后 action 消失或 revision 前进才算完成。普通路径不要等到
`expires_at` 后续租：过期 lease 仍走既有 reap/broker fail-closed 边界。

唯一保全例外是 task 只有一个 `ENV_IDENTITY_INCIDENT` hard hold，exact owner worker
session 仍 active，且 resource ledger 仍是原 `ACTIVE` lease。活 lease 只有已经进入正式
`RENEWAL_WINDOW` 时才能运行 `owner-capability`；尚未到窗口即使知道文件路径也拒绝。
若 TTL 已越界，还必须满足 revision/owner/fencing 未变，且不存在任何其它 `ACTIVE` 且
未过期的同资源 lease，
控制器才会投影 `expiry_state=EXPIRED_PRESERVATION` 的正式
`REQUEST_RESOURCE_RENEW`。owner 只能逐字执行该 action。为避免 worker 丢失本地路径后
死锁，`resourcectl owner-capability` 在上述正式续租边界内仍是 zero-write：它只向同一
active exact owner actor 返回 ledger 已有、verifier 匹配的 capability 文件路径。
CAPTAIN/FOREMAN、同角色 fresh attempt 和其它 worker 仍拒绝；acquire/verify/use/release
也不因此放行。续租只恢复原 lease 的时间有效性，不释放、reap、转移、重新 acquire 或
改变 fencing。任何其它 hard hold、terminal/lost/role lease 过期、newer fencing、竞争
中的 live lease 或非 `ACTIVE` 状态都继续 fail-closed。

若 `status/next` 或 CAPTAIN 的 `actions` 投影出
`type=REQUEST_RESOURCE_RELEASE`，CAPTAIN 必须使用该行的 `lease_id`、`resource`、
`expected_revision` 与 `owner.{role,thread_id,host_id}`，向这个 exact terminal owner
发送释放请求。该 owner 先恢复 owner capability 文件指针，再执行双能力释放：

```bash
gc_resourcectl <controlled-worktree> owner-capability \
  --lease <lease-id> \
  --actor-capability-file <exact-terminal-owner-actor-capability> \
  --json

gc_resourcectl <controlled-worktree> release \
  --lease <lease-id> \
  --owner-capability-file <上一步返回的-owner-capability-file> \
  --actor-capability-file <同一个-exact-terminal-owner-actor-capability> \
  --expected-revision <投影返回的-revision> \
  --event-id <调用前持久化的-stable-id> \
  --json
```

`owner-capability` 允许 exact terminal historical owner 做 `CLEANUP`，但 lease 必须仍是
durable `ACTIVE` 且 task 尚未 `ARCHIVED`；非 owner、同角色 fresh attempt 与 CAPTAIN
均拒绝。它只恢复 owner capability 文件指针，不把 owner 权限授给 CAPTAIN，也不替代
release 所需的 actor capability。普通 TECH/TOOLING 等 hold 仍投影请求并允许
exact-owner cleanup；hard hold 通常隐藏请求且拒绝 owner-capability/release，必须先
机械解除。唯一例外是上文 `ENV_IDENTITY_INCIDENT` 的正式保全续租边界：
活 lease 已进入 `RENEWAL_WINDOW`，或过期 lease 满足 `EXPIRED_PRESERVATION`；active
exact owner 才可 zero-write 恢复已有 capability 路径。release 仍拒绝，不能把该例外
用于 cleanup。
重读控制面确认请求行消失后，fresh attempt 才能 acquire/launch 或复用资源，旧 owner
才能 App archive；fresh registration 本身可提前完成。

## 6. 总表、compact 与 recovery

随时从 append-only events 重建总表：

```bash
gc_goalctl <controlled-worktree> rebuild-ledger --goal <goal-id> --json
```

人读总表位于：

```text
<git-common-dir>/goal-control/v1/goals/<goal-id>/ledger.md
```

它是投影，不可手改；机器真相是 accepted task/control/resource events 与 sealed heads。

普通 compact 不换 thread：新上下文第一条命令重新执行 `resume`，然后只做 `ALLOWED`。不要从聊天摘要恢复职责。

task 真正失联时：

1. `doctor` 确认 finding，提交合法 `ROLE_LOST` 事件；
2. 用授权者登记同角色 `attempt + 1`、不同 thread/host 的 successor；
3. 提交 `ROLE_RECOVERED`，再由 successor 执行 `resume/actions`；DEV successor 例外：
   首先只得到 `RECOVERY_BLOCKED` cleanup，不能开始开发，按下文 sealed handoff 闭环推进；
4. FOREMAN successor 只能使用初始化时单独保存的 `foreman_recovery_capability_file`。

### Generation odd：先判 witness / pristine，再按固定策略恢复

看到 `STORE_REPAIR_REQUIRED`、`STORE_TRANSACTION_MISMATCH`、
`STORE_PRISTINE_RECOVERY_*` 或 writer crash marker 时，先停止其它 writer，保留原命令
的 stable operation ID、完整参数和 capability 文件。不要换 event ID、换 identity、
试另一个 capability，也不要手改/删除 `.generation.json`。该文件的奇数 generation
表示原 writer 未闭合；v3 odd 中 `updated_at` 就是不可变
`transaction_started_at`，不是重试时间。

恢复决策只使用下面的固定矩阵。`RESUME_AT_START` 表示同一 odd transaction 从 callback
起点重跑；`ABORT_THEN_FRESH` 表示 controller 先以零 payload 写关闭已认证的 pristine
odd，再由 wrapper **至多一次**用当前事实创建 fresh transaction。二者都是控制器内部
策略，operator 不手工构造 `STORE_PRISTINE_ABORT_RETRY`，也不在失败后自行无限循环。

| operation boundary | v3 pristine 策略 | durable partial 已存在时 | 必须重验 / 禁区 |
|---|---|---|---|
| allowlist 内的普通 Goal event、deterministic rejection receipt、`init`、`register-role`、`control`、`recover-expired-foreman` | `RESUME_AT_START` | 用 accepted event、receipt、registration/recovery/control intent 等 exact **WITNESS** 恢复 | 同 stable ID/request/key/capability；有 actor/lease 的入口按 `transaction_started_at` 验证原边界资格。`P1_COMMITTED`、`MERGED` 和内部 reservation 不属于“普通 event” pristine allowlist |
| resource `acquire` / `renew` | `ABORT_THEN_FRESH` | 已有 resource intent/event 时按 exact **WITNESS** 完成或返回原结果 | 旧 authority 只用于证明可关闭原 odd；fresh attempt 重新检查当前 actor、lease revision/TTL、hold、scope 和冲突资源 |
| resource owner `release`、zero-runtime `reinitialize` | `RESUME_AT_START` | 已有 resource event 时按 exact **WITNESS** | 只允许原 owner/双 authority 绑定的 cleanup；仍须满足 operation 自己的 terminal、scope、零非终态 lease/broker 条件，不因此转移资源 |
| launch `preflight` ingress | `ABORT_THEN_FRESH` | prepared preflight 或 evidence registry 是 **WITNESS** | fresh attempt 重新检查当前 launch identity、HEAD、lease、resource、可执行文件与 live checks；旧 PASS 不继承 |
| `gate-fast` / `gate-full-ci` / `gate-ac-audit` ingress | `ABORT_THEN_FRESH` | prepared gate artifact 或 evidence registry 是 **WITNESS** | fresh attempt 重新绑定当前 candidate HEAD、producer identity、固定 adapter 与 live test/check 结果 |
| `goalctl merge-pr` 尚无 intent/reservation 的最初边界 | `RESUME_AT_START`，但只允许重新做只读 preflight并先 seal intent + append-only reservation | intent、reservation、invocation、receipt、accepted `MERGED` 各自是后续 **WITNESS** | reservation/invocation 前禁止外部 merge dispatch；一旦可能已 dispatch，pristine 绝不能证明 GitHub 未写，必须查询 provider并沿同 request/receipt 闭环 |
| source export/import/checkpoint/bind/abandon/promote | **不允许 pristine** | 只按 operation-specific sealed binding、snapshot、intent、receipt、checkpoint/event **WITNESS** exact retry | 缺 witness、foreign staging、source/worktree/identity 漂移就保留 odd并进入 audited repair；禁止从聊天重写 source |
| mechanical P1 commit/ref/abandon | **不允许 generic pristine**；`START_P1/P1_READY/P1_APPROVED/P1_RESTARTED` 仍按上面的普通 Goal event 规则 | `P1_COMMITTED` 只认 retained intent/bundle/ref/handoff/completion/accepted-event **WITNESS**；abandon 走既有两种 handoff | 与 §3.1 一致：不能用 pristine 绕过 carrier/ref CAS、代原 CAPTAIN、revive tombstone 或新建 event ID |

所有 pristine 路径都必须同时满足：v3、exact transaction key、当前 control payload vector
等于 sealed `pre_write_vector_sha256`、以及 callsite 专用 authority 检查。PRISTINE
**只证明 control payload 未写，不证明 GitHub、Git ref、source worktree、Preview、Browser、
external session、host-authorized environment 或其它外部 target 没有副作用**；无法由该 operation 的 durable witness
证明外部结果时保持 fail-closed。

错误 request/key、vector、capability/authority 或原边界资格一律零 control write
拒绝，generation 保持 odd。v1 odd 没有 transaction binding，只能 audited repair；v2
odd 没有 pre-write vector，只能 exact witness 或 audited repair，二者都禁止 pristine。
compact、successor 接力或 controller 异常退出后，先重读 `role-kernel.md` 和本节，再按
`pending_operations` 提供的原 stable ID exact retry；聊天中的“应该没写过”不构成证明。

### FOREMAN + CAPTAIN 同时过期

若旧 FOREMAN 和 CAPTAIN 的 lease 都已失效，旧角色不能再补 heartbeat，也没有一方能
替另一方提交 `ROLE_LOST`。先保持 task 停止；不要手改 `state.json`、event ledger、系统
时间或旧 session identity。创建一个全新 successor FOREMAN thread，先在控制面外持久化
一个唯一的 root recovery ID，然后从**同一次** `status --json` 快照记录
`control_epoch` 与 `foreman_recovery_scope.scope_sha256`：

```bash
gc_goalctl <frozen-goal-worktree-absolute-path> status \
  --goal <goal-id> \
  --task <task-id> \
  --json

gc_goalctl <frozen-goal-worktree-absolute-path> doctor \
  --goal <goal-id> \
  --json
```

`foreman_recovery_scope` 是所有 task FOREMAN 投影的规范化 Goal-wide CAS；不要从多个
status 结果拼接。`--task` 只是 root transaction 的 anchor/adoption target，不把恢复
缩小成单 task。用新的 successor FOREMAN identity 执行：

```bash
gc_goalctl <frozen-goal-worktree-absolute-path> recover-expired-foreman \
  --goal <goal-id> \
  --task <task-id> \
  --thread <fresh-foreman-thread-id> \
  --host <foreman-host-id> \
  --attempt <old-foreman-attempt-plus-1> \
  --lease-ms <lease-ms-at-most-14400000> \
  --expected-goal-scope-sha256 <foreman-recovery-scope-sha256> \
  --reason <audited-recovery-reason> \
  --incident-ref <durable-incident-reference> \
  --foreman-recovery-capability-file <foreman-recovery-capability-file> \
  --event-id <persisted-stable-root-recovery-id> \
  --json
```

`--expected-goal-scope-sha256` 是必需的 Goal-wide CAS。`--expected-control-epoch` 和旧版
per-task `--expected-*` 都只是可选兼容 guard；需要额外审计时可从同一快照传入，但不能
替代 scope hash，也不能混用不同快照。

命令只有在 frozen inputs 未漂移、旧 FOREMAN 已过期、没有可闭合当前状态的有效
CAPTAIN 常规恢复路径、Goal-wide scope CAS 精确匹配、新 thread 从未在 Goal 中使用，
且全部非 `ARCHIVED` FOREMAN 投影属于同一 identity/attempt/capability lineage 时才接受。
普通 batch 的 target 精确等于所有**非 `ARCHIVED` 且已有 current FOREMAN projection**
的 task（即 scope 的 `recoverable_task_ids`），不是所有非归档 task。控制器先发布
durable root intent，再只为这些 target 追加独立 accepted event，最后发布 commit；没有
projection 的其它非归档 task 之后仍按 projection 注册。若 Goal 已无 current projection，
唯一例外是显式 anchor 可从当前最大 attempt 的 `ARCHIVED` lineage adoption 成为一个
新 projection。中途崩溃会冻结其它写入，只允许同一 ID/request/recovery capability
继续完成。其余 `ARCHIVED` 投影保持 byte-identical。命令不会创建 Codex thread，也不
需要过期 predecessor CAPTAIN 确认。

root intent 与 successor FOREMAN capability 本身也先作为 request-bound private staging
一起 seal；在 canonical batch rename 前退出时，精确重试验证 Goal scope、successor、
request、capability 最终路径/bytes 后提升原树。任何 prepared/canonical root batch
pending 都冻结整个 Goal 及 resource/source writer；不能另起 recovery ID，也不能靠删除
staging 解锁。

已有 pending recovery 不会被覆盖：FOREMAN pending 由该原子事件闭合；CAPTAIN pending
保留给 successor FOREMAN 继续；DEV/REVIEW/RECEIPT pending 暂存进
`recovery_backlog`。backlog 存在时 worker verdict 一律被拒，successor
FOREMAN/CAPTAIN 恢复完成后原 pending 自动回到当前 recovery 槽。

成功输出的 `actor_capability_file` 属于 successor FOREMAN。随后严格按顺序恢复，不得跳级：

**已有 pending recovery 就复用；只有没有 pending recovery 才提交 `ROLE_LOST`。**
这里的“提交”也不是手工拼 payload：先从 successor FOREMAN/CAPTAIN 的 `actions` 或
`resume.allowed_actions` 取得 `type=ROLE_LOST` 的完整行，逐字使用其中的稳定
`event_id` 与 `payload` 执行
`event-template -> event`。该动作绑定目标 thread/host/attempt/原 lease deadline；若返回
`ROLE_LOST_TARGET_STALE`，说明目标已 heartbeat 或换代，必须丢弃旧行并重新读取投影，
不得换一个 event ID 重放旧 payload。live ingress 会拒绝缺任一 exact-target 字段的新
`ROLE_LOST`；只有已经存在于 append-only ledger 的历史旧格式 event 才能以同 ID、同
input hash 和原 capability 做幂等重放。

`ROLE_LOST` 只会在机械条件成立时出现在可执行 actions：目标 lease 已过期、目标已用
heartbeat 持久化 `systemError`，或 recovery backlog 明确要求替换 predecessor
CAPTAIN。仍是未过期 `active|idle` 的角色没有可执行 lost action；聊天或 thread UI
观察不能伪造成控制面 signal。

FOREMAN 是 Goal-wide replica：若只有当前 task 投影为 `systemError`，而同
identity/current attempt 在其它 task 仍有可用 replica，读取该 task 的 maintenance
actions 并执行 `GOAL_FOREMAN_REPLICA_REPAIR` exact heartbeat；不得把一个局部投影误做
Goal-wide replacement。若 current generation 的全部 coherent replica 都是
`systemError`/不可用：live CAPTAIN 仍优先提交 exact `ROLE_LOST(FOREMAN)`；没有 live
CAPTAIN 时，只有全部 source replica 的 exact lease deadline 都已客观过去，独立
`recover-expired-foreman` 才开放。任一同代 replica 尚有有效 lease 时 root recovery
保持关闭。

1. successor FOREMAN `resume/status/next/doctor` 后以 machine state 为准恢复 CAPTAIN：
   若已存在 pending CAPTAIN recovery，且 fresh successor CAPTAIN 已登记，就直接提交
   `ROLE_RECOVERED`；若 pending 但尚无 successor，则登记后提交 `ROLE_RECOVERED`；只有
   没有 pending CAPTAIN recovery 时才先提交 `ROLE_LOST(CAPTAIN)`，再登记 successor
   CAPTAIN 并闭合；
2. successor CAPTAIN `resume/actions` 后同样以当前 recovery/backlog 为准恢复
   DEV/REVIEW/RECEIPT：
   已有 fresh successor 就直接闭合；旧 worker 尚未进入 recovery 时才先提交相应
   `ROLE_LOST`；否则登记 fresh successor 后闭合；
3. `ROLE_RECOVERED(DEV)` 后 successor DEV 先保持 `RECOVERY_BLOCKED`，不得进入原
   worktree 或继续 dirty source。successor CAPTAIN 用
   `goalctl recovery-export-source ... --snapshot-id <stable-operation-id>
   --captain-capability-file <captain-capability-file>`
   从 predecessor canonical worktree 导出绑定精确 `source_observed_head` 的 sealed
   immutable snapshot。snapshot ID 必须在首次调用前持久化。publish 后响应丢失时，只能
   用同一 ID/参数/原 capability 精确重试；它重验 durable artifact 与 current/history
   authority，不重读已变化或消失的 source。若该 worktree 已被 Codex archive 回收，只能改用
   `goalctl recovery-export-codex-rollout --predecessor-launch <id>
   --predecessor-thread <id> --rollout-file <absolute-jsonl> ...`。该 broker 会绑定 lost
   lineage 并机械校验全部成功 patch 记录；它只恢复 tracked update，target 内
   add/delete/move、缺失或篡改记录立即停止，禁止按聊天内容手抄。若 rollout 另含 shell、
   `write_stdin`、跨 session send 或 outcome 不明的纯外部 patch，strict export 默认拒绝。只有
   `recovery-inspect-codex-rollout --allow-shell-audit` 列出的每条 exact call/result 都由
   successor CAPTAIN 逐条审计、successor FOREMAN 以 active capability 联合授权，并通过
   `--shell-audit-file ... --foreman-capability-file ...` 提交时才可继续；audit 只允许
   `READ_ONLY/IGNORED_PATH_ONLY/TEST_NO_UPDATE`，且必须断言 source untracked 为空。audit
   和全部原始记录会进 snapshot，import 再重验；只有内建 `tool_search`、plan 更新和
   terminal 只读读取可自动排除。任何未建模 tool call、漏项或 target/mixed patch
   outcome 不明仍永久 fail-closed。若 predecessor 自身来自上一轮 recovery，注册 HEAD 与被
   promotion seal 的 launch checkpoint 分开记录；只接受 promotion 之后的 target patch；

   export staging 在写 patch 前先落 `operation-binding.json`，其自 seal 同时绑定 stable
   ID、export kind、精确 CLI request 和完整 source/input/authority execution context。
   request-bound v2 目录、canonical marker 及唯一合法 atomic temp 都可被 exact retry
   机械识别；完整 `snapshot.json` 若停在 fsynced atomic temp，source/旧 actor 后续消失
   也可验证后提升。cross-kind、wrong request、source drift、权限漂移、lookalike 或多份
   staging 都保持 byte-identical 并停机。安全清理先原子 claim 到 deterministic discard，
   cleanup 自身崩溃也可幂等完成，不留永久 blocker。

   `inspect` 只列事实，不生成授权。先按它返回的 exact 顺序准备最小 dispositions 文件：

   ```json
   {
     "asserted_untracked_empty": true,
     "calls": [
       { "call_id": "call-001", "disposition": "READ_ONLY" },
       { "call_id": "call-002", "disposition": "TEST_NO_UPDATE" },
       { "call_id": "call-003", "disposition": "IGNORED_PATH_ONLY" }
     ]
   }
   ```

   再由固定 builder 补齐 line、name、call/result hashes、rollout/patch hashes 和确定性时间：

   ```bash
   gc_goalctl <controlled-worktree> recovery-build-codex-shell-audit \
     --goal <goal-id> \
     --task <task-id> \
     --predecessor-launch <lost-launch-id> \
     --predecessor-thread <lost-dev-thread-id> \
     --historical-worktree <lost-worktree-absolute-path> \
     --predecessor-head <40-char-launch-head> \
     --rollout-file <absolute-rollout-jsonl> \
     --captain-thread <active-captain-thread-id> \
     --foreman-thread <active-foreman-thread-id> \
     --incident-ref <durable-incident-ref> \
     --dispositions-file <absolute-dispositions-json> \
     --output-file <absolute-final-audit-json> \
     --json
   ```

   builder 不读写 control store；最终 `recovery-export-codex-rollout` 仍必须用 active
   CAPTAIN+FOREMAN capabilities 对当前 state 与这份 audit 做联合绑定。
4. 在不同 worktree、不同 branch、起点精确为 `source_observed_head` 的位置，successor
   DEV 用 dormant identity 授权 fixed controller adapter 调用
   `goalctl recovery-import-source ... --import-id <stable-operation-id>
   --actor-capability-file <dev-capability-file>`
   验证并只 materialize snapshot 明列的 exact paths，要求 index tree 等于 snapshot
   `expected_tree`、无额外 staged/unstaged/untracked path，再写 sealed receipt；该命令
   不自动 commit，也不激活或唤醒 successor DEV。import ID 必须在首次调用前持久化并直接
   成为 receipt ID。receipt 已发布时，同一 destination worktree/branch、ID/snapshot 与原 DEV
   capability 可在 commit、promotion、terminal 后返回原 receipt；完整 staged tree 已
   写完但 receipt 尚未发布的 crash 可只补 receipt，partial/异文状态不 reset、不覆盖。
   import mutation 前先发布由 import ID、snapshot、successor、destination identity 与
   sealed DEV authority 绑定的 durable intent；其 deterministic staging、完整合法 atomic
   temp 和 canonical intent 都只允许原请求 exact retry。若 crash 发生在 intent fsync 与
   rename 之间，即使 DEV lease 后续过期也提升同一 intent，不删除重建。若 crash 早到
   staging 尚无 canonical binding，`pending_operations` 只能公开
   `stable_id_sha256 + stable_id_unavailable=true`；调用方必须使用首次调用前自己持久化的
   原 ID，hash 不能冒充 CLI ID。
   receipt seal 完成后，仍由 dormant successor DEV identity 调用固定 checkpoint adapter：

   ```bash
   gc_goalctl <fresh-destination-worktree> recovery-checkpoint-source \
     --goal <goal-id> \
     --task <task-id> \
     --successor-thread <successor-dev-thread-id> \
     --snapshot <snapshot-id> \
     --import-receipt <import-receipt-id> \
     --actor-capability-file <dev-capability-file> \
     --json
   ```

   adapter 重验 sealed v3 snapshot/receipt、destination branch/HEAD/index 与 DEV authority，
   从 receipt 固定 commit identity/time/message，并固定 UTF-8 encoding，以 `commit-tree` 创建
   `source_observed_head` 单 parent、`expected_tree` 精确 tree 的 checkpoint，再用
   old-value `update-ref` CAS 发布；空 snapshot 走同一确定性 allow-empty 路径。响应丢失
   后同参数重试返回同一 `checkpoint_sha`，任何额外 dirty path、HEAD/ref/receipt 漂移都
   fail-closed，不 reset 或覆盖。destination 存在 `MERGE_HEAD`、rebase、cherry-pick、
   sequencer、bisect 等 hidden Git operation sentinel 时，即使 porcelain/index 看似 clean
   也拒绝。destination 必须是拥有专属 gitdir 的 linked worktree，禁止对 main/common
   gitdir 建 fence。初始 index/tree/diff 验证后，adapter 先在 control root durable seal
   request-bound `prepared.json`，再取得带 seal token 的 worktree-specific `index.lock`，
   并临时移除该 linked-worktree gitdir 的全部 write bits；随后在双 fence 内重新核对
   index hash、sentinel、branch/HEAD，以 common-gitdir old-value ref CAS 发布 checkpoint，
   并用 `--create-reflog` 保证 branch reflog 留下含 receipt ID 的记录；linked-worktree
   私有 `HEAD` reflog 不作为控制面证据。完成最终 clean 检查后 seal `completed.json`，
   恢复 gitdir 原 mode 并只释放自己 token
   绑定的 lock。这样写 index 的 Git 命令被 `index.lock` 挡住，只写
   `BISECT_START` 等 sentinel 的普通 Git 命令也无法在最后检查与 ref 发布之间插入。
   `prepared` 未 completion、或 completion 后尚残留 fence 时投影
   `SOURCE_CHECKPOINT pending`，冻结其它 writer；SIGKILL 后仅原 snapshot/receipt/request
   可接管。既有/异文 lock、缺 lock 的 fenced gitdir、mode/dev/inode 漂移均保留现场并
   fail-closed，绝不猜测 stale 或代为删除。`completed.json` 只证明 request 曾发布；
   精确重试仍核对 live branch，退回 sealed base 时重新 CAS 同一 checkpoint，第三方 HEAD
   一律拒绝。该机制只保护最终验证、CAS 与 completion 的临界区；恢复 gitdir 写权限是
   release 点，之后到 bind 之间的新 mutation 由 `recovery-bind` 再验证并 fail-closed。
   同 UID 主动 chmod/直写 `.git`、ACL 额外授权或跨命令持续排他仍须独占执行环境或 host
   broker，不能把用户态 fence 冒充 OS 隔离。旧 receipt 所指 disposable worktree 可以已消失；当前
   destination 仍必须存在且精确匹配；
5. successor CAPTAIN 先持久化 operation ID，再调用 `goalctl recovery-bind ...`，显式传入
   `--event-id <stable-id>`、`--import-commit <checkpoint-sha>` 和
   `--captain-capability-file <captain-capability-file>`，由控制器再验证
   receipt、staged tree 和 checkpoint，提交
   `RECOVERY_HANDOFF_BOUND` 后，successor DEV 仅进入
   `PREFLIGHT_ONLY`。此时只允许 fresh acquire、launch-template、preflight/PREFLIGHT
   evidence 与 cleanup；HEAD 必须保持精确等于 import checkpoint，identity 已冻结，
   `next/actions` 不再提供 `ROLE_LOST`；
6. fresh launch、完整 manifest leases 和确定性 preflight PASS 后，successor CAPTAIN
   先持久化新的 operation ID，再用 `goalctl recovery-promote ... --event-id <stable-id>
   --captain-capability-file <captain-capability-file>` 提交
   `RECOVERY_PROMOTED`。只有 scope=`FULL` 后才唤醒
   successor DEV 做源码、测试、commit、push、`DEV_READY`。所有 predecessor control
   actor 和旧 worker identity 均不得复用。

Codex handoff 会返回新 thread identity，不能把它当成已登记 successor DEV，也不能复用
其 capability。若 dormant successor DEV 在 `RECOVERY_BLOCKED` 且尚未 bind 时被 handoff
替换，先登记 fresh replacement DEV：recovery 的 `source_predecessor` 仍固定为最初 lost
DEV，controller 在 append-only `recovery_chain` 记录
predecessor→successor→replacement，fence 被替换 successor，并使其 identity-bound
receipt/checkpoint 失效；replacement 从同一 sealed source snapshot 重做未绑定步骤。若
已经进入 `PREFLIGHT_ONLY`，直接 handoff/thread replacement 仍 fail-closed：停止，不迁移
launch/lease/evidence，
不得继续 `recovery-promote`。若 successor 已永久丢失且 handoff 尚未 promotion，先确认
其名下没有非终态 resource lease，再由 active successor CAPTAIN+FOREMAN 显式废止
binding：

```bash
gc_goalctl <bound-destination-worktree> recovery-abandon-handoff \
  --goal <goal-id> \
  --task <task-id> \
  --successor-thread <lost-successor-thread-id> \
  --captain-thread <active-captain-thread-id> \
  --foreman-thread <active-foreman-thread-id> \
  --captain-capability-file <captain-capability-file> \
  --foreman-capability-file <foreman-capability-file> \
  --reason <audited-reason> \
  --incident-ref <durable-incident-ref> \
  --event-id <persisted-stable-abandon-id> \
  --json
```

成功后 scope 只退回 `RECOVERY_BLOCKED`；旧 handoff 留在 append-only history。此时才走
普通 `ROLE_LOST` → fresh attempt registration → `ROLE_RECOVERED`，并从 identity-bound
步骤重新开始。命令不会转移 runtime、resource、launch、receipt、preflight 或源码权限。

这条命令只恢复控制身份。它不释放或转移任何 port/profile/account/external-session/UI lease，不启动
Preview，不登录、不操作 external session、不做环境写；这些动作继续 fail-closed，直到资源隔离、
lease 和 launch identity 按正常流程重新验证。多 task Goal 的 FOREMAN 是一份
Goal authority 的 coherent replicas；禁止拆成多次单-task recovery 调用。

`resourcectl reinitialize-zero-runtime ...` 不是通用撤销器。它只在旧 launch 同时为
`target=NONE/environment=none/write_mode=NONE`、sealed lease set 为空、lost owner
没有非终态 lease 时返回 `no_op=true`；它不会写 `LEASE_SET_REVOKED`。只要旧 launch
列过任何 lease（包括已过期或已 `RELEASED`），或存在真实 target，就必须由对应 host
broker 机械 fence。仓内控制面无法机械阻止同一用户直接调用 Browser/Chrome/MCP，所以
`FULL` 前不得唤醒 successor 或交付任何外部资源 capability。

若旧账本已经含历史 `LEASE_SET_REVOKED`，新 decoder 会保留原事件并将 lease 隔离为
`UNVERIFIED_REVOKE`。看到该状态或 `RESOURCE_BROKER_REPAIR_REQUIRED` 时必须停在 broker
边界；它不是可复用的 terminal lease，也不能靠再次 acquire、TTL 或角色恢复绕过。

已运行中的 Goal 冻结的是初始化时 protocol/packet 的 bytes；修复版控制器代码与旧 Goal
worktree 可能来自不同 commit。此时必须从**包含该 event decoder 的新代码版本**启动
`goalctl`，并始终用 `--repository-worktree` 指向仍保留冻结 bytes 的旧 Goal worktree。
不能从旧 controlled worktree 的 package scripts/PATH 解析旧 controller（它不认识新
event），也不能把 cwd 换成已
更新 protocol 文档的新 worktree（会触发 `PROTOCOL_DRIFT`）。根恢复后的
`status/doctor/event/register-role/resourcectl` 也继续使用同一新 binary + 同一
`--repository-worktree`，直到该 Goal 结束。

用户改变 Goal 指令时，FOREMAN 先持久化稳定 event ID，再运行
`goalctl control ... --event-id <stable-id>` 提升 epoch，然后逐 task
`CONTROL_RECONCILED`；旧 epoch 的异步结果会被拒绝。响应丢失只用同一 ID/request 和原
FOREMAN capability 历史精确重试。控制面不会自动 spawn、send 或替你判断失联。

## 7. Merge 后机械归档

`repository.merge_policy=goalctl-github-squash-v1` 的 Goal 只能由当前 live FOREMAN
运行 canonical wrapper：

```bash
gc_goalctl <controlled-worktree> merge-pr \
  --goal <goal-id> \
  --task <task-id> \
  --thread <foreman-thread-id> \
  --event-id <stable-merge-event-id> \
  --expected-state-revision <revision> \
  --expected-control-epoch <epoch> \
  --actor-capability-file <foreman-actor-capability-file> \
  --json
```

调用前持久化 `event-id`。wrapper 从 sealed manifest/state 派生 canonical repo、PR、
base 与 expected head，不接受调用方覆盖。它先写 durable intent，随后以固定
`--squash` + expected-head match 执行 GitHub merge。GitHub 不提供 exact base CAS；
wrapper 在 dispatch 前最后双检 `ls-remote` + PR，仍明确保留“观察后、GitHub 接受前”
base 前移的 provider race，不能把它描述为原子消除。外部结果经独立 fetch、remote ref、
commit parent/tree 与 patch 边界核验后写 durable receipt，最后才以同一 event ID 接受
`MERGED`。任一阶段响应丢失都只用原 ID、原请求和原 FOREMAN capability exact retry；
wrapper 会从 intent/receipt 或 GitHub 已合并状态恢复，不盲目重复不可逆动作。

禁止直接运行 `gh pr merge` 后手写 `MERGED`，也禁止
用 `goalctl event` 提交携带 `MERGED` 的 raw event、`--admin`、`--auto`、
`--delete-branch` 或追加任意 gh 参数绕过边界。intent 已存在但未闭合时，
`status/next/actions/resume/doctor` 会暴露 pending operation；先按其中 stable ID
精确重放，不能继续普通事件或归档。

先提交并确认 `MERGED`；该不可逆边界会机械把仍 active/idle 的 DEV 置为
`terminal/TASK_MERGED`，使其 exact owner cleanup 合法，REVIEW/RECEIPT 则已在 verdict
边界 terminal。随后释放或由 broker 隔离该 task 的全部 resource leases，确保控制
worktree clean，再运行同一快照的 `status --task ... --json` 与 `doctor --json`：
该 task 及 Goal-wide `pending_operations` 必须均为空，`doctor` 必须 healthy/退出 0。
若存在 durable pending operation，先按其 stable ID、原请求和原 capability exact retry；
即使它原本是 archive allowlist 内操作，也不能先提交 `ARCHIVED`。FOREMAN 再用
`goalctl evidence` 登记绑定当前 packet/HEAD、状态
`PASS`、kind=`MERGE_BOUNDARY` 的持久 archive evidence，并把返回的 `evidence_id` 放入
`ARCHIVED` event。控制器只在 merge、DEV/REVIEW/RECEIPT 证据链、archive evidence、
clean worktree、零 pending durable operation 和零非终态 resource lease同时满足时接受。

只有 `status` 已显示 `phase=ARCHIVED` 后，才在 Codex App 归档该 task 的
DEV/REVIEW/RECEIPT/CAPTAIN。Goal 级 FOREMAN 可能仍是后续 task 的授权/control anchor；
只要 Goal 还有未归档 task，就保留其 task/session 并继续合法 HEARTBEAT，不能因为当前
task 已归档而提前 archive。全部 Goal task 都已机械归档且不再需要 control 后，才归档
FOREMAN。App archive 可能物理删除 worktree；它不是 interrupt、cancel 或“稍后再继续”。
