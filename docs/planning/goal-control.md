# Goal 控制面 · v1 运行契约

> 本文件定义 Goal 总工头、每 task 一个 `CAPTAIN`、DEV、REVIEW、RECEIPT 之间的机器运行真相。业务语义与外部权限仍由受控仓中已提交并绑定 hash 的 host constitution、host policy、Spec、Acceptance、Plan 和不可变 task packet 决定；聊天、session 摘要和本地 rollout JSONL 都不是状态源。

## 1. 设计目标与边界

控制面只做四件事：验证静态 Goal DAG 与 task packet、按角色和 CAS revision 接受事件、计算下一合法动作、管理本地运行身份与排他资源。它不理解业务代码、不替代 REVIEW/RECEIPT，controller binary 也不直接调用 Codex App 工具。启用自动运行后，FOREMAN/CAPTAIN 必须在控制面投影允许时自主调用 `create_thread`、`wait_threads`、`send_message_to_thread` 和 archive；正常流程不得要求用户逐步点击或转发消息。

本轮明确不做：

- 不解析 `~/.codex/sessions/*.jsonl` 推断状态；
- 不依赖实验性 Codex App Server 运行消息 daemon；
- 不从 implementation plan 的自然语言或 Mermaid/ASCII 图临场猜 DAG；
- 不把进度、thread、PR、HEAD、profile 或 lease 写回不可变 packet；
- 不把逻辑角色绑定描述成抵御恶意本地进程的安全认证。v1 防的是误投、重放、陈旧事件和职责漂移；`0600` capability、公开状态脱敏、event hash chain 都不是同一 OS UID 下的敌对隔离边界。同 UID 恶意进程防护必须由控制 broker、App 签发的 session 身份或 OS 隔离提供，并使用角色无法读取的签名密钥。

## 2. 三层数据模型

### 2.1 Goal manifest：版本化静态 DAG

manifest 放在仓库内并经过 review，至少包含：

```text
schema_version / goal_id / mode / repository / base_head
tasks[]: id / dependencies / integration_order / risk_class / resource_requirements /
         packet { revision, path, sha256 } / optional p1
```

受控仓还必须提交 protocol-pack binding 与 host policy binding：记录每个 portable
protocol 文件的 repo-relative path + SHA-256，以及 host constitution/policy 的
repo-relative path + SHA-256；task packet 重复引用该绑定，Goal 初始化后不得从 controller
checkout 的可变文档补读。若当前 manifest schema 尚未提供独立字段，就把 binding 作为
packet 的不可变权威输入并由 packet hash 间接 seal；不得用聊天或本机路径替代。portable
protocol 只定义协调规则，不授权 host 的环境、账号、浏览器、外部会话、API 或数据写入。

`mode` 支持 `shadow|enforce`，省略时默认 `shadow`。scaffold spec 明写 `enforce` 时，
命令还必须显式带 `--allow-enforce`；缺少该确认会在任何目标输出前 fail-closed，不会
静默降级、覆盖既有包或把 flag 当成外部副作用授权。`enforce` 只表示状态、动作和 merge
precondition 以控制面为权威；controller binary 仍不直接调用 Codex
thread/send/archive，但自主 FOREMAN/CAPTAIN 会按机器投影调用它们。任何调用都不能绕过
capability、resource、GitHub wrapper，以及受控仓已提交 host policy/packet 中的权限边界。

`base_head` 必须是完整 40 位 SHA，不能写符号 `main`。它记录 scaffold/provenance
边界；启用 mechanical P1 后，运行时真正的首项起点是 `init` 从已合并输入 seal 的
`goal_input_head`，后继项起点是 `status.required_start_head`。manifest 显式引用权威
implementation plan，但控制面不解析 prose 自动生成依赖。`resource_requirements` 是
packet 资源章节的机器投影；两者不一致时 `doctor` fail-closed，不能靠 CAPTAIN 临场选择。

fresh task 需要由 CAPTAIN 先产出 P1 时，必须显式 opt-in：

```yaml
p1:
  producer: CAPTAIN
  artifact_root: docs/issues/<issue>
  authority:
    kind: SCOPED_DELEGATION
    path: <committed authorization path>
    sha256: <sha256>
  dependency_gate: ARCHIVED
```

未声明 `p1` 的旧 manifest 保持原行为。声明后，`init` 会把已合入 base branch 的当前
HEAD seal 为 `goal_input_head`；root task 的 `required_start_head` 等于该值，后继 task
等于 integration order 最高的直接依赖所记录的 `main_merge_sha`。依赖未
`ARCHIVED`、authority 未提交或 hash 漂移、required head 不可达时，`START_P1`
fail-closed。

v1 的 mechanical P1 只接受全序 Goal：只要一个 task 声明 `p1`，全部 task 都必须声明；
按 `integration_order` 排序后首项无依赖，每个后继必须直接依赖紧邻前项（可以同时列出
更早的传递依赖）。并行 task 的 base refresh/rebase 需要独立 FSM，未实现前不靠 prose
猜测，因此 mixed、root siblings 或跨过前项的 mechanical-P1 manifest 在 init 前即拒绝。

### 2.2 Task packet：不可变语义包

每个 revision 是完整快照，例如 `TASK-example-r1.md`。范围、AC、seam、环境权限、实现方案或准出语义变化时，legacy task 创建新 revision并 supersede 旧版；mechanical P1 v1 冻结 fresh Goal + fresh authority。两者都不能在聊天中叠加 addendum，也不能原地改写后继续沿用旧 hash。

packet 不含任何动态运行字段。packet 的 SHA-256 由 manifest/runtime 外部记录，避免自引用 hash。

### 2.3 Launch/runtime：本地动态状态

动态数据保存在：

```text
$(git rev-parse --git-common-dir)/goal-control/v1/
```

所有 linked worktree 共享同一运行真相。launch/runtime 绑定：canonical repo/origin、worktree realpath、branch、base/full HEAD、PR、thread/host/cwd、requested/actual model、Node/runtime版本、不可猜测的 task nonce、executable/PID、profile、environment/account 和 leases。它不得提交进业务 PR，也不得存 secret/PII。

最小 launch manifest 形状：

```yaml
schema_version: 1
goal_id: <goal>
task_id: <task>
launch_id: <unique id>
role: CAPTAIN | DEV | REVIEW | RECEIPT
control_epoch: <current Goal epoch>
state_revision: <role registration revision>
thread: { id: <id>, host_id: <id>, cwd: <absolute path> }
repository:
  name_with_owner: <owner/repo>
  origin_url: <canonical credential-free url>
  root: <repo realpath>
  worktree: <worktree realpath>
  branch: <branch>
  base_head: <full sha>
  full_head: <full sha>
packet: { revision: <n>, path: <repo-relative path>, sha256: <hash> }
runtime: { node_version: <version>, pnpm_version: <version>, lockfile_sha256: <hash> }
execution:
  environment: <name>
  write_mode: NONE | TESTING_WRITE | READ_ONLY
  task_nonce: <control-plane-issued nonce>
  identity_probe: { path: <absolute path>, sha256: <hash> }
  target: { kind: <kind>, executable_path: <absolute path>, pid: <pid>, started_at: <time>, user_data_dir: <absolute path> }
resource_leases: [<resource lease ids>]
```

尚未使用的可选字段应省略或使用 schema 明确允许的空值，不能拿标题、显示名或当前 cwd 推断身份。

## 3. CLI 与职责

入口：固定、clean、committed controller root 中的 `scripts/goalctl.js` 与
`scripts/resourcectl.js`。所有可执行示例必须使用
[`goal-control-quickstart.md`](./goal-control-quickstart.md) 定义的 exact argv wrapper：
固定 Node 绝对路径和 controller root，同时把受控 linked worktree 作为 wrapper 第一个
参数，显式展开为 `--repository-worktree`。禁止从 `PATH`、受控仓的 package script 或
受控仓 lockfile 启动 controller；controller 与受控仓各自使用自己的 lockfile。
连续运行先读 [`goal-control-run-goal.md`](./goal-control-run-goal.md)；命令参数按需用
`gc_goalctl <controlled-worktree> --help`、
`gc_goalctl <controlled-worktree> <command> --help` 或对应 `--json` 形式查询。Runtime
角色不把整份命令参考读入上下文；store adoption/rotation 只由 supervisor 按
[`goal-control-store-operations.md`](./goal-control-store-operations.md) 执行。

```text
gc_goalctl <controlled-worktree> scaffold --spec <path> [--output-dir <path>]
gc_goalctl <controlled-worktree> init --manifest <path>
gc_goalctl <frozen-worktree> adopt-store-protocol --incident-ref <ref> --acknowledge-old-controller-drained ALL_OLD_CONTROLLERS_DRAINED_AND_ISOLATED
gc_goalctl <current-frozen-worktree> rotate-store-protocol --rotation-id <stable-id> --predecessor-controller-worktree <frozen-old-controller-worktree> [--goal-worktrees-file <absolute-json>] --expected-predecessor-seal-sha256 <sha256> --incident-ref <ref> --acknowledge-old-controller-drained ALL_OLD_CONTROLLERS_DRAINED_AND_ISOLATED
gc_goalctl <controlled-worktree> register-role ... [--event-id <stable-id>] --bootstrap-capability-file|--foreman-recovery-capability-file|--authorizer-capability-file|--actor-capability-file <0600 file> [--worker-bootstrap-receipt <0600 json> --worker-bootstrap-receipt-sha256 <sha256> --worker-bootstrap-operation-id <id> --worker-bootstrap-challenge <64hex> --worker-bootstrap-identity-plan-sha256 <sha256>]
gc_goalctl <frozen-worktree> recover-expired-foreman ... [--expected-control-epoch <n>] --expected-goal-scope-sha256 <sha256> --foreman-recovery-capability-file <0600 file> --event-id <stable-root-id>
gc_goalctl <controlled-worktree> recovery-export-source ... --captain-capability-file <CAPTAIN 0600 file>
gc_goalctl <controlled-worktree> recovery-inspect-codex-rollout ...
gc_goalctl <controlled-worktree> recovery-build-codex-shell-audit ...
gc_goalctl <controlled-worktree> recovery-export-codex-rollout ... --captain-capability-file <CAPTAIN 0600 file> [--shell-audit-file <json> --foreman-capability-file <FOREMAN 0600 file>]
gc_goalctl <fresh-destination-worktree> recovery-import-source ... --actor-capability-file <DEV 0600 file>
gc_goalctl <fresh-destination-worktree> recovery-checkpoint-source ... --actor-capability-file <DEV 0600 file>
gc_goalctl <bound-destination-worktree> recovery-bind ... --captain-capability-file <CAPTAIN 0600 file> --event-id <stable-id>
gc_goalctl <bound-destination-worktree> recovery-abandon-handoff ... --captain-capability-file <CAPTAIN 0600 file> --foreman-capability-file <FOREMAN 0600 file> --event-id <stable-id>
gc_goalctl <bound-destination-worktree> recovery-promote ... --captain-capability-file <CAPTAIN 0600 file> --event-id <stable-id>
gc_goalctl <controlled-worktree> rotate-runtime ... --predecessor-incarnation <n> --predecessor-launch <id> --expected-predecessor-launch-sha256 <sha256> --successor-launch <fresh-id> --hold <id> --expected-state-revision <n> --expected-control-epoch <n> --captain-capability-file <CAPTAIN 0600 file> --event-id <stable-id>
gc_goalctl <controlled-worktree> event-template ... --actor-capability-file <0600 file>
gc_goalctl <controlled-worktree> event --goal <id> --file <event.json> --actor-capability-file <0600 file>
gc_goalctl <actual-worker-worktree> launch-template ... --input-file <json> --actor-capability-file <0600 file>
gc_goalctl <actual-worker-worktree> evidence --goal <id> --file <evidence.json> --actor-capability-file <0600 file>
gc_goalctl <actual-worker-worktree> preflight ... --actor-capability-file <0600 file>
gc_goalctl <controlled-worktree> control --goal <id> --expected-epoch <n> --reason <text> --instruction-ref <ref> --thread <id> --actor-capability-file <0600 file> --event-id <stable-id>
gc_goalctl <controlled-worktree> status|next|doctor --goal <id> --json
gc_goalctl <controlled-worktree> actions --goal <id> --task <id> --role <role> --thread <id> --json
gc_goalctl <controlled-worktree> resume --goal <id> --task <id> --role <role> --thread <id>
gc_goalctl <controlled-worktree> rebuild-ledger --goal <id>

gc_resourcectl <controlled-worktree> acquire ... --event-id <stable-id> --actor-capability-file <0600 file>
gc_resourcectl <controlled-worktree> renew|verify|release|reap|reinitialize-zero-runtime|list|doctor
```

- `next` 只根据 manifest、当前状态、依赖、holds、写集/资源冲突和
  `pending_operations` 计算可启动任务；不派 session。任一 Goal-wide registration/root
  recovery pending 会冻结整个 batch，task pending 则令对应 row `eligible=false`。
- `resourcectl acquire` 的 `--event-id` 必填；调用方须先持久化稳定 ID，响应丢失时用
  完全相同参数重试。精确重试返回同一 lease 的当前 durable revision/status。
- 两种 recovery export 的 `--snapshot-id` 与 `recovery-import-source` 的
  `--import-id` 也必须在首次调用前持久化；它们就是 operation/receipt ID。响应丢失只允许
  同一 ID、同一请求、同一 sealed capability 的精确重试；同 ID 异文或同 snapshot
  改换 import ID 均拒绝。
- `next.batch` 对已声明的 `conflict_domains`、`expected_write_set` 和排他资源做确定性冲突消解；它只是待执行批次，CAPTAIN/FOREMAN 必须用 Codex App 工具自主创建 task、等待、发消息和归档，无需用户逐步点击。
- `actions` 返回调用角色当前允许的状态迁移动作；模型不得自行补出不存在的动作。
  `maintenance_actions` 与迁移动作正交，至少把 active/idle 角色当前合法的
  `HEARTBEAT` 及 `lease_until` 显式列出。角色每次接手或长操作前都先处理即将到期的
  maintenance action；它不推进 phase，也不授权任何业务、资源或环境动作。
- `rotate-runtime` 是 CAPTAIN 驾驶的窄化 remediation，不是通用 event。它只在同一健康
  worker、唯一 `ENV_IDENTITY_INCIDENT` hard hold、本地
  `environment=none/write_mode=NONE/127.0.0.1 PREVIEW` 和
  `LOCAL_PREVIEW_ZERO_WITNESS` 全部成立时，把 active launch 从 exact predecessor CAS
  到 fresh successor；旧 launch append-only 保留，thread/task nonce/capability/lease
  owner 与 fencing 不变。其它 target、真实环境或资源转移一律拒绝。
- `LAUNCH_ID_CONFLICT` 不直接等于 source 或 runtime。controller 必须从 canonical
  launch、controller-sealed parent PREFLIGHT、deterministic candidate artifact 与
  current worker session 重算 `SOURCE_ONLY|RUNTIME_IDENTITY|UNKNOWN`：source-only 要求
  除允许的 HEAD 字段外 byte invariant 且 ancestry 成立；runtime 要求 source 坐标不变；
  缺失/损坏/混合变化一律 `UNKNOWN`。只有前两态分别开放唯一对应 lane，`UNKNOWN`
  禁止两者并由 doctor 报错。
- 新 controller 接纳 `ENV_IDENTITY_INCIDENT` 时，会把 prepared incident
  authority 的 exact hash/provenance 写入 accepted event，重放不能靠调用方补时间或
  身份。历史 markerless event 只允许由 audited adoption 或 protocol rotation 生成、并被
  root protocol descriptor 锚定的 identity receipt 兼容；receipt 精确绑定
  goal/task/hold/event/evidence/source/parent launch/actor/authority。原 source URI 消失时
  可从该封存闭集重放，URI 仍存在但 hash 漂移则直接失败；自签 artifact、聊天信息和只
  匹配 source hash 的副本均不能开恢复 lane。
- `status`/`next` task projection 的 `launch_scope` 是 launch/action gate；
  `operational_scope` 仅为它的向后兼容 alias。带 role 的 `actions/resume` 中，
  `operational_scope` 才表示 session 的
  `RECOVERY_BLOCKED|PREFLIGHT_ONLY|FULL` recovery authority。四个读取面都会公开
  `pending_operations`；非空时不得返回普通或 maintenance action，只允许按
  `retry.stable_id`、原 request/capability exact retry。
- `resume` 的人读 capsule 不超过 15 行，包含 role kernel、packet/head、状态 revision、
  holds、leases、launch gate、当前合法动作集、maintenance actions 和禁区；正常 phase
  推进仍以 machine state 返回的候选为准，`ADD_HOLD` / `ROLE_LOST` 等事故动作可能并列；
  `resume --json` 另外公开独立的 task `launch_scope`、session `operational_scope` 与
  `pending_operations`。compact 后职责从这里恢复，不从聊天摘要猜。
- `doctor` 根据已登记 heartbeat、`ROLE_LOST`、checkpoint、HEAD/packet/lease 漂移及
  pending durable operation 报告问题；退出 1 表示 finding，退出 2 表示 store/control
  无法可信读取。它不读取 session 私有记录，也不猜 thread 实际状态。
- `status` / `next` / `actions` / `resume` / `doctor` / `event-template` 及
  `resourcectl list|doctor` 是真正的 zero-write stable read：不创建 `.lock`、不修 head、
  不刷新 projection。若发现 event tail/head 需修复，返回
  `STORE_REPAIR_REQUIRED`，由有写权限控制角色另跑 repair；worker 不因“只读查询”取得
  `.git/goal-control` 写权限。
- `rebuild-ledger` 从 append-only 事件重建生成式账本；账本不是第二份可手改状态。
- `adopt-store-protocol` 是现存非空 v1 root 的唯一显式 decoder/lock 升级入口。运行前
  必须在 root 外部 drain/isolate 全部旧 controller，并提供 durable incident ref 与 exact
  acknowledgment；同一 UID 的旧 binary 会忽略新 seal，控制 root 无法反向 fence 它。
  命令在 nonce writer lock 内以零写 validator 重放全部 Goal/evidence/resource ledger、
  校验 frozen repository inputs 与 head/tail；默认由单一 `--repository-worktree` 服务全部
  Goal，若不同 Goal 冻结了同一路径的不同历史 hash，则必须用
  `--goal-worktrees-file <absolute-json>` 精确映射每个 Goal 到各自 canonical、clean、同
  Git common-dir 的 frozen worktree。映射 bytes、worktree path/common-dir/HEAD、
  manifest/frozen-input hashes 会进入 migration receipt。全部通过后再原子安装 decoder
  seal 和 legacy evidence
  anchor/source bundle；protocol seal 同时锚定 incident/drain receipt 及每个 artifact 的
  exact hash。任一未知记录、hash/decoder/input 漂移或验证期写入都拒绝 seal；幂等重跑
  必须沿用首次 incident ref。
- `rotate-store-protocol` 是**已 seal root** 跨 decoder/schema 升级的唯一入口，与 v1
  adoption 互斥。successor binary 不放宽普通 strict reader，而是用 exact predecessor
  seal、稳定 rotation ID、旧 controller frozen worktree 和 drain acknowledgment 启动
  专用引导路径；旧、新 decoder 对锁内同一批 Goal/resource bytes 的语义重放必须一致。
  writer lock 在切换前后始终使用 predecessor lock-v2 identity，使旧 writer 等待、让
  successor 普通 writer 在 rotation 完成前 fail-closed。成功会追加不可变 rotation
  receipt、保留既有 legacy artifacts 原 bytes，并把当前完整 Goal worktree map 单独封存；
  protocol seal 是 receipt 链的 commit record。仅 exact transaction 能恢复 odd/crash
  window；不同 ID/incident/map/seal、foreign odd/transport 或 decoder/artifact/vector
  漂移全部拒绝。响应丢失必须使用同一参数重试。
- `init` 首次与精确幂等重试都会返回 `bootstrap_capability_file`、独立的
  `foreman_recovery_capability_file` 和 sealed `init_receipt_file`；只返回路径，不返回
  raw capability。新 Goal 在 `0700` 临时目录内生成 `0600` capability/receipt，fsync 后
  整目录 rename 并 fsync 父目录；响应丢失后必须以同一 committed manifest 重试。旧版
  pre-receipt Goal 只允许在 writer lock 内验证 sealed manifest/meta、同 owner 目录、
  capability hash（已消费 bootstrap 由 metadata + append-only lineage 证明）后做一次
  带 provenance 的 adoption，随后 metadata marker 禁止 receipt 丢失后静默重建。
  完整树在最终 rename 前退出时，exact retry 会验证 staged receipt/metadata/capability
  bytes 与最终路径后提升原树；未 seal 树只按精确 request 和严格 inventory 清理，
  foreign/lookalike/多份/权限漂移绝不 sweep。
  bootstrap 只能签发首个 FOREMAN、消费后失效；重试会以
  `bootstrap_capability_consumed` 明示路径是否已失效。Goal-wide FOREMAN registration
  只有三类：首次 bootstrap 建立唯一 authority；后续 task 用同一
  identity/attempt/status/capability 做 projection，不 mint 第二 authority；失联后才做
  replacement，存在多个 current projections 时必须由 `recover-expired-foreman` 原子批量
  替换。每次 `register-role` 都是 durable intent 写操作；调用前持久化 event ID（省略时
  控制器使用 deterministic ID），响应丢失以同一 request/ID 和原 authorizer 或 actor
  capability exact retry。历史 retry 返回原 registration，不代表历史 actor 仍有当前
  operational authority。普通单 projection replacement 仍先进入 `ROLE_LOST`/recovery。
  registration capability、nonce、`accepted_at` 与 authorizer authority 先在
  request-bound private staging 一起 seal；pre-rename crash 提升原 bytes，不能 remint。
  manifest 已 opt in worker bootstrap 时，DEV/REVIEW/RECEIPT registration 必须从 receipt
  绑定的 actual process cwd 携带同一 external authority；控制器在任何 intent/capability/
  event 写入前验证，并把 canonical worktree/gitdir/common-gitdir/branch/initial HEAD seal
  进 session。后续 launch/preflight/event/status/resume/doctor 始终重验；同 HEAD 的其它
  checkout 不是同一 worker identity。
  首个 BOOTSTRAP event 接受后，控制器先 durable 写 consumed marker、再删除 bootstrap
  capability；任一边界退出都由唯一 append-only BOOTSTRAP lineage 幂等 reconcile，
  旧 capability 不会重新取得授权。
  FOREMAN 与 CAPTAIN 同时不可用、常规互相确认链死锁时，由 Goal 级 recovery capability
  做完整 CAS 根恢复；CAPTAIN/普通 authorizer capability 无权走它。正常链路仍由
  FOREMAN→CAPTAIN→执行角色逐级签发独立 0600 capability。
- 不能机械复算的 REVIEW/RECEIPT 等语义结果先由 `evidence` 登记并 seal；preflight/Fast/Full CI/AC audit 只能由对应 controller adapter 执行和 attestation，通用入口禁止自报这些 PASS。调用方提交的 workflow event 只携带 evidence ID；接受后持久 envelope 会额外锚定当时的 evidence-registry digest，重放时同时校验 registry 记录与 durable source bytes。旧 event 必须经 audited protocol adoption 生成 legacy anchor/source bundle，不能继续依赖 disposable worker worktree。
- DEV 只运行 `goalctl gate-fast` 并提交、push、开 PR；当前 PR HEAD 的 `goalctl gate-full-ci` 与 `goalctl gate-ac-audit` 由 CAPTAIN 调用固定 adapter。AC audit adapter 在 shadow/enforce 下都不传 `--comment`：门禁必须是可安全重放的只读远端检查，PR 评论发布不属于门禁事务；若以后需要自动评论，必须另建带外部幂等 receipt 的发布动作。
- Resource acquire 的 stable event ID 在 intent seal 后即保留；若 append 前原 actor 已不再 live，精确重试 append `LEASE_ACQUIRE_ABORTED`、消费 fencing 且不创建 lease。successor 只能用 fresh event ID 重试，`ABORTED` 不是资源授权。

Codex App 的 `create_thread`、`wait_threads`、`send_message_to_thread` 和 archive 由
FOREMAN/CAPTAIN 按角色卡自主调用。脚本负责验证和落盘，App 消息只负责唤醒；正常执行
不要求用户逐步点击、复制消息或确认每个调度动作。
`archive` 不是无损的“取消当前 approval”：Codex 可能同步回收关联 worktree。活跃
worktree 被归档回收且尚有未形成 durable checkpoint 的源码，是已知事故家族。任何
active、blocked、待返工或未形成 durable checkpoint 的 thread 一律禁止
archive；需要停止 pending turn 时只能使用显式 interrupt/cancel 能力。若产品没有该能力，
保持 thread 卡住并由新 identity 走控制面恢复，不能拿 archive 代替。
App 侧角色尚未清理时，task 的 `ARCHIVED` 事件才可能安全接受，且必须同时满足：
已有 durable `MERGED`、DEV/REVIEW/RECEIPT 证据链完整、FOREMAN 新登记并 seal 的
`MERGE_BOUNDARY/PASS` archive evidence 绑定当前 HEAD、控制 worktree clean，且该 task
没有任何非终态 resource lease。归档前还必须用同一快照运行 `status` 与 `doctor`，
确认 task/Goal-wide `pending_operations` 均为空且 doctor healthy；有 pending 就先按原
stable ID/request/capability exact retry，`ARCHIVED` 不接受任何未闭合 durable operation。
先接受该事件，再归档该 task 的
DEV/REVIEW/RECEIPT/CAPTAIN；若 Goal 仍有后续 task，FOREMAN 继续作为 Goal
authorization/control anchor 保持 active/heartbeat，不能提前归档。全部 task 归档且不再
需要 control 后才归档 FOREMAN。自然语言“已收尾”不是归档凭证。

`MERGED` 是当前 FSM 的不可逆外部边界；接受时会机械把仍 active/idle 的 DEV 终结为
`TASK_MERGED`，从而让 terminal-owner resource release 投影可达。REVIEW/RECEIPT 已在
各自 verdict 边界终结，CAPTAIN 保持 active 直到完成 release、doctor 与 `ARCHIVED`。
因此不需要也不允许靠聊天补一个未建模的“停止 DEV”步骤。

每个 task 的 CAPTAIN 是独立 session，拥有本 task 的 DEV→REVIEW→RECEIPT 对话；Goal FOREMAN 不继承这些长对话，只接收启动请求、需用户/跨 task 仲裁、边界收货三类短摘要。V1 刻意不让 shell 脚本伪造 Codex 消息或解析 session JSONL；未来如接 App Server，也只能执行 `goalctl actions` 已返回的动作。

## 4. 事件信封与幂等

角色先写事件文件，再调用 `goalctl event`。事件至少包含：

```yaml
event_id: <全局唯一安全不透明 id；[A-Za-z0-9][A-Za-z0-9._:-]*>
type: <稳定枚举>
goal_id: <goal>
task_id: <task>
actor:
  role: FOREMAN | CAPTAIN | DEV | REVIEW | RECEIPT
  thread_id: <launch runtime 中已登记的 id>
actor_sequence: <该 actor 单调递增序号>
expected_state_revision: <CAS revision>
control_epoch: <当前用户控制 epoch>
packet: { revision: <revision>, sha256: <hash> }
base_head: <完整 40 位 SHA>
full_head: <完整 40 位 SHA；尚未产生 task commit 的 P1 事件使用冻结 base HEAD>
payload: <事件类型要求的结构化字段和持久化 evidence links>
```

`from/to/state_revision/packet hash` 由 reducer 根据接受前后的状态生成，不能相信调用者自报。处理规则：

- 同 `event_id`、同内容重放是幂等成功；
- 同 `event_id`、不同内容，序号倒退、CAS revision/epoch 陈旧、角色或 thread 不匹配、packet/head 错误、非法迁移全部拒绝，状态保持不变；
- 非法事件也写审计结果和拒绝原因；
- accepted task/resource/control ledger 各自使用连续序号、previous hash、record hash 和 sealed durable head；删尾、改字节、断链或 head 漂移均 fail-closed；
- 事件成功后只需发送 `event_id + goal/task + result` 的短唤醒消息，原始 `[REVIEW_PASS]` 等自然语言标签不再具有迁移权。

## 5. Phase FSM 与角色权力

```text
QUEUED
  -> P1_ACTIVE
  -> P1_READY
  -> P1_APPROVED
  -> P1_COMMITTED
  -> DEV_ACTIVE
  -> DEV_READY
  -> REVIEW_ACTIVE
       -> REVIEW_REWORK -> DEV_ACTIVE -> DEV_READY -> REVIEW_ACTIVE ...
       -> REVIEW_PASS
  -> RECEIPT_ACTIVE (每次 fresh session)
       -> RECEIPT_FAIL -> RECEIPT_FAILED -> DEV_ACTIVE/REVIEW_ACTIVE -> fresh RECEIPT
       -> RECEIPT_PASS
  -> ACCEPTED_PENDING_MERGE (由 CAPTAIN 的 READY_FOR_MERGE 事件进入)
  -> MERGED_TO_MAIN
  -> ARCHIVED
```

异常运行状态为 `RECOVERY_REQUIRED`，但不得伪装成某个业务 phase 的 PASS。DEV successor
另有正交运行 scope：`RECOVERY_BLOCKED -> PREFLIGHT_ONLY -> FULL`。它不改变业务 phase；
`ROLE_RECOVERED` 只进入 `RECOVERY_BLOCKED`，`RECOVERY_HANDOFF_BOUND` 才进入
`PREFLIGHT_ONLY`，`RECOVERY_PROMOTED` 才进入 `FULL`。

关键角色约束：

- FOREMAN 冻结 Goal/DAG/packet，做跨 task/seam/产品/安全仲裁和最终 merge；
- CAPTAIN 只驾驶一个 task 的 FSM、session、checkpoint、preflight 和 lease；
- DEV 只实现、测试、自审、提交和返工；
- REVIEW 只给当前 packet/head 的可证伪代码 finding；
- RECEIPT 只对当前 packet/head 做 fresh 最终验收；
- 任何角色都不能代另一个角色发状态事件。

`P1_READY` 必须绑定待批准 plan/context digest，尚未把批准当成既成事实；只有 FOREMAN 带用户批准证据可进入 `P1_APPROVED`。随后产生的 `P1_COMMITTED` 必须证明 commit 内容与获批 digest 一致。这样机械拒绝“先提交 P1、后补批准”。

启用 manifest `p1` 后，控制器还会机械执行 producer 窄权限：READY 时 worktree 必须从
`required_start_head` 开始，只允许 `artifact_root/{plan.md,context.md,_ref/**}` 为
dirty，普通文件 inventory 与 worktree/branch 一并冻结；APPROVED 必须使用由
authority、packet 与完整 artifact inventory 计算出的 canonical binding；COMMITTED
必须仍是同一 worktree/branch、clean，且只存在一个以 `required_start_head` 为 parent
的新 commit，commit tree inventory 必须与 READY 完全一致。任一 symlink、范围外改动、
先提交、换 worktree/branch 或 bytes 漂移均拒绝。未启用 `p1` 的历史事件形状不变。

同一 opt-in task 的 `expected_write_set` 也是 `DEV_READY` 硬边界：控制器先证明不可变的
`state.p1.commit_sha` 是 candidate ancestor，再用
`git diff --name-only -z --no-renames <p1-commit> <candidate>` 检查最终 delta；新增、
删除及 rename 两端都必须命中声明，空列表表示 DEV 不得产生任何 delta。pattern
大小写敏感，只支持仓库相对 POSIX 精确路径、单个 segment 内的 `*`，以及作为完整
segment 的 `**`（可跨任意层级）；绝对路径、`.`/`..`、反斜杠、`?`、字符组、
brace/extglob 和嵌入式 `**` 在 manifest ingress 即拒绝。未启用 `p1` 的旧 task 不改变
既有 pattern 行为。

机械 P1 的 CAPTAIN 在 `P1_ACTIVE/P1_READY/P1_APPROVED` 失联后，只有完成
`ROLE_LOST -> fresh CAPTAIN registration -> ROLE_RECOVERED` 的 successor 才能由
FOREMAN 用 `P1_RESTARTED` 放弃旧 binding。该 append-only event 精确绑定 recovery
lineage 与 abandoned worktree/branch，清除 READY/approval 并回 `QUEUED`；同一 lineage
只能使用一次。`P1_COMMITTED` 在 accepted event 前先原子持久化 exact-request
intent+单提交 bundle，再 CAS 发布 Goal/task/cycle-bound 的 controller-owned
`p1.commit_ref`，最后 append event/completion；`p1.commit_branch` 提供给 DEV
startingState。frozen read 验证该 ref，disposable CAPTAIN worktree/branch 被删且 Git
GC 后仍可从 sealed bundle exact retry。

尚未 accepted 的 P1 commit 只有两种可废止 handoff：

- pre-seal staging 的 object/bundle/HEAD carrier 经确定性核验不可恢复时，原
  `P1_COMMITTED` event/request 与原 CAPTAIN capability exact retry 可 seal
  unavailable-carrier marker、residue inventory 和 authority-bound `ABANDON_ONLY`
  intent；
- normal intent+bundle 已 seal、但 create-only `p1.commit_ref` 确定性指向另一个 40 位
  commit 时，normal intent 保持 immutable，foreign ref 保持不覆盖；原 event/request/key
  与原 CAPTAIN capability exact retry 只能 create-only seal 独立
  `ABANDON_HANDOFF`。它绑定 request/intent、task anchor、CAPTAIN authority、预期
  ref/head 与实际 foreign head。

两条 CAPTAIN retry 都返回 `accepted:false` 和 `abandonment_required:true`，不 append
`P1_COMMITTED`。pending 投影仍是 `P1_COMMIT_REF`，公开原 operation/request、
`prepared_stage=ABANDON_ONLY|ABANDON_HANDOFF`、prepared event、intent/ref/commit
锚点和 `p1-abandon-commit` retry；normal handoff 回报另含
`abandon_handoff_sha256`，后续控制器把它派生绑定进 abandonment request。只有 live
FOREMAN 能用 fresh abandonment ID、公开锚点、reason/incident 与自己的 capability
运行该命令；FOREMAN 不能创建 handoff，CAPTAIN 不能创建 tombstone。命令中断后改投影
`P1_COMMIT_REF_ABANDON`，只接受同一 ID/request/FOREMAN capability exact retry。

`ABANDON_ONLY`/`ABANDON_HANDOFF` 一经 seal 即 one-way：late carrier、late expected ref
和原 CAPTAIN retry 都不能 revive 或 append 原 event。FOREMAN 对 normal handoff 保留原
foreign ref；若 ref 后来变成 expected commit，同一 abandonment retry CAS 删除它；第三
个 foreign ref 则 fail-closed。任意非确定性 Git/IO/ref 错误、无法证明的 carrier 状态或
corrupt sideband 都不得升级成 handoff；已经留下 durable P1 partial/odd marker 时继续
保持 odd，只允许原 transaction 恢复。换 request/key 或 capability 的 odd preflight
零写拒绝，不改 generation、intent、handoff 或 ref。v1 保留
intent/bundle/handoff/completion/ref 与 abandonment lineage 至少到整个 Goal 全部归档，
且不做静默清理；受控清理须另行建模。

## 6. Hard holds

阻塞是正交于 phase 的 sticky `holds[]`，不覆盖原 phase：

- `BLOCKED_SECURITY`：潜在跨租户/越权、凭证/PII、破坏性数据或其它安全红线；
- `BLOCKED_EXTERNAL_FACT`：host-declared API/contract、generated client、外部实现、部署
  wire 或 owner 口径冲突，无法由仓内事实唯一决定；
- `ENV_IDENTITY_INCIDENT`：repo/HEAD/executable/PID/profile/environment/account 与 launch manifest 不一致。

hard hold 存在时，CAPTAIN 只能执行控制面允许的只读诊断、隔离、checkpoint、上报和已授权 remediation，不能降级成普通 TECH blocker，也不能继续 REVIEW/RECEIPT/merge。只有 FOREMAN 携带规定的 resolution authority 与持久化 evidence 才能解除；涉及 packet 语义时，legacy task 发布新 revision，mechanical P1 v1 冻结 fresh Goal + fresh authority，并使旧证据失效。

三类 hard hold 是红线，不是“风险提示”：preflight 与 resource acquire/renew/verify 同样拒绝执行；解除 evidence 必须来自 registry。legacy task 的 `PACKET_UPDATED` 无论标为实现还是规格变化都回到 P1 决策门，终态 task 必须先显式 `TASK_REOPEN`；机械 P1 v1 则在 append 前拒绝 packet update，要求冻结 fresh Goal，禁止靠字段命名或旧批准绕过重审。

唯一的 runtime-incarnation 窄例外是：一个健康 worker 的旧本地 PREVIEW 进程已终止，
registration/session 本身仍有效，且 task 只有对应的 `ENV_IDENTITY_INCIDENT`。CAPTAIN
只能在机械 launch-hold 分类为 `RUNTIME_IDENTITY` 时调用专用 `rotate-runtime`，由
controller 生成并验证
`LOCAL_PREVIEW_ZERO_WITNESS`、exact predecessor launch/hash、fresh successor identity
和未变化的完整 lease set，再 CAS active launch 指针。raw `RUNTIME_ROTATED` event
不具有同等权限；旧 launch 不覆盖，task nonce、capability、lease owner/revision/fencing
不变，也不提交 `ROLE_LOST`。

rotation 不解除 hold。它只开放同一 worker 用新 loopback 端口执行 fresh
`launch-template -> preflight` 的 remediation lane；控制面必须投影 deterministic
rotation/preflight operation IDs、完整 CLI 参数、exact CAPTAIN/worker dispatch、旧
runtime identity、lease set 与 freshness contract，调用方不得靠上下文记忆重构命令。
runtime successor 的 preflight evidence ID 由完整 exact launch 自动派生；旧端口、旧
launch 和旧 evidence 不可复用。fresh preflight PASS 后，仍由 FOREMAN 提交 fresh
resolution evidence，且
`RESOLVE_HOLD` 必须额外绑定 exact `runtime_preflight_evidence_id`；控制器会重放并核对
successor launch/incarnation 后才解除 hold。失败时 hold 保持 sticky。此例外不证明
browser/app/profile/account/external-session 或真实环境已经隔离，不得替代 host/resource
broker、DEV handoff 或角色恢复。

## 7. 运行身份与资源租约

每次会触达 preview/app、账号、外部会话或本地 profile 的动作，先验证 launch runtime，
再验证 lease。具体资源种类与 canonical key 必须由受控仓已提交、绑定 hash 的 host
policy 和 task packet 声明；例如网络端口组、browser/app profile、
environment+tenant+account、external-session、UI target/executable/PID。portable
protocol 本身不授予这些资源、环境或账号权限。共享只读资源与排他写资源必须显式区分。

租约原则：

- acquire 原子化；同一排他资源只能有一个 owner；
- acquire 只接受 manifest 的 `kind:id + access` 精确 canonical key，禁止用相似字符串或子 alias 领取同一物理资源；
- requirement 可选 `roles: [DEV|REVIEW|RECEIPT]`；省略时为兼容旧 manifest，仍适用于
  全部 worker。声明后 acquire 只接受被列出的角色，launch 也只要求并只接受当前角色的
  requirement。DEV、REVIEW、RECEIPT 需要并存或返工时应使用不同的排他 resource id；
  可共享的 fixture 才使用同一 `SHARED_READ` requirement；
- verify 失败立即产生 `ENV_IDENTITY_INCIDENT`；
- lease 到期不等于相关进程已经停止，禁止自动抢占仍活跃资源；v1 的 `reap` 在 shadow/enforce 都 fail-closed。`ROLE_LOST` 与同 lease/revision/owner 的 sealed `ROLE_FAILURE` 只能证明协调事实，不能机械证明 PID/profile/port/account 已隔离；按资源类型的 broker adapter 落地前一律不转手；
- UI 自动化只认 manifest 的绝对 executable、PID、profile/CDP target，不按应用显示名
  选择或杀进程；
- 环境写仅在已提交 host policy 与 task packet 明确授权的环境、租户、账号和 write mode
  内成立；portable protocol 不提供默认可写环境。

lease ownership 使用 0600 owner capability 文件，raw secret 不打印。若 acquire 已 durable commit 但响应丢失，owner 可凭 active actor capability 用 `resourcectl owner-capability` 恢复文件指针。该命令 zero-write，且只返回 ledger 已有、verifier 匹配的路径；唯一 `ENV_IDENTITY_INCIDENT` runtime-preservation hard hold 下也仅向 active exact owner 放行，并且必须已有正式续租边界：活 lease 进入 `RENEWAL_WINDOW`，或过期 lease 满足 exact `EXPIRED_PRESERVATION`（当前 fencing、无竞争中的 live lease）。尚未到窗口的活 lease、CAPTAIN/FOREMAN、fresh attempt 与其它 worker仍拒绝。`REQUEST_RESOURCE_RENEW.actor_role=CAPTAIN` 是兼容 coordinator 字段；新调用方必须按 `dispatch.executor_binding=EXACT_RESOURCE_OWNER` 与 exact executor identity 分发，续租仍要求 owner actor + lease-owner 双 capability。TTL 最长四小时；过期不自动转手。`resourcectl reap` 会核对 active FOREMAN/CAPTAIN、recovery 和 sealed ROLE_FAILURE 绑定，但即使全部满足仍返回 `REAP_REQUIRES_BROKER`；未来只有固定 broker 能机械证明旧 holder 已被 fence 后才可开放。

## 8. Gate 与证据顺序

固定顺序：

```text
packet/AC resolver lint
-> role registration 后、任何 LAUNCH_* 事件前执行 launch repo/runtime/environment identity preflight
-> DEV tests + clean + diff-check + Fast + evidence schema
-> DEV 候选 commit/push/开 PR 后，在 DEV_READY 前对候选 HEAD 复跑 preflight
-> CAPTAIN 对当前 PR HEAD 执行 fixed Full CI + scoped AC audit adapters
-> REVIEW
-> fresh RECEIPT
-> merge precondition
```

首次 preflight 是 `LAUNCH_DEV/LAUNCH_REVIEW/LAUNCH_RECEIPT` 的前置条件，不允许先迁移状态再补身份检查。DEV 产生候选 HEAD 后必须在 `DEV_READY` 前用同一 launch identity 复跑。canonical launch 是 byte-immutable runtime anchor；正常源码提交不换 PID/端口，也不覆盖它。`launch-template` 从 canonical 克隆 candidate：`NONE` 只前进 `repository.full_head` 且禁止 build head，`CLI/PREVIEW` 同步前进 full/build HEAD，`BROWSER/ELECTRON` 则必须投影 fresh `ROLE_LOST(DEV)` 后走 runtime/worker recovery；candidate 写入 evidence 专属 artifact，evidence 同时绑定 candidate 与 canonical runtime hash。`created_at`、worker bootstrap binding、lockfile、PR、PID/端口、executable、nonce/incarnation、lease、worktree/branch 等任一变化都拒绝同-runtime lane。DEV launch 不绑定 PR；PR 由 `DEV_READY` 与 Full/AC evidence 绑定。状态投影为 `REQUEST_CANDIDATE_PREFLIGHT` 时，CAPTAIN 只协调 exact DEV 重跑 launch-template/preflight，禁止据此 `rotate-runtime`。若纯 source 前进已形成唯一 stale-head hard hold，机器改投影 `REQUEST_CANDIDATE_HOLD_REVALIDATION`；FOREMAN 必须按 action 的 operation/hold event/canonical hash/candidate HEAD 执行 `goalctl revalidate-source-checkpoint-hold`。该事务只重验并登记 deterministic resolution evidence，绝不换 runtime；任何 hold、bytes、lineage 或 live HEAD 漂移都 fail closed。

每份证据必须绑定 `packet sha256 + full HEAD`。HEAD 或 packet 变化自动作废受影响的 preflight、audit、REVIEW 和 RECEIPT 结论。
证据登记后允许同一 active identity 的普通 `active/idle` heartbeat 穿过；controller 会逐条
证明中间 accepted event 全是这种无害续租。`systemError`、identity/checkpoint/head/
packet/control/phase 变化仍会使证据失效，不能把任意 revision 漂移概括成“只是心跳”。

fixed gate adapter 不继承调用者环境：`PATH`、`BASE_REF`、`SKIP_TESTS` 等由控制器固定；`HOME` 从 OS 账号数据库解析并 realpath 后注入，用于读取该账号已有的 `gh`/Codex 登录，绝不接受 caller 的 `HOME`/`CODEX_HOME`/Git config/token 覆盖。

- 机械 verdict：schema、SHA、clean、diff-check、gate、evidence 格式；
- 语义 verdict：实现行为和 AC/seam 正确性；
- traceability verdict：Spec/REQ/AC/test/code 回链；
- environment verdict：候选构建、账号、租户和写权限。

四者分别记录，不能把格式缺口和用户行为失败混成一个无来源的 FAIL。REVIEW 负责 finding；RECEIPT 负责最终 AC/seam/证据链与高风险抽查，不应第一次发现廉价格式问题，也不重复充当完整 code review。

## 9. 恢复与 control epoch

active 角色 thread 完成/失败却没有合法终态事件、`systemError`、heartbeat 超时、checkpoint 与 packet/HEAD 不一致时，`doctor` 报 `RECOVERY_REQUIRED`。CAPTAIN 的恢复顺序：

1. 只读核对 runtime、worktree、PR HEAD 和 checkpoint；
2. 原 session 仍可用时只唤醒一次；
3. 未恢复则创建同角色 successor，旧 partial verdict 不继承；
4. 同一失败指纹连续两次后上报 `BLOCKED_TOOLING` 给 FOREMAN。

### 9.1 Root generation v1/v2/v3 与 odd recovery

control root 的 `.generation.json` 是所有 writer 共用的 crash marker。偶数 generation
表示没有未闭合 writer；奇数 generation 表示一个 writer 已越过 transaction boundary，
但尚未证明完整提交。它不是业务 phase、event ledger 或可由 operator 修订的进度文件。

| generation schema | odd 时可验证的绑定 | 合法恢复 |
|---|---|---|
| v1 legacy | 没有 transaction key，也没有 pre-write vector | 不能自动判断原请求；只允许 audited repair |
| v2 transaction-only | `active_transaction` 精确绑定 kind/scope/stable operation ID/request hash；没有 pre-write vector | 只有 exact durable witness 才能恢复；没有 witness 就 audited repair |
| v3 current | v2 的 transaction binding，加 `pre_write_vector_sha256` | exact durable witness，或仅在显式 allowlist 且 payload vector 仍逐字相同时使用 pristine recovery |

v2/v3 的 even seal 必须令 `active_transaction=null`，v3 还必须令
`pre_write_vector_sha256=null`；odd seal 则必须有 exact `active_transaction`，v3 还必须有
合法的 pre-write vector。任何其它组合都是 corrupt store，不是可猜测修复的中间态。

v3 odd seal 的 `updated_at` 不是会随重试刷新的普通“最后更新时间”，而是该 odd
transaction 的不可变 `transaction_started_at`。它在 generation 从 even 变 odd 前选定，
stale-lock fencing 和同一 operation 的恢复都必须原样保留，直到 odd 被合法闭合。调用方
可以用它判断 actor/capability 在**原事务边界**是否有效，但不得据此假装当前 TTL、
远端状态、launch、lease、可执行文件或其它会老化的输入仍有效；这些是否必须按当前时间
重验由具体 operation policy 决定。

odd recovery 有两种互不替代的证明：

- **WITNESS**：accepted event、sealed intent、reservation、invocation、receipt、
  prepared artifact 等 durable bytes 精确证明 callback 已进行到哪个阶段。它允许同一
  transaction 从 operation 自己的幂等入口恢复部分写入；若恢复仍失败，原 odd marker
  保留，不能把失败解释成完成。
- **PRISTINE**：只在 v3 中可用。除 generation/lock transport 外的当前 control payload
  vector 必须仍等于 odd seal 中的 `pre_write_vector_sha256`，并且原 stable operation
  ID、逐字相同 request、transaction key 与调用方 authority 都通过该 callsite 的专用
  检查。它只证明 callback 尚未写 control payload，**不证明外部副作用没有发生**。

PRISTINE 通过后仍必须采用该 callsite 预先审计的唯一策略：

- `RESUME_AT_START`：在原 odd transaction 和原 `transaction_started_at` 下从 callback
  起点重跑。只允许用于“首次 durable control witness 之前不会产生外部语义写”的入口。
- `ABORT_THEN_FRESH`：原 callback 不做 live/external 工作，只抛内部
  `STORE_PRISTINE_ABORT_RETRY`；store 在确认 payload 仍未变化后闭合旧 odd，wrapper
  最多自动发起一次 fresh transaction，以当前 authority、时间和 live inputs 重验。

具体入口只能按 Quickstart 的 generation recovery 矩阵选择策略，不能由 FOREMAN、
CAPTAIN 或 worker 临场判断。尤其是 source handoff、P1 commit/ref/abandon，以及 GitHub
merge 已有 intent/reservation/invocation 后的阶段，不能用“payload 看起来没变”代替各自
的 durable witness。

request/key、pre-write vector、capability/authority、原事务时间上的资格或 operation
专用约束任一不匹配时，preflight 必须零 control write 拒绝并保留原 odd。v1/v2 不得升级
成 pristine；v1 odd 只能 audited repair，v2 odd 只能 witness 或 audited repair。任何
schema 都禁止手改、删除、重命名或重算 `.generation.json`，也禁止靠系统时间、替代
capability、新 event ID 或新 controller 猜测“修平” generation；需要升级旧 root 时只能
走已审计的 protocol adoption/repair 路径。

### 9.2 FOREMAN 与 CAPTAIN 同时过期

常规链要求 CAPTAIN 登记 `ROLE_LOST(FOREMAN)`，FOREMAN 又负责登记
`ROLE_LOST(CAPTAIN)`。两者 lease 同时过期时，任一旧 actor 都不能补 heartbeat 或
`ROLE_LOST`，也不能伪造 identity/time 绕过。该同时过期死锁已作为通用事故家族固定
下来，不依赖某个私有 Goal、task、日期或 session 标识。

`goalctl recover-expired-foreman` 是这个死锁唯一的根恢复入口。它不接受通用
`goalctl event` 代交，且必须同时满足：

- frozen manifest/packet/protocol 输入仍与初始化时的 committed bytes 一致；
- 独立 Goal FOREMAN recovery capability 匹配；若已有未闭合 recovery，必须由根恢复按
  固定顺序保留：FOREMAN recovery 原子闭合、CAPTAIN recovery 原位保留、worker
  recovery 暂存到 `recovery_backlog`，不得覆盖或丢弃；
- 旧 FOREMAN 是当前 `active|idle` registration，或已是 `lost` 且精确匹配当前
  `FOREMAN` recovery 的 lost identity；其登记 lease 必须已按控制器当前时间客观过期；
- Goal 当前不存在可闭合状态的 CAPTAIN 常规恢复路径；只要任一 source task 的有效
  CAPTAIN 能提交精确 `ROLE_LOST(FOREMAN)`，根恢复就以
  `CAPTAIN_RECOVERY_PATH_AVAILABLE` 拒绝。若常规 FOREMAN recovery 已在任一 source
  task 开始，根恢复可以原子接管并闭合该 Goal-wide lineage；
- 同一次 `status` 返回的 `foreman_recovery_scope.scope_sha256` 必须精确匹配；scope
  覆盖 control epoch/head、每个 task 的 phase/event head/packet/full HEAD 与 FOREMAN
  identity/attempt/capability/lease，禁止混拼多次读取。`expected-control-epoch` 与旧版
  per-task `expected-*` 仅是可选兼容 guard，不能替代 Goal scope CAS；
- successor attempt 恰好为旧 attempt + 1，thread identity 在整个 Goal 的当前与历史 session 中从未使用，lease 不超过四小时；
- 所有非 `ARCHIVED` 当前 FOREMAN 投影是同一 Goal authority 的 coherent replicas；
  若从 `ARCHIVED` lineage adoption，其 source 必须属于 Goal 当前最大 attempt generation。

调用前必须持久化稳定 `event-id`。普通 batch target 精确等于所有**非 `ARCHIVED` 且已有 current FOREMAN projection** 的 task，不包含其它未启动/未投影 task。接受时先发布 sealed
durable root intent，再只为这些 target 追加 hash-chained
`RECOVER_EXPIRED_FOREMAN` event，最后发布 sealed commit；整个 transaction 把旧
FOREMAN replicas 记入各自 history 并登记共享 capability 的 successor FOREMAN。Goal 已无 current
projection 时，唯一例外是显式 anchor 可从当前最大 attempt 的 `ARCHIVED` lineage
adoption 为一个新 projection。中途崩溃会冻结其它写入，只允许同一
ID/request/recovery capability 继续；不同请求复用 ID 拒绝。其余 `ARCHIVED` 投影、旧
event 与 ledger 真相不改写。

常规恢复不得手写泛化 `ROLE_LOST`。CAPTAIN/FOREMAN 必须逐字消费
`actions` / `resume.allowed_actions` 投影的精确动作：event ID 与 payload 同时绑定目标
thread、host、attempt、原 lease deadline 和 fingerprint，再走
`event-template` + `event`。若提交返回 `ROLE_LOST_TARGET_STALE`，说明目标已换代；丢弃
旧动作并重新读取投影，禁止改 event ID 后重放。root recovery 把 worker recovery 暂存到
`recovery_backlog` 时，successor FOREMAN 收到的 `ROLE_LOST(CAPTAIN)` 也遵守同一规则；
它只针对 exact predecessor CAPTAIN，不能误伤后来登记的 successor CAPTAIN。新 template
与新 event ingress 都强制完整 exact-target
binding；持久化 schema 只为读取历史 ledger 保留旧格式兼容，历史无 binding event 仅能
以已 accepted 的同 event ID、同 input hash 和原 capability 幂等重放，不能换新 ID
重新执行。

控制器不会仅因一个角色仍是 live `active|idle` 就把 `ROLE_LOST` 列为可执行 action；
机械执行条件只有三类：lease 客观过期、角色自己已经持久化 `systemError` heartbeat，
或 root recovery 已形成必须替换旧 CAPTAIN 的 `recovery_backlog`。普通聊天里的
“session 好像结束了”不是第四类信号；无法持久化 `systemError` 时等 lease 到期。
Goal-wide FOREMAN 还要求同 identity/current attempt 已没有任何可用 replica。所有泛化
`ROLE_LOST` 从 action projection 删除，避免自动 consumer 把条件提示当成失联事实。
若只有某个 task 的 FOREMAN replica 是 `systemError`、同一 Goal authority 在其它 task
仍有可用 replica，则不做单 task replacement；该可用 replica 按
`GOAL_FOREMAN_REPLICA_REPAIR` maintenance action 给故障投影提交 exact heartbeat，
恢复为 `active`。只有全部同 identity/current-attempt replicas 都不可用时才开放
Goal-wide FOREMAN loss/recovery。live CAPTAIN 的 exact `ROLE_LOST(FOREMAN)` 仍优先；
若 CAPTAIN 也不可用，root recovery 必须等 current generation 全部 source replica 的
exact lease deadline 都已过期，不能把 `systemError` 当作提前撤销 Goal-wide lease。

DEV source HEAD 前进时，controller 还会比较 live `pnpm-lock.yaml` hash 与 canonical
launch。若 lockfile binding 漂移，`NONE/CLI/PREVIEW` 也不能走 source checkpoint：
投影改为 exact
`ROLE_LOST(DEV, trigger=SOURCE_RUNTIME_BINDING_CHANGED)` +
`FRESH_RUNTIME_RECOVERY_REQUIRED`，并禁止 `REQUEST_CANDIDATE_PREFLIGHT`。lockfile 未变
时才保持原 `NONE/CLI/PREVIEW` candidate preflight lane。

root intent 与 successor capability 先在 stable ID + full request digest 命名的 private
staging 内 seal；最终 batch rename 前退出时只提升经 scope/request/path/bytes 验证的原树。
prepared 或 canonical root pending 都是 Goal-wide writer fence，所有 task、resource 与
source 操作必须等待同一 recovery exact retry 闭合。

对补丁发布前已经初始化、且 control root 仍无 decoder seal 的 Goal，先按 quickstart
“audited protocol adoption”流程在 root 外部 drain/isolate 所有旧 controller，再用包含
`RECOVER_EXPIRED_FOREMAN` decoder 的新 `goalctl adopt-store-protocol` 安装 seal。命令
通过绝对路径 `--repository-worktree <frozen-goal-worktree>` 读取初始化时冻结的
protocol/packet bytes。后续该 Goal 的所有 goal/resource 控制命令沿用同一 binary 与
worktree；旧 binary 无法重放新 event、且会忽略新 seal，新 worktree 的新版协议 bytes又会
触发 drift，三者都不得混用或做同 root 滚动升级。

successor FOREMAN 不能直接接管下层工作。**已有 pending recovery 就复用；只有没有 pending recovery 才提交 `ROLE_LOST`。**固定恢复顺序是：successor FOREMAN 先按机器
状态复用或建立 CAPTAIN recovery，登记/确认 successor CAPTAIN 并闭合；successor
CAPTAIN 再按同一规则处理 worker recovery/backlog，登记 successor DEV。
`ROLE_RECOVERED(DEV)` 不授予源码执行权，而是把 successor DEV 放入 sticky
`RECOVERY_BLOCKED`：
普通 `resume/actions` 只允许 cleanup。下述 export/import/bind 是独立的 control transition
adapter，不是 DEV 工作权限；每一步都使用 fresh thread 和递增 attempt，predecessor
actors 不得再发事件。

这里的 cleanup 只指控制面明确返回、可审计且不改变源码/业务状态的临时文件与登记清理；
sealed export 完成且导入校验前不得改动 predecessor worktree。真实进程/profile/account/
port/external-session/UI target 的清理由 host broker 执行，不属于 repo cleanup。

dirty source 的唯一恢复闭环如下：

1. successor CAPTAIN 用 `goalctl recovery-export-source` 从 predecessor DEV launch 已
   绑定的 canonical predecessor worktree 读取源；命令记录精确 `source_observed_head`，
   将 tracked diff、untracked
   manifest、必要 mode/path 元数据封装为 sealed immutable snapshot，并绑定精确
   `expected_paths` 与完整 Git `expected_tree`；seal 后再次核对 worktree/head 未变化。
   successor CAPTAIN 必须先持久化 `--snapshot-id`。v3 snapshot 还 seal exact operation request 与原
   CAPTAIN identity/attempt/capability path+hash；audited Codex export 同时 seal Goal-wide
   FOREMAN authority。artifact 在 operation staging 目录 fsync 后原子 rename，并 fsync
   snapshots 父目录。publish 后响应丢失时，同一 ID/参数/capability 的 retry 先重验 sealed
   artifact 和 current/history authority，再返回原 snapshot；phase 可已前进、authority
   可已 terminal、source/broker/rollout 可已消失或变化。不同 ID 仍是新操作并走当前
   phase/lease/source gates；清 orphan 也只清本 operation ID、当前 owner 的 staging。
   successor DEV 不能进入或继续编辑 predecessor worktree。
   v2 staging 在任何 patch/artifact 前 durable 写带自 seal 的 operation binding，绑定
   stable ID digest、kind、精确请求与完整 source/input/authority execution digest。唯一
   合法 binding/manifest atomic temp 可验证后提升；完整 manifest temp 即使 source/actor
   随后消失也不重读聊天。wrong request、cross-kind、source drift、权限或 inventory
   漂移、多份 staging 全部保留 fail-closed。清理先 claim 为 deterministic discard，删除
   中途再次崩溃仍可从 binding/name 幂等收尾。
   若 predecessor worktree 已被 Codex archive 物理回收，普通 export 必须失败，不能从聊天、
   截图或模型记忆重写 delta。唯一的降级入口是
   `goalctl recovery-export-codex-rollout`：由 successor CAPTAIN 指定 canonical lost
   launch/thread 和原始
   Codex rollout JSONL，adapter 校验 session identity、call/result/event 完整性、全部成功
   `patch_apply_end`、路径边界及原始记录 hash 后生成同一种 sealed snapshot。该入口只接受
   可机械重放的 tracked `update` unified diff；target 内 add/delete/move、缺事件或未知
   change 永久 fail-closed。rollout 只是 source evidence，不会成为运行状态源。

   默认 strict 模式下，只要 rollout 含不能机械证明不改 source 的
   `exec_command`/`write_stdin`/跨 session send，或 outcome 不明但路径完全在
   predecessor 外的 `apply_patch`，export 就报
   `CODEX_ROLLOUT_SHELL_UNVERIFIED`。事故恢复确需继续时，先用
   `recovery-inspect-codex-rollout --allow-shell-audit` 取得全部 call/result 的 exact
   line/hash 集合；successor CAPTAIN 逐条归类为 `READ_ONLY`、`IGNORED_PATH_ONLY` 或
   `TEST_NO_UPDATE`，并断言 source untracked 为空，successor FOREMAN 用独立 active
   capability 联合授权。
   audit 必须绑定 exact Goal/task/lost launch+thread/cwd/HEAD、完整 rollout hash、重建 patch
   hash 和 incident ref。控制器把 audit 及每条原始 call/result 一起 seal；import 会离线
   重验。只有显式建模的 `tool_search`、plan 更新和 terminal 只读读取可自动排除；任何
   未建模 function/custom/response tool call 直接 `CODEX_ROLLOUT_TOOL_UNVERIFIED`，
   不能靠事后 audit 放行。已建模调用少一条、乱序、hash 漂移、未知 disposition、
   target/mixed patch outcome 不明也拒绝。
   若 lost predecessor 本身是上一轮 recovered DEV，注册时 task HEAD 与其后来被
   `RECOVERY_PROMOTED` 接受的 launch HEAD 是两个事实：前者保留为
   `predecessor_registered_head`，后者由 handoff checkpoint、promotion launch id/hash
   共同 seal 为 `predecessor_launch_head`。rollout 只能恢复 promotion 时间之后的 target
   patch；更早的写入一律拒绝，不能被事后合法化。
2. 为 successor DEV 创建与 predecessor **不同 realpath、不同 branch** 的 fresh
   worktree，且起点必须精确等于 `source_observed_head`。固定 controller adapter 使用
   dormant successor DEV identity 调用
   `goalctl recovery-import-source` 导入已 seal snapshot；这不激活或唤醒 DEV。导入器校验
   snapshot/hash/path 边界，只把 snapshot 明列的 tracked patch 与 untracked bytes
   materialize 到 index，拒绝任何额外 staged、unstaged 或 untracked path，并要求
   `write-tree == expected_tree`。sealed import receipt 同时绑定 expected/materialized
   tree，**不**自动 commit。随后 dormant successor DEV 使用同一 DEV capability 调用
   `goalctl recovery-checkpoint-source --snapshot <id> --import-receipt <id> ...`；
   adapter 从 sealed receipt 固定 author/committer/date/message 与 UTF-8 encoding，以
   `commit-tree` 生成
   恰好以 `source_observed_head` 为唯一 parent、tree 等于 `expected_tree` 的确定性
   checkpoint，再用 old-value `update-ref` CAS 发布。snapshot 为空时走同一 allow-empty
   checkpoint 路径；响应丢失后的精确重试返回同一 `checkpoint_sha`。import/checkpoint/
   bind 前后均拒绝 worktree-specific merge/rebase/cherry-pick/sequencer/bisect 等 hidden
   Git operation sentinel，不能让下一次普通 commit 吞入未授权的多 parent 操作。
   checkpoint destination 必须是拥有专属 gitdir 的 linked worktree。初始验证后 adapter
   先在 control root seal request-bound prepared marker，再取得带 token 的
   worktree-specific `index.lock`，临时移除 linked-worktree gitdir 全部 write bits，并在
   双 fence 内重验 index hash/sentinel。checkpoint ref 通过 common gitdir 的 old-value
   CAS 发布，避免为了更新当前 symbolic HEAD 而在已 fenced gitdir 创建 `HEAD.lock`；同时
   用 `--create-reflog` 保证 destination branch 有带 receipt ID 的人工取证记录（linked
   worktree 私有 `HEAD` reflog 不作为控制面证据）。最终 clean 后先 seal completion，再
   恢复原 mode、释放 exact token lock。completion 只证明该 request 曾成功发布；精确重试
   仍须在 fence 内核对 live branch：仍为 checkpoint 才是无操作重放；若只被退回 sealed
   `source_observed_head`，则用同一 old-value CAS 重新发布；任何第三方 HEAD 都拒绝覆盖。
   prepared 未完成或
   completion 后仍有 fence residue 时投影 `SOURCE_CHECKPOINT pending`，冻结 Goal writer；
   SIGKILL 后只允许同 snapshot/receipt/request 接管。异文 token、缺 lock 的 fenced gitdir、
   mode/dev/inode 漂移一律保留 fail-closed。该组合保护最终验证、ref CAS 与 completion
   的临界区；恢复 gitdir 写权限是明确 release 点，不承诺 checkpoint CLI 返回后到 bind
   之间持续排他。release 后的新 Git operation/ref 漂移由 `recovery-bind` 再次精确核验并
   fail-closed。同 UID 主动 chmod/直写 `.git`、ACL 额外写权或需要跨命令持续排他的场景
   仍必须依赖独占执行环境或 host broker，不把用户态 fence 冒充 OS 隔离。
   Receipt 是长期证据，可以晚于 disposable Codex worktree 存活；重放旧 receipt 时允许其
   历史 source/destination 路径已消失，但当前 import/bind destination 仍必须现场
   canonicalize，并与 receipt 精确一致。
   controller 必须先持久化 `--import-id`，该值直接成为 receipt ID。v3 receipt seal 原 DEV
   identity/attempt/capability path+hash；publish 后，同一 ID/snapshot/destination
   worktree+branch/原 capability 可从 current/history 返回原 receipt，不再要求原 DEV
   active、phase 未推进或 HEAD/index 停在导入点，因此 checkpoint commit、promotion、
   terminal 后仍可精确重放。若进程在完整 materialization 后、receipt 前退出，retry
   只在 staged tree/paths 精确等于 snapshot 且没有 unstaged/untracked 时补 seal receipt；
   partial/异文状态 fail-closed，不 reset、不覆盖。
   worktree mutation 前还必须发布 request-bound import intent。完整 canonical/atomic-temp
   intent 在 pre-rename crash 后由原 ID/request/authority 提升，即使 DEV lease 后续过期
   也不删除或重写；unsealed staging 只有精确调用可严格清理。若 staging 尚无可恢复的 raw
   stable ID，公开 pending 只给出 `stable_id_sha256` 并标记 unavailable；原 ID 必须由
   调用方在首次执行前持久化，不能把 hash 当 CLI 参数。
   v1 artifact 仍可解码审计，但缺 exact tree 时禁止 import/bind；既有 v2 exact-tree
   snapshot/receipt 继续支持 import 与验证。只有 v3 具备本段 response-loss replay 所需的
   operation request 与 sealed authority。
   普通 patch、复制目录、cherry-pick 多 parent 历史或在旧 worktree 继续开发均禁止。
3. successor CAPTAIN 先持久化 operation ID，调用
   `goalctl recovery-bind ... --event-id <stable-id>`
   再验证 export/import receipt、exact paths/tree 与
   single-parent checkpoint 的 parent、commit tree、diff，验证通过才追加
   `RECOVERY_HANDOFF_BOUND`。successor DEV 从 `RECOVERY_BLOCKED` 进入
   `PREFLIGHT_ONLY`，但仍不是
   active DEV：只允许由 CAPTAIN 驱动 fresh resource acquire、`launch-template`、preflight/
   PREFLIGHT evidence 和 cleanup；源码、测试、commit、push、preview/login、
   external-session/UI/host integration 及 `DEV_READY` 全部禁用。该阶段 HEAD 必须始终
   精确等于 sealed import checkpoint，
   不能先产生 descendant commit；identity 已冻结，因此 `actions/next` 也不得再推荐
   `ROLE_LOST`。
4. successor CAPTAIN 为 successor DEV 生成 fresh launch，manifest 必须列全实际需要的
   fresh leases；旧 lease 不继承。确定性 preflight 对 fresh worktree/branch、import
   checkpoint、launch、完整 lease set、packet/epoch/head 全部 PASS 后，successor
   CAPTAIN 持久化新的 operation ID，才能调用
   `goalctl recovery-promote ... --event-id <stable-id>` 提交
   `RECOVERY_PROMOTED`。只有该事件接受后 scope 才变为 `FULL`，CAPTAIN 才可激活/唤醒
   successor DEV，
   发放运行时能力，让其开始源码、测试、commit、push 和最终 `DEV_READY`。
   registration HEAD 与 import checkpoint 是不可变的身份/谱系 anchor，不会随着后续开发
   commit 改写。候选 HEAD 前进后，DEV_READY 必须使用同一 session/launch identity 为当前
   PR HEAD 重新生成的 launch + PREFLIGHT evidence；controller 同时验证 anchor 是候选
   ancestor 和 candidate launch 精确绑定当前 HEAD。

Codex handoff 会创建新的 thread identity，不是已登记 successor 的续体。控制面禁止把
handoff 后的新 thread 填回原 registration、复用原 actor capability，或声称它仍是原
successor DEV。
若 handoff 发生在 `RECOVERY_BLOCKED` 且尚未接受 `RECOVERY_HANDOFF_BOUND`，controller
可以用 fresh attempt/thread 登记 dormant replacement，但必须：

- 保持 recovery 的 `source_predecessor` 仍指向最初 lost DEV 及其 canonical source
  worktree/launch；不得把中间 successor 改写成新的 source predecessor；
- 在 append-only `recovery_chain[]` 记录 predecessor→successor→replacement 的每段
  thread/host/attempt、handoff 原因和替换时 scope，fence 被替换 successor capability，
  并使其 identity-bound import receipt/
  checkpoint/bind 输入失效；
- replacement 仍停在 `RECOVERY_BLOCKED`，从同一 sealed source snapshot 按自身 identity
  重做尚未绑定的 import/checkpoint/bind，不能继承中间 successor 的普通聊天或权限。

一旦 `RECOVERY_HANDOFF_BOUND` 已接受、scope 进入 `PREFLIGHT_ONLY`，successor identity
即冻结。此后 Codex handoff、thread 变化或尝试登记替代者都必须 fail-closed；不得迁移
receipt、launch、lease、PREFLIGHT evidence 或继续 promote。controller 记录 incident，
保持非 FULL。唯一恢复决策是：当前 handoff 尚未 promotion、当前 successor 名下没有
非终态 resource lease 时，由 active CAPTAIN 与 active FOREMAN 以两份独立 capability
先持久化 operation ID，再调用
`goalctl recovery-abandon-handoff ... --event-id <stable-id>`。控制器追加
`RECOVERY_HANDOFF_ABANDONED`，保留旧 receipt/checkpoint/binding 的完整审计历史并把
scope 退回 `RECOVERY_BLOCKED`；随后才允许按普通 `ROLE_LOST`、fresh attempt registration、
`ROLE_RECOVERED` 重建 successor。旧 runtime、launch、receipt、preflight 和 capability
一律不迁移；任一联合身份失效或资源未释放就继续 fail-closed。

旧 launch/resource set 默认继续 fail-closed。仓内
`resourcectl reinitialize-zero-runtime` 只证明一个狭窄的 no-op：旧 launch 必须同时为
`target=NONE`、`environment=none`、`write_mode=NONE`，其 sealed `resource_leases`
必须为空，并且 lost owner 在资源账本中没有任何非终态 lease。返回
`no_op=true/event_id=null`，不会制造 `REVOKED` 事件。只要旧 launch 曾绑定一个 lease，
即使 lease 已过期或 `RELEASED`，仓内声明也不能证明旧 actor 没有消费对应
PID/profile/account/port/external-session/UI 状态，必须由资源专用 host broker 机械隔离后
再推进。

早期 v1 曾接受 `LEASE_SET_REVOKED`，但该事件只有控制身份双授权，没有资源类型专用的
host fence receipt。新 decoder 为保持 append-only replay 不改写旧记录，却把这类 lease
投影为 `UNVERIFIED_REVOKE`：它仍是非终态、`resourcectl doctor` 报
`RESOURCE_BROKER_REPAIR_REQUIRED`，同一物理资源禁止再次 acquire。只有对应 host broker
验证并落下资源专用 repair/isolation receipt 后，后续版本才可解除隔离；不得把历史
`REVOKED` 文案当作资源已释放。

这里的 repo 控制面只能机械限制仓内 action/event/capability 流程，不能阻止同一用户直接
调用 browser、app automation、MCP 或其它外部工具。因此 successor DEV 在 `FULL` 前保持
dormant：不发送普通
agent 唤醒、不交付浏览器/MCP/账号/lease owner capability。涉及真实 target 的撤销、fence
与 fresh capability 签发必须由 host broker 执行；文档约束不能冒充 OS/App 隔离。

若根恢复前已有 worker recovery，它会在 successor FOREMAN/CAPTAIN 恢复期间进入
backlog；任何 worker verdict/业务 transition 都被 `RECOVERY_BACKLOG_REQUIRED` 阻断。
successor CAPTAIN 恢复完成后控制面自动
把原 recovery 提升回当前槽，再登记/确认仍有效的 fresh worker。若已有 CAPTAIN
recovery，则 successor FOREMAN 直接继续确认或替换 CAPTAIN successor；有效 CAPTAIN
successor 不能因“仍在线”阻止 predecessor FOREMAN 根恢复，因为它无权自我确认。

根恢复只 fence 控制面 FOREMAN identity，**不**释放、reap 或转移任何
port/profile/account/external-session/UI lease，也不证明旧进程已停止。preview、login、
external-session、UI 和环境写继续 fail-closed；必须按原 resource
broker/identity preflight 规则隔离并重新验证，
不能把 recovery capability 当资源 capability。

用户新指令先提升 `control_epoch` 并重新 reconcile；旧 epoch 的异步事件一律拒绝。恢复不能把 `task_complete` 当作 PASS，也不能要求用户再说一次“继续”。

control epoch 本身也是 append-only、hash-chained、FOREMAN-capability 授权且带 expected-epoch CAS 的 Goal 事件，不再改写 `goal.json`。提升后每个 task 都进入 `CONTROL_RECONCILE_REQUIRED`；FOREMAN 必须逐 task 提交引用当前 control event 的 `CONTROL_RECONCILED`。reconcile 会同时终结旧 CAPTAIN 与所有执行角色 attempt、清空 P1/PR/evidence/merge；机械 P1 回 `QUEUED` 等 fresh successor 重新 START，legacy task 保持原回 P1 行为。legacy `PACKET_UPDATED` 同样终结旧 attempt；机械 P1 v1 直接拒绝。FOREMAN 必须登记不同 thread/host 的 successor CAPTAIN，旧 CAPTAIN 不能在 compact 后读取新 envelope 继续驾驶。

## 10. Shadow 迁移

控制面按四步启用：

1. **simulation**：fixture 覆盖正常、返工、RECEIPT fail、非法迁移、重复/陈旧事件、恢复和 lease 冲突；
2. **shadow capture**：旧流程仍是运行权威，控制面只记录 would-transition、生成账本和报告 divergence，不 spawn/send/archive、不改 GitHub；
3. **shadow coordinated**：一个低风险新 task 由 CAPTAIN 协调，FOREMAN 仍人工核验最终 merge；
4. **enforced task/goal**：状态、下一动作和 merge precondition 只认控制面，禁止回退到聊天账本。

当前 scaffold 已能生成两种 mode，但默认及省略值仍是 `shadow`；只有 spec 显式声明
`enforce` 且调用同时传 `--allow-enforce` 才生成 enforced 静态包。这个显式 flag 不跳过
上述 rollout 准入，不授权未建模外部动作；输入、authority 或 gate 不满足时仍
fail-closed。

不要把正在飞的旧 task 从 JSONL 重建历史。当前控制器**未实现** `LEGACY_IMPORT`：
正在飞的旧 task 只能按 legacy 流程完成，或保持停止并等待另一个显式、可审计的迁移工具
落地；禁止用手写 event/快照冒充迁移。shadow 至少跑过正常、REVIEW 返工、RECEIPT fail、
successor 和资源冲突且无未解释 divergence，才进入 enforced。
