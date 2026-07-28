# Goal 控制面 · Store 运维手册

> **仅供 supervisor / control-plane operator 使用。** FOREMAN、CAPTAIN 和执行角色的
> 正常运行路径不读取本文；它们遇到 `STORE_PROTOCOL_MIGRATION_REQUIRED`、
> `STORE_PROTOCOL_UNSUPPORTED`、odd generation 或 decoder 漂移时停止并把错误交给
> supervisor。正常建 Goal 和连续调度见
> [`goal-control-run-goal.md`](./goal-control-run-goal.md)。
> 本文 `gc_goalctl <controlled-worktree> ...` 使用
> [`goal-control-quickstart.md`](./goal-control-quickstart.md#01-固定双根目录与-exact-argv-wrapper)
> 定义的 audited Node + exact controller root wrapper；不得从受控仓 `pnpm` 或 `PATH`
> 解析 decoder。执行 rotation 时 wrapper 的 controller root 必须是 successor。

## 0.5 只对现存 v1 root：先做 audited protocol adoption

新版 controller 会用 root decoder seal、nonce writer lock 和 stable state vector 拒绝
不同 decoder 并发读写。全新 root 由 `init` 自动安装 seal；**已有 events/resources、但还
没有 `.store-protocol.json` 的非空 v1 root** 不会被普通命令顺手升级，而是返回
`STORE_PROTOCOL_MIGRATION_REQUIRED`。

迁移前先在进程/session 层停止并隔离所有仍可能访问该 root 的旧 `goalctl` /
`resourcectl`。这是硬前置条件：旧 binary 不认识新 seal，seal 安装后它仍可能再次写入；
同一 root 无法对这类同 UID 旧进程做双向 fencing。确认旧 controller 全部退出后，选择
初始化时 protocol/packet 字节仍完整且 `git status` 为空的 frozen Goal worktree，用
**新版 controller binary** 执行一次：

```bash
gc_goalctl <frozen-goal-worktree-absolute-path> adopt-store-protocol \
  --incident-ref <durable-incident-or-change-reference> \
  --acknowledge-old-controller-drained ALL_OLD_CONTROLLERS_DRAINED_AND_ISOLATED \
  --json
```

单 worktree 能满足 root 内全部 Goal 的 frozen protocol/packet hash 时可省略
`--goal-worktrees-file`，行为与旧命令一致。若多个 Goal 冻结了同一路径的不同历史 bytes，
在上述命令增加
`--goal-worktrees-file <absolute-goal-worktree-map.json>`，并提供精确覆盖全部非
rejection-only Goal 的映射文件：

```json
{
  "schema_version": 1,
  "goal_worktrees": [
    {
      "goal_id": "goal-a",
      "repository_worktree": "/absolute/canonical/worktree-at-goal-a-head"
    },
    {
      "goal_id": "goal-b",
      "repository_worktree": "/absolute/canonical/worktree-at-goal-b-head"
    }
  ]
}
```

数组按 `goal_id` 排序，不得缺项或多项。映射文件和每个 worktree 都必须是非 symlink
canonical path；worktree 必须 clean、属于 `--repository-worktree` 的同一 Git common
dir，并完整匹配对应 Goal 的 frozen protocol/packet。映射文件 exact hash、每个 worktree
的 canonical path/common-dir/HEAD、manifest hash 与 frozen-inputs hash 会写进 migration
receipt，并由 legacy anchor artifact 和 root protocol seal 双重锚定；幂等重跑必须继续
提供同一映射 bytes 与 identities。

命令持有唯一 nonce writer lock，但 validator 本身零写：它枚举 root 中每个 Goal，完整
重放 control/task event 与 evidence registry，逐 Goal 核对 frozen
manifest/protocol/packet；同时重放 resource event、head/tail 与 fencing token。旧 accepted
event 尚未携带 evidence digest 时，会生成
`.legacy-evidence-anchors.v1.json`，把 event identity/hash 与当时 registry digest
逐条冻结；它也把 `incident-ref` 与 exact drain acknowledgment 写入 migration receipt。
旧 semantic evidence 的 source bytes 按 SHA-256 去重复制到
`.legacy-evidence-sources.v1/`（单份不超过 16MiB、去重总量不超过 64MiB、最多 4096
份），registry URI 对应的原 worktree 后续消失时才允许从该副本重放；原 URI 若仍存在但
hash 漂移则直接失败，不用副本掩盖。index 与每个 source artifact 的 exact hash 都由 root
protocol seal 再锚定。旧 decoder 已接纳、但 event 尚无
`prepared_identity_incident_authority` 的 controller-generated launch identity hold，
还必须进入 `.legacy-identity-incidents.v1.json`：每条 binding 同时冻结
goal/task/hold、accepted event/input/hash、evidence registry/source、parent PREFLIGHT、
candidate launch、actor 与 controller authority，source bytes 也按 hash 内嵌。该 artifact
只有被 adoption protocol descriptor 明列并由 root seal 锚定后才可参与重放；放在 root
里的同名自签文件、聊天转述或孤立 source 副本都不构成 provenance。identity incident
receipt 内全部去重 source 的**解码后总量上限是 4 MiB**；这是因为 source 会以 base64
嵌入 canonical rotation receipt，而完整 receipt 仍受 16 MiB 上限约束。超过上限必须
fail-closed，不能截断、只留 hash 或改用未被 protocol seal 锚定的外部文件。
未知 event/evidence/resource、缺失或落后的 head、artifact/hash
漂移、decoder 不匹配、验证期 authoritative bytes 变化，都会在安装 seal 前失败。
validator 若发生写入则保留 lock/故障证据，不得删证后强行重跑。

成功 JSON 必须保存进 `--incident-ref` 指向的审计记录，至少核对：

- `adopted: true`（安全重跑则是 `idempotent: true`）；
- `protocol.controller_decoder_sha256` 与本次 decoder 一致；
- `source_state_vector_sha256`、`sealed_state_vector_sha256` 均存在；
- `validation.goals` 覆盖预期全部 Goal，resource/evidence event 数量符合现场；
- `validation.goal_worktree_map` 精确覆盖全部 Goal，mapping/worktree identity hash 与
  incident 审计记录一致；
- `migration_artifacts` 中的 legacy evidence anchor/source 与 identity incident receipt
  均和 protocol seal 一致；保存并核对
  `validation.legacy_identity_incident_count`，不能把非零值当成普通 semantic evidence
  略过。

同一 root 的幂等重跑必须继续使用首次 seal 的 `incident-ref`；换一个 ref 会以
`STORE_MIGRATION_INCIDENT_MISMATCH` 拒绝，不能用新 stdout 覆盖原审计身份。

迁移后所有命令固定使用同一新版 binary 与 frozen worktree。不要在同一 root 上做旧/
新 controller 滚动升级；需要并行版本时必须由外部 broker/OS 隔离到不同 root。

## 0.6 已 seal root 的 decoder 升级：audited protocol rotation

`.store-protocol.json` 已存在、但新 binary 返回 `STORE_PROTOCOL_UNSUPPORTED` 时，不得
手改 seal，也不得再跑 adoption。先停止并隔离所有旧 controller，准备：

- 首次调用前持久化的稳定 `rotation-id`；
- 当前 root 中 `.store-protocol.json` 的 exact `seal_sha256`；
- 仍保持 clean、可重放旧 decoder closure 的 frozen controller worktree；
- 精确覆盖 root 内全部 Goal 的 frozen worktree map（格式同 0.5；新增 Goal 可以加入，
  0.5 已封存的历史映射必须作为逐字段不变的子集保留）。

然后用 **successor binary** 执行：

```bash
gc_goalctl <current-frozen-goal-worktree-absolute-path> rotate-store-protocol \
  --rotation-id <stable-rotation-id> \
  --predecessor-controller-worktree <frozen-old-controller-worktree-absolute-path> \
  --goal-worktrees-file <absolute-goal-worktree-map.json> \
  --expected-predecessor-seal-sha256 <sha256:...> \
  --incident-ref <durable-incident-or-change-reference> \
  --acknowledge-old-controller-drained ALL_OLD_CONTROLLERS_DRAINED_AND_ISOLATED \
  --json
```

三种路径不要混淆：`--repository-worktree` 只用于定位共享 control root；
`--predecessor-controller-worktree` 只提供旧 decoder；真正要安装的 target
decoder/schema 永远由当前命令 binary 自己计算，CLI 不接受调用方指定 SHA。

命令先用旧 decoder 的严格 reader 证明 predecessor seal 与 closure 相符，再取得采用旧
lock-v2 wire identity 的专用 writer lock。锁内由旧、新 decoder 分别重放全部
Goal/resource，语义摘要一致且 frozen worktree、legacy artifacts、source vector 全部稳定
后，才依次原子创建不可变 rotation receipt、替换 successor protocol seal、完成 even
generation。旧 legacy anchor/index/source bytes 不会重写；新增 Goal 的完整 map 单独进入
rotation receipt。

若 predecessor 在上一次 adoption/rotation **之后**又接纳了尚无
`prepared_identity_incident_authority` 的 controller-generated identity hold，
successor 不回写旧 event，也不修改既有 migration artifact。它会在锁内用 predecessor
decoder 重放并重新验证原 event、parent PREFLIGHT、candidate launch、actor/authority 与
source bytes，把 exact
`validation_report.legacy_identity_incident_receipt` 内嵌进本次不可变 rotation
receipt；外层 receipt 再由 successor root protocol descriptor 锚定。以后原 evidence URI
或旧 worktree 消失时，accepted `ADD_HOLD` 重放、pending-operation 扫描和 launch-hold
分类只可从这个闭集按
`goal/task/hold/evidence/registry/source/event/authority` 全量精确匹配恢复 bytes。
同名自签 artifact、只匹 source hash 的副本、语义相似 hold 或未接纳 evidence 均不得走
该 fallback。

rotation 输出中的 `legacy_identity_incident_count` 是本轮封存数；
`legacy_identity_incident_skipped_semantic_count` /
`legacy_identity_incident_skipped_semantic_holds` 只记录确定不属于 controller identity
lane 的普通 hard hold。若 hold 具备 deterministic `env-hold-*` /
`env-incident-*` 形状、PREFLIGHT `LAUNCH_ID_CONFLICT`，或 source 可解析为
`goalctl/PREFLIGHT_IDENTITY_INCIDENT`，却无法生成完整 receipt，rotation 必须
fail-closed，不能把它归入 skipped。

只允许以下四种机器状态：fresh predecessor-even、同一 transaction 的 predecessor-odd、
receipt 已发布的 successor-odd、successor-even exact idempotent。foreign odd/transport、
不同 rotation ID/incident/map/predecessor seal、旧 decoder 或 artifact 漂移都会
fail-closed。响应丢失只用完全相同参数重试；成功时核对
`operation=STORE_PROTOCOL_ROTATION`、`rotation_receipt.sha256`、entry/exit generation、
双 decoder replay hash 与 `protocol.seal_sha256`，并把 JSON 保存到 incident 记录。

保存成功 JSON 后立刻做一次 post-rotation canary。以下命令必须继续使用同一个
successor binary 和同一个 frozen Goal worktree；`actions` 的 role/thread 替换成现场已
登记身份：

```bash
gc_goalctl <current-frozen-goal-worktree-absolute-path> status \
  --goal <goal-id> --json
gc_goalctl <current-frozen-goal-worktree-absolute-path> next \
  --goal <goal-id> --json
gc_goalctl <current-frozen-goal-worktree-absolute-path> doctor \
  --goal <goal-id> --json
gc_goalctl <current-frozen-goal-worktree-absolute-path> actions \
  --goal <goal-id> --task <task-id> --role FOREMAN \
  --thread <registered-foreman-thread-id> --json
```

`status`、`next`、`actions` 必须退出 0 且 JSON 可解析。`doctor` 在健康 Goal 上必须
healthy/退出 0；若 rotation 的目的正是恢复一个已有 hard hold，则退出 1 是预期的安全
诊断，不可要求它伪装 healthy。此时必须解析 JSON，逐条核对 findings 只包含 rotation 前
已知的现场问题，并确认没有 decoder/replay/protocol 错误，也没有把原 identity hold
降级为 `LAUNCH_IDENTITY_HOLD_UNCLASSIFIED`。退出 2、JSON 不可解析或出现新增未知 finding
一律停止。然后用 frozen predecessor binary 对同一 root 做一次只读 `status` 负向
canary：必须退出 2，且 code 只能是 `STORE_PROTOCOL_UNSUPPORTED` 或
`CORRUPT_STORE_PROTOCOL`。旧 decoder 的字段校验顺序不同：有的先拒绝 schema/decoder
compatibility，有的先拒绝 successor seal 的未知字段，所以精确 code 不稳定；两者都
表示旧 decoder 已 fail-closed。禁止为了得到单一 code 修改 frozen predecessor。

```bash
node <frozen-old-controller-worktree>/scripts/goalctl.js status \
  --repository-worktree <current-frozen-goal-worktree-absolute-path> \
  --goal <goal-id> --json
# 预期：exit 2；stderr code 属于上述两个 fail-closed code 之一。
```

最后核对 durable 清理边界：

```bash
CONTROL_ROOT="$(
  git -C <current-frozen-goal-worktree-absolute-path> \
    rev-parse --path-format=absolute --git-common-dir
)/goal-control/v1"
jq -e '
  (.generation % 2) == 0
  and .active_transaction == null
  and .pre_write_vector_sha256 == null
' "$CONTROL_ROOT/.generation.json"
node - "$CONTROL_ROOT" <<'NODE'
const fs = require('fs');
const path = require('path');
const root = process.argv[2];
const locks = fs.readdirSync(root).filter(
  (name) => name === '.lock' || name.startsWith('.lock.'),
);
if (locks.length > 0) throw new Error(`residual lock: ${locks.join(',')}`);
const atomic = path.join(root, '.atomic-transactions');
if (fs.existsSync(atomic)) {
  const stat = fs.lstatSync(atomic);
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new Error('atomic transport 不是 plain directory');
  }
  const entries = fs.readdirSync(atomic);
  if (entries.length > 0) {
    throw new Error(`residual atomic transport: ${entries.join(',')}`);
  }
}
NODE
```

任一 canary 失败都停止后续 FOREMAN/worker，不删除 lock/atomic/generation 证据。旧 decoder
strict probe（60 秒）与锁内 semantic replay（5 分钟）都有硬超时；超时会 SIGKILL
子进程并在 authoritative bytes 未变时释放 writer lock，不能靠无限等待推进 rotation。
