'use strict';

const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const { fileURLToPath } = require('url');
const { authorizeGoalSession, authorizeSession } = require('./auth');
const { ControlError, assertControl } = require('./errors');
const {
  evidenceFile,
  inspectPreparedEvidenceBytesForRetryUnderLock,
  readExistingEvidenceForRetryUnderLock,
  recordEvidenceBytesUnderLock,
  semanticIngressPreparedFile,
} = require('./evidence');
const { actorSequenceKey, allowedActions, TRANSITIONS } = require('./fsm');
const {
  acceptEventUnderLock,
  assertFrozenInputs,
  authorizeHistoricalActorCapability,
  completeMechanicalP1EventPayload,
  inspectSourceCheckpointHold,
  loadGoalState,
  loadGoalStateReadOnly,
  loadGoalStateUnlocked,
} = require('./goal');
const { assertOperationalScope, sessionOperationalScope } = require('./operational-scope');
const {
  assertLaunchRuntimeIncarnation,
  assertRotationSuccessorLaunch,
  predecessorLaunchForRotation,
} = require('./runtime-incarnation');
const {
  assertSourceCheckpointAdvance,
  canonicalRuntimeLaunchFile,
} = require('./launch-source-checkpoint');
const {
  assertWorkerBootstrapCurrentWorktree,
  assertWorkerBootstrapLaunchBinding,
  requiredWorkerBootstrapBinding,
} = require('./worker-bootstrap-binding');
const {
  canonicalTransactionKey,
  ensureDir,
  isOddTransactionRetry,
  withLock,
} = require('./store');
const {
  assertFullSha,
  assertIsolatedTestMode,
  canonicalJson,
  controlRoot,
  git,
  hashFile,
  hashObject,
  normalizeHash,
  nowIso,
  randomId,
  readJson,
  repoRoot,
  safeId,
  sha256,
} = require('./util');
const {
  EVENT_PAYLOAD_REQUIRED,
  ROLES,
  assertLiveRoleLostTargetBinding,
  parsePullRequestUrl,
  validateEvent,
  validateLaunchManifest,
  validateManifest,
} = require('./validation');

const DEFAULT_PROTOCOL = Object.freeze({
  entry: 'docs/planning/session-role-protocol.md',
  shared: 'docs/planning/session-protocol/shared.md',
  foreman: 'docs/planning/session-protocol/foreman.md',
  captain: 'docs/planning/session-protocol/captain.md',
  role_kernel: 'docs/planning/session-protocol/role-kernel.md',
});

const GOAL_COMMANDS = Object.freeze([
  ['help [command]', '显示总览或单个命令帮助'],
  ['scaffold --spec <json>', '从完整 task spec 原子生成 Goal 静态包（默认 shadow；enforce 须显式 --allow-enforce）'],
  ['preclaim-issues --manifest <json> --operation-id <id>', '在 Goal init 前幂等认领 manifest 精确 issue 白名单并 seal readback receipt'],
  ['canary-bootstrap-plan ...', '为 opaque dynamic worker 生成零权限 IDENTITY_ONLY plan'],
  ['canary-bootstrap-inspect ...', '从 worker 实际 process cwd 只读回报 thread/host/worktree identity'],
  ['canary-bootstrap-prepare ...', '以 durable intent/CAS 绑定 actual linked worktree branch 并 seal receipt'],
  ['canary-plan --repository-worktree <frozen-goal-worktree> --manifest <json> --role <role> [--task <id>] [--browser-canary-receipt <absolute-json>]', '用当前 absolute controller binary 对 frozen Goal worktree 与受控 localhost server receipt 机械计算当前角色的最小 canary probe'],
  ['prepare-probe-observation-challenge ...', '验证预先存在的 host-signed actual role identity observation，并在同一 locked upstream transaction 原子发布 durable identity intent/challenge'],
  ['init --manifest <json>', '从已提交的 manifest/packet 初始化 Goal'],
  ['adopt-store-protocol ...', '审计迁移现存非空 v1 control root 到当前 decoder/lock protocol'],
  ['rotate-store-protocol ...', '在 exact predecessor seal 与双 decoder 重放验证后轮换已 seal control root'],
  ['register-role ...', '登记角色；后续 task 的 FOREMAN 只投影同一 Goal authority'],
  ['refresh-probe-observation ...', '在现有 binding 过期前以 CAS 原子续订 sealed probe observation receipt'],
  ['recover-expired-foreman ...', '原子批量替换过期死锁中的 Goal-wide FOREMAN projections'],
  ['status --goal <id>', '读取机器状态投影'],
  ['next --goal <id>', '计算当前可并行启动的 task 批次'],
  ['actions --goal <id> --task <id> [--role <role> --thread <id>]', 'credentialless 读取 task 合法动作/identity intent；指定 exact role+thread 时追加当前 actor scope'],
  ['resume --goal <id> --task <id> --role <role> --thread <id>', '生成 compact/successor 恢复 capsule'],
  ['event-template ...', '生成绑定当前 CAS/epoch/packet/HEAD 的事件，不提交'],
  ['event --goal <id> --file <json>', '验证并接受一个结构化事件'],
  ['revalidate-source-checkpoint-hold ...', 'FOREMAN 机械复核 source-only stale-head hold，幂等登记 resolution evidence 并解除 hold'],
  ['merge-pr ...', '用 durable intent/receipt 执行并恢复 canonical GitHub squash merge'],
  ['p1-abandon-commit ...', 'FOREMAN 审计废止未 append 的 prepared P1 commit/ref'],
  ['recovery-export-source ...', '从 lost DEV 的 canonical worktree 导出不可变源码快照'],
  ['recovery-export-codex-rollout ...', '从 lost Codex DEV 的 rollout 导出可审计 sealed patch 快照'],
  ['recovery-inspect-codex-rollout ...', '只读列出 rollout patch 与 exact shell-audit call 集合'],
  ['recovery-build-codex-shell-audit ...', '从简化 dispositions 确定性构建完整 shell audit JSON'],
  ['recovery-import-source ...', '把快照导入不同 worktree/branch 并全量 stage'],
  ['recovery-checkpoint-source ...', '从 sealed import index 确定性创建 single-parent checkpoint'],
  ['recovery-bind ...', '验证 import checkpoint 并把 recovered DEV 限定为 PREFLIGHT_ONLY'],
  ['recovery-abandon-handoff ...', 'CAPTAIN+FOREMAN 联合废止未 promotion 的 sealed handoff'],
  ['recovery-promote ...', '验证 fresh launch/preflight 后把 recovered DEV 提升为 FULL'],
  ['rotate-runtime ...', '在唯一 ENV identity hard hold 下为同一 worker CAS 换用 fresh local PREVIEW runtime identity'],
  ['launch-template ...', '为已登记 worker 生成精确 launch manifest，不执行 preflight'],
  ['preflight ...', '验证并 seal launch/runtime/environment 证据'],
  ['evidence ...', '登记并 seal 语义证据'],
  ['gate-fast ...', '运行 DEV Fast gate 固定适配器'],
  ['gate-full-ci ...', '验证 CAPTAIN Full CI 固定适配器'],
  ['gate-ac-audit ...', '运行 CAPTAIN AC audit 固定适配器'],
  ['control ...', '提升 Goal control epoch'],
  ['doctor --goal <id>', '诊断漂移、过期、hold 与 recovery'],
  ['rebuild-ledger --goal <id>', '从 append-only events 重建总表'],
]);

const RESOURCE_COMMANDS = Object.freeze([
  ['help [command]', '显示总览或单个命令帮助'],
  ['acquire ...', '获取声明过的资源租约'],
  ['renew ...', '续租当前 owner 的资源'],
  ['release ...', '释放当前 owner 的资源'],
  ['verify ...', '验证租约 owner、resource 与 fencing'],
  ['owner-capability ...', '由合法 actor 恢复 owner capability 文件'],
  ['reap ...', '请求回收过期租约；v1 fail-closed，不转手'],
  ['reinitialize-zero-runtime ...', '双授权证明 sealed zero-runtime predecessor 的空租约 no-op'],
  ['list [--goal <id>] [--task <id>]', '列出资源租约'],
  ['doctor', '诊断资源事件与租约状态'],
]);

const GOAL_HELP = Object.freeze({
  scaffold: {
    usage: 'goalctl scaffold --spec <repo-relative-json> [--output-dir docs/planning/goals/<goal>] [--allow-enforce] [--json]',
    summary: '复制完整 packet 源文件并生成 deterministic manifest；不创建 session、capability、launch 或事件。',
    safety: '需要 dynamic worker bootstrap 时，必须由 scaffold spec 显式携带 worker_canary_bootstrap；生成器会按 manifest decoder 验证并原样纳入 deterministic output。禁止生成后手改 manifest opt-in。',
  },
  'preclaim-issues': {
    usage: 'goalctl preclaim-issues --manifest <repo-relative-json> --operation-id <stable-id> [--json]',
    summary: '从已提交 manifest/authorization 读取 exact issue whitelist；先在已迁移 control root seal request-bound intent/逐 issue初始观察，再幂等 claim + status:doing readback，最后 seal receipt。',
    safety: 'CLAIMED 与本次授权下 MINE_NEED_CONFIRM 均为合法结果；OTHERS_REJECT 会 seal BLOCKED receipt 并停止。外部 mutation 前后的 crash/响应丢失只允许同一 operation ID、同一 committed bytes 和 exact request 重试；不输出 token，不覆盖异文 intent/observation/receipt。',
  },
  'canary-plan': {
    usage: '<controller-root>/scripts/goal-control/canary-plan-launch.sh [--node-executable <canonical-absolute-path>] --repository-worktree <frozen-goal-worktree> --manifest <repo-relative-json> --role FOREMAN|CAPTAIN|DEV|REVIEW|RECEIPT [--task <id>] [--browser-canary-receipt <absolute-0600-json>] [--worker-bootstrap-receipt <absolute-0600-json> --worker-bootstrap-receipt-sha256 <sha256> --worker-bootstrap-operation-id <id> --worker-bootstrap-challenge <64hex> --worker-bootstrap-identity-plan-sha256 <sha256> --worker-thread <id> --worker-host <id>] [--json]',
    summary: '以 absolute clean committed controller 只读验证 frozen Goal worktree 中的 manifest、全部 packet/protocol/P1 authority/canary policy，再按 role/task 生成 hash-bound 的最小 canary plan、GitHub App repository-metadata 语义合同、probe 顺序和聚合规则。',
    safety: '必须用 canary-plan-launch.sh 清空 inherited environment；setup-node/fnm/asdf 等非固定安装位置必须由 supervisor 把其已信任运行时的 canonical realpath 作为 argv-only --node-executable TCB 传入，worker 禁止自选，且禁止从 PATH/环境变量发现。launcher 用固定 OS 工具独立验证无控制字符、ordinary single-link/mode；自动发现的固定候选还要求当前 uid/root owner，显式 override 的 owner/provenance 则属于 supervisor 外部批准的 TCB，以兼容 actions/setup-node 的异 uid runner toolcache。launcher 本身不认证调用者，worker 只能执行冻结的 exact argv。随后在 env-i 下做 Node >=22.19 兼容性检查；兼容性检查不是 executable provenance 证明，恶意 binary/同 UID pathname replacement 明确在本地边界之外。plan replay 也只能原样执行 hash-bound env -i shell_command。controller root/entrypoint 与 frozen Goal repository_worktree/HEAD 是两组独立 canonical identity，不能靠 cwd 或一个 HEAD 代替另一个；完整 control closure 必须逐 HEAD blob 匹配，assume-unchanged/skip-worktree 一律拒绝。dynamic worker 额外要求 receipt path/SHA、原始 operation/challenge/identity-plan SHA、actual thread/host 七项原子 binding；operation/challenge/identity-plan SHA 必须来自 supervisor 创建 worker 前持久化的值，thread/host 只认平台实际 identity，禁止 worker 从 receipt 或聊天自选/重建。canary 必须从 receipt 绑定的 actual process cwd 生成和重放；父/兄弟 cwd 或 detached/dirty/identity 漂移立即拒绝。CAPTAIN/DEV/REVIEW/RECEIPT 必须指定已知 task；FOREMAN 禁止指定 task。只有适用于该角色的 BROWSER_PROFILE/WINDOW 才要求 Browser；REQUIRED 必须绑定 browser-canary-launch.sh 产生的 private receipt、Goal/role/task、15 分钟 TTL、held fd/parent、minimal server environment、canonical server/controller、PID/start/executable/exact argv/cwd、全局唯一 OS listener owner、exact no-redirect endpoint/page probe 与 strict 127.0.0.1 contract，NOT_REQUIRED 时传 receipt 反而拒绝。CAPTAIN、PORT/EXECUTABLE 或空 requirements 不推出 Browser。required_probes 必须按数组顺序执行，Browser（若 REQUIRED）先于 GitHub App，App repository metadata read 固定最后；commit/PR/file/issue read 不可替代。只有 manifest-bound committed policy 的 exact versioned marker 可把 exact 404 先记 PROVISIONAL，并在全部同-session 补偿 PASS 后最终聚合。启用 probe_observation_receipts 时，host adapter 必须把 ordered results 写成 private sealed receipt；core 只验证 schema/hash/identity/TTL/aggregate，PASS 前不登记、不 launch、也不开 FULL。自由文本回执永远不是证据。结束时只能用 launch.sh stop 安全收口，禁止 raw PID kill。',
  },
  'canary-bootstrap-plan': {
    usage: '<controller-root>/scripts/goal-control/canary-plan-launch.sh [--node-executable <canonical-absolute-path>] canary-bootstrap-plan --repository-worktree <frozen-goal-worktree> --manifest <json> --role DEV|REVIEW|RECEIPT --task <id> --expected-head <40sha> --operation-id <stable-id> --challenge <64hex> --canary-policy <repo-relative-path> --canary-policy-sha256 <sha256> [--json]',
    summary: 'create_thread 前零写生成 IDENTITY_ONLY plan；绑定 frozen committed inputs/controller/policy、expected HEAD、stable operation/challenge 和 deterministic codex worker branch。',
    safety: 'manifest 必须用 worker_canary_bootstrap.protocol + exact committed policy path/hash 显式 opt-in，且 policy 必须包含精确协议 marker；冻结旧 policy 不会被追认。本阶段没有 capability/GitHub/Browser/source/resource/environment authority；initial prompt 只允许 worker 执行 canary-bootstrap-inspect 并返回实际 identity。',
  },
  'canary-bootstrap-inspect': {
    usage: '只执行 canary-bootstrap-plan 输出的 identity_plan.identity_capture.shell_command_template；其中已包含 canary-bootstrap-inspect、--expected-identity-binding-sha256 与完整 exact argv，只替换 thread/host 两个 placeholder',
    summary: '从 worker 当前真实 process cwd 只读验证专属 linked worktree、同仓、exact HEAD、clean 和 detached/exact branch，并输出 hash-bound observation。',
    safety: '操作流程禁止人工重建 inspect argv；生成的 IDENTITY_ONLY shell template 使用非循环 identity binding hash，只允许替换平台 thread/host placeholder 后原样执行。CLI 保留的 outer plan-hash ingress 仅供 controller/internal compatibility，不授权手工工作流。不写 Git、Goal store、GitHub、Browser 或环境；primary/异仓/dirty/hidden operation/replace ref/错误 hash 全部 fail-closed。',
  },
  'canary-bootstrap-prepare': {
    usage: '<controller-root>/scripts/goal-control/canary-plan-launch.sh [--node-executable <canonical-absolute-path>] canary-bootstrap-prepare --repository-worktree <frozen-goal-worktree> --manifest <json> --role DEV|REVIEW|RECEIPT --task <id> --expected-head <40sha> --operation-id <stable-id> --challenge <64hex> --canary-policy <repo-relative-path> --canary-policy-sha256 <sha256> --expected-identity-plan-sha256 <sha256> --expected-observation-sha256 <sha256> --worker-thread <id> --worker-host <id> --worker-worktree <actual-absolute-path> [--json]',
    summary: '在 source worktree 外、Git common-dir 下的 private artifact 根先 seal durable intent，以 fenced loose-ref CAS 创建 deterministic codex branch；Git >=2.50 使用原生 symref transaction，Git 2.43-2.49 使用 claim-bound files-backend hardlink-lock/HEAD-rename/completion protocol，按 durable protocol 绑定 worktree HEAD并 seal receipt。',
    safety: '第一次调用前持久化完整 exact argv（含 observation SHA、actual thread/host/worktree 与 Node executable），且首次只接受 detached HEAD + absent deterministic target ref；人工预 attach 不得回填 provenance。只允许 clean 专属 linked worktree；tree/index/remote/Goal store 均不变。调用崩溃或完成状态未知时只允许同 operation 同完整 request exact retry；已返回的 deterministic rejection 不得循环。异文、occupied branch、foreign/stale lock、HEAD/index/status/reciprocal-registry race 全部拒绝；无法证明归属的 Git lock 不自动删除。V1 不隔离 hostile same-UID pathname replacement；该边界需要 host broker/openat adapter。',
  },
  init: {
    usage: 'goalctl init --manifest <repo-relative-json> [--json]',
    summary: 'manifest、packet、protocol 必须与当前 HEAD 中的 Git blob 完全一致；响应丢失后用同一 committed manifest 精确重试，返回 sealed receipt 绑定的 capability paths。',
    safety: '只返回 0600 capability 文件路径，不返回 raw capability。manifest 配置 preclaim 时，init 先验证 exact operation/request lineage 与 PASS receipt path/hash；不会重复 claim。新 Goal以0700临时目录生成receipt后整目录原子发布；pre-receipt Goal仅在writer lock内完整验证sealed manifest/meta、同owner目录与capability hashes后才生成带legacy provenance的receipt。',
  },
  'adopt-store-protocol': {
    usage: 'goalctl adopt-store-protocol --repository-worktree <frozen-goal-worktree> [--goal-worktrees-file <absolute-json>] --incident-ref <ref> --acknowledge-old-controller-drained ALL_OLD_CONTROLLERS_DRAINED_AND_ISOLATED [--json]',
    summary: '在 nonce writer lock 内只读重放所有 Goal、evidence registry 与 resource ledger；多 Goal 可用显式 goal→frozen worktree map；全部通过后才原子安装当前 decoder/lock seal 与 legacy evidence anchors。',
    safety: '运行前必须停止并隔离所有旧 controller binary。旧 binary 会忽略新 seal；同一 root 无法对它做双向 fencing。mapping 必须精确覆盖全部 Goal，且每个 canonical worktree 均须属于同一 Git common dir、clean 并匹配该 Goal frozen bytes；缺项、错仓、symlink、dirty、未知 event/evidence/resource、head/tail 断裂、decoder 不匹配或验证期字节变化均拒绝 seal 并 fail-closed。',
  },
  'rotate-store-protocol': {
    usage: 'goalctl rotate-store-protocol --repository-worktree <current-frozen-goal-worktree> --rotation-id <stable-id> --predecessor-controller-worktree <absolute-frozen-old-controller-worktree> [--goal-worktrees-file <absolute-json>] --expected-predecessor-seal-sha256 <sha256> --incident-ref <durable-ref> --acknowledge-old-controller-drained ALL_OLD_CONTROLLERS_DRAINED_AND_ISOLATED [--json]',
    summary: '专用于已 seal root：successor binary 以 predecessor-compatible lock 拦住新旧 writer，严格验证旧 decoder closure、旧/新 decoder 对全部 Goal/resource 的同义重放与完整 frozen worktree map，再原子安装 append-only rotation receipt 和 successor seal。',
    safety: '--repository-worktree 决定共享 control root，--predecessor-controller-worktree 只读冻结旧 decoder；两者职责不同。rotation-id 必须在首次调用前持久化，响应丢失只允许同一参数 exact retry。target decoder/schema 由当前 binary 机械计算，调用方不得指定。fresh 入口必须是 exact predecessor seal + even generation；foreign odd/transport、旧 decoder 未 drain、worktree/map/artifact/decoder/vector 漂移均 fail-closed。未 seal v1 root 仍必须走 adopt-store-protocol。',
  },
  'event-template': {
    usage: 'goalctl event-template --goal <id> --task <id> --role <role> --thread <id> --type <TYPE> --actor-capability-file <file> [--payload-file <json>] [--full-head <40sha>] [--event-id <id>] [--json]',
    summary: '只自动填安全 envelope；有业务 payload 的事件必须显式提供 payload file。',
  },
  'merge-pr': {
    usage: 'goalctl merge-pr --goal <id> --task <id> --thread <foreman-thread> --event-id <stable-id> --expected-state-revision <n> --expected-control-epoch <n> --actor-capability-file <file> [--json]',
    summary: '仅对 repository.merge_policy=goalctl-github-squash-v1 的 Goal：先 seal durable intent，再以固定 squash + expected PR head 执行 canonical GitHub merge，独立核验远端结果并 seal receipt，最后提交同 event ID 的 MERGED；响应丢失只用同一请求、ID 与 capability exact retry。',
    safety: '禁止直接提交 raw MERGED；wrapper 不接受 --admin/--auto/--delete-branch 或调用方追加 gh 参数。GitHub 仅提供 head CAS、没有 exact base CAS；dispatch 前 ls-remote+PR 双检及 merge 后 parent 核验会 fail-closed，但不能宣称消除 provider 接受窗口。pending merge 未闭合时必须按投影的 stable ID exact retry，不得盲目重复 merge。',
  },
  'p1-abandon-commit': {
    usage: 'goalctl p1-abandon-commit --goal <id> --task <id> --prepared-event-id <P1_COMMITTED-id> --event-id <stable-abandon-id> --expected-intent-sha256 <sha256> --expected-commit-ref <ref> --expected-ref-head <40sha> --thread <foreman-thread> --reason <text> --incident-ref <ref> --foreman-capability-file <file> [--json]',
    summary: '仅当 prepared P1_COMMITTED 尚未进入 append-only ledger 时，由当前 live FOREMAN 发起 sealed abandonment，CAS-exact 删除 controller ref 并写永久 tombstone。',
    safety: 'intent/state/cycle/ref/head 任一漂移、accepted event 已存在、ref 指向异值、event/request/capability 非 exact retry 都 fail-closed。完成后旧 P1 event ID 永久拒绝；同 cycle 不得复用 ref，必须先走 P1_RESTARTED。',
  },
  'launch-template': {
    usage: 'goalctl launch-template --goal <id> --task <id> --role DEV|REVIEW|RECEIPT --thread <id> --actor-capability-file <file> [--input-file <json>] [--json]',
    summary: '只对已登记 worker 生成 launch；首次/fresh runtime 需要 input。启用 worker canary bootstrap 时必须从 registration receipt 绑定的 actual worker worktree 运行，并把同一 binding 原样带入 launch。DEV_ACTIVE canonical 已存在时可省略 input，由控制器克隆 immutable runtime 并只推进 source HEAD。',
    safety: 'canonical launch 已存在时保持 byte-immutable。DEV_ACTIVE 的同 runtime candidate 只允许 repository.full_head 与 execution.target.build_head 前进；created_at、worker bootstrap binding、lockfile、PID/端口、executable、nonce/incarnation、lease、worktree/branch 等逐字不变。任何 worktree/gitdir/common-gitdir/branch 漂移均 fail-closed。DEV launch 不绑定 PR；PR 由 DEV_READY 与 Full/AC evidence 绑定。NONE/CLI/PREVIEW 可走该 lane，Browser/Electron 必须 fresh runtime。',
  },
  'revalidate-source-checkpoint-hold': {
    usage: 'goalctl revalidate-source-checkpoint-hold --goal <id> --task <id> --thread <foreman-thread> --operation-id <projected-stable-id> --hold <id> --expected-hold-event-id <ADD_HOLD-event-id> --expected-canonical-launch-sha256 <sha256> --expected-candidate-head <40sha> --actor-capability-file <foreman-file> [--json]',
    summary: '只消费 REQUEST_CANDIDATE_HOLD_REVALIDATION：当前 decoder 重新证明 canonical runtime 到 projected immutable DEV checkpoint 仅是合法 source 前进，登记 deterministic HOLD_RESOLUTION evidence 并提交 RESOLVE_HOLD。',
    safety: 'FOREMAN capability、唯一 hard hold incarnation、canonical bytes、projected immutable candidate、Git lineage、runtime invariant 任一漂移都 fail-closed；若 live HEAD 后续前进，必须针对新 HEAD 另做 PREFLIGHT，不能复用旧证明。命令绝不 rotate/restart runtime。resolution evidence/event ID 由 exact 输入确定，generation/evidence/event 响应丢失均可同参数精确重试。',
  },
  'recovery-export-source': {
    usage: 'goalctl recovery-export-source --repository-worktree <lost-dev-worktree> --goal <id> --task <id> --snapshot-id <stable-id> --successor-thread <id> --captain-capability-file <file> [--json]',
    summary: '从 predecessor canonical worktree 导出 sealed snapshot；--snapshot-id 是调用前持久化的 operation ID。',
    safety: '首次调用只读 source 并 seal exact request、artifacts 与 CAPTAIN identity/attempt/cap path+hash。发布后响应丢失时用同一 ID/参数/capability 精确重试；即使原 actor terminal、phase 前进或 source worktree 消失，也只重验 sealed artifacts 后返回原 snapshot。ID 异文复用拒绝。',
  },
  'recovery-export-codex-rollout': {
    usage: 'goalctl recovery-export-codex-rollout --repository-worktree <frozen-goal-worktree> --goal <id> --task <id> --snapshot-id <stable-id> --successor-thread <id> --predecessor-launch <id> --predecessor-thread <id> --rollout-file <absolute-jsonl> --captain-capability-file <file> [--shell-audit-file <json> --foreman-capability-file <file>] [--json]',
    summary: '当 predecessor worktree 已消失时，从 Codex rollout 的全部成功 patch_apply_end 生成 sealed tracked patch。',
    safety: '--snapshot-id 必须在首次调用前持久化。严格核对并 seal session/call/event/result、request、CAPTAIN authority；使用 shell audit 时也 seal FOREMAN identity/attempt/cap path+hash。精确 retry 不重读已变化的 rollout/broker worktree，不接受不同 request/ID。',
  },
  'recovery-inspect-codex-rollout': {
    usage: 'goalctl recovery-inspect-codex-rollout --rollout-file <absolute-jsonl> --historical-worktree <lost-dev-worktree> --predecessor-thread <id> [--allow-shell-audit] [--json]',
    summary: '只读解析 rollout；strict 默认遇未验证 shell 即拒绝，--allow-shell-audit 仅列出生成外部 attestation 所需的 exact call/result line+hash 集合，不创建 snapshot。',
    safety: '输出 reconstructed patch hash、完整 rollout hash、shell_audit_required 与全量 shell_calls；disposition 仍须人工/外部 broker 决定，inspect 不等于授权。',
  },
  'recovery-build-codex-shell-audit': {
    usage: 'goalctl recovery-build-codex-shell-audit --goal <id> --task <id> --predecessor-launch <id> --predecessor-thread <id> --historical-worktree <lost-dev-worktree> --predecessor-head <sha> --rollout-file <absolute-jsonl> --captain-thread <id> --foreman-thread <id> --incident-ref <ref> --dispositions-file <json> [--output-file <absolute-json>] [--json]',
    summary: '不读写 control store：dispositions 仅含 asserted_untracked_empty=true 与有序 [{call_id,disposition}]；命令自动填充完整 line/name/raw/result hashes、rollout/patch hashes、确定性 created_at 与 audit_sha256。最终 export 才用当前 state 与 CAPTAIN+FOREMAN capabilities 做授权/绑定。省略 --output-file 时 stdout 仍是完整 final audit JSON；指定时 stdout 返回 artifact path/hash/call count。',
    safety: 'calls 必须与 inspect exact set 同序且无漏/多/重复；非法 disposition 或 outside aborted apply_patch 非 IGNORED_PATH_ONLY 均 fail-closed。--output-file 只原子创建该 audit artifact：必须是 canonical 绝对路径、parent 为非 symlink 目录；现有普通文件仅 bytes 完全相同时幂等成功，否则 AUDIT_OUTPUT_CONFLICT，绝不覆盖，也不写 control store。artifact 不替代 export 时 CAPTAIN+FOREMAN 双 capability。',
  },
  'recovery-import-source': {
    usage: 'goalctl recovery-import-source --repository-worktree <fresh-destination-worktree> --goal <id> --task <id> --import-id <stable-id> --successor-thread <id> --snapshot <id> --actor-capability-file <dev-file> [--json]',
    summary: '--import-id 在调用前持久化并直接成为 receipt ID；首次调用只允许 exact fresh destination 并全量 stage。',
    safety: 'receipt 发布后响应丢失时，同一 destination worktree/branch、ID/request 和原 DEV capability 可从 current/history 精确重放，即使已 commit、promotion 或 terminal。若 crash 发生在完整 materialization 后、receipt 前，exact expected tree/paths 且无 unstaged/untracked 时只补 seal receipt；partial/异文不 reset、不覆盖。命令不自动 commit；下一步必须调用 recovery-checkpoint-source。',
  },
  'recovery-checkpoint-source': {
    usage: 'goalctl recovery-checkpoint-source --repository-worktree <fresh-destination-worktree> --goal <id> --task <id> --successor-thread <id> --snapshot <id> --import-receipt <id> --actor-capability-file <dev-file> [--json]',
    summary: '完整验证 sealed v3 snapshot/receipt、DEV authority、destination branch/HEAD/index 后，以 commit-tree + update-ref CAS 创建 deterministic single-parent checkpoint；输出 checkpoint_sha。',
    safety: 'author/committer/message/date 与 UTF-8 commit encoding 全由 controller/sealed receipt 固定；非空与空 snapshot 使用同一路径。HEAD 必须是 source_observed_head 或同一 deterministic checkpoint，index tree/paths/diff 必须精确且无 unstaged/untracked；MERGE_HEAD、rebase、cherry-pick、sequencer、bisect 等 hidden Git operation sentinel 一律拒绝。destination 必须是拥有专属 gitdir 的 linked worktree。初始验证后，adapter 先 durable seal request-bound prepared marker，再取得带 token 的 worktree-specific index.lock，并临时移除专属 gitdir 全部 write bits；在 fence 内重新核对 index/sentinel 后，以 common-gitdir old-value ref CAS 发布、用 branch reflog 记录 receipt ID 并完成最终 clean 检查，再 seal completion、恢复原 mode、释放自有 lock。linked-worktree 私有 HEAD reflog 不作为证据。completion 只证明历史发布；精确重试仍核对 live branch，退回 sealed base 时重发同一 checkpoint，第三方 HEAD 拒绝覆盖。prepared 未完成时进入 SOURCE_CHECKPOINT pending；SIGKILL 后只有原请求能精确接管。既有/异文 lock、缺 lock 的 fenced gitdir、mode/identity 漂移一律保留 fail-closed，不猜测或清理。该 fence 保护最终验证/CAS/completion 临界区；恢复写权限后到 bind 之间的新漂移由 recovery-bind 再验证并 fail-closed。它不是同 UID/ACL 恶意绕过或跨命令持续排他的 OS 隔离。响应丢失以同参数重试返回同一 SHA；任何 HEAD/tree/branch/receipt/authority 漂移均 fail-closed，不 reset、不覆盖。',
  },
  'recovery-bind': {
    usage: 'goalctl recovery-bind --repository-worktree <fresh-destination-worktree|surviving-frozen-goal-worktree-for-retry> --goal <id> --task <id> --successor-thread <id> --snapshot <id> --import-receipt <id> [--import-commit <sha|HEAD>] --captain-capability-file <file> [--captain-thread <id>] --event-id <stable-id> [--json]',
    summary: '调用前持久化 event ID；fresh 调用重验 snapshot/receipt/单 parent import commit 后原子提交 RECOVERY_HANDOFF_BOUND。',
    safety: '响应丢失或 destination 消失时，可从任一 surviving frozen Goal worktree 携同原 CAPTAIN capability、同一 event ID/request 和显式完整 40 位 --import-commit 历史精确重试；绝不从新 cwd 的 HEAD/ref 猜原 commit。成功后仅进入 PREFLIGHT_ONLY。',
  },
  'recovery-abandon-handoff': {
    usage: 'goalctl recovery-abandon-handoff --repository-worktree <bound-or-surviving-frozen-goal-worktree> --goal <id> --task <id> --successor-thread <id> --captain-capability-file <file> --foreman-capability-file <file> [--captain-thread <id>] [--foreman-thread <id>] --reason <text> --incident-ref <ref> --event-id <stable-id> [--json]',
    summary: '调用前持久化 event ID；只在 PREFLIGHT_ONLY 且尚未 promotion 时，以 CAPTAIN+Goal-wide FOREMAN 双 capability 废止当前 receipt/checkpoint binding。',
    safety: '同一 ID/request/capabilities 可在后续 phase 或 successor 接管后历史精确重试；不迁移旧 launch/receipt/evidence/runtime，当前 successor 仍有任何非终态资源 lease 时拒绝。',
  },
  'recovery-promote': {
    usage: 'goalctl recovery-promote --repository-worktree <fresh-destination-worktree|surviving-frozen-goal-worktree-for-retry> --goal <id> --task <id> --successor-thread <id> --preflight-evidence <id> --captain-capability-file <file> [--captain-thread <id>] --event-id <stable-id> [--json]',
    summary: '调用前持久化 event ID；fresh 调用重验 launch、manifest leases、clean destination 与 sealed preflight 后进入 FULL。',
    safety: '同一 ID/request/原 CAPTAIN capability 可在后续状态历史精确重试；这是 recovered DEV 恢复开发权限的唯一 promotion，任何请求或 binding 漂移均 fail-closed。',
  },
  'rotate-runtime': {
    usage: 'goalctl rotate-runtime --repository-worktree <frozen-goal-worktree> --goal <id> --task <id> --role DEV|REVIEW|RECEIPT --worker-thread <id> --predecessor-incarnation <n> --predecessor-launch <id> --expected-predecessor-launch-sha256 <sha256> --successor-launch <fresh-id> --hold <ENV_IDENTITY_INCIDENT-hold-id> --expected-state-revision <n> --expected-control-epoch <n> --reason <text> --incident-ref <ref> --captain-thread <id> --captain-capability-file <file> --event-id <stable-id> [--json]',
    summary: '调用前持久化 event ID；只在唯一 ENV_IDENTITY_INCIDENT hard hold 下，把同一 active worker 的 launch pointer CAS 到 fresh local PREVIEW incarnation。',
    safety: '只接受 environment=none/write_mode=NONE/http://127.0.0.1 PREVIEW，并以三次 LOCAL_PREVIEW_ZERO_WITNESS + lock 内复查证明旧 PID/端口/已知子进程当前不可见。旧 launch append-only 保留；thread/attempt/task_nonce/capability/lease owner/revision/fencing 不变。hold 不在本命令解除；successor 必须换全新 web/proxy port 后重新 launch-template + preflight，再由 FOREMAN 单独 RESOLVE_HOLD。Browser/Electron/profile/account/TIM/真实环境不适用，必须走 host broker/recovery。',
  },
  event: {
    usage: 'goalctl event --goal <id> --file <json|-> --actor-capability-file <file> [--json]',
    summary: '接受成功才迁移状态；普通聊天与模板输出都不迁移状态。',
    safety: '这是持久化写命令：成功时追加 accepted event 并推进控制状态；响应丢失只能以同一 event ID、逐字相同 envelope 与原 capability 精确重试。',
  },
  'prepare-probe-observation-challenge': {
    usage: 'goalctl prepare-probe-observation-challenge --goal <id> --task <id> --role <role> --event-id <registration-or-recovery-id> --canary-plan-sha256 <sha256> --issuer-capability-file <bootstrap|recovery|live-authorizer-capability> --identity-receipt <absolute-0600-host-signed-json> --identity-receipt-sha256 <sha256> [--json]',
    summary: '在同一 locked upstream canary acceptance transaction 内，先验证预先存在的 host/platform-signed actual thread/host/session/launch observation，再从当前 controller lineage 派生 attempt/revision/HEAD 并原子发布 sanitized durable role identity intent 与 challenge。',
    safety: 'thread/host/attempt 不接受 argv；claim-only、伪造/过期/跨 Goal/task/role/HEAD observation、caller alias、敏感值全部在 generation 前拒绝且不发布 intent/challenge。status/actions 之后只读投影已验签 intent；不存在 credentialless 或 REGISTER_ROLE consumer seal 写。相同 event/receipt/hash/plan/issuer exact retry 返回同一 challenge，任一变体冲突。',
  },
  'register-role': {
    usage: 'goalctl register-role --goal <id> --task <id> --role <role> --thread <id> [--host <id>] [--attempt <n>] [--lease-ms <ms>] [--status active|idle] [--launch-id <id>] [--event-id <stable-id>] [--bootstrap-capability-file <file>|--foreman-recovery-capability-file <file>|--authorizer-capability-file <file>|--actor-capability-file <existing-actor-file>] [--authorizer-thread <id>] [--worker-bootstrap-receipt <absolute-json> --worker-bootstrap-receipt-sha256 <sha256> --worker-bootstrap-operation-id <id> --worker-bootstrap-challenge <64hex> --worker-bootstrap-identity-plan-sha256 <sha256>] [--probe-observation-receipt <0600-json> --probe-observation-receipt-sha256 <sha256> --probe-observation-plan <0600-json> --probe-observation-plan-sha256 <sha256> --probe-observation-stable-id <id> --probe-observation-challenge <64hex>] [--json]',
    summary: 'Goal-wide FOREMAN 有三条明确路径：首次 bootstrap 登记；后续 task 以同一 Goal authority 的 identity/attempt/status/capability 做 projection；失联后走 recovery replacement，存在多个 current projections 时必须用 recover-expired-foreman 批量替换。CAPTAIN 与 worker 仍由当前授权链签发独立 capability；启用 worker canary bootstrap 的 Goal 会把 sealed actual worker worktree identity 写入 registration。启用 probe_observation_receipts 后，所有角色 registration 都必须先机械验证 explicit replay + ordered host-adapter receipt，并得到 PASS 或 policy-finalized KNOWN_LIMITATION。',
    safety: '这是持久化写命令：首次调用会发布 durable registration intent、actor capability 与 REGISTER_ROLE event。启用 probe observation protocol 时，core 只 no-follow/有界读取并验证 sealed receipt；真实 GitHub CLI/Git transport/GitHub App/Browser/task broker 探针由 host adapter 执行。缺项、乱序、cross-identity、旧 plan/challenge、replay、过期或非 PASS 在任何 durable registration 写入前 fail closed；Allow/auth prompt 确定性 FAIL，不请求用户点击。启用 worker canary bootstrap 时，DEV/REVIEW/RECEIPT 必须从 receipt-bound actual worker process cwd 调用。省略 --event-id 时使用 deterministic ID；响应丢失必须以同一 request、stable ID 和原 capability exact retry，异文冲突。',
  },
  'refresh-probe-observation': {
    usage: 'goalctl refresh-probe-observation --goal <id> --task <id> --role <role> --thread <id> [--host <id>] --attempt <n> --expected-state-revision <n> --expected-binding-sha256 <sha256> --event-id <stable-id> --actor-capability-file <current-role-capability> --probe-observation-receipt <0600-json> --probe-observation-receipt-sha256 <sha256> --probe-observation-plan <0600-json> --probe-observation-plan-sha256 <sha256> --probe-observation-stable-id <id> --probe-observation-challenge <64hex> [--json]',
    summary: '在 current CAPTAIN/worker receipt 仍 live 时，以 accepted_at、current canonical plan、session identity/attempt、state revision 与 old binding hash 做 CAS，原子替换 fresh controller-held sealed binding。',
    safety: '先以相同 refresh event ID 准备 fresh challenge。旧 receipt 已过期、fresh receipt 过期/伪造/异文、HEAD/plan/identity/attempt/CAS 漂移均在 event append 前 fail closed。响应丢失只允许同一 event ID、逐字相同 request 与原 actor capability exact retry；变体冲突。',
  },
  'recover-expired-foreman': {
    usage: 'goalctl recover-expired-foreman --repository-worktree <frozen-goal-worktree> --goal <id> --task <anchor-task-id> --thread <fresh-id> --host <id> --attempt <n> --lease-ms <ms> [--expected-control-epoch <n>] --expected-goal-scope-sha256 <sha256> --reason <text> --incident-ref <ref> --foreman-recovery-capability-file <0600-file> --event-id <stable-root-id> --probe-observation-receipt <0600-json> --probe-observation-receipt-sha256 <sha256> --probe-observation-plan <0600-json> --probe-observation-plan-sha256 <sha256> --probe-observation-stable-id <id> --probe-observation-challenge <64hex> [--json]',
    summary: '调用前持久化 root event ID；CAS Goal-wide coherent FOREMAN replicas，以非 ARCHIVED 的 current FOREMAN projections 为 target，按 durable intent→per-target event→commit 的可恢复事务整体 fence/adopt fresh FOREMAN。',
    safety: 'recovery 是 activation path：fresh 请求必须先以 root event ID 准备 challenge 并提交 fresh canonical replay + ordered PASS receipt；缺失/过期/tampered 时零 task event 写入。pending root transaction 冻结其它写入，只允许同一 ID/request/capability/receipt 精确续跑；--expected-goal-scope-sha256 是必需的 Goal-wide CAS，--expected-control-epoch 与旧版 per-task expected-* 只作可选兼容 guard，不能替代它。普通 batch 不触碰未投影的非归档 task；仅当没有 current projection 时，显式 anchor 才能从当前最大 attempt 的 ARCHIVED lineage adoption 为一个新 projection。其余 ARCHIVED 投影不改写。不续租、转移或回收任何 runtime/resource lease。',
  },
  status: {
    usage: 'goalctl status [--repository-worktree <frozen-goal-worktree>] --goal <id> [--task <id>] [--json]',
    summary: 'zero-write 输出去敏 Goal/task 状态：Goal-wide foreman_recovery_scope、pending_foreman_recovery、pending_operations，以及 task launch_scope、向后兼容的 operational_scope alias、next_actions 与 maintenance_actions。',
    safety: 'pending_operations 非空时对应 task 的正常/maintenance actions 已清空；只允许 retry 字段给出的原 request exact retry。一般 stable_id_unavailable=true 时必须使用调用前持久化且 SHA-256 匹配的原 stable ID，hash 本身不是 CLI ID；SOURCE_CHECKPOINT 是固定例外，它由 sealed snapshot/receipt/request 派生，不接收另一个 stable ID，须按 retry.command 用原 CLI 参数与 DEV capability 重跑。task operational_scope 只是 launch_scope 的兼容别名，不等于 session recovery authority。',
  },
  next: {
    usage: 'goalctl next [--repository-worktree <frozen-goal-worktree>] --goal <id> [--json]',
    summary: 'zero-write 根据依赖、写集、冲突域、资源需求和 Goal/task pending_operations 计算下一批，并为每个 task 输出 launch_scope、兼容 operational_scope alias、next_actions 与 maintenance_actions。',
    safety: '任一 Goal-wide pending registration/root recovery 会冻结整个 batch；task pending operation 令该 task eligible=false。只按 pending_operations.retry 做 exact retry；一般 stable_id_unavailable 时取调用前持久化的原 ID，不得拿 hash 冒充或跳到其它 task；SOURCE_CHECKPOINT 按 retry.command 重放原 snapshot/receipt/DEV capability，不把 request hash 当 CLI ID。',
  },
  actions: {
    usage: 'goalctl actions [--repository-worktree <frozen-goal-worktree>] --goal <id> --task <id> --role <role> --thread <id> [--json]',
    summary: 'zero-write 返回登记角色当前 actions、maintenance_actions、pending_operations、task launch_scope 与该 role session 的 operational_scope。',
    safety: 'pending_operations 非空时 actions 与 maintenance_actions 均为空，只能完成列出的 exact retry；launch_scope 是当前 launch/action gate，operational_scope 是 session 的 RECOVERY_BLOCKED/PREFLIGHT_ONLY/FULL authority。',
  },
  resume: {
    usage: 'goalctl resume [--repository-worktree <frozen-goal-worktree>] --goal <id> --task <id> --role <role> --thread <id> [--json]',
    summary: 'zero-write 重新物化短角色内核；适用于启动、compact、异常和 successor，并返回 pending_operations、launch_scope 与 session operational_scope。',
    safety: 'pending operation 存在时普通与 maintenance actions 均为空，只允许 exact retry；不得从聊天摘要补出动作。',
  },
  doctor: {
    usage: 'goalctl doctor [--repository-worktree <frozen-goal-worktree>] --goal <id> [--json]',
    summary: 'zero-write 诊断 pending_operations、launch_scope/operational_scope 漂移、过期、hold 与 recovery；finding 非空退出 1，store/control 无法可信读取退出 2。',
    safety: 'TASK_OPERATION_PENDING/RECOVERY_BATCH_INCOMPLETE 只可按 finding 中 stable ID exact retry；doctor 不修 store、不提交事件，也不把 OPERATION_PENDING 或 recovery scope 错报为可执行。',
  },
  preflight: {
    usage: 'goalctl preflight --goal <id> --task <id> --launch <json> [--evidence-id <stable-id>] --actor-capability-file <file> [--stage <name>] [--json]',
    summary: '校验并 seal launch 与真实 repo/runtime/environment/target/resource 身份；普通 launch 必须预先持久化 evidence ID，runtime successor 可省略并由 controller 从 exact launch 自动派生稳定 ID。',
    safety: '省略 --evidence-id 只对带 runtime_incarnation 的 successor launch 合法；派生 ID 绑定完整 launch bytes，失败候选不会占用后续 fresh candidate 的 ID。',
  },
  evidence: {
    usage: 'goalctl evidence --goal <id> --file <json> --actor-capability-file <file> [--json]',
    summary: '登记并持久化 schema 严格、绑定 packet/HEAD 的证据。',
    safety: '这是持久化写命令；成功时 seal evidence registry，响应丢失按同一 evidence ID、request 与 capability 精确重试。',
  },
  'gate-fast': { usage: 'goalctl gate-fast --goal <id> --task <id> --evidence-id <stable-id> --actor-capability-file <file> [--json]', summary: '调用前持久化 evidence ID；DEV 固定 Fast gate。' },
  'gate-full-ci': { usage: 'goalctl gate-full-ci --goal <id> --task <id> --pr <number> --evidence-id <stable-id> --actor-capability-file <file> [--json]', summary: '调用前持久化 evidence ID；CAPTAIN 验证当前 PR Full required check。' },
  'gate-ac-audit': { usage: 'goalctl gate-ac-audit --goal <id> --task <id> --issue <number> --pr <number> --evidence-id <stable-id> --actor-capability-file <file> [--json]', summary: '调用前持久化 evidence ID；CAPTAIN 固定 AC audit，shadow/enforce 均不评论 GitHub。' },
  control: {
    usage: 'goalctl control --goal <id> --expected-epoch <n> --reason <text> --instruction-ref <ref> --thread <id> --actor-capability-file <file> --event-id <stable-id> [--json]',
    summary: '调用前持久化 event ID；用户指令变化时提升 epoch，随后逐 task reconcile。',
    safety: '响应丢失后用同一 ID/request 与原 FOREMAN capability 历史精确重试；即使 control epoch 已继续推进也返回原 accepted epoch，不追加第二条事件。不同请求复用 ID 一律拒绝。',
  },
  'rebuild-ledger': {
    usage: 'goalctl rebuild-ledger --goal <id> [--json]',
    summary: '从 accepted events 重建并持久化生成式总表；总表只是投影，accepted events 才是机器真源。',
    safety: '这是投影写命令，不追加业务 event；只在 event/head/store 完整验证后原子重写 ledger/state projection。',
  },
});

const RESOURCE_HELP = Object.freeze({
  ...Object.fromEntries(RESOURCE_COMMANDS
    .filter(([name]) => name !== 'help [command]')
    .map(([name, summary]) => [name.split(' ')[0], { usage: `resourcectl ${name}`, summary }])),
  acquire: {
    usage: 'resourcectl acquire --goal <id> --task <id> --role <role> --thread <id> [--host <id>] --resource <canonical-key> [--access EXCLUSIVE|SHARED_READ] [--ttl-ms <ms>] --event-id <stable-id> --actor-capability-file <file> [--json]',
    summary: '获取声明过的资源租约；event-id 是必填幂等键，响应丢失后必须用完全相同的参数重试。',
    safety: '同一 event-id 只能绑定一组逐字相同的 owner/resource/access/TTL 请求；精确重试返回该 lease 的当前 durable 状态，不创建第二份 lease。',
  },
  renew: {
    usage: 'resourcectl renew --lease <id> --owner-capability-file <file> --actor-capability-file <file> --expected-revision <n> --ttl-ms <ms> --event-id <stable-id> [--json]',
    summary: '调用前持久化 event ID；exact resource owner 以 actor + lease-owner 双 capability 按 CAS 续租，响应丢失后同 ID 精确重放。',
    safety: 'REQUEST_RESOURCE_RENEW.actor_role=CAPTAIN 是协调者兼容字段；执行者必须逐字匹配 action.dispatch.executor，CAPTAIN/FOREMAN capability 不能代 owner 续租。',
  },
  release: {
    usage: 'resourcectl release --lease <id> --owner-capability-file <file> --actor-capability-file <file> --expected-revision <n> --event-id <stable-id> [--json]',
    summary: '调用前持久化 event ID；按 CAS 释放，durable terminal 后同 ID 可在 owner capability 已清理时精确重放。',
  },
  verify: {
    usage: 'resourcectl verify --lease <id> --owner-capability-file <file> --actor-capability-file <file> [--resource <canonical-key>] --event-id <stable-id> [--json]',
    summary: 'event ID 是 identity incident operation ID；失败后同 ID 精确重抛 sealed 结果并只安装一份 hard hold。',
    safety: '成功验证是只读动作，不消费 event ID；失败才用该 ID 生成 deterministic evidence/event/hold，异文复用拒绝。',
  },
  'owner-capability': {
    usage: 'resourcectl owner-capability --lease <id> --actor-capability-file <exact-owner-file> [--json]',
    summary: 'zero-write 向 exact active/historical owner 返回已存在且 verifier 匹配的 owner capability 文件指针。',
    safety: 'CAPTAIN/FOREMAN、同角色 fresh attempt 与其它 worker 均拒绝。唯一 ENV_IDENTITY_INCIDENT runtime-preservation hard hold 下，仅 active exact owner 可恢复指针以执行投影续租；不放行 acquire/verify/release/use。',
  },
  'reinitialize-zero-runtime': {
    usage: 'resourcectl reinitialize-zero-runtime --repository-worktree <goal-worktree> --goal <id> --task <id> --successor-thread <id> --handoff-event-id <id> --captain-capability-file <file> --foreman-capability-file <file> [--captain-thread <id>] [--foreman-thread <id>] --event-id <stable-id> [--json]',
    summary: '仅对 sealed target=NONE/environment=none/write_mode=NONE 且 lease set 为空的 predecessor，写入 append-only ZERO_RUNTIME_REINITIALIZED 双授权 no-op receipt。',
    safety: 'receipt 不改变 lease projection、也不写 REVOKED event；任何历史 lease、非终态 owner lease、PID/profile/account/port/TIM/UI 或环境写都返回 REINITIALIZE_REQUIRES_BROKER，必须交资源专用 broker。',
  },
});

function helpDocument(kind, topic = null) {
  const program = kind === 'goal' ? 'goalctl' : 'resourcectl';
  const commands = kind === 'goal' ? GOAL_COMMANDS : RESOURCE_COMMANDS;
  const details = kind === 'goal' ? GOAL_HELP : RESOURCE_HELP;
  if (topic) {
    const detail = details[topic];
    assertControl(detail, 'UNKNOWN_HELP_TOPIC', `未知 ${program} help topic: ${topic}`);
    return {
      schema_version: 1,
      program,
      topic,
      usage: detail.usage,
      summary: detail.summary,
      safety: detail.safety || (kind === 'goal'
        ? '命令不会自动创建、发送、等待或归档外部 session；写命令成功时会按 Usage/Summary 持久化 control store，查询与模板命令保持只读。'
        : '租约输出不包含 owner capability 内容；资源回收 fail-closed。'),
    };
  }
  return {
    schema_version: 1,
    program,
    topic: null,
    usage: `${program} <command> [options]`,
    summary: kind === 'goal'
      ? 'Goal 工头控制面：静态 packet + append-only event + capability/CAS/epoch/HEAD 门禁。'
      : 'Goal 控制面的资源租约与 fencing 工具。',
    commands: commands.map(([name, summary]) => ({ name, summary })),
    quickstart: kind === 'goal' ? 'docs/planning/goal-control-quickstart.md' : 'docs/planning/goal-control.md',
  };
}

function renderHelp(document) {
  const lines = [
    `${document.program} — ${document.summary}`,
    '',
    `Usage: ${document.usage}`,
  ];
  if (document.commands) {
    lines.push('', 'Commands:');
    const width = Math.max(...document.commands.map((item) => item.name.length));
    for (const item of document.commands) lines.push(`  ${item.name.padEnd(width)}  ${item.summary}`);
    lines.push('', `Quickstart: ${document.quickstart}`);
  } else {
    lines.push('', document.safety);
  }
  return lines.join('\n');
}

function assertPlainObject(value, code, label) {
  assertControl(value && typeof value === 'object' && !Array.isArray(value), code, `${label} 必须是对象`);
  return value;
}

function assertOnlyKeys(value, allowed, code, label) {
  const unknown = Object.keys(value).filter((key) => !allowed.includes(key));
  assertControl(unknown.length === 0, code, `${label} 含未知字段: ${unknown.join(', ')}`);
}

function repoRelative(repositoryRoot, candidate, label) {
  const absolute = path.resolve(repositoryRoot, candidate);
  const relative = path.relative(repositoryRoot, absolute);
  assertControl(relative && relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative), 'PATH_OUTSIDE_REPO', `${label} 必须位于仓库内`);
  return relative.split(path.sep).join('/');
}

function existingRepoFile(repositoryRoot, candidate, label) {
  const relative = repoRelative(repositoryRoot, candidate, label);
  let canonical;
  try {
    canonical = fs.realpathSync(path.join(repositoryRoot, relative));
  } catch (error) {
    throw new ControlError('READ_FAILED', `${label} 不存在: ${error.message}`);
  }
  const canonicalRoot = fs.realpathSync(repositoryRoot);
  assertControl(canonical.startsWith(`${canonicalRoot}${path.sep}`), 'PATH_OUTSIDE_REPO', `${label} 必须位于仓库内`);
  assertControl(fs.statSync(canonical).isFile(), 'READ_FAILED', `${label} 必须是普通文件`);
  return { absolute: canonical, relative: path.relative(canonicalRoot, canonical).split(path.sep).join('/') };
}

function safeOutputDirectory(repositoryRoot, candidate) {
  const relative = repoRelative(repositoryRoot, candidate, 'output directory');
  assertControl(
    /^(?!.*(?:^|\/)\.\.(?:\/|$))(?!.*\/\/)[A-Za-z0-9._-]+(?:\/[A-Za-z0-9._-]+)*$/.test(relative),
    'INVALID_SCAFFOLD_SPEC',
    'output directory 必须是安全的仓库相对路径',
  );
  assertControl(!relative.split('/').some((component) => component.toLowerCase() === '.git'), 'PATH_OUTSIDE_REPO', 'output directory 禁止包含 .git 路径段');
  const canonicalRoot = fs.realpathSync(repositoryRoot);
  const absolute = path.join(canonicalRoot, relative);
  let cursor = canonicalRoot;
  const components = relative.split('/');
  for (let index = 0; index < components.length; index += 1) {
    cursor = path.join(cursor, components[index]);
    let stat;
    try {
      stat = fs.lstatSync(cursor);
    } catch (error) {
      if (error.code === 'ENOENT') continue;
      throw new ControlError('SCAFFOLD_PATH_INVALID', `无法检查 output path ${relative}: ${error.message}`);
    }
    assertControl(!stat.isSymbolicLink(), 'SCAFFOLD_PATH_SYMLINK', `output path 禁止 symlink component: ${components.slice(0, index + 1).join('/')}`);
    if (index < components.length - 1) {
      assertControl(stat.isDirectory(), 'SCAFFOLD_PATH_INVALID', `output ancestor 不是目录: ${components.slice(0, index + 1).join('/')}`);
    }
  }
  const commonGitDir = fs.realpathSync(path.resolve(git(canonicalRoot, ['rev-parse', '--path-format=absolute', '--git-common-dir'])));
  assertControl(
    absolute !== commonGitDir && !absolute.startsWith(`${commonGitDir}${path.sep}`),
    'PATH_OUTSIDE_REPO',
    'output directory 禁止写入 Git common-dir',
  );
  return { absolute, relative };
}

function writePublicFile(file, body) {
  ensureDir(path.dirname(file));
  const fd = fs.openSync(file, 'wx', 0o644);
  try {
    fs.writeFileSync(fd, body);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fs.chmodSync(file, 0o644);
}

function listTree(root) {
  const output = new Map();
  function walk(directory, prefix = '') {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
      const absolute = path.join(directory, entry.name);
      assertControl(!entry.isSymbolicLink(), 'SCAFFOLD_CONFLICT', `现有 output 含 symlink: ${relative}`);
      if (entry.isDirectory()) walk(absolute, relative);
      else {
        assertControl(entry.isFile(), 'SCAFFOLD_CONFLICT', `现有 output 含非普通文件: ${relative}`);
        output.set(relative, fs.readFileSync(absolute));
      }
    }
  }
  walk(root);
  return output;
}

function exactTreeMatches(outputDirectory, expected) {
  if (!fs.existsSync(outputDirectory)) return false;
  const stat = fs.lstatSync(outputDirectory);
  assertControl(stat.isDirectory() && !stat.isSymbolicLink(), 'SCAFFOLD_CONFLICT', 'output path 已存在且不是普通目录');
  const actual = listTree(outputDirectory);
  if (actual.size !== expected.size) return false;
  for (const [relative, body] of expected.entries()) {
    if (!actual.has(relative) || !actual.get(relative).equals(body)) return false;
  }
  return true;
}

function scaffoldGoal(cwd, options) {
  const repositoryRoot = repoRoot(cwd);
  const source = existingRepoFile(repositoryRoot, options.specFile, 'scaffold spec');
  const spec = assertPlainObject(readJson(source.absolute, 'scaffold spec'), 'INVALID_SCAFFOLD_SPEC', 'scaffold spec');
  assertOnlyKeys(spec, ['schema_version', 'goal_id', 'title', 'mode', 'repository', 'base_head', 'protocol', 'preclaim', 'worker_canary_bootstrap', 'probe_observation_receipts', 'tasks'], 'INVALID_SCAFFOLD_SPEC', 'scaffold spec');
  assertControl(spec.schema_version === 1, 'UNSUPPORTED_SCHEMA', 'scaffold spec.schema_version 必须为 1');
  const goalId = safeId(spec.goal_id, 'scaffold goal_id');
  const mode = spec.mode || 'shadow';
  assertControl(['shadow', 'enforce'].includes(mode), 'INVALID_SCAFFOLD_SPEC', 'scaffold mode 必须是 shadow 或 enforce');
  assertControl(mode !== 'enforce' || options.allowEnforce === true, 'ENFORCE_CONFIRMATION_REQUIRED', '生成 enforce Goal 必须显式传 --allow-enforce');
  const output = safeOutputDirectory(repositoryRoot, options.outputDir || `docs/planning/goals/${goalId}`);
  assertControl(output.relative !== path.dirname(source.relative), 'INVALID_SCAFFOLD_SPEC', 'scaffold spec 请放在 output directory 外，避免自引用和幂等冲突');

  assertPlainObject(spec.repository, 'INVALID_SCAFFOLD_SPEC', 'scaffold repository');
  assertOnlyKeys(spec.repository, ['name_with_owner', 'base_branch', 'merge_policy'], 'INVALID_SCAFFOLD_SPEC', 'scaffold repository');
  assertControl(spec.repository.base_branch === undefined || spec.repository.base_branch === 'main', 'INVALID_SCAFFOLD_SPEC', 'base_branch 只能是 main');
  assertControl(
    spec.repository.merge_policy === undefined
      || spec.repository.merge_policy === 'goalctl-github-squash-v1',
    'INVALID_SCAFFOLD_SPEC',
    'repository.merge_policy 只能是 goalctl-github-squash-v1',
  );
  assertFullSha(spec.base_head, 'scaffold base_head');
  git(repositoryRoot, ['cat-file', '-e', `${spec.base_head}^{commit}`]);
  const protocol = spec.protocol === undefined ? DEFAULT_PROTOCOL : spec.protocol;
  assertPlainObject(protocol, 'INVALID_SCAFFOLD_SPEC', 'scaffold protocol');
  assertOnlyKeys(protocol, Object.keys(DEFAULT_PROTOCOL), 'INVALID_SCAFFOLD_SPEC', 'scaffold protocol');
  assertControl(Object.keys(protocol).length === Object.keys(DEFAULT_PROTOCOL).length, 'INVALID_SCAFFOLD_SPEC', 'scaffold protocol 必须包含 entry/shared/foreman/captain/role_kernel');
  for (const [name, file] of Object.entries(protocol)) existingRepoFile(repositoryRoot, file, `protocol.${name}`);

  assertControl(Array.isArray(spec.tasks) && spec.tasks.length > 0, 'INVALID_SCAFFOLD_SPEC', 'scaffold tasks 必须是非空列表');
  const packetFiles = [];
  const taskIdsFolded = new Set();
  const tasks = spec.tasks.map((task, index) => {
    assertPlainObject(task, 'INVALID_SCAFFOLD_SPEC', `tasks[${index}]`);
    assertOnlyKeys(task, [
      'id', 'title', 'issue', 'dependencies', 'integration_order', 'parallel_group', 'risk_class',
      'packet_source', 'packet_revision', 'p1', 'expected_write_set', 'conflict_domains', 'resource_requirements',
    ], 'INVALID_SCAFFOLD_SPEC', `tasks[${index}]`);
    const id = safeId(task.id, `tasks[${index}].id`);
    const folded = id.toLowerCase();
    assertControl(!taskIdsFolded.has(folded), 'INVALID_SCAFFOLD_SPEC', `task id 在大小写不敏感文件系统冲突: ${id}`);
    taskIdsFolded.add(folded);
    assertControl(Number.isSafeInteger(task.packet_revision) && task.packet_revision > 0, 'INVALID_SCAFFOLD_SPEC', `${id}.packet_revision 必须是正整数`);
    const packetSource = existingRepoFile(repositoryRoot, task.packet_source, `${id}.packet_source`);
    const body = fs.readFileSync(packetSource.absolute);
    assertControl(!body.toString('utf8').includes('GOALCTL:SCAFFOLD_INCOMPLETE'), 'INCOMPLETE_TASK_PACKET', `${id} packet 仍含 GOALCTL:SCAFFOLD_INCOMPLETE`);
    const packetName = `${id}-r${task.packet_revision}.md`;
    const packetRelative = `${output.relative}/packets/${packetName}`;
    packetFiles.push({ name: packetName, body });
    return {
      id,
      ...(task.title !== undefined ? { title: task.title } : {}),
      ...(task.issue !== undefined ? { issue: task.issue } : {}),
      dependencies: task.dependencies,
      integration_order: task.integration_order,
      ...(task.parallel_group !== undefined ? { parallel_group: task.parallel_group } : {}),
      ...(task.risk_class !== undefined ? { risk_class: task.risk_class } : {}),
      packet: {
        revision: task.packet_revision,
        path: packetRelative,
        sha256: `sha256:${sha256(body)}`,
      },
      ...(task.p1 !== undefined ? { p1: task.p1 } : {}),
      expected_write_set: task.expected_write_set || [],
      conflict_domains: task.conflict_domains || [],
      resource_requirements: task.resource_requirements || [],
    };
  });

  const manifest = {
    schema_version: 1,
    goal_id: goalId,
    ...(spec.title !== undefined ? { title: spec.title } : {}),
    mode,
    repository: {
      name_with_owner: spec.repository.name_with_owner,
      base_branch: 'main',
      ...(spec.repository.merge_policy !== undefined
        ? { merge_policy: spec.repository.merge_policy }
        : {}),
    },
    base_head: spec.base_head,
    protocol,
    ...(spec.preclaim !== undefined ? { preclaim: spec.preclaim } : {}),
    ...(spec.worker_canary_bootstrap !== undefined
      ? { worker_canary_bootstrap: spec.worker_canary_bootstrap } : {}),
    ...(spec.probe_observation_receipts !== undefined
      ? {
        probe_observation_receipts:
          spec.probe_observation_receipts,
      } : {}),
    tasks,
  };
  const expected = new Map();
  for (const packet of packetFiles) expected.set(`packets/${packet.name}`, packet.body);
  expected.set('manifest.json', Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`));

  if (fs.existsSync(output.absolute)) {
    assertControl(exactTreeMatches(output.absolute, expected), 'SCAFFOLD_CONFLICT', `output ${output.relative} 已存在且内容不同；不会覆盖`);
    const existingManifestFile = path.join(output.absolute, 'manifest.json');
    validateManifest(
      readJson(existingManifestFile, 'existing scaffold manifest'),
      existingManifestFile,
      repositoryRoot,
    );
    return {
      goal_id: goalId,
      mode,
      output_dir: output.relative,
      manifest: `${output.relative}/manifest.json`,
      generated_files: [...expected.keys()].sort().map((file) => `${output.relative}/${file}`),
      initialized: false,
      idempotent: true,
      next: `review and commit ${output.relative}, then run goalctl init --manifest ${output.relative}/manifest.json`,
    };
  }

  ensureDir(path.dirname(output.absolute));
  const temporary = fs.mkdtempSync(path.join(path.dirname(output.absolute), `.${path.basename(output.absolute)}.scaffold-`));
  try {
    for (const [relative, body] of expected.entries()) {
      if (relative === 'manifest.json') continue;
      writePublicFile(path.join(temporary, relative), body);
    }
    const validationManifest = {
      ...manifest,
      tasks: manifest.tasks.map((task) => ({
        ...task,
        packet: {
          ...task.packet,
          path: path.relative(repositoryRoot, path.join(temporary, 'packets', path.basename(task.packet.path))).split(path.sep).join('/'),
        },
      })),
    };
    const validationFile = path.join(temporary, '.goalctl-validation.json');
    writePublicFile(validationFile, `${JSON.stringify(validationManifest, null, 2)}\n`);
    validateManifest(validationManifest, validationFile, repositoryRoot);
    fs.unlinkSync(validationFile);
    writePublicFile(path.join(temporary, 'manifest.json'), expected.get('manifest.json'));
    try {
      fs.renameSync(temporary, output.absolute);
    } catch (error) {
      if (['EEXIST', 'ENOTEMPTY'].includes(error.code) && exactTreeMatches(output.absolute, expected)) {
        fs.rmSync(temporary, { recursive: true, force: true });
      } else {
        throw error;
      }
    }
    validateManifest(manifest, path.join(output.absolute, 'manifest.json'), repositoryRoot);
  } catch (error) {
    if (fs.existsSync(temporary)) fs.rmSync(temporary, { recursive: true, force: true });
    if (error instanceof ControlError) throw error;
    throw new ControlError('SCAFFOLD_FAILED', `无法原子生成 ${output.relative}: ${error.message}`);
  }
  return {
    goal_id: goalId,
    mode,
    output_dir: output.relative,
    manifest: `${output.relative}/manifest.json`,
    generated_files: [...expected.keys()].sort().map((file) => `${output.relative}/${file}`),
    initialized: false,
    idempotent: false,
    next: `review and commit ${output.relative}, then run goalctl init --manifest ${output.relative}/manifest.json`,
  };
}

function eventTemplateActionAllowed(state, session, role, type) {
  if (type === 'HEARTBEAT') {
    return session
      && session.role === role
      && ['active', 'idle'].includes(session.status);
  }
  if (type === 'RUNTIME_ROTATED') {
    return role === 'CAPTAIN'
      && session
      && session.role === 'CAPTAIN'
      && ['active', 'idle'].includes(session.status);
  }
  return allowedActions(state).some((action) => (
    action.type === type && action.actor_role.split('|').includes(role)
  ));
}

function createEventTemplate(cwd, options) {
  const role = options.role;
  assertControl(ROLES.includes(role), 'INVALID_ROLE', `未知 role: ${role}`);
  safeId(options.type, 'event type');
  if (options.type === 'RUNTIME_ROTATED') {
    assertControl(
      options.runtimeRotationOperation === true,
      'RUNTIME_ROTATION_COMMAND_REQUIRED',
      'RUNTIME_ROTATED 只能通过 rotate-runtime 生成',
    );
  }
  return loadGoalStateReadOnly(cwd, options.goalId, (loaded) => {
    const worktree = assertFrozenInputs(cwd, loaded, options.taskId);
    const state = loaded.snapshot.tasks[options.taskId];
    assertControl(state, 'UNKNOWN_TASK', `未知 task ${options.taskId}`);
    const manifestTask = loaded.manifest.tasks.find(
      (candidate) => candidate.id === options.taskId,
    );
    const session = role === 'FOREMAN'
      ? authorizeGoalSession(loaded.snapshot, options.actorCapabilityFile, {
        role,
        threadId: options.threadId,
      })
      : authorizeSession(state, options.actorCapabilityFile, {
        role,
        threadId: options.threadId,
      });
    const legal = eventTemplateActionAllowed(state, session, role, options.type);
    assertControl(legal, 'EVENT_NOT_ALLOWED', `${role} 当前不能执行 ${options.type}`);
    const requiredPayload = EVENT_PAYLOAD_REQUIRED[options.type];
    assertControl(requiredPayload, 'UNKNOWN_EVENT_TYPE', `未知 event type: ${options.type}`);
    let payload = {};
    if (options.payload !== undefined) {
      assertControl(!options.payloadFile, 'INVALID_EVENT', 'payload 与 payloadFile 只能提供一个');
      payload = assertPlainObject(options.payload, 'INVALID_EVENT', `${options.type} payload`);
    } else if (options.payloadFile) {
      payload = readJson(path.resolve(cwd, options.payloadFile), `${options.type} payload`);
      assertPlainObject(payload, 'INVALID_EVENT', `${options.type} payload`);
    } else {
      assertControl(
        requiredPayload.length === 0
          || (
            manifestTask
              && manifestTask.p1
              && ['P1_READY', 'P1_APPROVED', 'P1_COMMITTED'].includes(options.type)
          ),
        'PAYLOAD_FILE_REQUIRED',
        `${options.type} 需要 --payload-file，必填字段: ${requiredPayload.join(', ')}`,
      );
    }
    if (
      manifestTask
        && manifestTask.p1
        && [
          'START_P1',
          'P1_READY',
          'P1_APPROVED',
          'P1_COMMITTED',
          'P1_RESTARTED',
        ]
          .includes(options.type)
    ) {
      payload = completeMechanicalP1EventPayload(
        cwd,
        loaded,
        state,
        manifestTask,
        options.type,
        payload,
      );
    }
    assertLiveRoleLostTargetBinding({
      type: options.type,
      payload,
    });
    const updatesHead = Boolean(TRANSITIONS[options.type] && TRANSITIONS[options.type].updatesHead);
    let fullHead = state.full_head;
    if (updatesHead) {
      assertControl(options.fullHead, 'FULL_HEAD_REQUIRED', `${options.type} 会更新 HEAD，必须显式传 --full-head`);
      fullHead = assertFullSha(options.fullHead, 'event full_head');
      const actualHead = git(worktree, ['rev-parse', 'HEAD']);
      assertControl(fullHead === actualHead, 'STALE_HEAD', `--full-head ${fullHead} 不是当前 worktree HEAD ${actualHead}`);
    } else if (options.fullHead) {
      assertControl(options.fullHead === state.full_head, 'STALE_HEAD', `${options.type} 不更新 HEAD，--full-head 必须等于控制面当前 HEAD`);
    }
    const actorKey = actorSequenceKey(session);
    return validateEvent({
      schema_version: 1,
      event_id: options.eventId || randomId(`event-${options.type.toLowerCase()}`),
      goal_id: options.goalId,
      task_id: options.taskId,
      type: options.type,
      actor: { role, thread_id: session.thread_id, host_id: session.host_id },
      actor_sequence: (state.actor_sequences[actorKey] || 0) + 1,
      expected_state_revision: state.state_revision,
      control_epoch: loaded.control.epoch,
      packet: { revision: state.packet.revision, sha256: state.packet.sha256 },
      base_head: state.base_head,
      full_head: fullHead,
      payload,
    });
  });
}

function maybeFaultAfterSourceHoldGeneration(cwd, dependencies) {
  if (
    typeof dependencies.afterGenerationBeforeCallback === 'function'
  ) {
    assertIsolatedTestMode(cwd);
    dependencies.afterGenerationBeforeCallback();
  }
  const mode =
    process.env.GOAL_CONTROL_TEST_FAULT_AFTER_SOURCE_HOLD_GENERATION;
  if (mode === undefined || mode === '') return;
  assertControl(
    ['1', 'throw', 'exit', 'sigkill'].includes(mode),
    'INVALID_TEST_FAULT',
    'GOAL_CONTROL_TEST_FAULT_AFTER_SOURCE_HOLD_GENERATION '
      + '只能是 1/throw/exit/sigkill',
  );
  assertIsolatedTestMode(cwd);
  if (mode === 'sigkill') {
    process.kill(process.pid, 'SIGKILL');
    return;
  }
  if (mode === 'exit') process.exit(86);
  throw new ControlError(
    'TEST_FAULT_AFTER_SOURCE_HOLD_GENERATION',
    'injected source hold generation boundary failure',
  );
}

function sourceHoldGenerationBoundaryFaultHook(cwd, dependencies) {
  const mode =
    process.env.GOAL_CONTROL_TEST_FAULT_AFTER_SOURCE_HOLD_GENERATION;
  if (
    typeof dependencies.afterGenerationBeforeCallback !== 'function'
      && (mode === undefined || mode === '')
  ) {
    return undefined;
  }
  assertIsolatedTestMode(cwd);
  return () => maybeFaultAfterSourceHoldGeneration(cwd, dependencies);
}

function revalidateSourceCheckpointHold(cwd, options, dependencies = {}) {
  const inspectHold = dependencies.inspectSourceCheckpointHold
    || inspectSourceCheckpointHold;
  const operationId = safeId(
    options.operationId,
    'source checkpoint revalidation operation_id',
  );
  const operationMatch =
    /^source-checkpoint-revalidation-([0-9a-f]{32})$/.exec(operationId);
  assertControl(
    operationMatch,
    'INVALID_ID',
    'source checkpoint revalidation operation_id 格式非法',
  );
  const operationDigest = operationMatch[1];
  const expectedHoldEventId = safeId(
    options.expectedHoldEventId,
    'expected ADD_HOLD event_id',
  );
  const canonicalSha256 = normalizeHash(
    options.expectedCanonicalLaunchSha256,
    'expected canonical launch sha256',
  );
  const candidateHead = assertFullSha(
    options.expectedCandidateHead,
    'expected candidate HEAD',
  );
  const resolutionEvidenceId =
    `source-checkpoint-resolution-${operationDigest}`;
  const resolveEventId =
    `resolve-source-checkpoint-hold-${operationDigest}`;
  const request = {
    schema_version: 1,
    kind: 'SOURCE_CHECKPOINT_HOLD_REVALIDATION',
    operation_id: operationId,
    goal_id: options.goalId,
    task_id: options.taskId,
    foreman_thread_id: options.threadId,
    hold_id: options.holdId,
    hold_event_id: expectedHoldEventId,
    canonical_launch_sha256: canonicalSha256,
    candidate_head: candidateHead,
  };
  const root = controlRoot(cwd);
  let boundary = null;
  return withLock(root, () => {
    const {
      registered,
      source,
      evidence,
      sourceBytes,
      resolutionEvent,
      preparedRegistration,
    } = boundary;
    if (typeof dependencies.beforeFinalInspection === 'function') {
      dependencies.beforeFinalInspection();
    }
    const current = loadGoalStateUnlocked(root, options.goalId, {
      repairHeads: false,
      repairBootstrapConsumption: false,
    });
    const currentState = current.snapshot.tasks[options.taskId];
    assertControl(
      currentState,
      'UNKNOWN_TASK',
      `未知 task ${options.taskId}`,
    );
    const activeHold = currentState.holds.find(
      (hold) => hold.hold_id === options.holdId,
    );
    if (activeHold) {
      const manifestTask = current.manifest.tasks.find(
        (candidate) => candidate.id === options.taskId,
      );
      // The proof is intentionally about the immutable candidate commit bound
      // by the operation, not a cross-process lock on the mutable worktree
      // HEAD. If DEV advances again, taskActionProjection independently
      // requires a fresh PREFLIGHT for that actual HEAD before DEV_READY.
      const finalInspection = inspectHold(
        current.paths,
        currentState,
        current.manifest.goal_id,
        manifestTask,
        {
          expectedCandidateHead: candidateHead,
          expectedHoldEventId,
          allowCurrentHeadDrift: true,
        },
      );
      assertControl(
        finalInspection
          && finalInspection.hold_event_id === expectedHoldEventId
          && finalInspection.canonical_launch_sha256
            === canonicalSha256
          && finalInspection.candidate_head === candidateHead
          && finalInspection.candidate_launch_sha256
            === source.proof.candidate_launch_sha256,
        'SOURCE_CHECKPOINT_HOLD_CHANGED',
        'source checkpoint proof 在最终提交边界发生漂移',
      );
    } else {
      assertControl(
        registered,
        'SOURCE_CHECKPOINT_HOLD_CHANGED',
        `hold ${options.holdId} 在 resolution evidence 提交前消失`,
      );
    }
    let durableEvidence = registered;
    if (!durableEvidence) {
      durableEvidence = recordEvidenceBytesUnderLock(
        cwd,
        evidence,
        sourceBytes,
        options.actorCapabilityFile,
        false,
        { allowEvidenceId: resolutionEvidenceId },
      );
      if (
        process.env.GOAL_CONTROL_TEST_FAULT_AFTER_SOURCE_HOLD_EVIDENCE
          === '1'
      ) {
        assertControl(
          process.env.GOAL_CONTROL_TEST_MODE === '1'
            && typeof process.env.GOAL_CONTROL_DIR === 'string',
          'TEST_MODE_FORBIDDEN',
          'source hold fault injection 只允许隔离测试',
        );
        throw new ControlError(
          'TEST_FAULT_AFTER_SOURCE_HOLD_EVIDENCE',
          'injected failure after durable source hold resolution evidence',
        );
      }
    }
    const accepted = acceptEventUnderLock(
      cwd,
      resolutionEvent,
      options.actorCapabilityFile,
      registered
        ? {
          pristineEventRecovery: true,
          pristineEventAcceptedAt: source.prepared_accepted_at,
        }
        : {},
    );
    return {
      operation: 'SOURCE_CHECKPOINT_HOLD_REVALIDATION',
      operation_id: operationId,
      idempotent:
        Boolean(registered)
          || Boolean(preparedRegistration)
          || accepted.idempotent === true,
      resolution_evidence_id: resolutionEvidenceId,
      resolve_event_id: resolveEventId,
      evidence: durableEvidence,
      result: accepted,
    };
  }, {
    beforeGeneration: (transaction) => {
      const loaded = loadGoalStateUnlocked(root, options.goalId, {
        repairHeads: false,
        repairBootstrapConsumption: false,
      });
      const state = loaded.snapshot.tasks[options.taskId];
      assertControl(state, 'UNKNOWN_TASK', `未知 task ${options.taskId}`);
      const currentHold = state.holds.find(
        (hold) => hold.hold_id === options.holdId,
      );
      const registryFile = evidenceFile(
        root,
        options.goalId,
        options.taskId,
        resolutionEvidenceId,
      );
      if (fs.existsSync(registryFile)) {
        const registered = readExistingEvidenceForRetryUnderLock(cwd, {
          goalId: options.goalId,
          taskId: options.taskId,
          evidenceId: resolutionEvidenceId,
          actorCapabilityFile: options.actorCapabilityFile,
        });
        const sourceUrl = new URL(registered.evidence.uri);
        assertControl(
          sourceUrl.protocol === 'file:',
          'CORRUPT_STORE',
          'source checkpoint resolution source 必须是 sealed file',
        );
        const source = readJson(
          fileURLToPath(sourceUrl),
          `source checkpoint resolution ${resolutionEvidenceId}`,
        );
        assertControl(
          source
            && source.adapter
              === 'SOURCE_CHECKPOINT_HOLD_REVALIDATION_V2'
            && hashObject(source.request) === hashObject(request)
            && source.resolution_event
            && source.resolution_event.event_id === resolveEventId
            && source.resolution_event.payload
            && source.resolution_event.payload.hold_id
              === options.holdId
            && source.resolution_event.payload.resolution_evidence_id
              === resolutionEvidenceId
            && source.resolution_event.payload.authority
              === `goalctl:SOURCE_CHECKPOINT_HOLD_REVALIDATION:v2:${operationId}`,
          'EVIDENCE_ID_CONFLICT',
          `source checkpoint resolution ${operationId} 已绑定不同 request`,
        );
        boundary = {
          loaded,
          state,
          registered,
          source,
          evidence: null,
          sourceBytes: null,
          resolutionEvent: source.resolution_event,
          preparedRegistration: null,
        };
        return;
      }
      assertControl(
        currentHold,
        'SOURCE_CHECKPOINT_HOLD_CHANGED',
        `找不到 exact hold incarnation ${expectedHoldEventId}`,
      );
      let foreman;
      if (transaction.mode !== 'FRESH') {
        const taskForeman = state.sessions.FOREMAN;
        assertControl(
          taskForeman
            && taskForeman.thread_id === options.threadId,
          'CAPABILITY_INVALID',
          'pristine source hold retry FOREMAN identity 不匹配',
        );
        foreman = authorizeHistoricalActorCapability(
          loaded.snapshot,
          options.actorCapabilityFile,
          {
            role: 'FOREMAN',
            thread_id: taskForeman.thread_id,
            host_id: taskForeman.host_id,
            attempt: taskForeman.attempt,
          },
          {
            goalWide: true,
            taskId: options.taskId,
          },
        );
        const transactionStartedAt = Date.parse(
          transaction.transaction_started_at,
        );
        const validReplicaAtStart = Object.values(
          loaded.snapshot.tasks || {},
        ).map((task) => task.sessions && task.sessions.FOREMAN)
          .filter(Boolean)
          .some((replica) => (
            replica.thread_id === foreman.thread_id
              && replica.host_id === foreman.host_id
              && replica.attempt === foreman.attempt
              && replica.capability_file === foreman.capability_file
              && replica.capability_sha256 === foreman.capability_sha256
              && ['active', 'idle'].includes(replica.status)
              && Date.parse(replica.lease_until) > transactionStartedAt
          ));
        assertControl(
          Number.isFinite(transactionStartedAt)
            && validReplicaAtStart,
          'ACTOR_LEASE_EXPIRED',
          'source hold FOREMAN 在原 transaction boundary 前已过期',
        );
      } else {
        foreman = authorizeGoalSession(
          loaded.snapshot,
          options.actorCapabilityFile,
          {
            role: 'FOREMAN',
            threadId: options.threadId,
          },
        );
      }
      const expectedOperationDigest = sha256([
        options.goalId,
        options.taskId,
        options.holdId,
        expectedHoldEventId,
        canonicalSha256,
        candidateHead,
        foreman.thread_id,
        foreman.host_id,
        String(foreman.attempt),
      ].join('\0')).slice(0, 32);
      assertControl(
        operationDigest === expectedOperationDigest,
        'SOURCE_CHECKPOINT_RESOLUTION_CONFLICT',
        `operation_id ${operationId} 未绑定当前 FOREMAN/hold/source checkpoint`,
      );
      const manifestTask = loaded.manifest.tasks.find(
        (candidate) => candidate.id === options.taskId,
      );
      const inspection = inspectHold(
        loaded.paths,
        state,
        loaded.manifest.goal_id,
        manifestTask,
        {
          expectedCandidateHead: candidateHead,
          expectedHoldEventId,
          allowCurrentHeadDrift: true,
        },
      );
      assertControl(
        inspection
          && inspection.hold.hold_id === options.holdId
          && inspection.hold_event_id === expectedHoldEventId
          && inspection.canonical_launch_sha256 === canonicalSha256
          && inspection.candidate_head === candidateHead,
        'SOURCE_CHECKPOINT_HOLD_CHANGED',
        'source checkpoint hold/canonical/candidate 已漂移',
      );
      const actorKey = actorSequenceKey(foreman);
      const resolutionEvent = validateEvent({
        schema_version: 1,
        event_id: resolveEventId,
        goal_id: options.goalId,
        task_id: options.taskId,
        type: 'RESOLVE_HOLD',
        actor: {
          role: 'FOREMAN',
          thread_id: foreman.thread_id,
          host_id: foreman.host_id,
        },
        actor_sequence: (state.actor_sequences[actorKey] || 0) + 1,
        expected_state_revision: state.state_revision,
        control_epoch: loaded.control.epoch,
        packet: {
          revision: state.packet.revision,
          sha256: state.packet.sha256,
        },
        base_head: state.base_head,
        full_head: state.full_head,
        payload: {
          hold_id: options.holdId,
          authority:
            `goalctl:SOURCE_CHECKPOINT_HOLD_REVALIDATION:v2:${operationId}`,
          resolution_evidence_id: resolutionEvidenceId,
          disposition: 'FALSE_POSITIVE',
        },
      });
      const source = {
        schema_version: 1,
        adapter: 'SOURCE_CHECKPOINT_HOLD_REVALIDATION_V2',
        request,
        prepared_accepted_at: transaction.transaction_started_at,
        hold_evidence_id: inspection.hold.evidence.evidence_id,
        parent_evidence_id: inspection.parent_evidence_id,
        proof: {
          canonical_launch_sha256:
            inspection.canonical_launch_sha256,
          canonical_head: inspection.canonical_head,
          candidate_head: inspection.candidate_head,
          candidate_launch_sha256:
            inspection.candidate_launch_sha256,
        },
        resolution_event: resolutionEvent,
        disposition: 'FALSE_POSITIVE',
        reason:
          'the immutable runtime identity remained exact; only the DEV source checkpoint advanced along the verified Git lineage',
      };
      const sourceBytes = Buffer.from(
        `${canonicalJson(source)}\n`,
        'utf8',
      );
      const evidence = {
        schema_version: 1,
        evidence_id: resolutionEvidenceId,
        goal_id: options.goalId,
        task_id: options.taskId,
        kind: 'HOLD_RESOLUTION',
        stage: 'SOURCE_CHECKPOINT_REVALIDATION',
        status: 'PASS',
        producer: {
          role: 'FOREMAN',
          thread_id: foreman.thread_id,
          host_id: foreman.host_id,
        },
        state_revision: state.state_revision,
        packet: { ...state.packet },
        packet_sha256: state.packet.sha256,
        base_head: state.base_head,
        full_head: state.full_head,
        created_at: transaction.transaction_started_at,
        source_sha256: `sha256:${sha256(sourceBytes)}`,
        checks: [{
          name: 'source-checkpoint-lineage-and-runtime-invariant',
          status: 'PASS',
          detail:
            `${inspection.canonical_head}->${inspection.candidate_head}; canonical=${inspection.canonical_launch_sha256}`,
        }],
      };
      const preparedFile = semanticIngressPreparedFile(
        root,
        options.goalId,
        options.taskId,
        resolutionEvidenceId,
      );
      let preparedRegistration = null;
      if (fs.existsSync(preparedFile)) {
        preparedRegistration =
          inspectPreparedEvidenceBytesForRetryUnderLock(
            cwd,
            evidence,
            sourceBytes,
            options.actorCapabilityFile,
            false,
          );
      }
      boundary = {
        loaded,
        state,
        registered: null,
        source,
        evidence,
        sourceBytes,
        resolutionEvent,
        preparedRegistration,
        pristineRecoveryAuthorized:
          isOddTransactionRetry(transaction.mode),
      };
    },
    authorizeOddRecovery: () => Boolean(
      boundary
        && (boundary.registered || boundary.preparedRegistration),
    ),
    authorizePristineOddRecovery: () => Boolean(
      boundary
        && boundary.pristineRecoveryAuthorized
        && !boundary.registered
        && !boundary.preparedRegistration,
    ),
    transactionKey: canonicalTransactionKey(
      'SOURCE_CHECKPOINT_HOLD_REVALIDATION',
      {
        goal_id: options.goalId,
        task_id: options.taskId,
      },
      operationId,
      hashObject(request),
    ),
    sameStableOperationMismatchCode:
      'SOURCE_CHECKPOINT_RESOLUTION_CONFLICT',
    sameStableOperationMismatchMessage:
      `source checkpoint revalidation ${operationId} 已绑定不同 request`,
    afterGenerationBeforeCallback:
      sourceHoldGenerationBoundaryFaultHook(cwd, dependencies),
  });
}

function commandVersion(command, args) {
  try {
    return execFileSync(command, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
  } catch (error) {
    throw new ControlError('RUNTIME_VERSION_FAILED', `无法读取 ${command} 版本: ${String(error.stderr || error.message).trim()}`);
  }
}

function canonicalOrigin(value) {
  const normalized = String(value || '')
    .trim()
    .replace(/^git@([^:]+):/, 'https://$1/')
    .replace(/^ssh:\/\/git@([^/]+)\//, 'https://$1/')
    .replace(/\.git$/, '')
    .replace(/\/$/, '');
  let parsed;
  try {
    parsed = new URL(normalized);
  } catch {
    throw new ControlError('ORIGIN_MISMATCH', 'origin URL 不是可规范化 URL');
  }
  assertControl(!parsed.username && !parsed.password, 'ORIGIN_CREDENTIAL_FORBIDDEN', 'origin URL 禁止内嵌凭证');
  return normalized;
}

function canonicalExisting(candidate, label) {
  assertControl(typeof candidate === 'string' && path.isAbsolute(candidate), 'INVALID_LAUNCH_INPUT', `${label} 必须是绝对路径`);
  try {
    return fs.realpathSync(candidate);
  } catch (error) {
    throw new ControlError('INVALID_LAUNCH_INPUT', `${label} 不存在: ${error.message}`);
  }
}

function canonicalRegularFile(candidate, label, executable = false) {
  const canonical = canonicalExisting(candidate, label);
  assertControl(fs.statSync(canonical).isFile(), 'INVALID_LAUNCH_INPUT', `${label} 必须是普通文件`);
  if (executable) {
    try {
      fs.accessSync(canonical, fs.constants.X_OK);
    } catch {
      assertControl(false, 'INVALID_LAUNCH_INPUT', `${label} 必须可执行`);
    }
  }
  return canonical;
}

function canonicalDirectory(candidate, label) {
  const canonical = canonicalExisting(candidate, label);
  assertControl(fs.statSync(canonical).isDirectory(), 'INVALID_LAUNCH_INPUT', `${label} 必须是目录`);
  return canonical;
}

function createLaunchTemplate(cwd, options) {
  assertControl(['DEV', 'REVIEW', 'RECEIPT'].includes(options.role), 'INVALID_ROLE', 'launch-template 只用于 DEV/REVIEW/RECEIPT');
  const loaded = loadGoalState(cwd, options.goalId);
  const worktree = assertFrozenInputs(cwd, loaded, options.taskId);
  const state = loaded.snapshot.tasks[options.taskId];
  assertControl(state, 'UNKNOWN_TASK', `未知 task ${options.taskId}`);
  const session = authorizeSession(state, options.actorCapabilityFile, {
    role: options.role,
    threadId: options.threadId,
  });
  if (loaded.manifest.probe_observation_receipts) {
    const {
      assertLivePassBinding,
    } = require('./canary-observation-receipt');
    assertControl(
      session.probe_observation,
      'CANARY_OBSERVATION_REQUIRED',
      'launch-template 前缺 sealed probe observation PASS binding',
    );
    assertLivePassBinding(
      session.probe_observation,
      undefined,
      {
        repositoryHead: state.full_head,
        role: options.role,
        taskId: options.taskId,
      },
    );
  }
  assertOperationalScope(state, options.role, 'LAUNCH_TEMPLATE');
  assertControl(!state.recovery, 'RECOVERY_REQUIRED', `launch-template 前必须先闭合 ${state.recovery && state.recovery.role} recovery`);
  assertControl(
    !Array.isArray(state.recovery_backlog) || state.recovery_backlog.length === 0,
    'RECOVERY_BACKLOG_REQUIRED',
    'launch-template 前必须先清空 recovery backlog',
  );
  assertControl(session.launch_id && session.task_nonce, 'LAUNCH_ID_REQUIRED', `${options.role} session 尚未绑定 launch_id/task_nonce`);
  assertControl(session.registered_control_epoch === loaded.control.epoch && !state.reconcile_required, 'STALE_CONTROL_EPOCH', 'worker registration 已被 control epoch 变更作废');
  assertControl(
    session.registered_packet_revision === state.packet.revision
      && session.registered_packet_sha256 === state.packet.sha256,
    'STALE_PACKET',
    'worker registration packet 已陈旧',
  );

  const fullHead = git(worktree, ['rev-parse', 'HEAD']);
  const branch = git(worktree, ['branch', '--show-current']);
  assertControl(branch, 'DETACHED_HEAD', 'launch-template 要求命名分支，当前是 detached HEAD');
  if (sessionOperationalScope(state, options.role) === 'PREFLIGHT_ONLY') {
    const handoff = session.recovery_handoff;
    assertControl(handoff, 'RECOVERY_HANDOFF_REQUIRED', 'recovery launch-template 缺 source handoff');
    assertControl(
      fs.realpathSync(worktree) === fs.realpathSync(handoff.destination_worktree),
      'WORKTREE_MISMATCH',
      'recovery launch-template 必须在 sealed destination worktree',
    );
    assertControl(branch === handoff.destination_branch, 'BRANCH_MISMATCH', 'recovery launch-template 必须在 sealed destination branch');
    assertControl(
      fullHead === handoff.import_commit,
      'STALE_HEAD',
      'PREFLIGHT_ONLY launch-template HEAD 必须精确等于 sealed import checkpoint',
    );
  }
  const gitDir = fs.realpathSync(path.resolve(
    git(
      worktree,
      ['rev-parse', '--path-format=absolute', '--absolute-git-dir'],
    ),
  ));
  const commonGitDir = fs.realpathSync(path.resolve(
    git(
      worktree,
      ['rev-parse', '--path-format=absolute', '--git-common-dir'],
    ),
  ));
  const commonRoot = fs.realpathSync(path.dirname(commonGitDir));
  const workerBootstrap = requiredWorkerBootstrapBinding(
    loaded.manifest,
    session,
    options.role,
  );
  const allowWorkerHeadAdvance =
    options.role === 'DEV' && state.phase === 'DEV_ACTIVE';
  assertWorkerBootstrapCurrentWorktree(
    session,
    {
      worktree,
      git_dir: gitDir,
      common_git_dir: commonGitDir,
      head: fullHead,
      branch,
    },
    { allowHeadAdvance: allowWorkerHeadAdvance },
  );
  const originUrl = canonicalOrigin(git(worktree, ['remote', 'get-url', 'origin']));
  const lockfile = path.join(worktree, 'pnpm-lock.yaml');
  assertControl(fs.existsSync(lockfile), 'LOCKFILE_MISSING', 'worktree 缺 pnpm-lock.yaml');
  const runtimeLaunchFile = canonicalRuntimeLaunchFile(
    path.dirname(path.dirname(loaded.paths.dir)),
    options.goalId,
    options.taskId,
    session.launch_id,
  );
  let canonicalLaunch = null;
  if (fs.existsSync(runtimeLaunchFile)) {
    canonicalLaunch = validateLaunchManifest(
      readJson(runtimeLaunchFile, `canonical launch ${session.launch_id}`),
    );
  }
  if (!options.inputFile) {
    assertControl(
      canonicalLaunch
        && options.role === 'DEV'
        && state.phase === 'DEV_ACTIVE',
      'LAUNCH_INPUT_REQUIRED',
      '省略 --input-file 只允许 DEV_ACTIVE 从既有 canonical runtime 派生 source checkpoint',
    );
    assertControl(
      canonicalLaunch.goal_id === options.goalId
        && canonicalLaunch.task_id === options.taskId
        && canonicalLaunch.role === 'DEV'
        && canonicalLaunch.thread.id === session.thread_id
        && (canonicalLaunch.thread.host_id || 'local') === session.host_id
        && canonicalLaunch.execution.task_nonce === session.task_nonce
        && canonicalLaunch.control_epoch === loaded.control.epoch
        && canonicalLaunch.state_revision === session.registered_state_revision
        && canonicalLaunch.packet.revision === state.packet.revision
        && normalizeHash(canonicalLaunch.packet.sha256) === state.packet.sha256
        && canonicalLaunch.repository.base_head === state.base_head
        && canonicalLaunch.repository.worktree === worktree
        && canonicalLaunch.repository.branch === branch
        && canonicalLaunch.repository.root === commonRoot
        && canonicalLaunch.repository.origin_url === originUrl
        && canonicalLaunch.runtime.lockfile_sha256 === hashFile(lockfile)
        && (
          canonicalLaunch.pull_request === null
            || canonicalLaunch.pull_request === undefined
        ),
      'STALE_LAUNCH',
      'canonical runtime launch 与当前 DEV session/repository binding 陈旧',
    );
    const candidate = JSON.parse(JSON.stringify(canonicalLaunch));
    candidate.repository.full_head = fullHead;
    if (candidate.execution.target.kind === 'NONE') {
      delete candidate.execution.target.build_head;
    } else {
      candidate.execution.target.build_head = fullHead;
    }
    const validatedCandidate = validateLaunchManifest(candidate);
    assertSourceCheckpointAdvance(canonicalLaunch, validatedCandidate);
    assertLaunchRuntimeIncarnation(session, validatedCandidate);
    assertWorkerBootstrapLaunchBinding(
      session,
      validatedCandidate,
      { allowHeadAdvance: true },
    );
    return validatedCandidate;
  }

  const input = assertPlainObject(readJson(path.resolve(cwd, options.inputFile), 'launch template input'), 'INVALID_LAUNCH_INPUT', 'launch template input');
  assertOnlyKeys(input, ['thread_title', 'runtime_model', 'execution', 'resource_leases'], 'INVALID_LAUNCH_INPUT', 'launch template input');
  const execution = assertPlainObject(input.execution, 'INVALID_LAUNCH_INPUT', 'launch input.execution');
  assertOnlyKeys(execution, ['environment', 'domain', 'account_alias', 'tim_alias', 'write_mode', 'identity_probe', 'target'], 'INVALID_LAUNCH_INPUT', 'launch input.execution');
  assertControl(Array.isArray(input.resource_leases), 'INVALID_LAUNCH_INPUT', 'launch input.resource_leases 必须是列表');
  if (input.runtime_model !== undefined) {
    assertPlainObject(input.runtime_model, 'INVALID_LAUNCH_INPUT', 'launch input.runtime_model');
    assertOnlyKeys(input.runtime_model, ['requested', 'actual', 'reasoning_effort'], 'INVALID_LAUNCH_INPUT', 'launch input.runtime_model');
  }

  const normalizedExecution = { ...execution, task_nonce: session.task_nonce };
  if (execution.identity_probe) {
    assertPlainObject(execution.identity_probe, 'INVALID_LAUNCH_INPUT', 'launch input.execution.identity_probe');
    assertOnlyKeys(execution.identity_probe, ['path', 'sha256'], 'INVALID_LAUNCH_INPUT', 'launch input.execution.identity_probe');
    normalizedExecution.identity_probe = {
      ...execution.identity_probe,
      path: canonicalRegularFile(execution.identity_probe.path, 'identity_probe.path'),
      sha256: normalizeHash(execution.identity_probe.sha256, 'identity_probe.sha256'),
    };
    assertControl(hashFile(normalizedExecution.identity_probe.path) === normalizedExecution.identity_probe.sha256, 'IDENTITY_PROBE_HASH_MISMATCH', 'identity probe hash 不匹配');
  }
  assertPlainObject(execution.target, 'INVALID_LAUNCH_INPUT', 'launch input.execution.target');
  normalizedExecution.target = { ...execution.target };
  if (execution.target.executable_path) normalizedExecution.target.executable_path = canonicalRegularFile(execution.target.executable_path, 'target.executable_path', true);
  if (execution.target.user_data_dir) normalizedExecution.target.user_data_dir = canonicalDirectory(execution.target.user_data_dir, 'target.user_data_dir');

  let pullRequest = null;
  if (options.role === 'DEV') {
    pullRequest = null;
  } else if (state.pr) {
    const parsed = parsePullRequestUrl(state.pr, loaded.manifest.repository.name_with_owner);
    pullRequest = {
      repository: parsed.repository,
      number: parsed.number,
      base: parsed.base,
      head: fullHead,
    };
  } else {
    assertControl(false, 'PULL_REQUEST_REQUIRED', `${options.role} launch 需要控制面已有 PR binding`);
  }
  const launch = {
    schema_version: 1,
    launch_id: session.launch_id,
    goal_id: options.goalId,
    task_id: options.taskId,
    role: options.role,
    control_epoch: loaded.control.epoch,
    state_revision: session.registered_state_revision,
    thread: {
      id: session.thread_id,
      host_id: session.host_id,
      ...(input.thread_title !== undefined ? { title: input.thread_title } : {}),
      cwd: worktree,
    },
    packet: { ...state.packet },
    repository: {
      name_with_owner: loaded.manifest.repository.name_with_owner,
      origin_url: originUrl,
      base_branch: loaded.manifest.repository.base_branch,
      base_head: state.base_head,
      full_head: fullHead,
      branch,
      root: commonRoot,
      worktree,
    },
    runtime: {
      node_version: process.version,
      pnpm_version: commandVersion('pnpm', ['--version']),
      lockfile_sha256: hashFile(lockfile),
      ...(input.runtime_model !== undefined ? { model: input.runtime_model } : {}),
    },
    ...(session.runtime_incarnation !== undefined
      ? {
        runtime_incarnation: {
          epoch: session.runtime_incarnation,
          nonce: session.runtime_nonce,
          rotation_event_id: session.last_runtime_rotation
            && session.last_runtime_rotation.event_id,
        },
      }
      : {}),
    ...(workerBootstrap
      ? { worker_bootstrap: workerBootstrap }
      : {}),
    execution: normalizedExecution,
    pull_request: pullRequest,
    resource_leases: input.resource_leases,
    created_at: nowIso(),
  };
  if (canonicalLaunch) {
    launch.created_at = canonicalLaunch.created_at;
    if (canonicalLaunch.repository.full_head !== fullHead) {
      assertControl(
        options.role === 'DEV' && state.phase === 'DEV_ACTIVE',
        'LAUNCH_ID_CONFLICT',
        '只有 DEV_ACTIVE 可以在同一 runtime 刷新 source checkpoint',
      );
      if (canonicalLaunch.execution.target.build_head !== undefined) {
        launch.execution.target.build_head = fullHead;
      } else {
        assertControl(
          canonicalLaunch.execution.target.kind === 'NONE'
            && launch.execution.target.build_head === undefined,
          'LAUNCH_ID_CONFLICT',
          '有执行 runtime 的 canonical launch 缺 build_head，必须换 fresh runtime',
        );
      }
    }
  }
  const validated = validateLaunchManifest(launch);
  if (
    canonicalLaunch
      && hashObject(canonicalLaunch) !== hashObject(validated)
  ) {
    assertSourceCheckpointAdvance(canonicalLaunch, validated);
  }
  assertLaunchRuntimeIncarnation(session, validated);
  assertWorkerBootstrapLaunchBinding(
    session,
    validated,
    { allowHeadAdvance: allowWorkerHeadAdvance },
  );
  const predecessor = predecessorLaunchForRotation(loaded, state, session);
  if (predecessor) {
    assertRotationSuccessorLaunch(predecessor, session, validated);
  }
  return validated;
}

module.exports = {
  createEventTemplate,
  createLaunchTemplate,
  eventTemplateActionAllowed,
  helpDocument,
  revalidateSourceCheckpointHold,
  renderHelp,
  scaffoldGoal,
};
