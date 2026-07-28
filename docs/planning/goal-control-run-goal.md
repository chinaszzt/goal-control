# Fresh Goal 连续运行

> 给 supervisor 和 FOREMAN 的短运行路径。所有执行性 CLI 都使用
> [`goal-control-quickstart.md`](./goal-control-quickstart.md#01-固定双根目录与-exact-argv-wrapper)
> 定义的 exact `gc_goalctl <controlled-worktree> ...` /
> `gc_resourcectl <controlled-worktree> ...` wrapper，禁止由 `PATH` 或受控仓
> package scripts 解析。参数细节按需运行
> `gc_goalctl <controlled-worktree> help <command>`；store adoption/rotation 只见
> [`goal-control-store-operations.md`](./goal-control-store-operations.md)。运行角色不要
> 整份读取 `goal-control-quickstart.md`。

## 1. 不可交换的启动顺序

1. 先合并本轮依赖的 controller、protocol、Goal authorization/manifest/packet PR。
2. fetch canonical `origin/<base_branch>`，让 clean base worktree 的
   `HEAD == refs/remotes/origin/<base_branch>`，并确认没有仍计划先合并的其它 PR。
3. 使用**从未 init 的 fresh Goal ID**。旧 Goal 的 `goal_input_head`、preclaim receipt、
   identity、capability、event ID 和 lease 都不得复用。
4. 若共享 store 需要 adoption/rotation，由 supervisor 在所有旧 controller 已
   drain/isolate 后先完成；任一 canary 不通过，不进入 Goal 初始化。
5. 运行 committed manifest 绑定的 `preclaim-issues` 并保存 exact receipt。receipt
   PASS 后、`init` 前必须再次 fetch canonical `origin/<base_branch>`，确认 clean base
   worktree 的 `HEAD == refs/remotes/origin/<base_branch>`，且该 full SHA 与 preclaim 前
   相同；只有这个二次观察 PASS 才立即 `init`。`init` 本身只读本地 remote-tracking
   ref，不替代 live fetch。任一漂移都不得 init：废弃该 Goal ID，从新 main 重新生成、
   review、merge fresh static package，再用 fresh preclaim operation/Goal ID 开始。
   机械 P1 会把该稳定边界 seal 为 `goal_input_head`。
6. `init` 后若首 task 开始前 main 又前移，或运行中出现不属于本 Goal 的 main merge，
   停止当前 Goal。Mechanical P1 v1 没有 base refresh/rebase FSM；不能改
   `goal_input_head`、重跑 init 或让旧 Goal追赶，必须从新 main 建另一个 fresh Goal ID。
7. 只有上述边界稳定后才登记 FOREMAN，并从 `goalctl next --json` 的
   `batch` 启动 task。

`base_head`、`goal_input_head` 和后继 task 的 `required_start_head` 都是完整 SHA，不用
聊天里的 branch 名或短 SHA代替。长期连续运行期间要把外部 main merge 视为调度输入，
不是可忽略噪声。

## 2. Session 启动：legacy full-plan canary 与 opt-in dynamic bootstrap

`create_thread` 会立即异步执行，不能先发送正式角色 prompt、再赌上级来得及
registration/preflight。legacy `CANARY_ONLY -> ACTIVE` 只允许用于创建前已知 actual
cwd，或 full plan 确实不需要绑定 opaque worker branch 的 session；FOREMAN/CAPTAIN
通常满足这一条件，但不能只按 role 名猜。对 DEV/REVIEW/RECEIPT，legacy 还要求
manifest 未启用 worker bootstrap；committed manifest 一旦显式 opt in，就必须使用
`IDENTITY_ONLY -> PREPARE_ACTUAL_WORKTREE -> CANARY_EXECUTE -> ACTIVE`。

旧 manifest 未 opt in 时，controller 会拒绝 bootstrap receipt；这不等于 opaque
dynamic worker 可以退化走 legacy。若其 actual thread/host/cwd/branch 只能在
`create_thread` 返回后知道，又需要把 full plan 绑定该 branch，就必须先把支持 bootstrap
的 static package 合并并初始化 fresh Goal。不能把 CAPTAIN/父 session cwd 生成的 full
canary plan 放进 worker 初始 prompt，也不能创建后用聊天补实际路径、让 worker raw
`git switch/checkout` 或反复创建候选碰碰运气。

### 阶段 A：外部 capability canary

创建 task 前，上级先分别冻结 clean committed controller root 与 frozen Goal
worktree；两者可以位于不同 HEAD，不能依赖当前 shell cwd 猜其中任何一个。满足上述
legacy 条件的角色在创建前生成 full canary plan；manifest 显式 opt-in 的 dynamic
worker 则先完成下文 bootstrap，等 actual
worktree receipt sealed 后才生成 full plan。若 committed manifest 对本 role/task 投影为
Browser `REQUIRED`，supervisor 必须在 full plan 前、从随后执行 `canary-plan` 的**同一份
committed controller** 用安全 launcher 启动仓库自带 server；动态 worker 的
`IDENTITY_ONLY` 和 `PREPARE_ACTUAL_WORKTREE` 期间严禁提前调用 Browser：

```text
<controller-root>/scripts/goal-control/browser-canary-launch.sh \
  [--node-executable <canonical-absolute-path>] launch \
  --receipt-file <canonical-private-dir>/<fresh-name>.json \
  --goal <goal-id> --role <ROLE> [--task <id>]
```

`<canonical-private-dir>` 必须先用 `pwd -P`/`realpath` 取得，归当前用户所有且
mode=0700；launcher 固定以 detached `serve --port 0` 启动，等待 fresh 0600 receipt
和 live identity 全部就绪后才输出 `READY`，无需 shell `&`、`$!` 或猜测 sleep。实际
shell launcher 以 `/bin/sh -p` 忽略 inherited startup/functions/options，只调用固定
absolute OS 工具，优先从 `/opt/homebrew/opt/node@22/bin/node`、
`/usr/local/opt/node@22/bin/node` 选择项目门禁使用的 versioned Node 22，再以
`/opt/homebrew/bin/node`、`/usr/local/bin/node`、`/usr/bin/node` 为 fallback；
选中后 realpath 绑定，然后用 `/usr/bin/env -i` 清掉 parent token、
`NODE_OPTIONS`、preload 和动态 loader 环境；无 trusted Node candidate 就 fail-closed，
不得退回直接 `node browser-canary-server.js launch`。
`actions/setup-node`、fnm、asdf 等解释器不在固定位置时，上级必须把已知当前
`process.execPath` 的 canonical realpath 作为 supervisor 已信任的 TCB，通过首个
argv-only `--node-executable` 传入；worker 禁止自选，也禁止用环境变量或 inherited
`PATH` 发现。override 与默认候选都由固定 OS 工具独立拒绝控制字符并验证 ordinary
single-link/mode；只有自动发现的固定候选再机械要求 owner 是当前 uid/root。显式
override 的 owner/provenance 属于 supervisor 已批准 TCB，不从 worker 进程 uid
反推——这兼容由 `actions/setup-node` 的 runner service owner 持有、但 job 以另一个
uid 执行的 toolcache。launcher 本身不认证调用者，所以 worker 只能执行上级冻结的
exact argv，禁止自行换 path。随后在 `env -i` 下做 Node `>=22.19` **兼容性**检查，
且 launch/stop 必须传同一个 exact path。兼容性输出不是 executable provenance
证明；恶意 binary 或同 UID 对可写 ancestor/pathname 的验证后替换仍在本地信任边界
之外。
端口只从 receipt 读取。FOREMAN 禁止 `--task`，worker role 必须绑定当前 task。server
只监听 `127.0.0.1:<port>`，且只在 exact
`/codex-capability-canary` path/Host/GET 上返回页面，不 redirect。它以 exclusive 方式
发布 fresh、当前用户私有的 0600 receipt；receipt 绑定 listener/URL、PID 与 process
start/executable/exact argv/cwd identity、canonical controller root/server script/HEAD、
Goal/role/task、15 分钟 TTL、随机 nonce、page/implementation SHA-256 和固定
title/button/status/screenshot contract。到期自动关闭。不得手写 receipt、跨 session
复用 receipt，或由聊天提供 raw URL。

launcher `READY` 后，上级从 absolute controller entrypoint 对 absolute frozen Goal
worktree 运行：

```text
<controller-root>/scripts/goal-control/canary-plan-launch.sh \
  [--node-executable <canonical-absolute-path>] \
  --repository-worktree <frozen-goal-worktree> \
  --manifest <repo-relative-json> --role <ROLE> [--task <id>] \
  [--browser-canary-receipt <canonical-absolute-0600-json>] \
  [--worker-bootstrap-receipt <canonical-absolute-0600-json> \
   --worker-bootstrap-receipt-sha256 <sha256> \
   --worker-bootstrap-operation-id <persisted-stable-id> \
   --worker-bootstrap-challenge <fresh-64-lowercase-hex> \
   --worker-bootstrap-identity-plan-sha256 <identity-plan-sha256> \
   --worker-thread <actual-thread-id> --worker-host <actual-host-id>] \
  --json
```

该 shell helper 使用同一 `sh -p` + fixed absolute tool/trusted Node bootstrap，再用
`/usr/bin/env -i` 启动初次 plan 生成，防止 Node 入口前继承
preload/inspect/credential 环境；禁止改回裸 `node ...goalctl.js canary-plan`。plan
内的 `replay.shell_command` 也绑定同一最小环境契约。
方括号中的 bootstrap 七项 binding 只由 manifest 已 opt-in 的 DEV/REVIEW/RECEIPT 在
`canary-bootstrap-prepare` seal receipt 后同时提供；其它 role/legacy route 七项全省略。
receipt path/SHA-256 来自 prepare 输出；operation/challenge 与
`identity_plan_sha256` 必须逐字复用 supervisor 在创建 worker 前已持久化的原始输入/plan，
不能由 worker 从 receipt 或聊天自选、重建，也不能缺少任一项。

CAPTAIN/DEV/REVIEW/RECEIPT 必须指定当前 task；FOREMAN 禁止指定 task。命令会在零
control-store 写入下验证 manifest、全部 packet/protocol/P1 authority 都是当前 HEAD
ordinary committed blobs，再由 role-scoped `resource_requirements` 计算 probe。只有
`BROWSER_PROFILE`/`WINDOW` 能推出 Browser：FOREMAN 是任一 task/worker 的 any-task
投影，worker 只看本 task/本 role，CAPTAIN 固定 `NOT_REQUIRED`；`PORT`/`EXECUTABLE`
或空 requirements 不推出 Browser。`REQUIRED` 时必须传上述 private receipt；
`NOT_REQUIRED` 时禁止传 receipt，传入会 fail-closed。输出把 canonical
`repository_worktree`/frozen Goal `repository_head` 与 canonical
`controller.root`/`controller.entrypoint`/controller
`repository_head`/decoder/module hashes 分开绑定，并把
receipt 证明的 exact target、nonce、page/implementation hash 与 contract 一并纳入 plan
hash；controller 会拒绝 dirty `scripts/goalctl.js`/`scripts/goal-control/**`，核 OS
唯一 listener owner、exact server argv/cwd 与实际打开的 receipt inode/parent identity，
并对 exact endpoint 做无 redirect raw page/header probe。不能用一个仓库的 HEAD 代替
另一个，也不能把任意 live PID 写进 receipt 充当 server。

#### Legacy full-plan canary（仅限已知 cwd / 无 opaque branch binding）

只有 actual cwd 在创建前已知，或 full plan 无需绑定 opaque worker branch 时，创建
task 才发送最小 `CANARY_ONLY` prompt，并逐字嵌入上一步输出的 `canary_plan` JSON 与
`canary_plan_sha256`：

```text
mode=CANARY_ONLY role=<ROLE>。不要运行 goalctl resume/event，不改业务源码，不打开业务
Preview，不登录或写环境，不读取 predecessor 长聊天。只在当前真实 session/host/worktree
把 canary_plan.replay.shell_command 作为一个完整 shell command 原样执行，不自行
quote、拼接或重组 controller/Goal worktree/manifest/role/task/browser-receipt 参数；
`node_executable` 与 `argv` 只供审计，不是要求 worker 手拼的步骤。核对 prompt 绑定的
exact canary_plan JSON 与 canary_plan_sha256；只执行 required_probes。
先重放 plan，随后严格按 `required_probes` 数组顺序执行；GitHub App 必须使用
`capability_targets.github_app.operation_contract` 的
`REPOSITORY_METADATA_READ`，并且永远是最后一项。commit/PR/file/issue read 不是
repository metadata read，不能替代。
browser.decision=REQUIRED 时只操作 browser.target：禁止 redirect，核 final URL 与
target.url 完全相同，核 nonce、title、initial status 和 exact button，点击后核
clicked status，并截图；Browser 操作后再次运行完全相同的 canary-plan，输出仍须逐字
匹配。NOT_REQUIRED 时禁止传 receipt，也严禁调用 Browser/Chrome。
执行后返回一条 CANARY_PASS 或
CANARY_FAIL(fingerprint, failed_capability, evidence_ref)，然后停止并等待激活消息。
canary_plan=<exact-json>
canary_plan_sha256=<sha256>
若本 Goal 有 committed pre-registration canary policy，初始 prompt 同时给出
canary_policy=<path>@sha256:<digest>；先核 exact bytes，再按 shared.md 的窄化规则使用，
不得从聊天摘要或其它 Goal 继承例外。
只有 policy 含 controller 识别的 exact
`GitHub-App-Known-Limitation: github_app_private_repo_404-v1` marker 时，plan 才会
列出 404 known limitation；该结果先为 PROVISIONAL，全部同-session 补偿 probe PASS
后才可最终聚合。
任何 Allow 对话框本身就是 FAIL；不要请求用户点击，不重试同一 fingerprint，不输出
token/cookie/capability bytes。
```

#### 动态 DEV/REVIEW/RECEIPT 的 worker bootstrap

本节只适用于 manifest 与 policy 已完成双重显式 opt-in 的 fresh Goal。manifest 必须
包含：

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

该 committed policy 在 frozen Goal HEAD 与 expected worker HEAD 上必须是相同 path/hash，
并包含下面这个 exact 独立行：

```text
Worker-Canary-Bootstrap-Protocol: goalctl-worker-canary-bootstrap-v1
```

缺 manifest 字段、protocol、policy hash 或 exact marker 均不是“自动兼容 legacy”，而是
bootstrap unsupported。dynamic worker 的初始 prompt 不能携带 full `canary_plan`，因为
此时 actual cwd/branch 尚不存在。CAPTAIN 必须先持久化一个 stable operation ID 和 fresh
64-lowercase-hex challenge，再从 frozen controller 对 frozen Goal worktree 零写生成
identity plan：

静态包通过 `goalctl scaffold` 生成时，必须把上述完整
`worker_canary_bootstrap` 放在 scaffold spec 顶层；生成器会用 manifest decoder 验证并
把它纳入 deterministic/idempotent output。禁止 scaffold 后手改 generated manifest
补 opt-in；那会使下一次 exact rerun 变成 `SCAFFOLD_CONFLICT`。

```text
<controller-root>/scripts/goal-control/canary-plan-launch.sh \
  [--node-executable <canonical-absolute-path>] canary-bootstrap-plan \
  --repository-worktree <frozen-goal-worktree> \
  --manifest <repo-relative-json> \
  --role <DEV|REVIEW|RECEIPT> --task <task-id> \
  --expected-head <40-sha> \
  --operation-id <persisted-stable-operation-id> \
  --challenge <fresh-64-lowercase-hex> \
  --canary-policy <repo-relative-committed-policy> \
  --canary-policy-sha256 <sha256> \
  --json
```

该命令把 controller closure、frozen repository/manifest、Goal/task/role、expected HEAD、
committed policy path+hash、operation/challenge 和 deterministic worker branch 绑定为
`identity_plan`。其中 `identity_binding_sha256` 是 identity core 的 hash；生成器把它
作为 `--expected-identity-binding-sha256` 烤进
`identity_capture.argv_template/shell_command_template`，然后才对最终完整 plan 计算
`identity_plan_sha256`。因此 template 不需要、也不得内嵌会造成循环的 outer plan hash。
然后以如下**初始且唯一**输入创建 dynamic worker：

```text
mode=IDENTITY_ONLY role=<DEV|REVIEW|RECEIPT>。本输入没有 role/capability/Goal/GitHub/
Browser/source/resource/environment 权限。只从当前 process cwd，把
identity_plan.identity_capture.shell_command_template 中仅有的
<platform-thread-id>/<platform-host-id> 替换为平台报告的本 session exact identity，
作为完整命令原样执行；不得重组其它 argv，不得运行 goalctl resume/event/canary-plan，
不得调用 gh/GitHub App/Browser/Chrome，不得写源码/index/ref或切换 branch。只返回 exact
identity_observation JSON 与 identity_observation_sha256，然后停止。
identity_plan=<exact-json>
identity_plan_sha256=<sha256>
```

`canary-bootstrap-inspect` 必须由 worker 从自己的 actual process cwd 运行。worker
只能在生成的 exact `identity_capture.shell_command_template` 中替换
`<platform-thread-id>/<platform-host-id>`，不得人工重建 argv。该 template 用同一组
manifest/role/task/expected-head/operation-id/challenge/policy 参数重算 plan core，并以
`--expected-identity-binding-sha256 <identity_plan.identity_binding_sha256>` 做非循环
绑定；outer `identity_plan_sha256` 用于核 initial prompt 和下游 prepare，不替换 template
中的 binding hash。inspect 只读验证专属 linked worktree、same common Git dir、exact
HEAD、clean、detached 或 exact deterministic branch，以及 hidden Git
operation/replace-ref/lock 边界；不写 Git、Goal store或外部系统。
这里“detached 或 exact deterministic branch”只描述只读 observation 与已有 durable
operation 的 exact retry。没有同 operation intent 的**首次** prepare 必须同时满足
detached HEAD 和 absent target ref；人工预先 attach 即使指向同一 OID，也不得回填
provenance。

CAPTAIN 收到 observation 后不得让 worker 自己 attach branch。它从 frozen Goal worktree
运行 controller adapter。第一次调用前必须把下面的完整 exact request 持久化：原始
operation/challenge/identity-plan SHA、expected observation SHA、actual
thread/host/worktree、manifest/policy/expected HEAD 与 exact Node executable。不能只记
operation ID：

```text
<controller-root>/scripts/goal-control/canary-plan-launch.sh \
  [--node-executable <same-canonical-absolute-path>] canary-bootstrap-prepare \
  --repository-worktree <frozen-goal-worktree> \
  --manifest <same-repo-relative-json> \
  --role <same-worker-role> --task <same-task-id> \
  --expected-head <same-40-sha> \
  --operation-id <same-stable-operation-id> \
  --challenge <same-64-lowercase-hex> \
  --canary-policy <same-committed-policy> \
  --canary-policy-sha256 <same-sha256> \
  --expected-identity-plan-sha256 <identity-plan-sha256> \
  --expected-observation-sha256 <identity-observation-sha256> \
  --worker-thread <actual-thread-id> --worker-host <actual-host-id> \
  --worker-worktree <actual-canonical-worktree> \
  --json
```

`prepare` 先在 source worktree 外、Git common-dir 下的 private artifact root seal
durable intent，再以 fenced loose-ref CAS transaction 创建 deterministic non-base
`codex/...` branch。Git ≥2.50 使用原生 `git-update-ref-symref-v1`，以
`update-ref` symref transaction 同时验证 target ref 与 detached HEAD old OID；Git
2.43–2.49 使用独立的 `git-files-backend-hardlink-head-v1`，仅允许 files ref backend、
同一 filesystem 与 POSIX hardlink/rename。fallback 把 protocol 和 HEAD/target/index/
packed-refs preimage 写入 durable claim，以 0600 HEAD fence 依次占有
packed-refs/ref/index/HEAD lock，锁内重验后 rename `HEAD.lock -> HEAD`，先 seal
protocol-bound completion 再逆序清锁。exact retry/receipt verifier 始终服从 claim 中的
protocol，不因中途 Git 升降级切 backend；reftable 或缺 completion 一律 fail-closed。
两条协议最终都把 linked worktree `HEAD` 绑定到 deterministic branch，并发布
0600 receipt。它必须证明 tree/index/status、remote、Goal store、角色/资源/
环境均未改变；异文 operation、occupied branch、foreign lock、HEAD/index/status race
全部 fail-closed。异常 Git child 若遗留无法证明归属的 lock，V1 也只 fail-closed，不猜测
删除。V1 覆盖 deterministic residue 与 ordinary race，但 Node/POSIX 没有
inode-conditional unlink；任意 hostile same-UID Git metadata pathname 替换不在本地
threat model内，若要覆盖必须使用 host broker/openat adapter。调用进程崩溃或完成状态
未知时，只允许用已持久化的相同完整 request exact retry，
不能换 observation、thread/host/worktree、challenge、branch 或候选 session；controller
已经返回的结构化 deterministic rejection 不是“响应丢失”，不得无修复循环重试。调用方
只使用输出的 `worker_bootstrap_receipt_file`、
`worker_bootstrap_receipt_sha256` 和 `worker_branch`，不得自行推导或手写 receipt path；
full canary 另须逐字复用 prepare 所绑定的原始 operation/challenge 与
`identity_plan_sha256`。

receipt sealed 后，CAPTAIN 才可按 manifest 启动所需 Browser canary server，并且必须从
worker 的 actual cwd 运行 full plan：

```text
<controller-root>/scripts/goal-control/canary-plan-launch.sh \
  [--node-executable <same-canonical-absolute-path>] \
  --repository-worktree <frozen-goal-worktree> \
  --manifest <same-repo-relative-json> \
  --role <same-worker-role> --task <same-task-id> \
  [--browser-canary-receipt <canonical-absolute-0600-json>] \
  --worker-bootstrap-receipt <canonical-absolute-0600-bootstrap-receipt> \
  --worker-bootstrap-receipt-sha256 <worker-bootstrap-receipt-sha256> \
  --worker-bootstrap-operation-id <same-persisted-stable-id> \
  --worker-bootstrap-challenge <same-fresh-64-lowercase-hex> \
  --worker-bootstrap-identity-plan-sha256 <same-identity-plan-sha256> \
  --worker-thread <actual-thread-id> --worker-host <actual-host-id> \
  --json
```

full plan 会重验 receipt 中完整 identity-plan preimage 对 supervisor plan SHA 的绑定，
并交叉核对 exact thread/host/cwd/gitdir/common-gitdir/HEAD/branch/challenge/policy 与
actual invocation cwd；同时只读复核 durable claim owner/operation hardlink、
claim-bound transaction protocol 与 fallback completion（适用时）、single-link loose
target ref、无 packed shadow/reflog/残留 fence、attached HEAD、
唯一 branch occupancy、worktree registry 以及无 foreign/stale Git lock。任一漂移都
fail-closed。CAPTAIN 给该 worker 的**第一条 follow-up**必须是：

```text
mode=CANARY_EXECUTE role=<DEV|REVIEW|RECEIPT>。bootstrap receipt 已由 controller
sealed；把 canary_plan.replay.shell_command 作为完整命令原样执行，逐字核
canary_plan/canary_plan_sha256，只执行 required_probes。除 plan 明列的 probe 外仍无
role/capability/Goal/source/resource/environment 权限。Browser REQUIRED 时只操作 exact
browser.target，NOT_REQUIRED 时严禁调用 Browser/Chrome。返回 CANARY_PASS 或带稳定
fingerprint/evidence 的 CANARY_FAIL，然后停止；任何 Allow 即 FAIL，不请求用户点击。
worker_bootstrap_receipt=<path>@sha256:<digest>
canary_plan=<exact-json>
canary_plan_sha256=<sha256>
```

`IDENTITY_ONLY` 初始输入与第一条 `CANARY_EXECUTE` follow-up 共同构成 dynamic worker 的
pre-registration 授权，中间不得插入聊天补路径、full plan、raw Git 命令或其它探针。
任一步失败都不登记、不发 capability、不 acquire lease；CAPTAIN seal 一次
`BLOCKED_TOOLING` durable incident/hold 后停止，不以新 session/operation/challenge 循环
重试。同请求调用崩溃/完成状态未知时的 exact retry 不算新尝试；已返回的 deterministic
failure 必须按原 fingerprint 停止。若修复要求变更已冻结
canary policy/protocol/manifest，禁止修改旧 Goal 的 frozen bytes，尤其不得编辑其
goal-specific `*.canary-policy.md`；新 policy 使用新 committed path/hash，随修复合并后
创建 fresh Goal。

上级用 `wait_threads` 取得结果。CANARY 尚未 PASS 时不登记该 identity，不发 capability，
不 acquire lease，也不提交 `LAUNCH_*`。

Browser `REQUIRED` 的 PASS/FAIL 收到后，上级必须通过同一 committed controller 的
stop helper 收口：

```text
<controller-root>/scripts/goal-control/browser-canary-launch.sh \
  [--node-executable <same-canonical-absolute-path>] stop \
  --receipt-file <canonical-private-dir>/<fresh-name>.json \
  --goal <goal-id> --role <ROLE> [--task <id>]
```

stop 会在发信号前重新验证 receipt 的实际 inode/parent、PID start/executable/exact
argv/cwd 与唯一 listener；任一漂移都 fail-closed，不得退化成 `kill <receipt.pid>`。
只有 stop 返回 `STOPPED`/`ALREADY_STOPPED` 且证明 listener 已消失才算收口。0600
receipt 作为 immutable 审计 artifact 保留，stop 输出其 path/hash；不要在运行链中 raw
`rm -f` 或删除 parent 来掩盖失败，也不要按聊天里的数字 PID 停进程。

这套证明的本地信任边界是“同一 OS 用户不恶意篡改 controller、receipt 或进程”。fd
identity、parent 重验、唯一 listener inventory 与 Browser 前后两次 plan 能拒绝陈旧、
误连和普通竞争，但不是同 UID hostile process 的持续 OS fence；攻击者仍可能在检查
间隙做 A→B→A pathname/进程/端口替换。若威胁模型包含恶意同 UID 进程，必须改用持有
socket/dirfd reservation 的 host broker/sandbox，不能把本 canary 描述成已消除该竞态。

### 阶段 B：`ACTIVE`

- FOREMAN / CAPTAIN：CANARY PASS 后由授权者完成 role registration，再发送包含
  goal/task、当前 role kernel/card、manifest/packet 指针、controller binary 与 frozen
  Goal worktree 指针的激活消息。角色收到后第一步才运行 `status/next/doctor`
  （FOREMAN）或 `resume/actions`（CAPTAIN）。
- DEV / REVIEW / RECEIPT：按 manifest 选择的 opt-in bootstrap 或合法 legacy canary
  PASS 后，由 CAPTAIN 从该 worker 的 actual process cwd 调用 `register-role`；opt-in
  route 必须把 prepare 输出的 receipt path/SHA 与创建前持久化的
  operation/challenge/identity-plan SHA 原样带入 registration。控制器把
  thread/host/canonical worktree/gitdir/common-gitdir/branch/initial HEAD seal 进
  session，兄弟/CAPTAIN checkout 即使 HEAD 相同也会在 capability/event 写入前拒绝。
  随后按 manifest acquire 当前角色资源，并以该 actual worker worktree 作为
  `launch-template`/preflight 的 `--repository-worktree`；launch 继承同一不可变
  bootstrap binding，最后提交对应 `LAUNCH_*`。全部接受后才发送正式角色启动词，worker
  收到后第一步才运行 `goalctl resume`。

激活消息只传 capability **文件路径**、launch/evidence/event ID 和短摘要，不传 raw
bytes。CANARY task 已结束不等于 thread 被 archive；只有协议终态满足时才归档。

## 3. 权限 canary 与 `goalctl preflight` 的边界

`goalctl preflight` 证明 launch 的 Goal/packet、repo/HEAD、registered session、
runtime、execution target 和 resource lease 绑定。它**不证明**：

- Codex child 继承了 parent 的 Full Access 或 approval profile；
- shell `gh` 能认证、Git transport 能 push；
- GitHub App connector 已安装，并能读取 canary-plan 指定的 canonical repository；
- Browser/Chrome adapter 能 open/read/click；
- 运行中不会弹 Allow。

这些仍须在每个实际 session 做外部 canary；结果不能伪装成 goalctl preflight
evidence。平台 permission envelope / inheritance 是 host integration 责任，portable
controller 只验证当前实际 session。

最小 probe：

- shell `gh`：`gh auth status -h github.com`，再对 canonical repo 查询
  `nameWithOwner/viewerPermission` 与 `.permissions`；
- Git remote：`git ls-remote origin HEAD`；DEV 还在自己的实际 branch 执行
  `git push --dry-run --no-verify origin HEAD:refs/heads/<actual-worker-branch>`。
  `--no-verify` 只避免尚无 Fast evidence 时把本地 pre-push gate 误当权限失败；dry-run
  不更新 remote，也不替代真实 push gate，但能在业务实现前暴露 credential/transport
  write 缺口；
- GitHub App：这是 `canary_plan.required_probes` 中的独立必做 probe；用 connector
  按 `operation_contract.semantic_operation=REPOSITORY_METADATA_READ` 读取
  `canary_plan.capability_targets.github_app.repository` 的仓库元数据。commit、PR、
  file、issue read 均为禁止的 substitute。登记前 scope 固定为
  `REPOSITORY_ONLY`、`pull_request=null`，不得把尚不存在的角色 PR 伪装成已验证；
  实际 PR 生成后仍在对应正常流程中另验。App 是 required probes 的最后一项；
  `gh` PASS 不能推出 App PASS，反之亦然。只有 hash-bound policy marker + exact
  `404/repo_not_found` 能进入 PROVISIONAL；同 session 的全部补偿项 PASS 后才最终记
  `KNOWN_CONNECTOR_LIMITATION`；
- 登记前 shell `gh` 也只探测上述 canonical repository；CAPTAIN/REVIEW/RECEIPT 不得
  猜一个尚未由 plan hash 绑定的 PR。实际 PR 出现后，再按角色职责对 exact PR/check/diff
  独立验证；
- Browser：仅在 `browser.decision=REQUIRED` 时操作 canary-plan `browser.target`
  绑定的 strict `127.0.0.1` exact path；不接受 redirect，核 final URL、nonce、title、
  initial status 和 button，点击后核 clicked status，并截图。
  `NOT_REQUIRED` 是 exact committed manifest 的机械结论，不是 policy 例外，严禁调用
  Browser/Chrome，也禁止向 canary-plan 传 Browser receipt。业务
  Preview/profile/window/login/environment 仍在 task launch+lease 后按 packet 验证；
- App 编排角色：FOREMAN/CAPTAIN 各自在自己的 session 实际闭合一次
  create/send/wait/archive canary；执行角色不得为 canary 创建 child。

只记录角色、session/host、工具身份、时间、PASS/FAIL、fingerprint 和 evidence ref。
不得把 token、cookie、Keychain 内容或 capability bytes 写进聊天、packet、launch 或
仓库。
v1 controller 机械生成并 hash operation/顺序/聚合合同，但尚未接收结构化 probe
observation receipt；上级必须复核实际 session 的 evidence，不能把自由文本
`CANARY_PASS` 宣称成 controller 已机械证明调用顺序。

## 4. 失败如何落状态

- supervisor/host 的 pre-init canary 失败：不运行 preclaim/init，保留只读诊断并停止。
- 尚未 registration 的 `CANARY_ONLY` session 失败：不登记、不发 capability、不消费
  lease；由上级记录 `BLOCKED_TOOLING` 摘要并停止该启动。
- dynamic worker 的 identity/prepare/execute 任一步失败：CAPTAIN seal 一次 durable
  `BLOCKED_TOOLING` incident/hold并停止，不以新session/operation/challenge循环；只有
  同一request响应丢失可exact retry。
- 已登记角色后来发现工具缺口：先 seal evidence，再提交
  `ADD_HOLD(kind=TOOLING)`。`BLOCKED_TOOLING` 是对外摘要类别，不是 event type。
- 只有已区分 Keychain/sandbox 可见性、网络、repo identity 和工具故障，并确证远端权限
  被拒时才用 `ADD_HOLD(kind=PERMISSION)`。沙箱内 `token invalid` 默认仍是
  `CREDENTIAL_VISIBILITY_UNKNOWN` / `TOOLING`。
- 同一 fingerprint 不循环 probe、不让用户连续点 Allow；修复后由控制面允许的
  hold-resolution 和 fresh canary 恢复。

## 5. 连续 task 循环

FOREMAN 每轮只做：

1. `status/next/doctor`；`pending_operations` 非空或 doctor 不 healthy 时先闭合原
   stable operation，不启动下一个 task。
2. 只取 `next.batch`。对后续 task，先用现任 FOREMAN capability 投影完全相同的
   thread/host/attempt/status，再两阶段创建并登记独立 CAPTAIN。
3. CAPTAIN 驾驶 P1 → DEV → fresh REVIEW → fresh RECEIPT，只向 FOREMAN发送
   `NEEDS_FOREMAN`、`READY_FOR_MERGE` 或 `TASK_INCIDENT`。
4. FOREMAN 用 `goalctl merge-pr` 串行 merge。CAPTAIN完成 exact-owner lease cleanup；
   FOREMAN确认 task/Goal-wide pending 为空、doctor healthy，登记 archive evidence并提交
   `ARCHIVED`。
5. 控制面显示 `phase=ARCHIVED` 后才归档该 task 的 CAPTAIN/worker。Goal 仍有 task 时，
   FOREMAN 保持 heartbeat，重新从第 1 步读取 `next.batch`；不等用户再说“继续”。
6. 全部 task `ARCHIVED` 后才归档 FOREMAN。

聊天不保存 worker 长对话或手写进度表。compact、异常和接力后，FOREMAN只重新读取
role kernel、本角色卡并运行 `status/next/doctor`；CAPTAIN/worker 运行
`resume/actions`。人读总表需要时运行 `goalctl rebuild-ledger`，但 ledger 仍是
append-only machine state 的投影，不可手改。
