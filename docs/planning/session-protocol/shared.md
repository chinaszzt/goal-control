# Session 协议 · 共享核心

> DEV、REVIEW、RECEIPT 只读 `role-kernel.md`、本文件、自己的角色卡、当前不可变 task packet 和 launch 指针。不要读取其它角色卡，也不要继承 FOREMAN/CAPTAIN 历史聊天。控制面总契约见 [`../goal-control.md`](../goal-control.md)。

本文出现的 `goalctl <subcommand>` / `resourcectl <subcommand>` 只是逻辑动作名。实际执行
必须使用 [`../goal-control-quickstart.md`](../goal-control-quickstart.md#01-固定双根目录与-exact-argv-wrapper)
中的 exact `gc_goalctl <controlled-worktree> ...` /
`gc_resourcectl <controlled-worktree> ...` wrapper：固定 audited Node 与 clean committed
controller root，并显式绑定本次操作要求的 controlled worktree；禁止从 `PATH` 或受控仓
package scripts 启动 controller。

## 1. 权威与问题路由

语义冲突按以下顺序处理：

1. system/developer 指令、用户当轮明确指令；
2. manifest/packet 绑定的 committed host constitution/policy；
3. 已批准 Spec、Acceptance、Plan、Goal/issue 用户裁决；
4. 当前 immutable task packet；
5. 本共享协议与当前角色卡；
6. session 自己的偏好。

运行状态另有唯一真源：Goal manifest + packet SHA-256 + git common-dir 下的 control-plane runtime/event log。聊天标签、session 摘要、项目 memory 和本地 rollout JSONL 都不能迁移状态。

任何执行角色发现冲突都不得自行选边、改 Spec/Acceptance 或直接问用户。先核实一手事实并发结构化 blocker 事件给 CAPTAIN；CAPTAIN 只处理机械路由，需语义裁决时压成 `NEEDS_FOREMAN`。只有 FOREMAN 可以整理事实、选项和建议后询问用户。

DEV 自审与项目生命周期由 committed host policy 定义。本文 REVIEW/RECEIPT 是由
CAPTAIN 启动的独立外部交付门，不替代 host policy 要求的 DEV 自审。

## 2. 共同不变量

- 一 task 一个 CAPTAIN；普通代码返工可复用原 DEV；每轮 REVIEW 和每次 RECEIPT 都必须是新 attempt/fresh session；角色异常退出可由 successor 接管，但 partial verdict 不继承；
- worker 不改 Spec/Acceptance/task packet，不扩范围，不自 merge，不排 follow-up；
- 只实现 packet 范围，非目标和禁止触碰项不得顺手实现；
- task packet 是完整、不可变、带 revision/hash 的语义快照；thread、PR、HEAD、model、profile、lease 等动态字段只进 launch/runtime；
- PR base 是 `main`，每个 task 使用独立 branch/worktree；DAG 无依赖且冲突域不重叠的 task 可从同一冻结 base HEAD 并行，PR 仍按 integration order 串行 merge；
- DEV 可改 task worktree；REVIEW/RECEIPT 源码只读；FOREMAN/CAPTAIN 都不得代 DEV 改代码或代 REVIEW 产 finding；
- 长证据落 PR/check/artifact/docs；消息只传已接受的 event id、状态、链接和需裁决项；
- 任何 commit、full HEAD 或 packet hash 变化，旧 preflight、audit、REVIEW PASS、RECEIPT PASS 按控制面规则失效；
- 开始行动、context compact、`systemError`、handoff/successor 后先运行 `goalctl resume`，只做 `actions` 与 `maintenance_actions` 返回的动作；没有状态动作也要按返回值维护 heartbeat；
- 并行中发现写集、生成物、账号、外部 session、profile、端口或窗口冲突时，只冻结冲突域并提交 blocker/lease 事件，禁止两个 session 私自解决同一共享面。

### GitHub CLI / Keychain 门禁

Codex 沙箱可能看不到 host credential store：同一份有效登录在受限上下文执行
`gh auth status` 可能显示 `token invalid`，在已授权上下文才可读取私仓。

- 所有认证 `gh` 命令必须在可读取系统 credential store 的授权上下文执行；
- 沙箱内 `token invalid` 只表示 `CREDENTIAL_VISIBILITY_UNKNOWN`，不得据此要求用户重登或判定阻塞；
- 先运行 `gh auth status -h github.com`，再用目标私仓真实只读命令验证权限；
- 区分 Keychain/认证、仓库权限、repo 标识、网络和工具故障；只有确证权限问题才报 PERMISSION；
- GitHub App connector、浏览器登录态和 `gh` Keychain 是三套独立凭证；
- 禁止输出 `gh auth token`，或把 token 明文写进 prompt、事件、runtime、环境变量或日志；
- 所有 PR 操作显式带 canonical `--repo <owner/repo>`，写入/merge 前校验 expected base/head。
- manifest 冻结 `repository.merge_policy=goalctl-github-squash-v1` 时，merge 只能由
  FOREMAN 调用 `goalctl merge-pr`；该命令用 durable intent/receipt 包住固定
  squash + expected-head match，并以同一 stable event ID exact retry。任何角色都不得
  直接调用 `gh pr merge`、手写 raw `MERGED`，或使用 `--admin/--auto/--delete-branch`。
  GitHub merge API 只提供 head CAS，没有 exact base CAS；wrapper 会在 dispatch 前最后
  重读 `ls-remote` 与 PR，并在 merge 后验证唯一 parent，但两次观察之间的 base race
  不能宣称原子消除，命中时 fail-closed 并保留证据。

### Session 权限 canary

Codex App 当前的 `create_thread` 接口没有可审计的 permission/approval-profile/inherit
参数；父 task 有 full access 不能证明 child 已继承。仓内协议只能在每个实际 session
做 fail-fast canary，不能宣称已经修复平台继承。平台 permission envelope /
inheritance 仍是 host integration 责任，portable controller 只验证当前实际 session。

启动分两类：

1. legacy `CANARY_ONLY -> ACTIVE` 只用于创建前已知 actual cwd，或 full plan 确实无需
   绑定 opaque worker branch 的 session；FOREMAN/CAPTAIN 通常满足，但不能只凭 role
   名推断。对 DEV/REVIEW/RECEIPT，这条 legacy route 还要求 manifest 未启用 worker
   bootstrap。初始 prompt 绑定 full canary plan，只运行本角色无业务副作用的外部
   capability canary；
2. manifest 显式 opt in 后，DEV/REVIEW/RECEIPT 必须使用
   `IDENTITY_ONLY -> PREPARE_ACTUAL_WORKTREE -> CANARY_EXECUTE -> ACTIVE`。初始
   `IDENTITY_ONLY` 只允许从 actual process cwd 运行 controller 生成的
   `canary-bootstrap-inspect` template，回报 hash-bound identity observation；CAPTAIN
   再用 `canary-bootstrap-prepare` 对该 actual linked worktree 做 CAS branch attach并
   seal private receipt；第一条 follow-up 才携带 receipt-bound full canary plan并进入
   `CANARY_EXECUTE`；
3. PASS 后 FOREMAN/CAPTAIN 先完成 registration 再发 `ACTIVE`；worker 先完成
   registration、resource acquire、launch、`goalctl preflight` 和 `LAUNCH_*`，再发
   `ACTIVE`。角色收到 `ACTIVE` 后才运行 `resume/actions` 并开始职责。

worker bootstrap 的 opt-in 不是 prose 推断。fresh Goal manifest 必须显式包含
`worker_canary_bootstrap.protocol=goalctl-worker-canary-bootstrap-v1`，以及 committed
policy 的 repo-relative path 和 SHA-256；policy bytes 必须包含这个完全相同的独立行：

```text
Worker-Canary-Bootstrap-Protocol: goalctl-worker-canary-bootstrap-v1
```

manifest 字段或 exact marker 缺失时，bootstrap 子命令和 receipt-bound full plan 都会
fail-closed。旧 manifest 未 opt in 只表示 bootstrap unsupported；若 session 的 actual
cwd 不可预知且 full plan 需要 opaque branch binding，不得借此退化到 legacy，必须使用
支持该 opt-in 的 fresh Goal。

动态 worker 的两条 pre-registration 输入共同构成授权：创建时的 exact
`identity_plan + identity_plan_sha256`，以及第一条 follow-up 的 exact
`worker bootstrap 七项 binding（receipt path/SHA、原始 operation/challenge/plan SHA、
actual thread/host）+ canary_plan + canary_plan_sha256`。中间禁止用聊天
补 actual cwd/branch、发送父/CAPTAIN cwd 生成的 full plan、让 worker raw
`git switch/checkout`，或插入其它 probe。`IDENTITY_ONLY` 与
`PREPARE_ACTUAL_WORKTREE` 均无 gh/GitHub App/Browser/Goal event/source/resource/
environment 权限；prepare 只允许 durable intent、fenced loose-ref CAS 创建
deterministic non-base branch；Git ≥2.50 使用原生 target-ref verify + detached-HEAD
old-OID symref transaction，Git 2.43–2.49 使用仅限 files backend/同 filesystem/POSIX
的 claim-bound hardlink-lock + HEAD rename + completion transaction。retry 不得按当前
Git 版本切 protocol。两者都产出 linked-worktree symbolic HEAD 与 0600 receipt，不得改变
tree/index/status/remote/Goal store；无法证明归属的 stale Git lock 一律 fail-closed，
不自动删除。没有同 operation durable intent 的首次 prepare 只接受 detached HEAD +
absent deterministic target ref；人工预 attach 不得回填 provenance。V1 不宣称隔离
hostile same-UID Git metadata pathname 替换；该边界需要 host broker/openat adapter。

创建 session 前，上级分别冻结 clean committed controller root 与 frozen Goal
worktree；两者可以位于不同 HEAD，不能靠 shell cwd 混用。若 committed manifest 对本
role/task 投影为 Browser `REQUIRED`，supervisor 必须从随后执行 `canary-plan` 的**同一
份 committed controller** 启动安全 launcher；dynamic worker 要等
`canary-bootstrap-prepare` PASS 后才允许启动，identity/prepare 阶段禁止 Browser：
`<controller-root>/scripts/goal-control/browser-canary-launch.sh
[--node-executable <canonical-absolute-path>] launch
--receipt-file <canonical-private-dir>/<fresh-name>.json --goal <goal-id>
--role <ROLE> [--task <id>]`。
`<canonical-private-dir>` 必须由 `pwd -P`/`realpath` 得到，归当前用户所有且 group/other
不可写、mode=0700；launcher 固定 detached `serve --port 0`，等待 fresh 0600 receipt
及 live identity PASS 后才输出 `READY`，无需 shell 后台 PID/sleep。shell launcher
以 `sh -p` 忽略 inherited startup/functions/options，只用 fixed absolute OS tools，
从固定 trusted Node candidate 列表选取并 realpath 绑定 executable，再用
`/usr/bin/env -i` 丢弃 parent token、`NODE_OPTIONS`、preload 与动态 loader 环境，只传
固定最小 allowlist；无 trusted Node 就 fail-closed，禁止退回直接
`node ...server.js launch`。
`actions/setup-node`、fnm、asdf 等非固定安装位置必须由上级把当前解释器的 canonical
realpath 作为 supervisor 已信任的 TCB，通过首个 argv-only `--node-executable`
传入；worker 禁止自选，也禁止从 inherited `PATH` 或环境变量发现。launcher 用固定
OS 工具独立拒绝控制字符并核 ordinary single-link/mode；自动发现的固定候选还必须
由当前 uid/root 持有。显式 override 的 owner/provenance 是 supervisor 外部批准的
TCB，不拿 job uid 反推，因此可兼容 `actions/setup-node` 由 runner service owner
持有的 toolcache。launcher 本身不认证调用者，worker 只能执行上级冻结的 exact argv，
不得自行换 path。随后在 `env -i` 下做 Node `>=22.19` 兼容性检查。同一 Browser
runtime 的 launch/stop 必须使用同一个 exact path。该兼容性检查不证明 executable
provenance；恶意 binary 或同 UID pathname replacement 仍在本地信任边界之外。
FOREMAN 禁止 `--task`，worker 必须绑定当前 task。server 只监听
`127.0.0.1:<port>`，且只接受 exact
`/codex-capability-canary` path/Host/GET，不 redirect；它 exclusive 发布 fresh、当前
用户私有的 0600 JSON receipt。receipt 绑定 listener/URL、PID/process
start/executable/exact argv/cwd identity、canonical controller root/server script/HEAD、
Goal/role/task、15 分钟 TTL、随机 nonce、page/implementation SHA-256 与固定
title/button/status/screenshot contract；到期自动关闭。不得手写、跨 session 复用
receipt 或从聊天接收 raw URL。

随后，上级运行
`<controller-root>/scripts/goal-control/canary-plan-launch.sh
[--node-executable <canonical-absolute-path>]
--repository-worktree <frozen-goal-worktree>
--manifest <repo-relative-json> --role <ROLE> [--task <id>]
[--browser-canary-receipt <canonical-absolute-0600-json>]
[--worker-bootstrap-receipt <canonical-absolute-0600-json>
 --worker-bootstrap-receipt-sha256 <sha256>
 --worker-bootstrap-operation-id <persisted-stable-id>
 --worker-bootstrap-challenge <fresh-64-lowercase-hex>
 --worker-bootstrap-identity-plan-sha256 <identity-plan-sha256>
 --worker-thread <actual-thread-id> --worker-host <actual-host-id>]
--json`。
该 shell helper 使用同一 `sh -p` + fixed absolute tool/trusted Node bootstrap，再用
`/usr/bin/env -i` 启动初次 plan 生成；禁止换回裸 `node ...goalctl.js canary-plan`，
plan 内的 replay 继续绑定同一最小环境契约。
bootstrap 七项 binding 只由 manifest 已 opt-in 的 DEV/REVIEW/RECEIPT 在 prepare
receipt sealed 后同时提供；其它 role/legacy route 七项全省略。receipt path/SHA 来自
prepare 输出；operation/challenge/identity-plan SHA 必须复用 supervisor 在 worker
创建前持久化的原始值，不能由 worker 从 receipt 或聊天自选/重建。
命令会验证 manifest、全部 packet/protocol/P1 authority 都是当前 HEAD 的 ordinary
committed blobs，并输出 `canary_plan` JSON 与其 canonical `canary_plan_sha256`。已知
cwd 角色的初始 `CANARY_ONLY` prompt、dynamic worker 的第一条 `CANARY_EXECUTE`
follow-up，必须分别逐字绑定这两个字段；plan 的 `replay.shell_command` 是已经逐参数
安全 quote 的唯一可执行命令，session 必须把它作为一个完整 shell command原样执行，
不得从聊天或 cwd自行重组参数；`replay.node_executable`/`argv` 只供审计。session先执行
replay并核 JSON/hash，再且只运行 `required_probes`。CAPTAIN/DEV/REVIEW/RECEIPT必须绑定
当前 task；FOREMAN不接受 task。
缺 task、未知 task、role/task 不匹配、dirty/uncommitted/symlink 输入都使计划生成或
复核 FAIL，禁止凭聊天补齐。plan 将 canonical `repository_worktree`/frozen Goal
`repository_head` 与 canonical `controller.root`/`controller.entrypoint`/controller
`repository_head`/decoder/module hashes 分开绑定；二者不能互相代替。Browser
`REQUIRED` 时必须提供上述 private receipt，plan 把 receipt 证明的进程、exact target、
nonce、page/implementation hash 与 contract 一并 hash；session 必须带同一 receipt
复核并只操作 `browser.target`。controller 必须是 clean committed
`scripts/goalctl.js`/`scripts/goal-control/**`，plan 会机械核 receipt TTL/binding、
实际打开的 receipt inode/parent、唯一 OS socket owner、PID/start/executable/exact
argv/cwd/canonical server script，并实抓 exact endpoint 的 200、no-redirect、security
headers 与 raw page hash；任一不符即 FAIL。Browser 操作完成后还要重跑同一 plan并逐字
匹配，缩小操作期间的意外漂移窗口。`NOT_REQUIRED` 时禁止传 receipt，传入会被拒绝。

Browser `REQUIRED` 的 PASS/FAIL 后，上级运行
`<controller-root>/scripts/goal-control/browser-canary-launch.sh
[--node-executable <same-canonical-absolute-path>] stop
--receipt-file <canonical-private-dir>/<fresh-name>.json
--goal <goal-id> --role <ROLE> [--task <id>]`。stop 在发 signal 前重验上述
进程/receipt/listener 身份；禁止按 receipt 数字 PID raw kill，也禁止用 `rm -f` 掩盖
cleanup 失败。stop 返回 `STOPPED`/`ALREADY_STOPPED` 且证明 listener 已消失后，0600
receipt 作为 immutable 审计 artifact 保留并记录 path/hash；运行链不删除其 parent。

本地信任边界明确排除恶意同 UID 进程：fd/parent identity、全局唯一 listener 与 Browser
前后复核能发现陈旧、误连和普通竞争，但不是跨检查窗口持续持有的 OS fence；同 UID
A→B→A pathname/process/port swap 仍需 host broker 持有 socket/dirfd reservation 或更强
sandbox。协议不得宣称这一竞态已被完全消除。

初始 prompt 可以额外携带一个**已提交的 pre-registration canary policy path+SHA-256**。
该 session 必须先读取并 hash exact bytes；缺失、dirty、未提交或不匹配即 FAIL。policy
只能把一个 exact repo/tool/error fingerprint 归类为已知 connector limitation，并要求
同 session 的补偿 probe 全部 PASS；它不能省略 probe、把父/兄弟 PASS 继承给当前
session，不能授予 packet/capability/lease/业务动作，也不能放宽本文件的 merge、安全、
环境和 Allow 红线。没有该精确 policy 时，任何 connector 例外都不存在。
这里的“可以额外携带/没有 policy”描述 legacy canary 的 connector 例外；manifest 已
opt-in 的 dynamic worker 必须携带下述 manifest-bound policy，不能省略。

controller 只识别下面这个独立、版本化的 exact marker；自然语言里描述“允许 404”、
旧 policy、拼写相近或未知版本都不授予例外：

```text
GitHub-App-Known-Limitation: github_app_private_repo_404-v1
```

`canary-plan` 必须把 policy path/hash、识别到的 marker、GitHub App 语义 operation 和
结果聚合规则写入 plan hash。没有该 marker 时
`canary_policy.known_limitations=[]`。重复/未知的
`GitHub-App-Known-Limitation:` marker fail-closed。

对于 manifest 已 opt-in 的 dynamic worker，policy 是 bootstrap binding 的必填输入，
必须同时在 frozen Goal HEAD 与 expected worker HEAD 上以相同 path/hash committed。
CAPTAIN 在创建 worker 前先持久化 stable operation ID 与 fresh 64-lowercase-hex
challenge，再运行 `canary-bootstrap-plan`。输出中的
`identity_binding_sha256` 只 hash identity core，并作为
`--expected-identity-binding-sha256` 内嵌到生成的
`identity_capture.shell_command_template`；最终 `identity_plan_sha256` 再覆盖 binding
与 template，所以两者不得互换。worker 只替换模板中平台报告的本 session thread/host
两个 placeholder 并从 actual cwd 原样执行，不能人工重建 inspect argv。CAPTAIN 把 exact
observation hash、actual thread/host/worktree 与 full `identity_plan_sha256` 交给
`canary-bootstrap-prepare`，随后从 actual worker cwd 运行 `canary-plan`，并同时追加
`--worker-bootstrap-receipt`、`--worker-bootstrap-receipt-sha256`、
`--worker-bootstrap-operation-id`、`--worker-bootstrap-challenge`、
`--worker-bootstrap-identity-plan-sha256`、
`--worker-thread`、`--worker-host`。full plan/receipt 任一 identity 漂移都拒绝。完整
可复制命令与提示词见
[`../goal-control-run-goal.md`](../goal-control-run-goal.md#动态-devreviewreceipt-的-worker-bootstrap)。

full canary PASS 后，opt-in DEV/REVIEW/RECEIPT 的 `register-role` 仍必须从同一 actual
worker process cwd 执行，并把 receipt path/SHA、原始 operation/challenge/identity-plan
SHA 五项逐字带入；thread/host 继续使用正常 registration 参数。registration 会把
canonical worktree/gitdir/common-gitdir/branch/initial HEAD 一并 seal 到 session。
`launch-template`、preflight、`LAUNCH_*`/verdict、`status/actions/resume/doctor` 都会重验
这条 binding；DEV 只允许在同一 worktree/branch 上推进 source HEAD。HEAD 相同不构成
checkout identity，CAPTAIN/兄弟/主 worktree 均不能代 worker 登记或生成 launch。

`goalctl preflight` 只证明 Goal/packet、repo/HEAD、session、runtime、execution target
和 lease 的绑定，**不证明** child 继承 Full Access/approval profile，也不证明
`gh`/Git push、GitHub App connector、Browser/Chrome adapter 可用或运行中不会弹 Allow。
这些能力必须由每个实际 session 另做 canary，不能把结果伪装成 preflight evidence。
任何 Allow 对话框本身就是 FAIL；同一 fingerprint 不反复重试、不让用户连续点 Allow，
也不复制 token/cookie/capability bytes。

最小角色矩阵：

| role | 必须实测 | 禁止为 canary 扩权 |
|---|---|---|
| FOREMAN | task create/send/wait/archive；`gh` canonical repository/merge-capable permission 查询；`git ls-remote origin HEAD`；goalctl；GitHub App repository metadata 独立只读 probe；仅当 canary-plan 对任一 task 的 worker-scoped `BROWSER_PROFILE`/`WINDOW` 投影为 `REQUIRED` 时，按 `browser.target` 做隔离 localhost Browser open/read/click/screenshot | 业务 Preview、登录态、源码写；`NOT_REQUIRED` 时调用 Browser/Chrome |
| CAPTAIN | task create/send/wait/archive；`gh` canonical repository permission 查询；`git ls-remote origin HEAD`；goalctl/resourcectl；GitHub App repository metadata 独立只读 probe | 猜测或探测未绑定 PR、push、merge、业务源码写 |
| DEV | git/worktree 临时写入并清理、`git ls-remote origin HEAD`、实际 branch push dry-run、`gh` canonical repository permission 查询；GitHub App repository metadata 独立只读 probe；仅当本 task 对 DEV 声明 `BROWSER_PROFILE`/`WINDOW` 时做隔离 localhost Browser probe | 真实 push/开 PR、create child、merge；`NOT_REQUIRED` 时调用 Browser/Chrome |
| REVIEW | `gh` canonical repository permission 查询；`git ls-remote origin HEAD`；GitHub App repository metadata 独立只读 probe；仅当本 task 对 REVIEW 声明 `BROWSER_PROFILE`/`WINDOW` 时做隔离 localhost Browser probe | 猜测或探测未绑定 PR、push、merge、create child；`NOT_REQUIRED` 时调用 Browser/Chrome |
| RECEIPT | `gh` canonical repository permission 查询；`git ls-remote origin HEAD`；GitHub App repository metadata 独立只读 probe；仅当本 task 对 RECEIPT 声明 `BROWSER_PROFILE`/`WINDOW` 时做隔离 localhost Browser probe | 猜测或探测未绑定 PR、push、merge、create child；`NOT_REQUIRED` 时调用 Browser/Chrome |

shell canary 不输出 secret：用 `gh auth status`、canonical `gh repo view`/
`gh api ...permissions`、`git ls-remote` 和隔离临时目录写入；DEV 还要在自己的真实
branch 执行
`git push --dry-run --no-verify origin HEAD:refs/heads/<actual-worker-branch>`；
`--no-verify` 仅避免尚无 Fast evidence 时把本地 pre-push gate 误当权限失败。GitHub
App connector 是与 `gh` 独立的凭证面，必须由 `required_probes` 明确列出并单独读取
`canary_plan.capability_targets.github_app.repository`。调用必须满足
`operation_contract.semantic_operation=REPOSITORY_METADATA_READ`，并只读 canonical
repository metadata；commit、PR、file、issue read 都是明确禁止的 substitute，不能用
它们的 404 触发 known limitation。角色登记前该目标固定为
`pre_registration_scope=REPOSITORY_ONLY` 且 `pull_request=null`，因为角色 PR 可能尚未
创建；不得伪造 PR 级证明。登记前 shell `gh` probe 同样只查这一个 canonical
repository，不能猜测未被 plan hash 绑定的 PR；角色实际 PR 一旦存在，仍须在对应正常
流程中另验。每个 session 必须先重放 plan，再严格按 `required_probes` 数组顺序执行；
Browser（若 REQUIRED）也排在 GitHub App 之前，GitHub App 永远是最后一项。只有当前
启动授权绑定的 committed canary policy 含上述 exact marker、operation/repo 精确匹配、
结果正好为 `404/repo_not_found`，且当前 session 的全部补偿 probe 都 PASS 时，该
404 才先记 `PROVISIONAL_KNOWN_LIMITATION`，最终聚合为
`KNOWN_CONNECTOR_LIMITATION` 并让整体 canary PASS；其它结果仍 FAIL。即使 policy
允许用 `gh` 执行角色范围内的 issue/PR/check/review 操作，manifest 绑定
`goalctl-github-squash-v1` 时也仍禁止 direct `gh pr merge`，merge 只走
`goalctl merge-pr`。GitHub App probe 是每个角色 `required_probes` 中的独立必做项，
不能因 `gh` PASS、Browser decision 或其它 probe 而省略。Browser 能力只对 plan hash
绑定的 `browser.target` 操作：不得跟随 redirect，final URL 必须与 target URL
完全相同；核对 nonce、title、initial status 与 exact button，点击后核对 clicked
status，并截图。不得借 canary 进入其它 localhost 页、业务 Preview、profile、登录态或
环境。
`BROWSER_PROFILE`/`WINDOW` 是 Browser probe 的唯一 manifest 触发源：FOREMAN 对全部
task 的 worker requirements 做 any-task 投影，DEV/REVIEW/RECEIPT 只看当前 task 与当前
role，CAPTAIN 固定不需要 Browser（resource schema 不含 CAPTAIN role）。省略 `roles`
按全部 worker 兼容；`PORT`/`EXECUTABLE`、其它 kind 或空 `resource_requirements` 都
得到 `browser.decision=NOT_REQUIRED`，此时严禁调用 Browser/Chrome。`NOT_REQUIRED`
时也禁止传 `--browser-canary-receipt`；它是对 exact committed bytes 的机械结论，不是
canary policy 例外，也不豁免 GitHub App 等其它 required probe。
每项只记录 PASS/FAIL、工具身份、时间和 receipt 链接，不把凭证或冗长输出写进聊天。
当前 v1 的 hash-bound plan 机械规定 operation、顺序和聚合条件，但自由文本
`CANARY_PASS` 尚不是结构化 observation receipt；不得宣称 controller 已从聊天机械验证
实际调用顺序。独立监督方仍需按 plan/evidence 复核，后续可再增加 observation
evaluator。

pre-init supervisor/host canary 失败时不运行 preclaim/init。未登记的 `CANARY_ONLY`
或 dynamic bootstrap session 失败时不登记、不发 capability、不消费 lease；dynamic
worker 由 CAPTAIN seal 一次 durable `BLOCKED_TOOLING` incident/hold 后停止，不为同一
fingerprint换 session/operation/challenge循环。只有 response 丢失时可对同一 request做
exact retry。修复若改变 frozen policy/protocol/manifest，旧 Goal继续冻结；合并后使用
fresh Goal。不得原地编辑旧 Goal 的 goal-specific `*.canary-policy.md`；新 policy
bytes 必须使用新 committed path/hash，并只由 fresh manifest 引用。
已登记角色后来失败时先 seal evidence，再提交 `ADD_HOLD(kind=TOOLING)`；
`BLOCKED_TOOLING` 不是 event type。只有排除 Keychain/sandbox 可见性、网络、repo identity
与工具故障并确认远端拒绝权限时，才提交 `ADD_HOLD(kind=PERMISSION)`；沙箱内
`token invalid` 默认仍是 `CREDENTIAL_VISIBILITY_UNKNOWN` / `TOOLING`。

## 3. Phase FSM、恢复和 holds

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
  -> RECEIPT_ACTIVE (fresh session)
       -> RECEIPT_FAIL -> RECEIPT_FAILED -> DEV_ACTIVE/REVIEW_ACTIVE -> fresh RECEIPT
       -> RECEIPT_PASS
  -> ACCEPTED_PENDING_MERGE (由 CAPTAIN 的 READY_FOR_MERGE 事件进入)
  -> MERGED_TO_MAIN
  -> ARCHIVED
```

`RECOVERY_REQUIRED` 表示当前预期角色失联、systemError、heartbeat/checkpoint/head 不一致；它不是 PASS，也不能靠普通“继续”消息解除。

`ARCHIVED` 是 task 的机械终态：必须先完成 merge、证据链、零非终态资源租约与 clean
worktree，并以同一快照确认 `status` 中 task/Goal-wide `pending_operations` 均为空、
`doctor` healthy。任何 durable pending operation 都先按原 stable ID/request/capability
exact retry，不能先归档。控制面接受 `ARCHIVED` event 后才能调用 App archive。终态后禁止 fresh
CAPTAIN/worker registration、资源获取和业务 phase 恢复；Goal 尚有其它 task 时，现有
FOREMAN 仅保留 Goal 级 control/heartbeat 权限。

GitHub merge 是不可逆外部边界。启用 `goalctl-github-squash-v1` 后，wrapper 必须先
seal intent，外部 merge 后再 seal receipt，最后才接受 `MERGED`。intent、invocation、
receipt 或 event 任一断点都属于 durable pending operation；只能以投影中的原
event ID/request/capability exact retry，普通 event、heartbeat、归档或下一个 task
不得越过。

DEV successor 的恢复 scope 正交于 phase：
`RECOVERY_BLOCKED -> PREFLIGHT_ONLY -> FULL`。`ROLE_RECOVERED` 后普通 actions 只有 cleanup；
dedicated export/import/bind adapter 不激活 DEV。`RECOVERY_HANDOFF_BOUND` 只开放预检面，
`RECOVERY_PROMOTED` 才开放完整 DEV 权限。

cleanup 仅限控制面列出的、不改源码/业务状态的可审计清理；snapshot seal/import 验证前
不能碰 predecessor worktree，真实外部 target 的清理由 host broker 执行。

hard holds 正交于 phase、保留原 phase 且 sticky：

- `BLOCKED_SECURITY`：租户/权限/PII/凭证/破坏性数据等安全红线；
- `BLOCKED_EXTERNAL_FACT`：host-declared contract、generated artifact、部署事实或 owner 口径冲突；
- `ENV_IDENTITY_INCIDENT`：repo/HEAD/executable/PID/profile/environment/account 身份不匹配。

CAPTAIN 和 worker 都不得解除、降级或越过 hard hold。只有 FOREMAN 带 resolution authority/evidence 的专用事件可解除；packet 语义变化时，legacy task 先发布新 revision，mechanical P1 v1 冻结 fresh Goal + fresh authority，旧证据全部失效。

控制面同时阻断 `preflight` 与 resource `acquire/renew/verify`；模型不得绕过控制面直接操作受影响环境。解除事件只引用 registry 中已 seal 的 resolution evidence ID。

普通阻塞类别保留 `TECH / CONTRACT / SPEC_CONFLICT / ENV / PERMISSION / TOOLING`，但不能拿普通类别包装上述红线。

## 4. Packet、SHA 与 AC 绑定

任务包每个 revision 都是完整文件。范围、方案、AC、seam、环境权限和准出语义任一变化都不能用聊天 addendum 延续旧 hash：legacy task 创建新 revision，mechanical P1 v1 冻结 fresh Goal + fresh authority。动态 launch/runtime 变化不升级 packet。

所有交审、审查、收货只针对 clean worktree 的完整 40 位 SHA，并满足：

```text
PR head == audit head == reviewed_head == verified_head
PR base == main
packet revision + sha256 全程一致
control epoch 与 state revision 未陈旧
```

任一值不等、只有短 SHA、工作树 dirty、PR base 非 `main`，结论无效且 fail-closed。

拆分 task 必须让 AC resolver 只审 packet 声明的责任：

- change plan 省略 `acceptance`：审核 `implements` 指向 Spec 的全部 active AC；
- 提供 `acceptance`：只审核列出的 AC；
- 空列表、未知/重复 AC、跨 Spec AC、AC 不属于 `implements` 均硬失败；
- packet 的责任枚举使用 `FULL / SEAM_PRODUCER / SEAM_CONSUMER / EVIDENCE_ONLY / NOT_APPLICABLE`，并填写 final closing task；
- auditor 只按当前责任 verdict，不能用后置 task 尚未完成制造当前 task 假失败。

`P1_READY` 绑定待批准 plan/context digest；`P1_APPROVED` 必须有用户批准证据；`P1_COMMITTED` 必须证明 commit 内容与批准 digest 一致。机械 P1 v1 不接受 `PACKET_UPDATED`；语义输入变化须冻结 fresh Goal，不能在旧审批链上原地换 packet。

CAPTAIN 在 `P1_ACTIVE/P1_READY/P1_APPROVED` 失联且 disposable worktree 消失时，FOREMAN
先完成正常 `ROLE_LOST -> fresh CAPTAIN -> ROLE_RECOVERED`，再提交
`P1_RESTARTED`。事件必须机械绑定 lost/successor identity、recovery event 和被放弃的
worktree/branch；接受后清空 READY/approval、递增 task cycle 并回到 `QUEUED`，由
successor 在 fresh linked worktree 重新 `START_P1`。同一 recovery lineage 只能重启一次，
旧 CAPTAIN 与旧批准均不得复用。机械 task 的 `CONTROL_RECONCILED` 同样回 `QUEUED`，
不得留下没有 START binding 的 `P1_ACTIVE`。

默认批准证据是 `P1_READY` 之后用户对精确 digest 的明确回复。若用户在 Goal 启动前已经
签发**有界委托批准**，packet 可以引用仓内已提交的 authorization artifact；artifact
必须绑定 Goal、task 白名单、冻结权威来源、允许的纯整理范围、禁止代裁的事项和原始用户
指令引用。FOREMAN 只能在 `P1_READY` 后核对 plan/context 与 packet/冻结来源语义完全
一致、开放问题为空时应用该委托，并把 authorization path+hash 和本次 digest 写进
`approval_ref`。任何新增产品选择、契约歧义、安全/权限变化或 scope/seam/AC 变化都超出
委托，必须重新问用户。委托不允许先 commit 后补事件，也不允许批准与授权时未知的语义。

机械 P1 commit 可以不 push；CAPTAIN 无 push 权限也不得把提交复制回默认 base。
控制器在接受 `P1_COMMITTED` 前，先把该单提交写入 0600 bundle 并 seal exact-request
intent，再把 commit CAS 发布到 `state.p1.commit_ref`，最后 append accepted event 和
completion receipt；任一崩溃点只允许原 event/request/capability exact retry。该
controller-owned ref 绑定 Goal/task/cycle，独立于 disposable CAPTAIN worktree/branch；
所有 frozen read 都会核对它仍精确指向 `state.p1.commit_sha`。sealed
intent/bundle/completion 和 ref 在 v1 中作为审计与 GC root 保留，至少到整个 Goal
全部 `ARCHIVED`；当前没有静默清理，禁止手删。创建 DEV 时必须让 Codex worktree 的
`startingState.branchName` 指向 `state.p1.commit_branch`，创建后先证明实际
`HEAD == state.full_head` 再登记/launch。
默认从 `origin/main` 创建、复用 CAPTAIN worktree、聊天转贴 patch 或让 DEV 手工
checkout 都不构成合法交接。

## 5. 环境身份与资源权限

portable protocol 默认不授权任何环境写或真实外部 target。允许的 environment、identity、
read/write mode、数据范围和可回收策略必须同时出现在 committed host policy 与当前 task
packet 中。当前 schema 的 `TESTING_WRITE` lane 使用 canonical environment id
`testing`，但这个名字本身不构成授权；host 未显式 opt in 时仍必须使用
`NONE`/`READ_ONLY`。

任何写动作前必须同时满足：

1. host policy 指定的只读 identity probe 确认 environment/domain/tenant/account；
2. launch runtime 的 repo、完整 HEAD、executable/PID/profile 与实际候选一致；
3. `resourcectl verify` 证明当前 task 持有 packet 声明的 environment/account/external-session/profile/port/UI-target lease。

任一身份不明立即提交 `ENV_IDENTITY_INCIDENT`，停止受影响资源。UI 自动化禁止按应用
显示名选窗口或杀进程，只认 launch runtime 中的精确目标。任何未被 host policy 与 packet
共同列出的外部 mutation 都禁止。若多个工具共享同一账号或外部 session，必须按 host
policy 的 broker/fencing 顺序获取、释放并复核身份，不能把 session 被抢占误判成业务 bug。

## 6. 事件与跨 session 送达

### 6.1 状态先落控制面

普通回复只留在当前 session，不会自动回传。执行角色必须：

1. 按 [`../goal-control.md`](../goal-control.md) 生成带 `event_id / actor role+thread / actor_sequence / expected_state_revision / control_epoch / packet revision+sha256 / full head` 的事件；
2. 调用 `goalctl event --goal <id> --file <event.json> --actor-capability-file <0600 file>`；
3. 只有事件被接受后，才通过 launch runtime 声明的 App/collaboration send 工具发送短 event id 唤醒 CAPTAIN或目标角色。

原始 `[DEV_READY]`、`[REVIEW_PASS]`、`[RECEIPT_PASS]` 等标签没有迁移权。重复 event id由控制面幂等；错误角色、陈旧 seq/CAS/epoch、packet/head 不符和非法迁移均拒绝且不改变状态。

没有 send 工具时可由 CAPTAIN 用 `wait_threads/read_thread` 按 cursor 拉取当前 session 的 event receipt；不得要求用户人肉搬运，也不得声称普通回复已经送达。

### 6.2 Blocker payload

普通 blocker 事件 payload 至少包含：

```yaml
category: TECH | CONTRACT | SPEC_CONFLICT | ENV | PERMISSION | TOOLING
blocking: true | false
facts: [已核实的一手事实]
options: [方案与代价]
recommendation: <角色建议>
decision_needed: <一句话>
evidence: [持久化链接]
```

hard hold 使用专用事件类型，不复用普通 `ROLE_BLOCKED`。CAPTAIN只把需要语义裁决的 blocker压成 `NEEDS_FOREMAN`，不转发 worker长对话。

## 7. 固定 Gate 顺序与准出

```text
packet/AC resolver lint
-> role registration 后、LAUNCH_* 前的 repo/runtime/environment identity preflight
-> DEV tests + clean + git diff --check + Fast + evidence schema
-> DEV_READY 前对候选 HEAD 复跑 preflight
-> CAPTAIN fixed Full CI + scoped AC audit adapters
-> REVIEW
-> fresh RECEIPT
-> merge precondition
```

首次 preflight 必须先于相应 `LAUNCH_*` 状态迁移；DEV 产生候选 commit/PR 后，必须在 `DEV_READY` 前对候选完整 HEAD 复跑。DEV 只负责 Fast、push 和开 PR，CAPTAIN 负责调用不可改命令的 Full CI/AC audit adapters；AC audit gate 在 shadow/enforce 下都不写 GitHub 评论，评论须走独立的外部幂等发布动作。

机械、语义、traceability、environment verdict 分开记录，全部绑定 packet SHA-256 + full HEAD。REVIEW 负责当前实现的可证伪 finding；RECEIPT 负责最终 AC/seam/证据链和高风险抽查，不应第一次发现廉价格式问题，也不重复充当完整 code review。

通用准出：

- 只改 packet 范围，方案和 seam 全部实现；
- 相关测试覆盖正常、边界及任务相关的错误/竞态；
- clean、`git diff --check`、Fast 和当前 HEAD Full gate 通过；
- UI task 满足 host policy/packet 声明的视觉与交互验收路径；
- scoped AC audit 与 evidence schema 对当前 packet/full SHA 通过；
- host policy 声明的语言、fixture、日志、代码生成与静态质量门禁全部满足；
- tenant、环境权限、外部资源与 resource lease 满足 host policy/packet；
- REVIEW 与 fresh RECEIPT 对同一 packet/head PASS；
- 无 hard hold、RECOVERY_REQUIRED、未答问题；follow-up 已交 FOREMAN triage。

## 8. 恢复、控制 epoch 与消息预算

CAPTAIN 用有界 `wait_threads`、显式 heartbeat/`ROLE_LOST` 和 `goalctl doctor` 判断 liveness。active 角色退出却没有合法终态事件时，先核对 checkpoint，再只唤醒原 session 一次；仍失败则 fresh successor。同一失败指纹连续两次升级 `BLOCKED_TOOLING`，不无限重试。

lost DEV 的 successor 不接管原 branch/worktree。`ROLE_RECOVERED` 后先是
`RECOVERY_BLOCKED`，普通 actions 只允许 cleanup：CAPTAIN 从 predecessor canonical dirty worktree
导出 sealed immutable snapshot；DEV 在不同 worktree、不同 branch、精确
`source_observed_head` 上的导入由 fixed controller adapter 使用 dormant DEV identity
完成。import 命令只 materialize snapshot sealed 的 exact paths/tree，拒绝任何额外
staged/unstaged/untracked 内容并写 sealed receipt，不自动 commit；controller 随后创建以
该 HEAD 为唯一 parent 的 checkpoint：dormant DEV 用原 capability 调用
`recovery-checkpoint-source`，adapter 从 sealed receipt 确定性派生 commit 并以 ref CAS
发布；空 snapshot 走同一路径。checkpoint destination 必须是 linked worktree；adapter
用 durable prepared/completed marker、token-bound `index.lock` 与专属 gitdir 临时去写
权限保护最终验证、ref CAS 与 completion 临界区，未完成 fence 投影为
`SOURCE_CHECKPOINT pending`，仅原请求可在 SIGKILL 后接管。completion 只证明历史发布；
精确重试仍核对 live branch，sealed base 可重发同一 checkpoint，第三方 HEAD 拒绝覆盖。
释放 fence 后不承诺跨命令持续排他；bind 使用返回的 `checkpoint_sha` 再验证
receipt/parent/tree/diff/checkpoint，整个过程不唤醒 DEV。
export 的 `--snapshot-id` 与 import 的 `--import-id` 必须在首次调用前持久化；它们就是
operation/receipt ID。v3 artifact seal exact request 与原 CAPTAIN/FOREMAN/DEV authority，
响应丢失后只允许同一请求、原 capability 的 exact retry；原 authority 可已 terminal，
source/broker 可已消失，import destination 可已 commit/promotion，但异文 ID/request
一律拒绝。完整 materialization 后、receipt 前只接受 exact staged tree/paths 且无
unstaged/untracked；partial 不 reset、不覆盖。v2 exact-tree artifact 仍可 import/verify，
但没有 v3 response-loss replay authority。
CAPTAIN 提交 `RECOVERY_HANDOFF_BOUND` 后只进入 `PREFLIGHT_ONLY`，允许范围仅为 fresh
resource acquire、launch-template、preflight/PREFLIGHT evidence 与 cleanup。

若 predecessor worktree 已消失，只能从原始 Codex rollout 的成功 patch event 恢复。
默认 strict 模式拒绝任何不能机械证明不改 source 的 shell/`write_stdin`/跨 session
send。事故降级只能由 active
CAPTAIN+FOREMAN 双 capability 接受 exact audit：每条 call/result 的 line/hash、lost
launch/thread/cwd/HEAD、完整 rollout/patch hash、untracked-empty 断言与 incident ref
都必须 seal；disposition 仅限 `READ_ONLY/IGNORED_PATH_ONLY/TEST_NO_UPDATE`。这是逐条
broker attestation，不是“相信聊天摘要”；target/mixed patch 缺成功事件没有降级通道。
只有 controller 明确建模的 `tool_search`、plan 更新和 terminal 只读读取可自动排除；
未知 function/custom/response tool call 一律 fail-closed。
promoted recovered predecessor 的注册 HEAD 与 sealed launch checkpoint 必须分别保留；
promotion launch hash 必须匹配 canonical launch，且 promotion 之前的 target patch 永不进入
snapshot。

fresh launch 声明完整 fresh leases 且确定性 preflight PASS 后，CAPTAIN 提交
`RECOVERY_PROMOTED`；只有 scope=`FULL` 才可激活/唤醒 successor 并允许源码、测试、
commit、push、`DEV_READY`。仓内控制面不能机械阻止 Browser/Chrome/MCP 的外部直接调用，
所以 FULL 前不得给 successor 外部资源 capability；真实 target 必须由 host broker fence
并签发能力。

Codex handoff 创建新 thread identity，绝不继承旧 registration/capability。若 dormant
successor 在 `RECOVERY_BLOCKED`、尚未 bind 时被替换，controller 保留最初 lost DEV 及其
canonical source 为不可变 `source_predecessor`，把每个中间 successor 追加到
`recovery_chain`，fence 旧 identity，并让 replacement 重做 identity-bound 未绑定步骤。
`RECOVERY_HANDOFF_BOUND` 后 identity 冻结；`PREFLIGHT_ONLY` 阶段再 handoff/thread
replacement 必须 fail-closed，不迁移 receipt/checkpoint/launch/lease/evidence，不允许
promote。该阶段 worktree HEAD 只能精确等于 import checkpoint；`actions/next` 不得提供
执行时必然被 `RECOVERY_IDENTITY_FROZEN` 拒绝的 `ROLE_LOST`。若当前 successor 永久
丢失，唯一出口是未 promotion、其名下零非终态 resource lease 时，由 active
CAPTAIN+FOREMAN 双 capability 接受 `RECOVERY_HANDOFF_ABANDONED`，保留旧 binding 全量
审计记录并退回 `RECOVERY_BLOCKED`；之后才登记 fresh attempt，且不得迁移旧 runtime、
launch、receipt、preflight 或 capability。

FOREMAN 与 CAPTAIN 同时过期时，过期 actor 都不能提交 heartbeat/`ROLE_LOST`。唯一 v1
根恢复是用独立 Goal recovery capability 和同一状态快照的完整 CAS 执行
`goalctl recover-expired-foreman`：调用前必须持久化稳定 root event ID，并以同一次
`status` 的 `foreman_recovery_scope.scope_sha256` 做 Goal-wide CAS。控制器发布 durable
intent，只为**非 `ARCHIVED` 且已有 current FOREMAN projection** 的 task 追加 recovery
event，再发布 commit；同一 Goal authority 的 coherent FOREMAN replicas 被整体
fence/adopt 为 successor FOREMAN，不依赖 predecessor CAPTAIN。若已无 current
projection，显式非归档 anchor 只能从当前最大 attempt 的 `ARCHIVED` lineage adoption
为一个新 projection。
中途崩溃时其它写入冻结，只能用同一 ID/request/capability 续跑。随后仍按
successor FOREMAN→successor CAPTAIN→由 machine recovery/backlog 选择的 worker
successor 逐层恢复：**已有 pending recovery 就复用；只有没有 pending recovery 才提交
`ROLE_LOST`**，再登记缺失 successor 并提交 `ROLE_RECOVERED`；任何旧 identity 都不得
复用。只有 DEV successor 进入 sealed source handoff，REVIEW/RECEIPT 按各自角色状态恢复。

若死锁发生前已有未闭合 recovery，控制面不得覆盖：FOREMAN pending 由根事件闭合，
CAPTAIN pending 留给 successor FOREMAN，worker pending 进入有序 backlog；backlog
清空前所有业务 transition 机械拒绝。

资源租约到期不自动释放所有权。v1 在 shadow/enforce 都不允许真正 `reap`；`ROLE_LOST` recovery 与 sealed `ROLE_FAILURE` 只是必要审计事实，不是旧进程/profile/账号已经隔离的机械证明。固定 broker adapter 落地前返回 `REAP_REQUIRES_BROKER`，TTL、普通 heartbeat、语义 evidence 或单独 capability 都不足以授权回收。

`recover-expired-foreman` 同样不转移资源或解除环境门禁。Preview/login/external-session/UI/环境写在
resource isolation、lease 和 launch identity 重新验证前继续 fail-closed。

旧 launch 仅在 `target=NONE/environment=none/write_mode=NONE`、sealed lease set 为空且
lost owner 没有非终态 lease 时，可由 active FOREMAN+CAPTAIN 双授权
`resourcectl reinitialize-zero-runtime` 得到 `no_op=true` 证明；该命令不写撤销事件，也
不回收资源。旧 launch 只要曾列过任何 lease（包括已过期或已 `RELEASED`）或存在真实
target，就必须交资源专用 host broker，继续 fail-closed。

兼容重放历史 `LEASE_SET_REVOKED` 时，控制面只承认它是一次未经 host fence 验证的旧
声明，并投影为非终态 `UNVERIFIED_REVOKE`。该资源继续隔离，`resourcectl doctor` 必须报
`RESOURCE_BROKER_REPAIR_REQUIRED`；TTL、角色恢复或重新 acquire 都不能解除。

用户新指令由 FOREMAN 提升 `control_epoch` 后再 reconcile；旧 epoch 异步事件一律拒绝。长 finding、日志和返工历史不能复制进 CAPTAIN/FOREMAN聊天。FOREMAN只接收 CAPTAIN 的 `NEEDS_FOREMAN / READY_FOR_MERGE / TASK_INCIDENT` 三类摘要。
