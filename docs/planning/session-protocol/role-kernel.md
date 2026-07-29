# Session 角色内核

> 本文件故意保持短小。长协议可能被 context compact；运行角色必须在启动、compact、异常和接力后用 `goalctl resume` 重新生成当前 capsule，不能只依赖聊天记忆。

**启动模式不可被 compact 掉**：legacy `CANARY_ONLY` 只用于创建前已知 actual cwd，
或 full plan 确实不需要绑定 opaque worker branch 的 session；对
CAPTAIN 若 manifest 显式启用
`goalctl-captain-canary-bootstrap-v1`，也必须先走独立的
`IDENTITY_ONLY → PREPARE_ACTUAL_WORKTREE → CANARY_EXECUTE` route；旧 worker-v1
marker 不授权 CAPTAIN，registration 与 `START_P1` 都重新验证 sealed actual-worktree
identity。DEV/REVIEW/RECEIPT，legacy 还要求 manifest 未启用 worker bootstrap。manifest 以
`goalctl-worker-canary-bootstrap-v1` + committed policy exact marker 显式 opt in 后，
这些 worker 初始只能是 `IDENTITY_ONLY`，只读回报 actual
thread/host/cwd/git identity，待 controller `PREPARE_ACTUAL_WORKTREE` seal receipt 后，
第一条 follow-up 才可进入 `CANARY_EXECUTE`。两类 session 都须 canary PASS；此前禁止
`goalctl resume/event`、role/capability/lease/`LAUNCH_*` 和业务动作。dynamic worker
禁止接受父 cwd full plan、聊天补路径或自行 `git switch/checkout`。只有上级完成本角色卡
规定的 registration（worker还包括 lease/launch/preflight/`LAUNCH_*`）并明确发送
`mode=ACTIVE` 后，下面的运行规则才生效。任何 Allow 即 canary FAIL，不请求用户点击。
旧 manifest 未 opt in 只表示 bootstrap unsupported，不授权 opaque worker 走 legacy；
已冻结 Goal 的 manifest 和 goal-specific `*.canary-policy.md` 均不得原地修改。

1. 身份只认 launch runtime 中登记的 `role + thread_id`，不从标题或聊天推断。
2. 业务语义只认当前不可变 task packet；运行状态只认 Goal 控制面。
3. 普通消息和 `[TAG]` 不迁移状态；只有 `goalctl event` 接受的结构化事件有效。
4. `ACTIVE` 角色开始行动、context compact、`systemError` 或 successor 接管后，CAPTAIN/执行角色先运行 `goalctl resume`；Goal级 FOREMAN重新读取本内核并运行 `goalctl status/next/doctor`。
5. 只执行 `resume/actions` 返回的合法状态动作和 `maintenance_actions`；先区分 task `launch_scope` 与 session `operational_scope`。`pending_operations` 非空时两类动作都必须为空，只能按列出的 stable ID/request/capability exact retry；此时不得另发 HEARTBEAT，先闭合 pending operation，再重新读取 actions。其余情况下没有状态动作就停止推进，但 active/idle 角色仍须按返回值及时 HEARTBEAT。heartbeat 不授予源码、资源或环境权限。
6. 每个 verdict/事件绑定当前 packet SHA-256、完整 HEAD、state revision 和 control epoch。
7. 不替其它角色编辑、审查、验收、裁决或发事件。
8. hard hold 存在时只做允许的诊断、隔离、checkpoint、上报或已授权 remediation。
9. 用户新指令先由 FOREMAN 提升 control epoch；旧 epoch 消息不得继续推进。
10. 角色 capability 和 lease owner capability 只通过 0600 文件传递；raw 值不得进入聊天、argv、事件或证据。
11. 长日志、diff、finding 和证据落 PR/check/artifact/docs；即时消息只传 event id、状态和链接。
12. 事件被拒绝时保持原状态并停下，不用自然语言绕过控制面。
13. 当前角色的具体权限与禁区只认自己的角色卡。
14. 任何 `LAUNCH_*` 前先通过该 launch 的 preflight；DEV 候选 HEAD 在 `DEV_READY` 前复跑，Full CI/AC audit fixed adapters 只由 CAPTAIN 调用。
15. 过期 lease 不自动转手：v1 的 shadow/enforce 都要求 fail-closed；即使 `ROLE_LOST` 与 sealed `ROLE_FAILURE` 匹配，没有资源专用机械隔离 broker 仍返回 `REAP_REQUIRES_BROKER`。
16. FOREMAN/CAPTAIN 同时过期时，旧 actor 不得补事件；只允许完整 CAS 的 `recover-expired-foreman` 原子登记 F2，再按 F2→C2→machine-selected worker successor 逐层恢复。已有 pending recovery 就复用；只有没有 pending recovery 才提交 `ROLE_LOST`；只有 DEV successor 进入 sealed source handoff。
17. 根恢复只换控制身份，不转移资源；Preview/login/TIM/UI/环境写在 lease 与 launch identity 重新验证前继续 fail-closed。
18. `ROLE_RECOVERED(DEV)` 先进入 `RECOVERY_BLOCKED`，普通 actions 只允许不改源码/业务状态的可审计 cleanup；禁止在 predecessor worktree/branch 继续 dirty source，真实 target cleanup 交 host broker。
19. dirty source 只可由 CAPTAIN seal export；snapshot 必须绑定 exact paths/tree。fixed controller adapter 使用 dormant DEV identity，在不同 worktree/branch、精确 `source_observed_head` 上只 materialize sealed paths，拒绝任何额外 staged/unstaged/untracked 内容，写 receipt但不 commit；随后用同一 DEV capability 调用 `recovery-checkpoint-source`，从 sealed receipt 确定性创建 single-parent checkpoint（空 snapshot 走同一 allow-empty 路径），bind 使用返回的 SHA 复核 commit bytes/parent/tree/diff 后才产生 `RECOVERY_HANDOFF_BOUND` 并进入 `PREFLIGHT_ONLY`。
20. `PREFLIGHT_ONLY` 只允许 fresh acquire、launch-template、preflight/PREFLIGHT evidence、cleanup；fresh launch、完整 leases、确定性 preflight 后由 CAPTAIN 提交 `RECOVERY_PROMOTED`，scope=`FULL` 才允许激活 DEV。
21. repo 控制面不能阻止直接调用 Browser/Chrome/MCP；`FULL` 前不唤醒 successor、不交付外部资源 capability，真实 target 必须由 host broker fence/签发。
22. Codex handoff 会产生新 thread，不能复用已登记 successor/capability；未 bind 的 `RECOVERY_BLOCKED` replacement 保留原 lost `source_predecessor` 并追加 `recovery_chain`，重做 identity-bound 步骤。
23. `RECOVERY_HANDOFF_BOUND` 后 successor identity 冻结；`PREFLIGHT_ONLY` 直接 handoff/thread replacement 一律 fail-closed，不迁移 receipt/launch/lease/evidence，不 promote。唯一退出是未 promotion、successor 零非终态 lease 时，由 active CAPTAIN+FOREMAN 双 capability 显式 `RECOVERY_HANDOFF_ABANDONED` 回到 `RECOVERY_BLOCKED`，再登记 fresh attempt；旧 binding 全量留痕且不迁移。
24. `ARCHIVED` 前必须从同一快照确认 task/Goal-wide `pending_operations` 均为空且 `doctor` healthy；有 pending 就先 exact retry，控制面接受归档事件后才调用 App archive。
25. manifest 启用 `repository.merge_policy=goalctl-github-squash-v1` 时，只有 FOREMAN 可用 `goalctl merge-pr` 进入不可逆 merge；先 durable intent、后 durable receipt、再接受 `MERGED`。禁止直接 `gh pr merge` 或 raw `MERGED`；断点只按原 stable ID/request/capability exact retry。
26. `.generation.json` 为 odd 时只允许原 stable operation 精确恢复：优先认 durable **WITNESS**；只有 v3、exact key/authority 且 control payload 仍匹配 `pre_write_vector_sha256` 时，才按命令参考固定矩阵执行 `RESUME_AT_START` 或 `ABORT_THEN_FRESH`。v3 odd 的 `updated_at` 是不可变 `transaction_started_at`；pristine 只证明 control payload 未写、不证明外部无副作用。错误 key/vector/capability 必须零写保留 odd；v1/v2 禁止 pristine，任何版本都禁止手改/删除 generation。compact、异常或接力后，在 retry 前重读本条；只有机器 actions 明确给出原 operation exact retry 时才按链接直达
    [Generation odd 小节](../goal-control-quickstart.md#generation-odd先判-witness--pristine再按固定策略恢复)，不整份读取。

`goalctl resume` 的人读 capsule 应不超过 15 行，并至少显示：role、goal/task、state revision、control epoch、packet revision/hash、冻结 protocol path/hash、phase、holds、控制面 full HEAD、当前 worktree HEAD、leases、当前合法动作集、maintenance actions 和禁止动作。正常推进候选与 `ADD_HOLD` / `ROLE_LOST` 等事故动作可能并列；需要机械判断时使用 `resume --json`，并读取其中独立的 `launch_scope`、session `operational_scope` 与 `pending_operations`。
