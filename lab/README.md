# Goal control lab

`fixture-repo` 是一个无业务依赖的三任务项目：

- TASK-A：写入一个 JSON 值；
- TASK-B：依赖 A，生成 checksum；
- TASK-C：依赖 B，验证 checksum 并形成交付结果。

`run-scenario.js` 每次：

1. 复制 fixture 到新的临时目录；
2. 初始化真实 Git 仓和 base commit；
3. 生成绑定该 commit 的 A → B → C scaffold spec；
4. 使用本仓 `goalctl` 执行 scaffold 和 init；
5. 读取 doctor/next，断言只有 TASK-A 可启动；
6. 删除临时仓和 control store。

当前场景只验证静态包生成、初始化、`doctor`、`next` 和初始 DAG eligibility。它不会
登记 FOREMAN/CAPTAIN/worker，不执行 TASK-A/B/C 的文件变更，不推进完整 phase，不创建
或检查 PR，也不执行 merge/archive。因此它不是连续全流程验收，不能替代真实 host 的
L2 fresh Goal。

运行：

```bash
pnpm test:lab
```

调试时保留临时目录：

```bash
GOAL_CONTROL_KEEP_LAB=1 pnpm test:lab
```

后续故障场景应作为独立 scenario 加入，而不是把大量条件塞进一个脚本。优先覆盖：

- 同时 lease 过期后的恢复；
- response loss 后 exact retry；
- decoder rotation/replay；
- worktree 被删除或同 HEAD 错 checkout；
- CAPTAIN detached branch bootstrap；
- gh/browser/preview 权限 canary；
- 每个 durable boundary 的 crash injection。
