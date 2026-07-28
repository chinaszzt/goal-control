# Architecture

## 两个根目录

控制器运行时必须区分：

1. **controller root**：本仓 checkout，提供固定 decoder、CLI 和脚本。
2. **repository worktree**：被控制项目的已验证 Git worktree，提供 manifest、packet、
   已提交 protocol pack、host policy、项目锁文件和实际源码。

controller root 也有自己的 lockfile，用来固定 controller 的工具链依赖。两份 lockfile
职责不同，不能互相替代。CLI 必须由固定 controller root 和固定 Node 绝对路径启动，并
显式传入 `--repository-worktree`；不得从 `PATH` 或受控仓的 package scripts 解析 decoder。

live store 位于被控制项目的 Git common dir：

```text
<controlled-repo>/.git/goal-control/v1/
```

它不属于 controller 源码，也不得被复制、提交或打包进本仓。

## 首轮抽取为何保留原路径

`canary-controller-attestation.js` 会对 `scripts/goalctl.js` 与 `scripts/goal-control/**` 做闭包和 fingerprint 校验。迁移时同时改目录、模块系统或 public API，会把“机械抽取”和“行为重构”混在一次变更里，无法证明旧 ledger 可由同一语义 decoder 重放。

因此首轮采用 compatibility-first：

- production 文件以 Git tree/blob provenance 证明，只有独立轮换、host probe
  provider-name 泛化和公开 schema ID 属于显式 portable delta；
- 原 CommonJS require graph 不变；
- 原 CLI 入口不变；
- 原测试整体迁移；
- 独立 package、CI、lab 只包在外层。

## 后续模块边界

完成 snapshot parity 和真实仓 L2 验收后，再逐步形成：

```text
core
├── FSM / validation
├── append-only ledger / replay
├── actor leases / recovery
└── action projection

adapters
├── Git / worktree
├── GitHub
├── Codex task broker
├── browser / preview
└── host project gates

surfaces
├── goalctl
├── resourcectl
└── lab scenario runner
```

每次拆分只能迁移一条边界，并用旧/新 decoder 对同一 fixture ledger 做 state hash、allowed-actions hash 和 rejection-code 对比。

## 版本与 replay

一个 Goal 必须冻结：

- controller source commit；
- decoder fingerprint；
- store protocol/schema generation；
- repository worktree、branch 与 HEAD；
- protocol/packet/authorization bytes。

升级 controller 不是“换一个路径继续跑”。它必须通过明确的 protocol rotation/migration，验证旧新 decoder 的语义重放结果，再原子切换。

## 测试策略

- L0 不启动 GitHub、browser 或业务项目，专测确定性语义。
- L1 使用临时 Git 仓和匿名 fixture，覆盖真实文件系统、worktree、锁、崩溃边界与 exact retry。
- L2 才连接真实 Codex task、GitHub、browser/preview 和宿主 Quality Gate。

快速实验的结果可以证明控制器逻辑；不能单独证明宿主权限、浏览器登录态或业务验收可用。
