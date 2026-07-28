# goal-control

`goal-control` 是一个面向多 session 软件交付的本地控制面。它用可重放、追加写的事件账本约束 FOREMAN、CAPTAIN、DEV、REVIEW、RECEIPT 的身份、租约、任务状态、资源和交付证据，并在身份或运行环境不确定时 fail closed。

这个仓库从业务项目中独立出来，目的是把控制器迭代从大型应用的构建和全量测试中解耦。控制器可以在匿名的三任务实验仓里做秒级/分钟级验证，最终版本再回到真实项目做集成验收。

## 当前状态

- 首个独立版本保留原来的 `scripts/goal-control/**` 布局和 CommonJS API。
- 该布局是 decoder fingerprint 和 canary attestation 的一部分；首轮抽取不移动模块，
  保留既有 FSM、ledger 与 replay 语义，仅包含
  [`docs/extraction.md`](docs/extraction.md) 列出的 7 个已审计 portable delta。
- 运行时状态仍写入“被控制仓库”的 Git common dir，不写入本仓。
- 本仓不包含任何真实 Goal ledger、capability、lease、evidence 或用户环境数据。

## 环境

- Node.js `>=22.19`
- pnpm `10.33.0`
- Git
- macOS 或 Linux；涉及 browser/preview/GitHub 的 L2 集成还需要相应外部工具和权限

安装依赖：

```bash
corepack enable
pnpm install
```

查看 CLI：

```bash
pnpm --silent goalctl --help
pnpm --silent resourcectl --help
```

从另一个仓库调用时，优先显式传入目标 worktree：

```bash
/absolute/path/to/audited-node \
  /absolute/path/to/clean-committed-goal-control/scripts/goalctl.js \
  status \
  --repository-worktree /absolute/path/to/controlled-repo \
  --goal example-goal \
  --json
```

不要把 controller checkout 和 controlled repository worktree 混为一个身份：

- controller checkout 提供固定 decoder、CLI、controller 自己的 `pnpm-lock.yaml` 和依赖；
- controlled repository 提供已提交的 manifest、packet、protocol pack、host policy、业务源码及它自己的 lockfile；
- 每次调用都使用固定的 controller root/Node 绝对路径，并显式传
  `--repository-worktree <controlled-worktree>`；禁止通过 `PATH` 或受控仓的
  `pnpm goalctl` 猜测 controller。

## 接入一个受控仓

在 `init` 前，受控仓必须提交并冻结：

1. 本 Goal 使用的 protocol pack；可以从本仓 `docs/planning/` 选择兼容版本，但复制后的
   文件属于受控仓，manifest 只引用受控仓内的 repo-relative path/hash；
2. host constitution/policy，声明项目生命周期、环境、外部资源、gate、日志和权限边界；
   portable protocol 本身不授予任何环境写、账号、浏览器、外部 session 或业务 API 权限；
3. Goal manifest、完整 task packets，以及这些文件引用的 authorization/plan/acceptance；
4. 受控仓自己的 lockfile 和 canonical base HEAD。

protocol 或 host policy 的字节变化必须通过新提交、新 hash 和控制面允许的升级路径进入，
不能引用 controller checkout 中的可变文档，也不能在 Goal 初始化后原地修改。

## 快速验证

```bash
# 秒级：FSM、租约边界、runtime rotation、事务覆盖
pnpm test:fast

# 相同 HEAD、错误 checkout 的 worker identity binding
pnpm test:binding

# 分钟级以内：初始化三任务 DAG，并验证首次 eligibility
pnpm test:lab

# 真实临时 Git/CAS 与 crash boundary
pnpm test:l1

# 完整兼容回归
pnpm test:full
```

`pnpm check` 先验证不可改写的 extraction baseline，再依次运行 fast、identity binding
和 lab，是日常改控制面的默认反馈环。baseline 只锚定首轮抽取 snapshot，不禁止后续
controller 独立演进。

## 测试分层

| 层级 | 内容 | 默认入口 |
|---|---|---|
| L0 | 纯状态机、schema、hash、租约与事务不变量 | `pnpm test:fast` |
| L1 | 真实临时 Git/worktree、CLI、崩溃恢复；lab 当前只覆盖 scaffold/init/doctor/next 与首个 task eligibility | `pnpm test:lab`、`pnpm test:l1` |
| L2 | 真实 Codex task、GitHub、browser、preview、业务仓 Quality Gate | 在集成仓运行 |

L0/L1 用于快速迭代，不替代 L2。当前 lab 不启动 worker、不推进完整 task 生命周期，也不
创建 PR、merge 或 archive。任何会影响 decoder、身份绑定或外部副作用的版本，都必须在
真实集成仓完成一次 fresh Goal 验收后才能视为可发布。

## 目录

```text
scripts/goal-control/   controller、FSM、ledger、resource 与 adapter 实现
scripts/goalctl.js      Goal CLI
scripts/resourcectl.js  Resource CLI
__tests__/              从生产控制面迁移的兼容回归
lab/fixture-repo/       无业务依赖的三任务实验仓模板
lab/run-scenario.js     临时建仓、scaffold、init、doctor/next 验证
docs/                   架构、抽取边界和后续模块化说明
```

## 安全边界

- 不伪造身份、时间、lease、capability 或外部工具结果。
- 不改写或删除已接受事件；恢复和协议升级必须保持可重放。
- 不复用旧 launch/PID/port 证明新的 runtime。
- 不把聊天消息当作 durable authority。
- 不把 test mode、fixture secret 或临时路径带入生产 store。
- GitHub/browser/preview 权限 canary 必须在派 worker 前执行；当前仓只提供控制器和测试，Codex 权限继承仍由宿主集成负责。

详见 [架构与迁移策略](docs/architecture.md) 和 [实验仓说明](lab/README.md)。
