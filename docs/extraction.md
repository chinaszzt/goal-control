# Extraction provenance

首个独立快照来自一个私有 host project 中经过实际试跑的 control-plane 文件。迁移采用
文件白名单，不携带源仓身份或历史。

白名单：

- `scripts/goal-control/**`
- `scripts/goalctl.js`
- `scripts/resourcectl.js`

33 个 controller Jest suite 和匿名 example/lab 也随首轮迁移进入本仓，但它们经过了
公开仓脱敏和 host-neutral 改写，不属于 production source-equivalence inventory。

明确排除：

- `.git/goal-control/**`
- capability、lease、evidence、launch/preflight 的真实运行产物
- host 应用源码、业务 fixture、账号和环境配置
- 本机绝对路径与 Codex thread 数据
- 源仓 Git 历史

首轮生成流程：

```bash
pnpm provenance:create -- \
  --source-worktree /absolute/path/to/source-worktree

git add extraction/provenance.json
git commit -m "chore: attest extraction provenance"

pnpm verify:provenance
pnpm verify:source -- \
  --source-worktree /absolute/path/to/source-worktree
```

生成器与 source verifier 不信任 `git status`：它们从固定完整 commit 的 Git tree/blob
读取 inventory、mode 和 bytes，并额外核对 worktree、index stage/blob/mode 及
assume-unchanged/skip-worktree flag。缺少 provenance、dirty/隐藏 dirty、非普通文件或
非 canonical 路径都 fail closed。

`extraction/provenance.json` 是首轮抽取的**历史基线**，不是以后每个独立版本都必须继续
等同私有 source 的永久门禁。它不记录私有 source commit，也不绑定 PR 分支上的 commit
ID。`verify:provenance` 在当前历史中定位唯一一次新增该文件的 commit，并要求当前
manifest 与该 first-add blob 完全一致；production tree、mode、target hashes、decoder
和 controller closure 都从同一 first-add commit 读取。这样 normal merge、rebase 和
squash merge 改写分支 commit ID 后仍可验证，同时后续普通 commit 不能回写首轮声明。
后续独立 controller 演进通过正常测试、版本化 protocol rotation 和 release
provenance 验收，不改写这份历史基线。

验证必须在完整 Git 历史上运行；shallow clone 会直接 fail closed，不能把浅历史边界误认
为 first-add commit。CI 因而必须使用 `fetch-depth: 0`。provenance 工具只从固定可信路径
解析 Git，并清除调用方 Git 配置和 PATH 影响。

因此，生成 manifest 后必须把生成器、verifier、测试和 manifest 一起落进
`extraction/provenance.json` 的首次新增 commit；若在尚未发布的抽取分支上升级 schema，
应 amend 该 first-add commit，而不是再追加一个“修 manifest”的 commit。

首轮 7 个 production portable delta 是：独立 controller-to-controller rotation、
保持旧 host probe 兼容的 provider-name 泛化，以及 5 个公开 schema `$id`。它们必须逐
文件出现在固定 allowlist。`portable_delta_sha256` 只用于发现 manifest/审核后 bytes
漂移；它不是独立审批 authority，初始 delta 的授权来自 PR diff review。
