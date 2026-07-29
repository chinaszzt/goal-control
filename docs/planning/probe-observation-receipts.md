# Sealed probe observation receipts

`probe_observation_receipts` 把 canary 的实际观察从聊天摘要移到结构化、可重放拒绝的
registration input。它是 manifest 冻结时的显式协议选择：

```json
{
  "probe_observation_receipts": {
    "protocol": "goalctl-sealed-probe-observation-v1",
    "max_ttl_ms": 900000,
    "host_attestation": {
      "algorithm": "ED25519",
      "key_id": "host-observation-v1",
      "public_key_sha256": "sha256:<64 lowercase hex>",
      "public_key_spki_base64": "<canonical Ed25519 SPKI DER>"
    }
  }
}
```

旧 Goal 没有这个冻结字段时继续使用旧协议；字段一旦存在，所有角色 registration 都
必须携带完整 observation 参数组，不能通过省略参数回退。scaffold spec 会原样携带并
用 manifest decoder 验证这个字段，禁止 init 后修改 frozen manifest 来切换协议。

## Host adapter 与 core 的边界

host adapter 必须先把 canonical plan replay 作为显式 `sequence=0` PASS 结果，
然后才按 `canary_plan.required_probes` 的数组顺序执行真实探针。adapter
负责 GitHub CLI、Git transport、GitHub App、Browser 和 task broker 的真实操作，
并把脱敏 evidence hash/reference 写入 receipt。core 不执行、补写或推断探针结果；
它只做以下机械验证：

- 重新运行真实 `canary-plan`，逐字节比较 mechanically generated canonical plan，
  而不是信任 caller 自报的 repository/controller/probe claims；
- registration stable ID、controller durable issuer 预先创建并绑定 plan/event/identity
  的一次性 challenge、thread、host、attempt 和 live target identity；
- 显式 replay result 必须最先 PASS；缺失、失败、重复或乱序一律拒绝；
- probe 不缺失、不重复、不乱序，adapter 类型与 probe 匹配；
- disposition 只来自
  `PASS | PROVISIONAL_KNOWN_LIMITATION | KNOWN_LIMITATION | FAIL`，并由 core
  重新聚合；
- 只有 committed canary policy 的 exact private-repository 404 claim，且所有
  同-session compensation probes 为 PASS，才能从 provisional finalize 为
  `KNOWN_LIMITATION`；401/403/prompt/wrong target 等不得补偿；
- `observed_at`、`expires_at`、TTL 和 manifest 的最大 TTL；
- receipt/plan 是当前 uid 持有、单硬链接、exact `0600` 的 ordinary file，父目录
  exact `0700`，使用 no-follow、有界 descriptor read，并在读取前后核对 inode、
  完整 mode bits、owner、type、link count、size、mtime/ctime，并在打开前后重验所有
  ancestor identity；任何 intermediate symlink、special bit 或 parent swap 都拒绝；
- receipt content hash、self-binding hash、evidence reference hash 和所有 target
  binding。

每个 `evidence_refs[].id` 只允许
`controller-evidence-v1-<64 lowercase hex>`。core 用 controller-issued challenge
重算该引用，hash 输入包含 stable event、canonical plan、Goal/task/role、
thread/host/attempt、target identity/fingerprint、probe 顺序、result fingerprint、
limitation/interactive disposition、evidence index 和 evidence digest；因此 adapter
不能选择 opaque ID，也不能把另一 challenge、session、target 或 probe 的引用重放过来。
receipt 的每个可变字符串叶还会机械拒绝 capability 形状、GitHub token 形状、
Authorization payload 和 credential URL，作为封闭引用格式之外的纵深防线；错误输出
只报告通用拒绝代码，不回显命中的原文。

manifest 冻结可信 host integration 的 Ed25519 公钥、key ID 和指纹；私钥生命周期完全
位于 controller/role 同 UID control-root 之外的 host signer，不写入 challenge、
control store、仓库或 CLI 参数。可信 host adapter 对 challenge、exact plan、producer
identity、replay、ordered results/evidence、TTL 和 target binding 的 canonical bytes
签名；core 只用冻结公钥在接受时和每个 live gate 重新验签。普通 role 即使知道
control-root、event ID 和全部公开 receipt bytes，也无法发现/读取私钥或重算可接受签名。
把 synthetic receipt namespace 改成 `HOST_ADAPTER`、重算 self-hash 或用同 UID 自建 key
重签都不能通过。private key、capability、token 和其它认证原文从不进入
event、projection、日志或命令输出；公钥轮换必须通过 fresh committed manifest/Goal。

receipt 禁止 token、cookie、credential URL、Authorization 或 capability 原文。
known limitation 只接受 `id` 和封闭的 exact 404 match 六字段；额外、嵌套或未知字段
（包括未标注的 capability bytes）在 schema/runtime 两层均 fail closed。
任何 Allow/auth prompt 都重新聚合为 `FAIL` 并返回
`INTERACTIVE_APPROVAL_REQUIRED`，不会挂起、唤醒 worker 或请求用户点击。

## Gate 与 replay

只有 aggregate `PASS` 或 policy-finalized `KNOWN_LIMITATION` 才能落盘
`REGISTER_ROLE`。先由 host/platform signer 在 controller 之外观测 actual
thread/host/session/launch/HEAD，生成 private `0600` 的
`GOALCTL_HOST_ROLE_IDENTITY_OBSERVATION_V1` 并用 manifest 冻结的 Ed25519 authority
签名。随后用 `prepare-probe-observation-challenge` 提交 observation 的 absolute path
和 content SHA。这个命令不接受 thread/host/attempt argv：它在同一个 locked upstream
canary acceptance transaction 中先验证 pre-existing observation，再从当前 durable
controller state 派生 attempt、revision、epoch、packet、task cycle 和 HEAD，最后原子发布
sanitized `ROLE_IDENTITY_INTENT` 与 controller-held challenge。

host signer 的 exact producer protocol（Node 22）如下。先把除
`attestation.signature_base64url`、`record_sha256` 外的 observation 写入
`$OBSERVATION_INPUT`，把 Ed25519 PKCS#8 PEM private key 放在 controller control-root
之外的 `$HOST_PRIVATE_KEY`；命令会以 `0600` 原子目标文件 `$OBSERVATION_OUTPUT`
产生 exact bytes，并打印 CLI 所需 content SHA：

```bash
node --input-type=module <<'NODE'
import crypto from "node:crypto";
import fs from "node:fs";

for (const name of [
  "OBSERVATION_INPUT", "OBSERVATION_OUTPUT", "HOST_PRIVATE_KEY",
]) {
  if (!process.env[name]) throw new Error(`missing ${name}`);
}
const canonicalValue = (v) => Array.isArray(v)
  ? v.map(canonicalValue)
  : v && typeof v === "object"
    ? Object.fromEntries(Object.keys(v).sort()
      .map((k) => [k, canonicalValue(v[k])]))
    : v;
const canonical = (v) => JSON.stringify(canonicalValue(v));
const signedPayload = JSON.parse(
  fs.readFileSync(process.env.OBSERVATION_INPUT, "utf8"),
);
const hostPrivateKey = crypto.createPrivateKey(
  fs.readFileSync(process.env.HOST_PRIVATE_KEY),
);
const signature_base64url = crypto.sign(
  null, Buffer.from(canonical(signedPayload)), hostPrivateKey
).toString("base64url");
const sealed = {
  ...signedPayload,
  attestation: { ...signedPayload.attestation, signature_base64url }
};
const record = {
  ...sealed,
  record_sha256: `sha256:${crypto.createHash("sha256")
    .update(canonical(sealed)).digest("hex")}`
};
const fileBytes = Buffer.from(`${JSON.stringify(record, null, 2)}\n`);
const identity_receipt_sha256 = `sha256:${crypto.createHash("sha256")
  .update(fileBytes).digest("hex")}`;
fs.writeFileSync(
  process.env.OBSERVATION_OUTPUT,
  fileBytes,
  { mode: 0o600, flag: "wx" },
);
process.stdout.write(`${identity_receipt_sha256}\n`);
NODE
```

`observed_at/expires_at` 必须是实际日历有效且可 round-trip 的
`YYYY-MM-DDTHH:mm:ss.sssZ`。actual thread/host/session platform ID 只允许
canonical UUID（包括 UUIDv7）；goal/task/operation/launch/key ID 使用各自 bounded
controller opaque grammar。冒号、`local`/role alias、capability 长度和
credential/token/key 形状全部拒绝且不回显。
receipt 必须位于 owner `0700` parent 下的 `0600`、single-link ordinary file；
controller 以 `O_NOFOLLOW` descriptor 做 lstat/open/fstat、ancestor 和 after-read
identity 检查，并用同一组 bytes 做 content hash、JSON parse 和验签。

worker producer 同时提交 exact bootstrap receipt/hash/operation/challenge/plan 和 actual
worker worktree。`launch_id` 必须等于 bootstrap operation ID；transaction 在发布前重验
controller task/role、thread/host、worktree/git identity、HEAD 和 bootstrap seal。control
role 的 launch/bootstrap 两字段必须都是 `null`。

发布物是单一 canonical `ROLE_IDENTITY_CHALLENGE_BUNDLE`，不是先写 intent、再写
challenge 的 split pair。generation、atomic reservation、temporary publication、
canonical rename 和 generation completion 任一边界崩溃后，只有逐字相同 original
request 能收敛到同一 bundle。每个
goal/task/role/controller-attempt/lifecycle/launch semantic slot 只有一个 original
operation；不同 operation 在 generation 前整树零写拒绝。

签名 observation 仍无权自报 attempt，也不能覆盖 active session。首次
FOREMAN 只能由未消费 bootstrap 签发，CAPTAIN/worker 只能由当前 controller authorizer
签发，Goal-wide later-task FOREMAN 必须复用 exact current Goal identity，terminal、
`ROLE_LOST` recovery 和 `REVIEW_REWORK` successor 的 higher attempt 只由 controller
lineage 推导。claim-only、伪造、过期、cross Goal/task/role/HEAD、synthetic alias 或含
credential-shaped leaf 的 observation 在 generation 前拒绝；不会出现 public pending
intent。public `status`/`actions` 只读投影已经验签且仍绑定 current state 的 intent，
重复读取不写 generation/tree；credentialless consumer 和 `REGISTER_ROLE` 都没有另一个
seal/project mutation prerequisite。后续 registration 只能精确消费 intent 的 actual
identity/attempt/session/launch，不能由 caller 改写。

accepted event 指向 controller 私有目录中 exact `0600` 的 plan/receipt 副本，并保存
ordered results seal、identity、challenge、stable ID、time 和 hash；caller 文件之后
移动或消失也不影响审计。launch、verdict、preflight/Fast/Full/AC mechanical
boundaries 会从 controller-held bytes 重新核对 seal 和 live TTL。TTL 用同一锁内将要
写入事件的 `accepted_at` 判断，避免检查与 durable acceptance 之间的 TOCTOU。
receipt 缺失、过期或 binding 非法时，registration、recovery activation、launch、
verdict 和 FULL scope 全部 fail closed。

registration event ID 决定 observation stable ID：

```text
canary-observation-<registration-event-id>
```

challenge response loss 只能使用相同 event ID、identity receipt path/hash、plan hash
和 issuer authority exact retry；registration response loss 只能使用相同 event ID、
receipt path/hash、plan path/hash、challenge 和 sealed identity exact retry。相同
stable ID 的任何异文请求冲突。
同一 receipt 不能改绑到另一 event、thread、host、attempt、Goal/task/role、旧 plan、
旧 challenge 或不同 target fingerprint。`recover-expired-foreman` 也是 activation
path，必须用 recovery root event ID 准备并提交 fresh FOREMAN observation；durable
intent 后的 response-loss exact retry 使用已封存 binding，异文冲突。

长生命周期 current CAPTAIN/worker 必须在旧 receipt 尚未过期时先用同一 refresh
event ID 准备 fresh challenge，再调用 `refresh-probe-observation`。该命令在同一
durable lock 内以 event `accepted_at` 重新验证旧 binding 仍 live、当前 HEAD 的
canonical plan、session role/thread/host/attempt、state revision 和 old binding hash，
并验证 fresh authenticated receipt 后原子替换 binding。旧 receipt 已过期、任一 CAS
漂移或 fresh bytes 变体都零 task-event 写入拒绝；响应丢失只允许原 event ID、原
request 与原 actor capability exact retry。它只续 probe observation，不延长 lease、
改变 role identity 或提供通用 session mutation。

## L1 fake adapters

`lab/fakes/probe-observation-adapters.js` 为 GitHub CLI、Git transport、GitHub App、
Browser、task broker（以及 controller CLI）提供 deterministic fake adapter。
它只在 `GOAL_CONTROL_TEST_MODE=1`、隔离临时 repository/control root 和
controller-issued `ISOLATED_TEST_FAKE` challenge namespace 同时成立时运行；
production challenge 固定绑定 `HOST_ADAPTER`，不能接受 fake namespace。L1 用它验证
receipt contract；它不声称证明真实账号、Browser 登录态、Codex 权限或外部副作用。
真实 L2 必须由 host adapter fresh 执行并留下自己的 sealed evidence。
