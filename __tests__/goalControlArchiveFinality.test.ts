import { createRequire } from "module";
import path from "path";
import { fileURLToPath } from "url";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const nodeRequire = createRequire(import.meta.url);
const { applyEvent, initialTaskState } = nodeRequire(
  path.join(ROOT, "scripts", "goal-control", "fsm.js")
) as {
  applyEvent: (
    state: Record<string, any>,
    event: Record<string, any>,
    epoch: number
  ) => Record<string, any>;
  initialTaskState: (
    task: Record<string, unknown>,
    manifest: Record<string, unknown>
  ) => Record<string, any>;
};

const PACKET_HASH = `sha256:${"a".repeat(64)}`;
const HEAD = "b".repeat(40);
const ACCEPTED_AT = "2026-07-24T00:00:00.000Z";

function archivedState(): Record<string, any> {
  const state = initialTaskState(
    { id: "TASK-A", packet: { revision: 1, path: "packet.md", sha256: PACKET_HASH } },
    { base_head: HEAD }
  );
  state.phase = "ARCHIVED";
  state.state_revision = 10;
  state.sessions.FOREMAN = {
    role: "FOREMAN",
    thread_id: "foreman-1",
    host_id: "local",
    attempt: 1,
    status: "active",
    last_seen_at: ACCEPTED_AT,
    lease_until: "2026-07-24T04:00:00.000Z",
    launch_id: null,
  };
  state.sessions.CAPTAIN = {
    role: "CAPTAIN",
    thread_id: "captain-1",
    host_id: "local",
    attempt: 1,
    status: "terminal",
    lease_until: "2026-07-24T04:00:00.000Z",
    launch_id: null,
  };
  return state;
}

function event(
  type: string,
  role: "FOREMAN" | "CAPTAIN",
  payload: Record<string, unknown> = {}
): Record<string, unknown> {
  const state = archivedState();
  return {
    schema_version: 1,
    event_id: `${type.toLowerCase()}-after-archive`,
    goal_id: "demo",
    task_id: "TASK-A",
    type,
    actor: {
      role,
      thread_id: role === "FOREMAN" ? "foreman-1" : "captain-2",
      host_id: "local",
    },
    actor_sequence: 1,
    expected_state_revision: state.state_revision,
    control_epoch: state.control_epoch,
    packet: state.packet,
    base_head: state.base_head,
    full_head: state.full_head,
    payload,
    accepted_at: ACCEPTED_AT,
  };
}

function expectCode(callback: () => unknown, code: string): void {
  try {
    callback();
    throw new Error(`expected ${code}`);
  } catch (error: unknown) {
    expect((error as { code?: string }).code).toBe(code);
  }
}

describe("ARCHIVED task finality", () => {
  it.each(["REGISTER_ROLE", "RECOVER_EXPIRED_FOREMAN"] as const)(
    "rejects %s before its special recovery/registration branch can revive a role",
    (type) => {
      expectCode(() => applyEvent(archivedState(), event(type, "FOREMAN"), 0), "TASK_TERMINAL");
    }
  );

  it("allows only the already-registered FOREMAN heartbeat", () => {
    const next = applyEvent(
      archivedState(),
      event("HEARTBEAT", "FOREMAN", { lease_ms: 3600000, status: "idle" }),
      0
    );
    expect(next).toMatchObject({
      phase: "ARCHIVED",
      state_revision: 11,
      sessions: { FOREMAN: { status: "idle" } },
    });

    expectCode(
      () => applyEvent(
        archivedState(),
        event("HEARTBEAT", "CAPTAIN", { lease_ms: 3600000, status: "active" }),
        0
      ),
      "TASK_TERMINAL"
    );
  });
});
