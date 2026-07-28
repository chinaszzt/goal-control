import { createRequire } from "module";

const nodeRequire = createRequire(import.meta.url);

type ControlFailure = Error & { code?: string };

const { actorSequenceKey, applyEvent } = nodeRequire(
  "../scripts/goal-control/fsm.js"
) as {
  actorSequenceKey: (actor: {
    role: string;
    host_id: string;
    thread_id: string;
  }) => string;
  applyEvent: (
    state: Record<string, unknown>,
    event: Record<string, unknown>,
    controlEpoch: number
  ) => Record<string, unknown>;
};

const PACKET_SHA = `sha256:${"a".repeat(64)}`;
const GIT_SHA = "b".repeat(40);
const CAPTAIN_THREAD = "captain-lease-gate";
const DEV_THREAD = "dev-successor-lease-gate";

function recoveryState(
  scope: "RECOVERY_BLOCKED" | "PREFLIGHT_ONLY",
  devLeaseUntil: string
): Record<string, unknown> {
  const devSession: Record<string, unknown> = {
    role: "DEV",
    thread_id: DEV_THREAD,
    host_id: "host-dev",
    attempt: 2,
    status: "active",
    lease_until: devLeaseUntil,
    launch_id: "launch-dev-successor-a2",
    task_nonce: "task_nonce_lease_gate",
    recovered_from: {
      role: "DEV",
      thread_id: "dev-predecessor",
      host_id: "host-dev",
      attempt: 1,
      predecessor_launch_id: "launch-dev-predecessor-a1",
    },
    operational_scope: scope,
  };
  if (scope === "PREFLIGHT_ONLY") {
    devSession.recovery_handoff = {
      event_id: "handoff-bound-before-expiry",
      import_commit: GIT_SHA,
    };
  }
  return {
    task_id: "TASK-LEASE-GATE",
    phase: "DEV_ACTIVE",
    state_revision: 20,
    control_epoch: 7,
    task_cycle: 1,
    packet: {
      revision: 3,
      path: "docs/planning/goals/lease-gate/packet.md",
      sha256: PACKET_SHA,
    },
    base_head: GIT_SHA,
    full_head: GIT_SHA,
    pr: null,
    holds: [],
    sessions: {
      CAPTAIN: {
        role: "CAPTAIN",
        thread_id: CAPTAIN_THREAD,
        host_id: "host-captain",
        attempt: 2,
        status: "active",
        lease_until: "2099-01-01T00:00:00.000Z",
      },
      DEV: devSession,
    },
    session_history: { DEV: [] },
    actor_sequences: {
      [
        actorSequenceKey({
          role: "CAPTAIN",
          host_id: "host-captain",
          thread_id: CAPTAIN_THREAD,
        })
      ]: 4,
    },
    last_reconciled_epoch: 7,
    reconcile_required: null,
    p1: {},
    evidence: {},
    recovery: null,
    recovery_backlog: [],
    merge: null,
    last_event: null,
  };
}

function event(
  type: "RECOVERY_HANDOFF_BOUND" | "RECOVERY_PROMOTED",
  acceptedAt: string,
  payload: Record<string, unknown>
): Record<string, unknown> {
  return {
    schema_version: 1,
    event_id: `${type.toLowerCase()}-lease-gate`,
    type,
    accepted_at: acceptedAt,
    actor: {
      role: "CAPTAIN",
      thread_id: CAPTAIN_THREAD,
      host_id: "host-captain",
    },
    actor_sequence: 5,
    expected_state_revision: 20,
    control_epoch: 7,
    packet: { revision: 3, sha256: PACKET_SHA },
    base_head: GIT_SHA,
    full_head: GIT_SHA,
    payload,
  };
}

function expectControlCode(run: () => unknown, code: string): void {
  try {
    run();
    throw new Error(`expected control failure ${code}`);
  } catch (error) {
    expect((error as ControlFailure).code).toBe(code);
  }
}

describe("recovery successor lease gates", () => {
  it("rejects RECOVERY_HANDOFF_BOUND when the DEV lease is expired at accepted_at", () => {
    const state = recoveryState(
      "RECOVERY_BLOCKED",
      "2030-01-01T00:00:00.000Z"
    );
    const handoff = event(
      "RECOVERY_HANDOFF_BOUND",
      "2030-01-01T00:00:00.000Z",
      {
        successor_thread_id: DEV_THREAD,
        predecessor_launch_id: "launch-dev-predecessor-a1",
      }
    );

    expectControlCode(
      () => applyEvent(state, handoff, 7),
      "SUCCESSOR_LEASE_EXPIRED"
    );
    expect(
      (
        (state.sessions as Record<string, Record<string, unknown>>).DEV
      ).operational_scope
    ).toBe("RECOVERY_BLOCKED");
  });

  it("rejects RECOVERY_PROMOTED when the DEV lease expired before accepted_at", () => {
    const state = recoveryState(
      "PREFLIGHT_ONLY",
      "2030-01-01T00:00:00.000Z"
    );
    const promotion = event(
      "RECOVERY_PROMOTED",
      "2030-01-01T00:00:00.001Z",
      {
        successor_thread_id: DEV_THREAD,
        handoff_event_id: "handoff-bound-before-expiry",
        launch_id: "launch-dev-successor-a2",
      }
    );

    expectControlCode(
      () => applyEvent(state, promotion, 7),
      "SUCCESSOR_LEASE_EXPIRED"
    );
    expect(
      (
        (state.sessions as Record<string, Record<string, unknown>>).DEV
      ).operational_scope
    ).toBe("PREFLIGHT_ONLY");
  });
});
