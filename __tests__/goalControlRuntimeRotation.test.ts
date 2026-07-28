import { createRequire } from "module";

const nodeRequire = createRequire(import.meta.url);

type ControlFailure = Error & { code?: string };
type JsonRecord = Record<string, unknown>;

const { actorSequenceKey, applyEvent } = nodeRequire(
  "../scripts/goal-control/fsm.js"
) as {
  actorSequenceKey: (actor: {
    role: string;
    host_id: string;
    thread_id: string;
  }) => string;
  applyEvent: (
    state: JsonRecord,
    event: JsonRecord,
    controlEpoch: number
  ) => JsonRecord;
};
const { validateEvent } = nodeRequire(
  "../scripts/goal-control/validation.js"
) as {
  validateEvent: (event: JsonRecord) => JsonRecord;
};
const {
  assertLaunchRuntimeIncarnation,
  assertRotationSuccessorLaunch,
  buildLocalPreviewZeroWitness,
  isRuntimeRotationHoldLane,
  validateLocalPreviewZeroWitness,
} = nodeRequire("../scripts/goal-control/runtime-incarnation.js") as {
  assertLaunchRuntimeIncarnation: (
    session: JsonRecord,
    launch: JsonRecord
  ) => void;
  assertRotationSuccessorLaunch: (
    predecessor: JsonRecord,
    session: JsonRecord,
    launch: JsonRecord
  ) => void;
  buildLocalPreviewZeroWitness: (
    launch: JsonRecord,
    options?: {
      sample?: (candidate: JsonRecord) => JsonRecord;
      sampleCount?: number;
      intervalMilliseconds?: number;
    }
  ) => JsonRecord;
  isRuntimeRotationHoldLane: (
    state: JsonRecord,
    session: JsonRecord,
    launch?: JsonRecord
  ) => boolean;
  validateLocalPreviewZeroWitness: (
    launch: JsonRecord,
    proof: JsonRecord
  ) => JsonRecord;
};

const PACKET_SHA = `sha256:${"a".repeat(64)}`;
const LAUNCH_SHA = `sha256:${"b".repeat(64)}`;
const LEASE_SET_SHA = `sha256:${"c".repeat(64)}`;
const BASE_HEAD = "d".repeat(40);
const FULL_HEAD = "e".repeat(40);
const CONTROL_EPOCH = 30;
const STATE_REVISION = 19;
const ACCEPTED_AT = "2030-07-26T00:00:00.000Z";
const LEASE_UNTIL = "2030-07-26T04:00:00.000Z";
const CAPTAIN_THREAD = "captain-runtime-rotation";
const DEV_THREAD = "dev-runtime-rotation";
const PREDECESSOR_LAUNCH = "launch-dev-runtime-1";
const SUCCESSOR_LAUNCH = "launch-dev-runtime-2";
const HOLD_ID = "env-hold-runtime-identity";
const ROTATION_EVENT_ID = "runtime-rotated-dev-1-to-2";
const RUNTIME_NONCE = "f".repeat(40);
const TASK_NONCE = "task_nonce_runtime_rotation";
const CAPABILITY_SHA = "9".repeat(64);
const PREVIEW_PID = 41001;
const PREVIEW_PORT = 8737;
const PROXY_PORT = 4107;
const RESOURCE_LEASES = [
  "lease-preview-runtime",
  "lease-browser-runtime",
];

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function expectControlCode(run: () => unknown, code: string): void {
  try {
    run();
    throw new Error(`expected control failure ${code}`);
  } catch (error: unknown) {
    expect((error as ControlFailure).code).toBe(code);
  }
}

function zeroSample(index: number): JsonRecord {
  return {
    observed_at: `2030-07-25T23:59:5${index}.000Z`,
    predecessor_pid_absent: true,
    preview_listener_absent: true,
    proxy_listener_absent: true,
    matching_process_count: 0,
  };
}

function retirementProof(): JsonRecord {
  return {
    schema_version: 1,
    kind: "LOCAL_PREVIEW_ZERO_WITNESS",
    predecessor_launch_id: PREDECESSOR_LAUNCH,
    predecessor_pid: PREVIEW_PID,
    preview_port: PREVIEW_PORT,
    proxy_port: PROXY_PORT,
    sample_count: 3,
    samples: [zeroSample(0), zeroSample(1), zeroSample(2)],
  };
}

function rotationPayload(): JsonRecord {
  return {
    role: "DEV",
    worker_thread_id: DEV_THREAD,
    worker_host_id: "local",
    worker_attempt: 1,
    predecessor_incarnation: 1,
    successor_incarnation: 2,
    predecessor_launch_id: PREDECESSOR_LAUNCH,
    predecessor_launch_sha256: LAUNCH_SHA,
    successor_launch_id: SUCCESSOR_LAUNCH,
    runtime_nonce: RUNTIME_NONCE,
    hold_id: HOLD_ID,
    reason: "replace a stopped local preview without replacing the worker",
    incident_ref: "incident:launch-id-conflict",
    retirement_proof: retirementProof(),
    lease_set_sha256: LEASE_SET_SHA,
  };
}

function strictRotationEvent(): JsonRecord {
  return {
    schema_version: 1,
    event_id: ROTATION_EVENT_ID,
    goal_id: "goal-runtime-rotation",
    task_id: "TASK-RUNTIME-ROTATION",
    type: "RUNTIME_ROTATED",
    actor: {
      role: "CAPTAIN",
      thread_id: CAPTAIN_THREAD,
      host_id: "local",
    },
    actor_sequence: 4,
    expected_state_revision: STATE_REVISION,
    control_epoch: CONTROL_EPOCH,
    packet: { revision: 1, sha256: PACKET_SHA },
    base_head: BASE_HEAD,
    full_head: FULL_HEAD,
    payload: rotationPayload(),
  };
}

function activeState(): JsonRecord {
  const captainActor = {
    role: "CAPTAIN",
    thread_id: CAPTAIN_THREAD,
    host_id: "local",
  };
  return {
    task_id: "TASK-RUNTIME-ROTATION",
    phase: "DEV_ACTIVE",
    state_revision: STATE_REVISION,
    control_epoch: CONTROL_EPOCH,
    task_cycle: 1,
    packet: {
      revision: 1,
      path: "docs/planning/goals/runtime/packet.md",
      sha256: PACKET_SHA,
    },
    base_head: BASE_HEAD,
    full_head: FULL_HEAD,
    pr: null,
    holds: [
      {
        hold_id: HOLD_ID,
        kind: "ENV_IDENTITY_INCIDENT",
        hard: true,
        reason: "canonical launch id cannot be rebound to the new PID",
        evidence: { evidence_id: "env-incident-runtime-identity" },
        raised_by: captainActor,
        raised_at: "2030-07-25T23:50:00.000Z",
        resume_phase: "DEV_ACTIVE",
      },
    ],
    sessions: {
      CAPTAIN: {
        role: "CAPTAIN",
        thread_id: CAPTAIN_THREAD,
        host_id: "local",
        attempt: 1,
        status: "active",
        lease_until: LEASE_UNTIL,
      },
      DEV: {
        role: "DEV",
        thread_id: DEV_THREAD,
        host_id: "local",
        attempt: 1,
        status: "active",
        lease_until: LEASE_UNTIL,
        launch_id: PREDECESSOR_LAUNCH,
        task_nonce: TASK_NONCE,
        capability_sha256: CAPABILITY_SHA,
        capability_file: "/control/capabilities/dev-runtime.cap",
      },
    },
    session_history: { DEV: [] },
    actor_sequences: {
      [actorSequenceKey(captainActor)]: 3,
    },
    last_reconciled_epoch: CONTROL_EPOCH,
    reconcile_required: null,
    p1: {},
    evidence: {},
    recovery: null,
    recovery_backlog: [],
    merge: null,
    merge_reservation: null,
    last_event: null,
  };
}

function acceptedRotationEvent(): JsonRecord {
  return {
    ...strictRotationEvent(),
    accepted_at: ACCEPTED_AT,
  };
}

function previewLaunch(options: {
  launchId: string;
  pid: number;
  port: number;
  startedAt: string;
  runtimeIncarnation?: JsonRecord;
  resourceLeases?: string[];
}): JsonRecord {
  return {
    launch_id: options.launchId,
    runtime: {
      node_version: "v25.5.0",
      pnpm_version: "10.14.0",
    },
    ...(options.runtimeIncarnation
      ? { runtime_incarnation: options.runtimeIncarnation }
      : {}),
    execution: {
      environment: "none",
      write_mode: "NONE",
      task_nonce: TASK_NONCE,
      target: {
        kind: "PREVIEW",
        executable_path: "/opt/homebrew/bin/node",
        pid: options.pid,
        started_at: options.startedAt,
        preview_url: `http://127.0.0.1:${options.port}/`,
      },
    },
    resource_leases: options.resourceLeases || RESOURCE_LEASES,
  };
}

function rotatedSession(): JsonRecord {
  return {
    role: "DEV",
    thread_id: DEV_THREAD,
    host_id: "local",
    attempt: 1,
    status: "active",
    lease_until: LEASE_UNTIL,
    launch_id: SUCCESSOR_LAUNCH,
    task_nonce: TASK_NONCE,
    runtime_incarnation: 2,
    runtime_nonce: RUNTIME_NONCE,
    last_runtime_rotation: {
      event_id: ROTATION_EVENT_ID,
      successor_incarnation: 2,
      predecessor_launch_id: PREDECESSOR_LAUNCH,
      successor_launch_id: SUCCESSOR_LAUNCH,
      runtime_nonce: RUNTIME_NONCE,
      hold_id: HOLD_ID,
    },
  };
}

describe("RUNTIME_ROTATED validation", () => {
  it("accepts the complete, strictly shaped event", () => {
    expect(validateEvent(strictRotationEvent())).toMatchObject({
      type: "RUNTIME_ROTATED",
      actor: {
        role: "CAPTAIN",
        thread_id: CAPTAIN_THREAD,
        host_id: "local",
      },
      payload: {
        predecessor_incarnation: 1,
        successor_incarnation: 2,
        predecessor_launch_id: PREDECESSOR_LAUNCH,
        successor_launch_id: SUCCESSOR_LAUNCH,
      },
    });
  });

  it("rejects missing fields, forged proof bytes, and a non-successor incarnation", () => {
    const missingField = clone(strictRotationEvent());
    delete (missingField.payload as JsonRecord).lease_set_sha256;
    expectControlCode(() => validateEvent(missingField), "INVALID_EVENT");

    const forgedProof = clone(strictRotationEvent());
    (
      (forgedProof.payload as JsonRecord).retirement_proof as JsonRecord
    ).predecessor_launch_id = "launch-dev-forged";
    expectControlCode(() => validateEvent(forgedProof), "INVALID_EVENT");

    const forgedSample = clone(strictRotationEvent());
    const forgedSamples = (
      (forgedSample.payload as JsonRecord).retirement_proof as JsonRecord
    ).samples as JsonRecord[];
    forgedSamples[1].preview_listener_absent = false;
    expectControlCode(() => validateEvent(forgedSample), "INVALID_EVENT");

    const skippedIncarnation = clone(strictRotationEvent());
    (skippedIncarnation.payload as JsonRecord).successor_incarnation = 3;
    expectControlCode(
      () => validateEvent(skippedIncarnation),
      "INVALID_EVENT"
    );
  });
});

describe("RUNTIME_ROTATED state projection", () => {
  it("rotates only the DEV runtime identity and keeps the worker and hard hold intact", () => {
    const before = activeState();
    const beforeHold = clone((before.holds as JsonRecord[])[0]);
    const next = applyEvent(before, acceptedRotationEvent(), CONTROL_EPOCH);
    const dev = (next.sessions as Record<string, JsonRecord>).DEV;

    expect(next).toMatchObject({
      phase: "DEV_ACTIVE",
      state_revision: STATE_REVISION + 1,
      holds: [beforeHold],
    });
    expect(dev).toMatchObject({
      thread_id: DEV_THREAD,
      host_id: "local",
      attempt: 1,
      status: "active",
      lease_until: LEASE_UNTIL,
      launch_id: SUCCESSOR_LAUNCH,
      task_nonce: TASK_NONCE,
      capability_sha256: CAPABILITY_SHA,
      capability_file: "/control/capabilities/dev-runtime.cap",
      runtime_incarnation: 2,
      runtime_nonce: RUNTIME_NONCE,
      runtime_history: [
        {
          incarnation: 1,
          launch_id: PREDECESSOR_LAUNCH,
          launch_sha256: LAUNCH_SHA,
          retirement_proof: retirementProof(),
          lease_set_sha256: LEASE_SET_SHA,
          retired_at: ACCEPTED_AT,
          rotation_event_id: ROTATION_EVENT_ID,
        },
      ],
      last_runtime_rotation: {
        event_id: ROTATION_EVENT_ID,
        predecessor_incarnation: 1,
        successor_incarnation: 2,
        predecessor_launch_id: PREDECESSOR_LAUNCH,
        successor_launch_id: SUCCESSOR_LAUNCH,
        hold_id: HOLD_ID,
      },
    });
    expect((before.sessions as Record<string, JsonRecord>).DEV).not.toHaveProperty(
      "runtime_incarnation"
    );

    expectControlCode(
      () => applyEvent(next, acceptedRotationEvent(), CONTROL_EPOCH),
      "STALE_STATE_REVISION"
    );

    const stalePredecessor = {
      ...acceptedRotationEvent(),
      event_id: "runtime-rotated-stale-predecessor",
      expected_state_revision: STATE_REVISION + 1,
      actor_sequence: 5,
    };
    expectControlCode(
      () => applyEvent(next, stalePredecessor, CONTROL_EPOCH),
      "RUNTIME_INCARNATION_CAS_MISMATCH"
    );
  });

  it("requires the CAPTAIN, one exact hard hold, and an active worker", () => {
    const wrongActorState = activeState();
    const wrongActor = {
      ...acceptedRotationEvent(),
      actor: {
        role: "DEV",
        thread_id: DEV_THREAD,
        host_id: "local",
      },
      actor_sequence: 1,
    };
    expectControlCode(
      () => applyEvent(wrongActorState, wrongActor, CONTROL_EPOCH),
      "RUNTIME_ROTATION_AUTHORITY"
    );

    const multipleHolds = activeState();
    (multipleHolds.holds as JsonRecord[]).push({
      hold_id: "second-hold",
      kind: "ENV_IDENTITY_INCIDENT",
      hard: true,
    });
    expectControlCode(
      () => applyEvent(multipleHolds, acceptedRotationEvent(), CONTROL_EPOCH),
      "RUNTIME_ROTATION_HOLD_REQUIRED"
    );

    const stoppedWorker = activeState();
    (
      (stoppedWorker.sessions as Record<string, JsonRecord>).DEV
    ).status = "lost";
    expectControlCode(
      () => applyEvent(stoppedWorker, acceptedRotationEvent(), CONTROL_EPOCH),
      "RUNTIME_ROTATION_WORKER_MISMATCH"
    );
  });
});

describe("runtime incarnation launch boundaries", () => {
  const predecessor = previewLaunch({
    launchId: PREDECESSOR_LAUNCH,
    pid: PREVIEW_PID,
    port: PREVIEW_PORT,
    startedAt: "2030-07-25T23:00:00.000Z",
  });
  const incarnation = {
    epoch: 2,
    nonce: RUNTIME_NONCE,
    rotation_event_id: ROTATION_EVENT_ID,
  };

  it("accepts the exact incarnation and a fresh, lease-preserving port group", () => {
    const session = rotatedSession();
    const successor = previewLaunch({
      launchId: SUCCESSOR_LAUNCH,
      pid: PREVIEW_PID + 1,
      port: 8837,
      startedAt: "2030-07-26T00:01:00.000Z",
      runtimeIncarnation: incarnation,
    });

    expect(() => assertLaunchRuntimeIncarnation(session, successor)).not.toThrow();
    expect(() =>
      assertRotationSuccessorLaunch(predecessor, session, successor)
    ).not.toThrow();
    const state = activeState();
    state.sessions = { ...(state.sessions as JsonRecord), DEV: session };
    expect(isRuntimeRotationHoldLane(state, session, successor)).toBe(true);
  });

  it("rejects incarnation spoofing, lease drift, and predecessor port reuse", () => {
    const session = rotatedSession();
    const successor = previewLaunch({
      launchId: SUCCESSOR_LAUNCH,
      pid: PREVIEW_PID + 1,
      port: 8837,
      startedAt: "2030-07-26T00:01:00.000Z",
      runtimeIncarnation: incarnation,
    });
    const spoofedIncarnation = clone(successor);
    (
      spoofedIncarnation.runtime_incarnation as JsonRecord
    ).nonce = "0".repeat(40);
    expectControlCode(
      () => assertLaunchRuntimeIncarnation(session, spoofedIncarnation),
      "RUNTIME_INCARNATION_MISMATCH"
    );

    const changedLeases = {
      ...successor,
      resource_leases: ["lease-preview-runtime"],
    };
    expectControlCode(
      () =>
        assertRotationSuccessorLaunch(
          predecessor,
          session,
          changedLeases
        ),
      "RUNTIME_SUCCESSOR_BINDING_MISMATCH"
    );

    const reusedPort = clone(successor);
    (
      (reusedPort.execution as JsonRecord).target as JsonRecord
    ).preview_url = `http://127.0.0.1:${PREVIEW_PORT}/`;
    expectControlCode(
      () => assertRotationSuccessorLaunch(predecessor, session, reusedPort),
      "RUNTIME_SUCCESSOR_PORT_REUSE"
    );
    const unrelatedHold = activeState();
    (unrelatedHold.holds as JsonRecord[])[0].hold_id = "new-incident";
    expect(
      isRuntimeRotationHoldLane(unrelatedHold, session, successor)
    ).toBe(false);
  });
});

describe("runtime rotation hold resolution", () => {
  function resolveEvent(withPreflight: boolean): JsonRecord {
    return {
      schema_version: 1,
      event_id: "resolve-runtime-hold",
      goal_id: "goal-runtime-rotation",
      task_id: "TASK-RUNTIME-ROTATION",
      type: "RESOLVE_HOLD",
      actor: {
        role: "FOREMAN",
        thread_id: "foreman-runtime-rotation",
        host_id: "local",
      },
      actor_sequence: 1,
      expected_state_revision: STATE_REVISION,
      control_epoch: CONTROL_EPOCH,
      packet: { revision: 1, sha256: PACKET_SHA },
      base_head: BASE_HEAD,
      full_head: FULL_HEAD,
      payload: {
        hold_id: HOLD_ID,
        authority: "runtime successor passed preflight",
        resolution_evidence: { evidence_id: "resolution-runtime-hold" },
        disposition: "FIXED",
        ...(withPreflight
          ? {
              runtime_preflight_evidence: {
                kind: "PREFLIGHT",
                status: "PASS",
                launch_id: SUCCESSOR_LAUNCH,
                producer: {
                  role: "DEV",
                  thread_id: DEV_THREAD,
                  host_id: "local",
                },
              },
            }
          : {}),
      },
      accepted_at: ACCEPTED_AT,
    };
  }

  it("rejects premature resolution and accepts the exact successor preflight", () => {
    const state = activeState();
    const rotated = applyEvent(state, acceptedRotationEvent(), CONTROL_EPOCH);
    rotated.sessions = {
      ...(rotated.sessions as JsonRecord),
      FOREMAN: {
        role: "FOREMAN",
        thread_id: "foreman-runtime-rotation",
        host_id: "local",
        attempt: 1,
        status: "active",
        lease_until: LEASE_UNTIL,
      },
    };
    const sequenceKey = actorSequenceKey({
      role: "FOREMAN",
      thread_id: "foreman-runtime-rotation",
      host_id: "local",
    });
    (rotated.actor_sequences as JsonRecord)[sequenceKey] = 0;

    const premature = resolveEvent(false);
    premature.expected_state_revision = STATE_REVISION + 1;
    expectControlCode(
      () => applyEvent(clone(rotated), premature, CONTROL_EPOCH),
      "RUNTIME_PREFLIGHT_EVIDENCE_REQUIRED"
    );

    const complete = resolveEvent(true);
    complete.expected_state_revision = STATE_REVISION + 1;
    const resolved = applyEvent(rotated, complete, CONTROL_EPOCH);
    expect(resolved.holds).toEqual([]);
  });
});

describe("local preview zero witness", () => {
  it("collects exactly three injected samples without invoking system probes", () => {
    const predecessor = previewLaunch({
      launchId: PREDECESSOR_LAUNCH,
      pid: PREVIEW_PID,
      port: PREVIEW_PORT,
      startedAt: "2030-07-25T23:00:00.000Z",
    });
    let sampleIndex = 0;
    const sample = jest.fn(() => {
      const value = zeroSample(sampleIndex);
      sampleIndex += 1;
      return value;
    });

    const proof = buildLocalPreviewZeroWitness(predecessor, {
      sample,
      intervalMilliseconds: 0,
    });

    expect(sample).toHaveBeenCalledTimes(3);
    expect(proof).toEqual(retirementProof());
    expect(validateLocalPreviewZeroWitness(predecessor, proof)).toBe(proof);
  });
});
