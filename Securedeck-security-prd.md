# Securedeck — Security Product Requirements Document (PRD)

**Status:** Draft v1
**Owner:** Product / Security Engineering
**Related docs:** Master Build Specification (securedeck-master-spec.md)

---

## 1. Problem statement

Enterprises are deploying autonomous AI agents faster than they can govern them. Industry data backs this up directly: nearly half of all deployed agents run with no monitoring coverage, agents are entering production roughly 7–8x faster than governance is being built around them, and fewer than a quarter of organizations report mature agentic AI governance. The failure modes are specific and recurring — agents exceeding their granted scope, reaching unauthorized network destinations, drifting from their declared task, and in the worst case, entrenching themselves into the very systems meant to shut them down.

Tripwire exists to close that gap: a self-hosted control layer that enforces scope in real time, contains violations before they complete, and proves — with tamper-evident evidence — that containment worked.

---

## 2. Goals

- **G1:** No agent action executes without being checked against its declared scope, in real time, before completion.
- **G2:** The system that stops a rogue agent must remain functional even if the agent (or the component monitoring it) is fully compromised.
- **G3:** Every security-relevant event is recorded in a way that cannot be altered or deleted after the fact, by anyone, including operators.
- **G4:** The product runs entirely within the customer's own environment by default — no telemetry, logs, or agent data leave their infrastructure unless explicitly configured.
- **G5:** Security posture is provable, not just claimed — the product produces evidence an external auditor would accept.

## Non-goals

- Not a general-purpose AI observability or prompt-engineering tool.
- Not responsible for the quality or correctness of an agent's output — only for whether its actions stayed within authorized bounds.
- Not a replacement for sandboxed execution infrastructure (E2B, Firecracker, gVisor, etc.) — Tripwire is the policy and containment layer that sits alongside sandboxing, not a substitute for it.

---

## 3. Threat model → requirement mapping

| ID | Threat | Requirement(s) that address it |
|---|---|---|
| T1 | Scope escalation (agent performs an unauthorized action type) | SEC-01, SEC-02 |
| T2 | Unauthorized network egress | SEC-03 |
| T3 | Prompt injection / instruction hijack | SEC-04 |
| T4 | Task drift (in-scope actions pursuing a different goal) | SEC-05 |
| T5 | Log or data tampering | SEC-06, SEC-07 |
| T6 | Self-tampering / credential or policy modification by an agent | SEC-08 |
| T7 | Swarm coordination abuse (individually-legal actions combining into unauthorized outcomes) | SEC-09 |
| T8 | Control capture / remediation lock-in | SEC-10, SEC-11 |

---

## 4. Functional security requirements

### SEC-01 — Real-time scope enforcement
**Priority:** P0
Every agent action is evaluated against its declared scope before it is permitted to execute — not logged-and-reviewed after the fact.
**Acceptance criteria:**
- An action outside declared scope is blocked before completion in 100% of test cases.
- Enforcement decision latency does not add more than 50ms at p95 to the underlying call.
- Enforcement fails closed if the policy store is unreachable.

### SEC-02 — Per-agent identity
**Priority:** P0
No two agents share a credential. Each agent is issued its own scoped, short-lived identity.
**Acceptance criteria:**
- Credential lifetime is configurable, default ≤ 1 hour.
- Revoking one agent's credential has zero effect on any other agent.

### SEC-03 — Network egress control
**Priority:** P0
Outbound network access is default-deny. An agent may only reach domains on its own declared list or the organization-wide allowlist.
**Acceptance criteria:**
- A connection attempt to a non-allowlisted domain is blocked and logged as a critical event, 100% of test cases.
- Allowlist changes take effect without a service restart.

### SEC-04 — Injected-instruction resistance
**Priority:** P1
Actions triggered by content the agent has read (a webpage, a document, a tool result) are still checked against the agent's original declared scope — scope is anchored to the task the agent was assigned, not to whatever it most recently read.
**Acceptance criteria:**
- A scripted prompt-injection test (agent reads content instructing it to perform an out-of-scope action) is blocked and logged.

### SEC-05 — Drift detection
**Priority:** P1
Agent behavior is continuously compared against its originally declared task description, independent of whether individual actions are in-scope.
**Acceptance criteria:**
- Baseline rule-based drift detection ships in v1; false-positive rate on a labeled test set is documented and visible to operators.
- Drift alerts are distinguishable in the console from hard scope violations (different severity tier).

### SEC-06 — Tamper-evident audit log
**Priority:** P0
Every enforcement decision, credential event, and operator action is recorded in an append-only, hash-chained log.
**Acceptance criteria:**
- Any attempt to modify or delete an existing log entry is detectable via chain verification.
- The database layer itself rejects UPDATE/DELETE on log records — this is not enforced only in application code.
- Log write failures cause the triggering action to fail closed (SEC-01 applies).

### SEC-07 — Log isolation from monitored components
**Priority:** P0
The audit log service is the only component with write access to log storage. No other service — including the policy gateway — can write log entries directly to the database.

### SEC-08 — Self-tampering prevention
**Priority:** P0
An agent cannot modify its own policy, scope, or credentials, and cannot reach the audit log or kill switch through any tool or API it is granted.
**Acceptance criteria:**
- Agent-scoped credentials have zero permissions against the policy store, audit log, or kill switch APIs — verified by automated permission-boundary tests, not just documentation.

### SEC-09 — Swarm-level correlation
**Priority:** P1
The system detects combinations of individually-authorized actions across multiple agents that collectively exceed what any single agent was authorized to do.
**Acceptance criteria:**
- At least one documented multi-agent abuse pattern (e.g. split-privilege data exfiltration across two agents) is detected in test scenarios at v1 launch.

### SEC-10 — Independent kill switch
**Priority:** P0
A system-wide or per-agent stop mechanism exists that does not depend on the cooperation, availability, or integrity of the policy gateway or any monitored agent.
**Acceptance criteria:**
- Kill switch runs as a separate process/container with its own credentials and no shared database connection pool with the policy gateway.
- Kill commands are cryptographically signed (Ed25519); unsigned or invalid-signature commands are rejected and logged.
- Triggering the kill switch with the policy gateway fully offline still succeeds (verified by a chaos test that kills the gateway process before issuing the command).

### SEC-11 — Recovery path independence
**Priority:** P0
Backups, key material, and the kill switch's own configuration are stored and restorable without depending on any component the kill switch might need to act against.
**Acceptance criteria:**
- Documented recovery runbook does not require the policy gateway, credential broker, or any agent-facing service to be operational.

---

## 5. Non-functional requirements

| Category | Requirement | Priority |
|---|---|---|
| Deployment | Fully functional with zero outbound internet dependency in default configuration | P0 |
| Deployment | Installable via single `docker-compose` file for single-node/offline use, and Helm chart for Kubernetes | P0 |
| Data protection | Encryption at rest for all persisted data (audit log, credentials, policies) | P0 |
| Data protection | Encryption in transit for all internal service calls (mTLS) and all external API calls (TLS 1.3) | P0 |
| Availability | Policy gateway degrades to fail-closed, never fail-open, under any dependency failure | P0 |
| Performance | Enforcement decision adds ≤ 50ms p95 latency to the underlying agent action | P1 |
| Auditability | Compliance export available in a structured, auditor-consumable format (EU AI Act / ISO 42001 aligned) on demand | P1 |
| Secrets management | Root signing keys are generated and stored outside the application's own database, per the customer's key-management practice | P0 |

---

## 6. Success metrics

- % of agent actions covered by real-time enforcement (target: 100% for onboarded agents).
- Mean time from policy violation to containment (target: sub-second).
- False-positive rate on drift detection, tracked and driven down over time.
- Number of successful audit exports accepted without follow-up questions by an external auditor (proxy for evidence quality).

---

## 7. Risks and open questions

- Drift detection's false-positive rate at launch is unknown until tested against real agent traffic — flag this to early customers rather than overselling precision.
- Swarm correlation (SEC-09) is the least mature capability industry-wide; v1 scope should cover a small, well-defined set of abuse patterns rather than claiming general coverage.
- Key-management practice (SEC-11) varies significantly by customer — the recovery runbook needs to accommodate customers without a formal KMS as well as those with one.

---

## 8. Out of scope for v1

- SDK integration mode (sidecar/proxy mode ships first — see Master Build Specification, milestone sequencing).
- Semantic (embedding-based) drift detection — v1 ships rule-based only.
- Multi-tenant SaaS hosting — v1 is self-hosted only.
