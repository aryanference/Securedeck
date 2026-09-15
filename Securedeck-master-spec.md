# Securedeck — Master Build Specification

A single reference for building the agent containment platform end to end: what to build it in, how the six components connect, and how an enterprise actually gets it running against their own agents. Written to be handed to an engineering team — or an AI coding assistant — as the source of truth.

---

## 1. Non-negotiable principles

These aren't style preferences. Violating any of them defeats the product's purpose.

- **Fail closed, always.** If the policy gateway can't reach its policy store, it denies the action — it never defaults to allow because a dependency was slow.
- **The kill switch shares no trust boundary with anything it can kill.** Different process, different credentials, different network path. If the gateway is compromised, the switch must still work.
- **Nothing overwrites its own audit trail.** Enforced at the storage layer, not just in application code — a compromised service should not be able to delete or edit what it already wrote.
- **Deny by default.** An agent gets nothing it wasn't explicitly granted — scope and network egress both.
- **Every agent has its own identity.** No shared API keys standing in for a fleet of agents.

---

## 2. Tech stack

The backend is where the engineering rigor lives. The frontend is deliberately the least interesting part of this system.

| Layer | Choice | Why |
|---|---|---|
| Core backend language | **Go** | Strong static typing, excellent concurrency primitives for handling many simultaneous agent connections, small static binaries (good for on-prem/offline install), mature ecosystem for infra tooling — this is what Vault, Consul, and most serious infra-security software is built in. |
| Kill switch specifically | **Rust** | The one component where memory-safety guarantees matter more than development speed. It runs isolated from everything else, so the cost of a second language is contained to one small, rarely-changed service. |
| Primary datastore | **PostgreSQL** | Relational integrity for agents, policies, credentials. Supports the constraints needed to make the audit table genuinely append-only at the database level (see §4.1). |
| Offline/single-node fallback | **SQLite (WAL mode)** | For small deployments or air-gapped environments where running a separate Postgres instance is overkill. Same schema, same guarantees, one binary. |
| Event streaming | **NATS JetStream** | Lightweight, embeddable, persistent, runs entirely local with no external dependency — unlike Kafka, it doesn't require a cluster to be useful for a single enterprise's traffic. This is what the audit log fans out through to the drift detector and swarm engine. |
| Internal service-to-service | **gRPC over mTLS** | Every internal call is both strongly typed (protobuf contracts catch integration bugs at compile time) and mutually authenticated — no internal service trusts another just because it's on the network. |
| External-facing API | **REST/JSON, OpenAPI-documented** | This is the integration surface enterprises actually touch. Keep it boring and well-documented; it's not where you spend engineering creativity. |
| Agent identity tokens | **PASETO v4 (or short-lived Ed25519-signed tokens)** | Avoids the well-known JWT footguns (algorithm confusion, "alg: none"). Short-lived, signed, scoped per agent. |
| Cryptographic primitives | **Ed25519 signing** for kill-switch commands and credential issuance; **SHA-256 hash chaining** for the audit log (each entry references the hash of the one before it, so tampering breaks the chain visibly). |
| Console frontend | **Go templates + HTMX**, minimal CSS | No Node build pipeline, no JS framework version treadmill — for a security product being installed on-prem, fewer moving parts in the frontend is a real security and maintenance win, not just a shortcut. If a richer UI is wanted later, React + TypeScript is a fine drop-in replacement without touching the backend. |
| Deployment | **OCI containers**; `docker-compose` for single-node/offline installs, a **Helm chart** for Kubernetes at larger scale. No component calls out to the internet by default. |
| Testing | Standard Go test suite + **property-based tests** on the policy engine (scope-checking logic is exactly the kind of code where edge cases hide) + fuzz testing on anything that parses agent-submitted input. |

---

## 3. Component specifications

### 3.1 Audit log service
- **Language:** Go
- **Storage:** Postgres table with a database-level trigger that rejects `UPDATE` and `DELETE` on the log table outright — this isn't just an application-layer convention, the database itself refuses. Each row stores `sha256(previous_row_hash + this_row_content)`.
- **Writes:** every other service publishes events to it over gRPC; it's the only service with write access to the log table.
- **Reads:** exposed as a NATS JetStream stream so downstream consumers (drift detector, swarm engine, compliance reporter) subscribe rather than poll the database directly.
- **Failure behavior:** if the log service is unreachable, the policy gateway fails closed — no log, no execution.

### 3.2 Credential broker
- **Language:** Go
- **Responsibility:** issues short-lived, scoped tokens per agent. No agent ever holds a long-lived credential to anything.
- **Storage:** Postgres — agent registry, scope definitions, token issuance history (which is itself streamed to the audit log).
- **Interface:** gRPC `IssueToken(agent_id, requested_scope) → token`, `RevokeToken(token_id)`.
- **Connects to:** audit log (every issuance/revocation logged), policy gateway (validates tokens on every call), kill switch (can trigger mass revocation on command).

### 3.3 Policy gateway
- **Language:** Go
- **Responsibility:** the enforcement point. Every action an agent attempts is routed through it — checked against the agent's declared scope and the network egress allowlist before being allowed to proceed.
- **Interface:** can run as a **sidecar proxy** (transparent, no code changes to the agent) or as an **SDK call** (the agent's own code explicitly asks permission — richer signal, requires integration work).
- **Storage:** reads policy definitions from Postgres, writes every decision to the audit log stream.
- **Failure behavior:** fail closed.

### 3.4 Kill switch
- **Language:** Rust
- **Deployment:** its own process, own container, own credentials, ideally its own network segment. It does not share a database connection pool, a service account, or a deployment pipeline with the gateway.
- **Responsibility:** exposes a single, deliberately small surface — `Suspend(agent_id)`, `Terminate(agent_id)`, `LockdownAll()` — each requiring an Ed25519-signed operator command.
- **Mechanism:** on trigger, it calls the credential broker's `RevokeToken` and, separately, updates a deny-list that the policy gateway checks on every single request — so even a gateway that's misbehaving still can't let a revoked agent through, because the deny-list check doesn't depend on the gateway's own judgment.
- **This is the component where "separate trust boundary" is not negotiable.** If it's ever deployed sharing infrastructure with the gateway for convenience, the whole design's core guarantee is gone.

### 3.5 Drift detector
- **Language:** Go
- **Responsibility:** subscribes to the audit log stream, compares each agent's stream of actions against its originally declared task. Start with deterministic rule/category matching (cheap, explainable, fully offline); a local embedding model for semantic similarity can be added later without changing the interface.
- **Output:** publishes drift alerts back onto the event bus, which the console and compliance reporter both consume.

### 3.6 Swarm correlation engine
- **Language:** Go
- **Responsibility:** also subscribes to the audit log stream, but looks across agents rather than within one — building a short-window graph of which agents touched which resources, and flagging combinations that individually pass policy but collectively look like something no single agent was authorized to do.
- **This is graph and event-correlation logic — deterministic, testable, no ML required for a solid first version.**

### 3.7 Compliance report generator
- **Language:** Go
- **Responsibility:** the only component with no write access anywhere — pure read, over the audit log, drift alerts, swarm alerts, and kill-switch history. Renders evidence in the formats auditors expect (structured export, PDF summary).

---

## 4. How the pieces connect

```
Agent → Policy Gateway → [allow/deny] → Audit Log ──┬─→ Drift Detector ─┐
              ↑                                       ├─→ Swarm Engine ──┼─→ Console / Alerts
     Credential Broker                                └─→ Compliance Reporter
              ↑
        Kill Switch (separate boundary, signs revocation commands)
```

Everything downstream of the Policy Gateway learns what happened by subscribing to the audit log's event stream — nothing queries another service's private database directly. This keeps each component independently testable and means the audit log stays the single source of truth rather than state drifting between services.

---

## 5. The enterprise user journey

This is the path a real customer takes, from first hearing about the product to running it against their own agents.

**1. Evaluation.** Security or platform engineering lead finds the product, reads the threat model, sees it maps to failure modes they already recognize (scope escalation, unauthorized egress, drift, log tampering). Deployment model (fully self-hosted, no data leaves their environment) is usually the deciding factor at this stage for regulated buyers.

**2. Deployment decision.** Two paths, made explicit up front:
   - *Single-node / offline* — `docker-compose up`, everything runs on one box or air-gapped cluster, SQLite backend. Suited to smaller teams or highly regulated environments.
   - *Enterprise / Kubernetes* — Helm chart, Postgres, horizontal scaling for larger agent fleets.

**3. Installation.** Operator installs, generates the root signing key for the kill switch offline (never transmitted, stored per their own key-management practice), and brings the console up.

**4. Org and policy setup.** Admin defines the initial network egress allowlist and creates the first policy templates (what a "research agent" or "data-sync agent" is normally allowed to do).

**5. Agent onboarding — two integration modes, and the customer picks per-agent:**
   - **Retrofit / sidecar mode** — for agents already in production. No code changes: the agent's outbound traffic is routed through the policy gateway as a transparent proxy. Fastest to adopt, coarser-grained signal.
   - **SDK mode** — for agents being newly built. The agent's own code requests permission from the broker directly, declaring intent, which gives the drift detector a much richer signal to work with. Slower to adopt, better long-term signal quality.

**6. Go live.** Agents start running through the gateway. Every action is now logged, checked, and — if it violates scope — quarantined automatically, with the operator notified through the console.

**7. Day-to-day operation.** Security team lives in the console: reviewing quarantined agents, releasing false positives, occasionally hitting the kill switch, watching drift and swarm alerts accumulate.

**8. Compliance cycle.** Quarterly (or on-demand), the compliance reporter exports evidence — this is usually what turns the product from "useful tool" into "budget line item," because it's the artifact that satisfies an external auditor.

---

## 6. Suggested build milestones

1. Audit log + Credential broker (testable in isolation, no dependents yet)
2. Policy gateway in sidecar mode only — this alone is a demoable, sellable MVP
3. Kill switch, deployed genuinely separately from day one
4. Drift detector (rule-based first)
5. Swarm correlation engine
6. SDK integration mode + compliance reporter

Each milestone should be independently deployable and independently valuable — nobody should have to wait for milestone 6 to get real protection from milestone 2.
