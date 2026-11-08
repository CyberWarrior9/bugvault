# PentAGI Analysis — Architecture, Gaps, and Enhancement Path

> Deep-dive on https://github.com/vxcontrol/pentagi (Go-based multi-agent
> penetration-testing orchestrator). Produced by a three-agent code analysis:
> agent architecture, tool/sandbox layer, and memory/provider/deployment layer.
> Conclusion: use it as the orchestration backbone, inject the hunting
> intelligence (plan3/plan4) as enhancements.

## What PentAGI is

A self-hosted multi-agent system: user describes a target + goal, a team of ~15
specialized LLM agents plans, runs 20+ tools inside a Docker-sandboxed Kali
container, remembers results (pgvector + optional Graphiti/Neo4j), and reports.

Critical clarification: the "20+ tools" are CLI binaries in the Kali image.
The only execution primitive is a single `terminal` tool that forwards any LLM
string to `sh -c` as root inside the sandbox.

## The agent team

Defined in `backend/pkg/providers/agent_for_chain.go` + `pconfig/config.go`:

- **Primary agent** — top supervisor; delegates one subtask at a time; ends via `done` barrier
- **Generator / Refiner** — decomposes goal into subtasks; re-plans with delta patches
- **Pentester / Coder / Installer** — the workers
- **Searcher / Memorist** — web research; memory retrieval
- **Adviser** — mentor + execution monitor + task planner (3 roles in one)
- **Reporter** — final evaluation with independent judgment
- **Reflector / toolcall_fixer / summarizer** — self-repair for weak models

## What's genuinely strong

- **Durable, resumable orchestration** — the whole hierarchy (flow/task/subtask/
  msg-chain) is DB-persisted; crash/restart recovery via `LoadFlowWorker`
- **Weak-model supervision stack** — reflector (no-tool-call recovery), mentor
  (loop detection splices adviser analysis into tool responses), pre-task
  planner checklists, tool-call fixer, repeating-call detector, iteration caps
- **Serious context engineering** — chain summarization (csum), per-model
  context-window compaction, progressive context enrichment
- **Per-agent model configs** — 13 slots (simple/primary/generator/pentester/...)
  each with model, temperature, top_k, reasoning params
- **Observability everywhere** — Langfuse, OTel/Grafana, per-chain cost accounting
- **Delta-based replanning** (SubtaskPatch add/remove/modify/reorder)

## The six gaps that matter

1. **Zero scope enforcement in code.** The `terminal` tool forwards any string to
   `sh -c` as root. No command parsing, no target allowlist, no approval gate.
   Scope lives entirely in prompt templates. Combined with anti-refusal framing
   and raw scraped content flowing into context, hostile targets can steer
   command execution via prompt injection.
2. **No first-class Finding entity.** Vulnerabilities live in free-text reports
   and vector chunks. No findings table, no lifecycle states.
3. **One provider per flow.** No cross-provider routing (can't run simple agents
   on a local 30B while the pentester runs a hosted model).
4. **Network-pentest generalist, not a structured bug hunter.** No vuln-class
   modules, canaries, auth matrix, race bursts, raw sockets, GraphQL awareness.
   The browser tool is read-only — no request manipulation.
5. **Memory limits** — flow-scoped pgvector memory purged on flow deletion; no
   ANN index; retrieval hyperparameters hardcoded; browser results never stored.
6. **Strictly sequential subtasks** — no parallelism, no dependency graph.

## Local deployment notes

- Base stack: `pentagi` (:8443), `pgvector` (:5432), `scraper` (:9443)
- LLM: agent workflows consume ~64K tokens; PentAGI uses a 110K context window.
  Tested full-local config: 4x RTX 5090 (128GB VRAM) with Qwen3.5-27B-FP8 via vLLM.
  On weaker hardware, a hosted provider (DeepSeek) as primary is pragmatic.
- Local embeddings required for memory: `EMBEDDING_PROVIDER=ollama`
- Hardening env vars: `DOCKER_ALLOWED_IMAGES` (lock the image allowlist),
  `DOCKER_PUBLIC_IP=127.0.0.1` (default publishes sandbox ports on 0.0.0.0),
  `EXECUTION_MONITOR_ENABLED=true`, `AGENT_PLANNING_STEP_ENABLED=true`
- Validate providers with `ctester` before trusting them

## Enhancement path (PentAGI as backbone + plan3 as brain)

1. **Immediate (no code):** mind-hunt doctrine as prompt overrides
   (per-user prompt templates are supported from the DB)
2. **Scope-enforcing terminal + egress firewall** — parse target IPs/domains,
   validate against flow scope before Docker exec
3. **New tools in the registry:** `http_request` (auth-state pool),
   `canary_server` (OOB callbacks), `burst_send` (races), `graphql_query`,
   `store_finding` (structured findings with lifecycle)
4. **Findings table + lifecycle** — hypothesis -> observed -> confirmed -> report_ready
5. **Cross-provider routing** — per-slot provider selection
6. **Attack graph <-> Graphiti bridge** — chain planning as graph queries over the
   taxonomy PentAGI already defines (YIELDED_ACCESS, ESCALATED_VIA, PIVOTED_TO)
