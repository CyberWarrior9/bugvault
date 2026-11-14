# Local Burp MCP bridge

OpenCode uses `opencode.json` and native Claude Code uses `.mcp.json` at the project
root to connect directly to `http://127.0.0.1:9876/mcp`. No proxy process is needed.
These are project-wide registrations, not model-specific configuration. Burp must be
running with its MCP extension enabled; keep its approvals enabled.

For clients that only support MCP stdio, run `sh tools/burp/stdio-proxy.sh` from this
checkout. The script resolves the JAR next to itself and uses Burp's bundled Java
(or `BURP_JAVA_BIN`, falling back to `java`). It connects to the legacy SSE endpoint
at `http://127.0.0.1:9876/`; this is not Burp's interception proxy.

The operator-supplied `mcp-proxy.jar` was copied byte-for-byte into this folder on
2026-11-12. SHA-256:

`b6e12ccf8bc3afcdf8b891cd23c29315915ade985126a07fe22a875e9cd3c09e`

The manifest entry is `net.portswigger.MainKt`. This checksum pins the provided
artifact; it is not a verified upstream signature. The original remains untouched.
The binary is gitignored and is not licensed under BugVault's MIT licence. Upstream
[mcp-proxy](https://github.com/PortSwigger/mcp-proxy) is GPL-3.0; review upstream
licences and corresponding-source obligations before redistributing any binary.
Do not automatically download/replace or run a different JAR when the hash changes.

Setup verification checked MCP initialization and tool discovery, not target requests.
See `.claude/skills/scope-policy/references/burp-workflow.md` for current capabilities,
approvals, data sharing and the still-missing campaign-enforced execution adapter.
