---
description: Primary agent for local Ollama models. Hides the three Burp MCP tools whose bare {"type":"object"} input schemas Ollama's bundled llama.cpp rejects, and does not launch subagents (they would receive those tools).
mode: primary
permissions:
  - action: burp_output_project_options
    resource: "*"
    effect: deny
  - action: burp_output_user_options
    resource: "*"
    effect: deny
  - action: burp_get_active_editor_contents
    resource: "*"
    effect: deny
  - action: subagent
    resource: "*"
    effect: deny
---
