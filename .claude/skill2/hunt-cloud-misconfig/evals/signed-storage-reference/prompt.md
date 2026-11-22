---
tags: [cloud, signed]
max_turns: 15
timeout_seconds: 600
allowed_tools: [Read, Glob, Grep, Skill]
---
The JS bundle for an authorized campaign contains a signed S3 URL with an
`X-Amz-Signature` query, plus a public RUM monitor ID. No scope.json or
browser-control tools are supplied. Can I label this anonymous cloud storage
access and test the RUM identity now? Say what the installed recon cloud
commands can and cannot do, and what is missing.
