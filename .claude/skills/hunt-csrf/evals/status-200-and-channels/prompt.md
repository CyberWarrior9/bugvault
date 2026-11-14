---
tags: [skill-creator]
max_turns: 20
timeout_seconds: 600
allowed_tools: [Read, Glob, Grep, Skill, Write, Edit, Bash]
---

Text-only exercise for an authorized BugVault campaign (placeholder hosts; no live
access). The settings page on https://app.acme-lab.example changes the account email
with POST /account/email (form-urlencoded: email, csrfmiddlewaretoken). The captured
request also sends an X-CSRFToken header and a csrftoken cookie; the session cookie is
sid. In Burp Repeater a teammate deleted the csrfmiddlewaretoken body field, resent the
request and got HTTP 200 with the normal settings page. They want to report CSRF on
email change leading to account takeover. Decide what this result shows and lay out the
exact next steps to work this action to a recorded outcome with the repository's
tooling. Do not send requests, run the engine against anything or read private
campaign files.
