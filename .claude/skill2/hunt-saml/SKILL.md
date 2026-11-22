---
name: hunt-saml
description: "SAML / SSO hunting for authorized BugVault campaigns: XML signature wrapping (XSW1-XSW8), signature stripping, comment injection in NameID, audience-restriction and recipient checks, assertion replay, key confusion and XXE in the assertion parser. Use for coverage rows of class `saml` and any /saml, /sso/saml, assertion consumer service, Shibboleth or ADFS endpoint. Assertions come from your own test accounts' logins; a forged identity may only be another operator-owned test account."
license: "MIT; adapted from mind-hunt (Copyright (c) 2026 MindflareX), see LICENSE.txt"
metadata:
  source: "mind-hunt skills/hunt-saml"
  source-sha256: "93a92589e9b7a5e5fbcf7ad23c216d7c136d793d0ed34fe8e473fb7b5555e33a"
  adapted: "2026-11-11"
---

# Hunt: SAML / SSO

SSO bugs frequently pay High or Critical, because XML parsers are notoriously
inconsistent.

## When this skill applies

- A coverage row of class `saml`: `recon/score.py` adds it for in-scope paths
  containing saml.
- Endpoints such as `/saml/acs` (assertion consumer service), `/sso/saml`,
  `/auth/saml/callback`, `/Shibboleth.sso/`, and ADFS `/adfs/ls/`. Find them with
  `python3 -m recon recall <campaign> "saml sso acs shibboleth adfs"`.

## Setup

Test accounts **A** and **V** that you own; if the program supplies an admin test
account, it may be the target identity, but real users and real admins never are. Log in
as A through SSO in your own browser and take A's `SAMLResponse` from your exported HAR
file or DevTools. BugVault's HAR import never stores request bodies, so the original
export is the source. Decode, edit and re-encode the XML locally (base64, then
URL-encoding inside the form). Submitting to the assertion consumer service is a POST, so
`"allowed_methods"` must include `POST`. Every submission goes through `recon send`:

```bash
python3 -m recon send <campaign> https://app.example.com/saml/acs --method POST \
  --form SAMLResponse=<base64 of the edited response> --form RelayState=<original value>
```

## Attacks

1. **XML Signature Wrapping (XSW1–XSW8)** — keep the signed element and its signature
   valid but move it, and insert an unsigned assertion the application reads first:

   ```xml
   <!-- before: valid assertion for A -->
   <saml:Response>
     <saml:Assertion ID="legit">
       <NameID>a@your-test-domain.example</NameID>
       <ds:Signature><!-- valid, covers ID=legit --></ds:Signature>
     </saml:Assertion>
   </saml:Response>

   <!-- after: the signature still validates (it covers #legit),
        but the application processes the first assertion -->
   <saml:Response>
     <saml:Assertion ID="evil">
       <NameID>v@your-test-domain.example</NameID>
     </saml:Assertion>
     <saml:Assertion ID="legit">
       <NameID>a@your-test-domain.example</NameID>
       <ds:Signature><!-- valid --></ds:Signature>
     </saml:Assertion>
   </saml:Response>
   ```

2. **Comment injection in NameID** — `v@your-test-domain.example<!---->.attacker.example`
   or `v<!---->@your-test-domain.example`: the signer and the application may handle
   comments differently, so the signature covers one value and the application reads
   another.
3. **Signature stripping** — delete the whole `<ds:Signature>` element, change NameID from
   A to V, and submit. Accepted means the service provider never requires a signature.
4. **Audience and recipient** — change `<Audience>` to another service provider or replay
   an assertion issued for a different one; check `Recipient` and `Destination`.
5. **Replay** — submit the same assertion twice inside its validity window, and after
   logout.
6. **Key confusion** — an assertion signed by an identity provider you control is
   accepted by a service provider that does not pin the issuer's certificate.
7. **XXE in the assertion parser** — a DOCTYPE with an external entity inside the
   assertion. Prefer a unique Burp Collaborator (Pro) callback or an approved listener
   you control, with no file contents or secrets in the callback. Intruder can insert
   Collaborator payloads but is not itself the listener. Send the target request through
   `recon send` and correlate its `request_id` with the operator's callback export and
   a distinct negative control. A DNS lookup alone does not prove file read or takeover;
   rule out browser, scanner and analyst-originated callbacks. Read
   `.claude/skills/scope-policy/references/burp-workflow.md` for the manual-only
   workflow and fallback. Operator-approved MCP generation/polling tools are available,
   but recon does not import their interactions into its native fact store.
   If no permitted listener exists, park the hypothesis. A direct file-read test is
   limited to a non-sensitive file such as `/etc/hostname`, only when the program allows.
8. **NameID manipulation** — the target identity is **V** (or the program's admin test
   account). Never use real users' or real administrators' identities, and never take
   identities from disclosed reports. If NameID is rendered into a template, test
   `${7*7}` on A's own identity.

## Proof and severity

Success means a session as V obtained from A's login, shown by V's marker:

```bash
python3 -m recon finding add <campaign> --title "SAML signature stripping accepted on /saml/acs" --class saml --url https://app.example.com/saml/acs
python3 -m recon fact check <campaign> --response <request_id> --predicate '{"type":"body_contains_raw","marker":"canary_ato_..."}'
```

| Result | Typical severity |
|---|---|
| XSW accepted | Critical (takeover of any user) |
| Signature stripping accepted | Critical |
| Comment injection | High |
| XXE in the assertion | High (file read or SSRF) |
| NameID manipulation | Medium to High, depending on what NameID maps to |

Changing attributes that cross no authorization boundary (display name, locale) is
informational, not critical. The change in the authentication decision is the gate.
Hand the lead to the validator; the reportability gate decides what is reported.

## Tools

SAML Raider (Burp extension) for crafting XSW variants in your own browser session;
manual decoding, editing and re-encoding of the XML. Submissions still go through
`recon send`.

## Hard limits

Only identities you own; no real user or administrator as the target; minimum data once
V's marker is proven.

## Related skills

`hunt-ato` (an XSW without audience validation is the canonical service-provider
impersonation chain) · `hunt-auth-bypass` (signature stripping is a textbook bypass) ·
`hunt-oauth` (SAML-fronted OAuth issuers turn assertion bugs into token-level takeover).
