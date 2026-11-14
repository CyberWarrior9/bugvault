# Surface and trigger inventory

Keep one row per exact URL/method/account/role/tenant/workflow/input. Inventory from
captured browser traffic, UI/JS/API schemas, supported integrations and authorized
source review. A parameter name is a lead; an unknown hidden parameter is not license
to fuzz it. Source-only references should be observed in the permitted browser first.

| Location | Examples of legitimate functionality | Trigger and comparison |
|---|---|---|
| Query/path | Fetch proxy, oEmbed, URL preview, download/import | Normal public resource vs controlled canary; inspect whether response bytes came from receiver |
| JSON/form | `sourceUrl`, `callbackUrl`, `image`, nested `integration.endpoint` | Exact observed operation; note duplicate-field behavior without pooling input sources |
| Multipart | Remote-source field, document references, image-processing job | Import only your small harmless file; distinguish uploaded bytes from subsequently fetched assets |
| Stored configuration | Webhook, feed, remote repository, analytics URL | Save alone may not fetch; capture test/delivery/refresh/worker trigger and undo your configuration |
| Headers | Referer/analytics collection, observed server routing configuration | Only where sink evidence exists; never spray every request header or spoof unrelated users |
| Rendered content | PDF/screenshot generation, HTML email preview, SVG/image/video processing | Your document references one small controlled resource; separate browser preview from server export |
| XML | External stylesheet/schema/resource references or an entity-capable parser | Confirm parser behavior and separate XXE authority; never use entity expansion or sensitive file paths |
| API/GraphQL | URL scalars, import mutations, integration health checks | Use schema/captured traffic and supplied test objects; no batching amplification |
| Identity | Remote JWKS/certificate retrieval, SAML resource handling | Link to auth skill; retrieval, key trust and successful test-account action are separate stages |
| Product sink | A concrete proxy/import/render endpoint in a known product | Exact version/configuration/advisory and harmless prerequisite check, not an old platform list |

Test before changing authentication/tenant state, and again only when that state
meaningfully changes the sink or authorization. Different roles, exact API versions,
workers, saved-vs-preview flows and response transformations can behave differently.
Use `field` labels such as `json.integration.callbackUrl`, `query.url`, `multipart.source`
or `svg.image.href`, plus a meaningful workflow label (`draft-preview`, `saved-test`).

## What a baseline records

- Which test principal owns the object; entry URL/method and original field value.
- Intended destination policy: unrestricted public webhook, allowlisted partner,
  image-only URL, same-tenant resource, or no network access expected.
- Trigger, response/job identifiers, asynchronous timing and retries/cache behavior.
- Captured initiating request, receiver logs and response/control artifacts; secrets
  redacted in shared context, originals private if retention is permitted.
- Outbound method, content/header/body influence, cookies/authorization forwarding
  (use synthetic test values), supported schemes, ports, redirects and response access.

Do not confuse an open redirect (the browser is redirected) with server-side redirect
following. Do not call a client-side image load SSRF. A normal webhook reaching an
approved public URL demonstrates functionality; reportability needs a forbidden
destination, data or action boundary demonstrated with permission.
