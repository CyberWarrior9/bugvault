---
name: static-api-mapping
description: Extract authorized BugVault HTML/form, JavaScript/lazy-chunk, source-map, route, method and parameter-name surfaces, or ingest existing Katana outputs without executing API operations.
---

# Static API mapping

Use built-in wellknown/jsharvest/jsparse/mapparse jobs under permitted active mode. Import existing crawls with `python3 -m recon import <campaign> <file> --format katana`.

Preserve the exact authorized URL seed. Optional same-origin HTML BFS is bounded by `collection.max_pages` and `max_depth`; the default remains one page. Widen a path grant to fetch root well-known paths or follow API-looking links automatically.

Keep frontend routes separate from backend endpoint families. Preserve methods as separate operations, exact path variants and query parameter names. A regex call-site match is a static reference, not proof that an endpoint exists or accepts the inferred parameters.

Collect referenced source maps within scope; guessed `.map` requests additionally require loud mode. Recognized webpack 4/5, Vite and Next manifest shapes now produce bounded chunk leads, with federation/out-of-scope gaps recorded. These parsers are not a full runtime evaluator: do not promise complete build coverage. For already stored native/Burp script/map bodies, `python3 -m recon js sync <campaign>` is offline; `js status` remains incomplete until the full build-stage workflow exists. Never submit possible client secrets or source-map exposure alone as confirmed vulnerabilities.

Output endpoint families, methods, path variants, parameter names, routes and source links. Implementation: `recon/extract.py`, `recon/active.py`.
