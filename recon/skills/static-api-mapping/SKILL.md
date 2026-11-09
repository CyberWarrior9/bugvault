---
name: static-api-mapping
description: Extract authorized BugVault HTML/form, JavaScript/lazy-chunk, source-map, route, method and parameter-name surfaces, or ingest existing Katana outputs without executing API operations.
---

# Static API mapping

Read scope-policy first. Use built-in wellknown/jsharvest/jsparse/mapparse jobs under permitted active mode. Import existing crawls with `python3 -m recon import <campaign> <file> --format katana`.

Keep frontend routes separate from backend endpoint families. Preserve methods as separate operations, exact path variants and query parameter names. A regex call-site match is a static reference, not proof that an endpoint exists or accepts the inferred parameters.

Collect referenced source maps within scope; guessed `.map` requests additionally require loud mode. Do not promise complete webpack/Vite runtime-manifest reconstruction. Never submit possible client secrets or source-map exposure alone as confirmed vulnerabilities.

Output endpoint families, methods, path variants, parameter names, routes and source links. Implementation: `recon/extract.py`, `recon/active.py`.
