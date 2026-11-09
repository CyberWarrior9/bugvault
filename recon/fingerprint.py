"""Tech fingerprinting -> stack tags -> plan4 §4 tool packs. Also SPA + takeover signals."""
from __future__ import annotations

import re
from typing import Dict, List, Tuple

# (tag, where, regex). where = "body" | "cookie" | "header:<name>"
SIGNATURES: List[Tuple[str, str, str]] = [
    ("wordpress", "body", r"/wp-content/|/wp-includes/|/wp-json/"),
    ("drupal", "body", r"Drupal\.settings|/sites/default/files/|drupal\.js"),
    ("drupal", "header:x-generator", r"Drupal"),
    ("joomla", "body", r"/media/jui/|/components/com_|Joomla!"),
    ("shopify", "header:x-shopid", r"."),
    ("shopify", "body", r"cdn\.shopify\.com"),
    ("rails", "header:x-runtime", r"^\d"),
    ("aspnet", "header:x-aspnet-version", r"."),
    ("aspnet", "header:x-powered-by", r"ASP\.NET"),
    ("aspnet", "body", r"__VIEWSTATE"),
    ("aspnet", "cookie", r"ASP\.NET_SessionId"),
    ("java", "cookie", r"JSESSIONID"),
    ("spring", "body", r"Whitelabel Error Page"),
    ("express", "header:x-powered-by", r"Express"),
    ("php", "header:x-powered-by", r"PHP"),
    ("php", "cookie", r"PHPSESSID"),
    ("nextjs", "body", r"/_next/static/|__NEXT_DATA__"),
    ("nuxt", "body", r"/_nuxt/|__NUXT__"),
    ("react", "body", r"data-reactroot|<div id=\"root\"|<div id='root'"),
    ("vue", "body", r"<div id=\"app\"|<div id='app'|data-v-[0-9a-f]{8}"),
    ("angular", "body", r"<app-root|ng-version="),
    ("sharepoint", "header:microsoftsharepointteamservices", r"."),
    ("cloudflare", "header:server", r"cloudflare"),
    ("cloudflare", "header:cf-ray", r"."),
    ("akamai", "header:server", r"AkamaiGHost"),
    ("cloudfront", "header:x-amz-cf-id", r"."),
    ("aws-s3", "header:server", r"AmazonS3"),
    ("nginx", "header:server", r"nginx"),
    ("apache", "header:server", r"Apache"),
    ("iis", "header:server", r"Microsoft-IIS"),
]
SPA_TAGS = {"react", "vue", "angular", "nextjs", "nuxt"}
WAF_CDN_TAGS = {"cloudflare", "akamai", "cloudfront"}

# Response-body fingerprints of unclaimed third-party services (subdomain takeover leads).
TAKEOVER_SIGNATURES: Dict[str, str] = {
    "github-pages": r"There isn't a GitHub Pages site here",
    "heroku": r"No such app|herokucdn\.com/error-pages/no-such-app",
    "aws-s3": r"NoSuchBucket",
    "shopify": r"Sorry, this shop is currently unavailable",
    "fastly": r"Fastly error: unknown domain",
    "azure": r"404 Web Site not found|Error 404 - Web app not found",
    "zendesk": r"Help Center Closed",
    "readme": r"Project doesnt exist\.\.\. yet!",
    "surge": r"project not found",
    "netlify": r"Not Found - Request ID:",
    "ghost": r"The thing you were looking for is no longer here",
}

# plan4 §4 packs, condensed: tag -> [(check_id, what to do)]
PACKS: Dict[str, List[Tuple[str, str]]] = {
    "wordpress": [("wp-users-rest", "/wp-json/wp/v2/users and /?author=1 user enumeration"),
                  ("wp-xmlrpc", "xmlrpc.php: system.multicall amplification, pingback.ping SSRF"),
                  ("wp-plugins", "plugin/theme versions -> known CVEs (wpscan)")],
    "drupal": [("drupal-version", "version -> Drupalgeddon-family CVE check (droopescan)")],
    "joomla": [("joomla-version", "administrator/manifests/files/joomla.xml -> CVE match")],
    "shopify": [("shopify-products-json", "/products.json and app-proxy exposure")],
    "rails": [("rails-mass-assignment", "add privileged attrs to every write"),
              ("rails-secret", "secret_key_base/credentials disclosure")],
    "aspnet": [("aspnet-viewstate", "ViewState MAC/encryption"),
               ("aspnet-trace", "trace.axd / elmah.axd exposure")],
    "java": [("java-manager", "/manager, /jmx-console, deserialization surfaces")],
    "spring": [("spring-actuator", "/actuator/env, /actuator/heapdump, /actuator/mappings")],
    "express": [("node-proto-pollution", "__proto__/constructor.prototype in JSON/query"),
                ("node-ssrf", "URL params fetched by axios/got")],
    "php": [("php-info", "phpinfo(), include/LFI params, unserialize")],
    "nextjs": [("next-data", "/_next/data/<build>/*.json SSR props leakage, middleware bypass")],
    "nuxt": [("nuxt-state", "__NUXT__ state leakage across users")],
    "sharepoint": [("sharepoint-download", "download.aspx?SourceUrl= handling")],
    "aws-s3": [("s3-perms", "bucket list/read/write with an unauth and an authed principal")],
    "cloudflare": [("origin-ip", "origin discovery: historical DNS, cert SANs, direct-IP vhosts")],
    "akamai": [("origin-ip", "origin discovery: historical DNS, cert SANs, direct-IP vhosts")],
    "cloudfront": [("cache-keys", "cache poisoning / deception: unkeyed headers and paths")],
}


def fingerprint(headers: Dict[str, str], body: str, set_cookie: str = "") -> List[str]:
    tags: List[str] = []
    for tag, where, pat in SIGNATURES:
        if where == "body":
            hay = body[:300_000]
        elif where == "cookie":
            hay = set_cookie
        else:
            hay = headers.get(where.split(":", 1)[1], "")
        if hay and re.search(pat, hay, re.I) and tag not in tags:
            tags.append(tag)
    return tags


def is_spa(body: str, tags: List[str]) -> bool:
    if SPA_TAGS & set(tags):
        return True
    text = re.sub(r"<script.*?</script>|<style.*?</style>|<[^>]+>", " ", body, flags=re.S)
    return len(text.split()) < 80 and bool(re.search(r"<script[^>]+src=", body, re.I))


def takeover_match(body: str) -> List[str]:
    return [svc for svc, pat in TAKEOVER_SIGNATURES.items() if re.search(pat, body[:100_000])]


def packs_for(tags: List[str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for t in tags:
        for check_id, what in PACKS.get(t, []):
            out[f"pack:{check_id}"] = f"[{t}] {what}"
    return out
