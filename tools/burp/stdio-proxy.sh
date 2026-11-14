#!/bin/sh
# Optional bridge for stdio-only clients. OpenCode/Claude Code use /mcp directly.
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
jar="$here/mcp-proxy.jar"
python3 -I - "$jar" <<'PY'
import hashlib, pathlib, sys
path = pathlib.Path(sys.argv[1])
expected = 'b6e12ccf8bc3afcdf8b891cd23c29315915ade985126a07fe22a875e9cd3c09e'
if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
    raise SystemExit('Burp MCP proxy JAR missing or checksum changed; inspect it before use')
PY
java=${BURP_JAVA_BIN:-/Applications/Burp Suite.app/Contents/Resources/jre.bundle/Contents/Home/bin/java}
if [ ! -x "$java" ]; then
    java=$(command -v java) || { echo 'Java not found; set BURP_JAVA_BIN' >&2; exit 1; }
fi
exec "$java" -jar "$jar" --sse-url http://127.0.0.1:9876
