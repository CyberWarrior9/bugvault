#!/usr/bin/env python3
"""Corpus analysis: format, quality, and quantity of paid HackerOne reports.

Produces the statistics behind docs/h1-report-standard.md:
  - section/evidence prevalence (bounty vs no-bounty)
  - length distributions and bounty rate by length bucket
  - bounty rate by weakness class
  - informative-vs-resolved structural comparison
"""
import re
from collections import Counter

import pyarrow.parquet as pq

PARQUET = "h1_train.parquet"

PATTERNS = {
    "Steps to Reproduce": r"steps?\s+to\s+reproduc",
    "Impact section": r"^#+\s*impact|^impact\b",
    "Summary section": r"^#+\s*summary|^summary\b",
    "PoC labeled": r"proof[- ]of[- ]concept|\bpoc\b",
    "Code blocks": r"```",
    "HTTP request evidence": r"(GET|POST|PUT|DELETE)\s+/\S+\s+HTTP",
    "Payload included": r"<script|onerror|union\s+select|\bor\s+1=1|sleep\(",
    "Specific URL": r"https?://[\w\.\-]+\.[a-z]{2,}",
    "Screenshot refs": r"!\[|\.png|\.jpg|screenshot",
    "CVE reference": r"CVE-\d{4}-\d{4,}",
}


def pct(x, n):
    return f"{100 * x / n:.1f}%"


def main():
    t = pq.read_table(PARQUET)
    cols = {c: t.column(c).to_pylist() for c in t.column_names}
    n = len(cols["id"])
    print(f"TOTAL ROWS: {n}")
    print(f"substates: {Counter(cols['substate']).most_common()}")
    print(f"with bounty: {sum(1 for b in cols['has_bounty?'] if b)}")

    idx_content = [i for i, v in enumerate(cols["vulnerability_information"]) if v and v.strip()]
    bounty = [i for i in idx_content if cols["has_bounty?"][i]]
    nobounty = [i for i in idx_content if not cols["has_bounty?"][i]]
    print(f"\nwith content: {len(idx_content)} (bounty {len(bounty)} / no-bounty {len(nobounty)})")

    cb, cn = Counter(), Counter()
    for i in idx_content:
        body = cols["vulnerability_information"][i]
        tgt = cb if cols["has_bounty?"][i] else cn
        for name, pat in PATTERNS.items():
            if re.search(pat, body, re.I | re.M):
                tgt[name] += 1

    print(f"\n{'ELEMENT':28} {'BOUNTY':>8} {'NO-BOUNTY':>10}")
    for name in PATTERNS:
        print(f"{name:28} {pct(cb[name], len(bounty)):>8} {pct(cn[name], len(nobounty)):>10}")

    for label, idxs in (("bounty", bounty), ("no-bounty", nobounty)):
        lens = sorted(len(cols["vulnerability_information"][i]) for i in idxs)
        print(f"\n{label} body chars: median={lens[len(lens)//2]:,} "
              f"mean={sum(lens)//len(lens):,} p90={lens[int(len(lens)*0.9)]:,}")

    # bounty rate by length (resolved only)
    res = [i for i in idx_content if cols["substate"][i] == "resolved"]
    print("\nbounty rate by report length (resolved):")
    for name, lo, hi in (("<300", 0, 300), ("300-1k", 300, 1000), ("1k-3k", 1000, 3000),
                         ("3k-10k", 3000, 10000), (">10k", 10000, 10**9)):
        grp = [i for i in res if lo <= len(cols["vulnerability_information"][i]) < hi]
        if grp:
            rate = 100 * sum(1 for i in grp if cols["has_bounty?"][i]) / len(grp)
            print(f"  {name:>8}: {rate:5.1f}% (n={len(grp)})")

    # bounty rate by weakness (n>=40)
    wc, wb = Counter(), Counter()
    for i in range(n):
        w = cols["weakness"][i]
        if isinstance(w, dict) and w.get("name"):
            wc[w["name"]] += 1
            if cols["has_bounty?"][i] and cols["vulnerability_information"][i]:
                wb[w["name"]] += 1
    print("\nbounty rate by weakness (n>=40):")
    rows = sorted(((w, wb[w], wc[w]) for w in wc if wc[w] >= 40), key=lambda x: -(x[1] / x[2]))
    for w, b, c in rows[:15]:
        print(f"  {100*b/c:5.1f}%  ({b:>4}/{c:>4})  {w}")


if __name__ == "__main__":
    main()
