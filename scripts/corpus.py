#!/usr/bin/env python3
"""
corpus.py
---------
Selects N from manifest.json and writes corpus.json — the frozen set the
validation run is performed over.

Three jobs, in order:

  1. FILTER    to what is in scope: os == linux, arch in {x86, x86_64}, and
               bytes actually extracted. See docs/scope.md.

  2. NORMALISE to the vocabulary in docs/schema.md. manifest.py emits the raw
               directory names ("Linux", "x86-64") and its own key names; the
               schema mandates "linux", "x86_64", and path/length/bytes/format.
               The translation happens here, at the boundary, so nothing
               downstream of corpus.json ever sees the un-normalised form.

  3. SELECT    ~N, spread across effect categories and both architectures
               rather than picked for likelihood of passing. The deliverable
               is a failure taxonomy; a corpus of clean execve payloads yields
               one bucket and no signal.

Selection is deterministic — same manifest in, same corpus out, so the
committed file diffs cleanly when the mirror changes.

Usage:
    python3 scripts/corpus.py [--manifest manifest.json] [--out corpus.json] [-n 60]
"""
import argparse
import json
import re
from collections import defaultdict
from pathlib import Path

# --- scope ------------------------------------------------------------------

ARCH_NORMALISE = {"x86": "x86", "x86-64": "x86_64"}   # docs/schema.md vocabulary
OS_NORMALISE = {"Linux": "linux"}

# --- effect categories ------------------------------------------------------
# Derived from docs/classes.md. Ordered: first match wins, so the more specific
# network patterns are tested before the generic execve one — a bind shell ends
# in execve("/bin/sh") too, and would otherwise be swallowed by execve_shell.

RULES = [
    ("bind_shell",    r"bind|listen.*port|port.*bind|portshell"),
    ("reverse_shell", r"reverse|connect[_ ]?back|back[_ ]?connect|connectback"),
    ("execve_shell",  r"execve|/bin/sh|bin-sh|bin sh|/bin/bash|bin-bash|zsh|ksh|csh|ash"),
    ("add_user",      r"add.*user|add.*root|passwd.*add|/etc/passwd|etc-passwd|shadow"),
    ("chmod_chown",   r"chmod|chown|setuid|setreuid|setgid|seteuid"),
    ("file_op",       r"read|write|open|cat |copy|unlink|mkdir|rm |file|dir|touch"),
    ("egghunter",     r"egg[_ ]?hunt|stager|stage"),
    ("encoder",       r"encod|xor|polymorph|alpha[- ]?numeric|alphanumeric|obfusc|self[- ]?modif"),
    ("proc_kill",     r"kill|reboot|shutdown|halt|power[_ ]?off|exit"),
    ("net_other",     r"socket|download|http|udp|tcp|icmp|dns"),
    ("system_state",  r"iptables|aslr|hostname|sethostname|apparmor|selinux|mbr|dev/sda"),
]


def categorise(claimed_effect: str) -> str:
    s = claimed_effect.lower()
    for name, pattern in RULES:
        if re.search(pattern, s):
            return name
    return "uncategorised"


def doc_ratio(path: Path) -> float:
    """
    Fraction of the source file that is comment text.

    Used as a proxy for how well annotated a shellcode is. docs/scope.md asks
    for deliberately old, undocumented and badly annotated entries in the
    corpus, because that is where the interesting failures live. Selecting a
    spread of this value inside each category is how that is honoured without
    hand-reading 250 files.
    """
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return 0.0
    if not text:
        return 0.0
    comment = sum(len(m.group(0)) for m in re.finditer(
        r"/\*.*?\*/|//[^\n]*|^\s*;[^\n]*|^\s*#[^\n]*", text, re.S | re.M))
    return comment / len(text)


def spread(items, k):
    """Take k items evenly spaced across a sorted list, always including both ends."""
    if k >= len(items):
        return list(items)
    if k == 1:
        return [items[0]]
    step = (len(items) - 1) / (k - 1)
    return [items[round(i * step)] for i in range(k)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", default="manifest.json")
    ap.add_argument("--out", default="corpus.json")
    ap.add_argument("-n", type=int, default=60)
    ap.add_argument("--root", default=".")
    args = ap.parse_args()

    records = json.loads(Path(args.manifest).read_text())

    # 1. filter + 2. normalise
    pool = []
    for r in records:
        if r["os"] not in OS_NORMALISE or r["arch"] not in ARCH_NORMALISE:
            continue
        if not r["supported"]:
            continue
        path = r["source_file"]
        pool.append({
            "path": path,
            "os": OS_NORMALISE[r["os"]],
            "arch": ARCH_NORMALISE[r["arch"]],
            "claimed_effect": r["claimed_effect"],
            "category": categorise(r["claimed_effect"]),
            "length": r["byte_count"],
            "bytes": r["bytes_hex"],
            "source_title": Path(path).name,
            "format": r["bucket"],
            "doc_ratio": round(doc_ratio(Path(args.root) / path), 3),
            "flags": [],
        })

    # 3. select
    by_cat = defaultdict(list)
    for r in pool:
        by_cat[r["category"]].append(r)

    # Quota: even split, then redistribute what small categories cannot fill.
    cats = sorted(by_cat)
    quota = {c: args.n // len(cats) for c in cats}
    leftover = args.n - sum(quota.values())
    short = sum(max(0, quota[c] - len(by_cat[c])) for c in cats)
    for c in cats:
        quota[c] = min(quota[c], len(by_cat[c]))
    # hand the shortfall to the categories that still have material, largest first
    spare = leftover + short
    for c in sorted(cats, key=lambda c: -len(by_cat[c])):
        if spare <= 0:
            break
        take = min(spare, len(by_cat[c]) - quota[c])
        quota[c] += take
        spare -= take

    selected = []
    for c in cats:
        group = by_cat[c]
        # Both architectures must appear in a category that has both. x86_64
        # is scarce (26 of 250), so an unconstrained pick starves x86 in every
        # category where 64-bit examples exist -- which silently left the
        # largest category, execve_shell, with no 32-bit payload at all. Split
        # the quota, then let whichever arch has material absorb the shortfall.
        wide = sorted((r for r in group if r["arch"] == "x86_64"),
                      key=lambda r: (r["doc_ratio"], r["path"]))
        rest = sorted((r for r in group if r["arch"] == "x86"),
                      key=lambda r: (r["doc_ratio"], r["path"]))
        want_wide = min(len(wide), quota[c] // 2 or (1 if wide else 0))
        want_rest = min(len(rest), quota[c] - want_wide)
        want_wide = min(len(wide), quota[c] - want_rest)   # absorb any shortfall
        selected.extend(spread(wide, want_wide) + spread(rest, want_rest))

    selected.sort(key=lambda r: r["path"])          # deterministic on disk
    Path(args.out).write_text(json.dumps(selected, indent=2) + "\n")

    # summary
    print(f"pool (in scope, bytes extracted): {len(pool)}")
    print(f"selected: {len(selected)} -> {args.out}\n")
    print(f"{'category':16} {'pool':>5} {'sel':>4} {'x86':>4} {'x86_64':>7}")
    for c in cats:
        s = [r for r in selected if r["category"] == c]
        print(f"{c:16} {len(by_cat[c]):5} {len(s):4} "
              f"{sum(r['arch']=='x86' for r in s):4} {sum(r['arch']=='x86_64' for r in s):7}")
    tot = selected
    print(f"{'TOTAL':16} {len(pool):5} {len(tot):4} "
          f"{sum(r['arch']=='x86' for r in tot):4} {sum(r['arch']=='x86_64' for r in tot):7}")
    dr = sorted(r["doc_ratio"] for r in tot)
    print(f"\ndoc_ratio spread: min {dr[0]}  median {dr[len(dr)//2]}  max {dr[-1]}")
    print(f"length spread:    min {min(r['length'] for r in tot)}  "
          f"max {max(r['length'] for r in tot)} bytes")


if __name__ == "__main__":
    main()
