#!/usr/bin/env python3
"""
corpus.py
---------
Selects N from manifest.json and writes corpus.json — the frozen set the
validation run is performed over.

Two jobs, in order:

  1. FILTER    to what is in scope: os == linux, arch in {x86, x86_64}, and
               bytes actually extracted. See docs/scope.md.

  2. SELECT    ~N, spread across effect categories and both architectures
               rather than picked for likelihood of passing. The deliverable
               is a failure taxonomy; a corpus of clean execve payloads yields
               one bucket and no signal.

There is deliberately no normalisation step. manifest.py emits the
docs/schema.md vocabulary directly, so records are consumed as they are
found.

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

IN_SCOPE_OS = "linux"
IN_SCOPE_ARCH = ("x86", "x86_64")

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


def _match_text(claimed_effect: str) -> str:
    """
    Filename form -> matchable text: drop the .c, underscores to spaces.

    manifest.py stores claimed_effect as the raw filename
    ("Read_-etc-passwd.c"). RULES is written against prose, and two of its
    patterns match on a trailing space, so matching against the raw form
    would silently stop firing. Derived on the fly rather than stored --
    the category it produces is already on the record, and a second stored
    field would only be able to disagree with the first.
    """
    stem = claimed_effect.rsplit(".", 1)[0]
    return re.sub(r"\s+", " ", stem.replace("_", " ")).strip().lower()


def categorise(claimed_effect: str) -> str:
    s = _match_text(claimed_effect)
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


ESCAPE = re.compile(r"\\x[0-9a-fA-F]{2}")


def truncated(path: Path, bucket: str, length: int) -> bool:
    """
    True if far fewer bytes came out than the source obviously contains.

    Guards one known defect in manifest.py's F2 handling: LOOSE_HEX_RUN
    matches a *contiguous* run of escapes and keeps only the longest, so a
    payload printed as a `;`-prefixed comment block -- one line per 13 bytes,
    which is how several x86_64 files in this mirror are written -- yields a
    single line and silently discards the rest.

    Deliberately narrow. Only the asm bucket is checked, because that is the
    only place the longest-run behaviour applies; the hex and ascii paths read
    a real declaration and are not affected. Remove this once the extractor is
    fixed upstream -- it is a gate on untrustworthy input, not a second
    extractor.
    """
    if bucket != "asm":
        return False
    try:
        found = len(ESCAPE.findall(path.read_text(errors="replace")))
    except OSError:
        return False
    return found > 0 and length < found


# Smallest payload that could possibly implement each effect. Only categories
# where "too short to be real" is a matter of physics are listed: a socket
# plus bind/listen/accept plus dup2 plus execve cannot fit in 20 bytes, and
# neither can opening /etc/passwd and writing a line to it. Categories where
# short really is legitimate are deliberately absent -- exit(0) is 3 bytes,
# sys_sync is 6, and an egghunter is short by design because the payload it
# searches for is not part of it.
MIN_PLAUSIBLE = {
    "bind_shell": 20,
    "reverse_shell": 20,
    "net_other": 20,
    "add_user": 20,
}


def implausible(category: str, length: int) -> bool:
    """
    True if the payload is too short to be what it claims.

    Catches extraction failures that the truncated() check cannot see because
    they happen in the hex bucket, where the extractor reads a real (but
    wrong) declaration rather than a partial one. The live example is
    Linux/x86/connect_back&send;&exit;_-etc-shadow.c, which yields 2 bytes:
    its file documents a `char shellcode[]="\x31\xdb"` snippet inside a `;`
    asm comment, and comment stripping upstream only handles /* */ and //, so
    the snippet is matched as the declaration.

    A ratio test was tried first and rejected -- extracted-versus-present
    ratios form a continuous distribution in which real egghunters (16%) sit
    below real truncations (11%), so no threshold separates them. Absolute
    floors reason about the payload instead of about the extractor, so they
    do not misfire on payloads that are legitimately tiny.
    """
    floor = MIN_PLAUSIBLE.get(category)
    return floor is not None and length < floor


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

    # 1. filter
    pool = []
    excluded = []
    for r in records:
        if r["os"] != IN_SCOPE_OS or r["arch"] not in IN_SCOPE_ARCH:
            continue
        if not r["supported"]:
            continue
        src = Path(args.root) / r["path"]
        category = categorise(r["claimed_effect"])
        if truncated(src, r["bucket"], r["length"]):
            excluded.append(("truncated", r["path"], r["length"]))
            continue
        if implausible(category, r["length"]):
            excluded.append(("implausible", r["path"], r["length"]))
            continue
        pool.append({
            "path": r["path"],
            "os": r["os"],
            "arch": r["arch"],
            "claimed_effect": r["claimed_effect"],
            "category": category,
            "length": r["length"],
            "bytes": r["bytes"],
            "bucket": r["bucket"],
            "doc_ratio": round(doc_ratio(src), 3),
        })

    # 2. select
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
    if excluded:
        print(f"EXCLUDED {len(excluded)} record(s) -- upstream extraction "
              f"defects in manifest.py, see truncated() and implausible():")
        for reason, path, length in sorted(excluded):
            print(f"  {reason:12} {length:4}b  {path}")
        print()
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
