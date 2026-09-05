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
found. The manifest is checked for freshness first -- see check_fresh().

Selection is deterministic — same manifest in, same corpus out, so the
committed file diffs cleanly when the mirror changes.

Usage:
    python3 scripts/corpus.py [--manifest manifest.json] [--out corpus.json] [-n 60]
"""
import argparse
import json
import re
from collections import Counter, defaultdict
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

    A backstop against extraction regressions. It excludes nothing on the
    current manifest -- the case it was written for,
    Linux/x86/connect_back&send;&exit;_-etc-shadow.c, extracted 2 bytes when
    `;` comments went unstripped and a documentation snippet was read as the
    declaration; it now extracts its full 155. The check is kept because it
    reasons about the payload rather than about the extractor, so it stays
    valid as the extractor changes, and because a silently short payload
    enters the taxonomy as a broken shellcode rather than as a broken tool.

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


def check_fresh(manifest: Path, generator: Path) -> str | None:
    """
    Return a complaint if the manifest is older than the tool that writes it.

    corpus.py consumes manifest.json as a file rather than importing
    manifest.py, so nothing structurally ties the two together and a manifest
    left over from a previous version of the extractor reads as perfectly
    valid. That has happened three times: once the key names had changed and
    the scope filter would have matched nothing, and twice the extraction
    itself had improved and the corpus was selected from superseded bytes. In
    none of those cases was an error raised.

    mtime is a crude signal but the right one here -- a checkout or a rebase
    that brings in a new extractor touches its mtime, which is exactly the
    condition worth refusing on.
    """
    if not manifest.exists() or not generator.exists():
        return None
    if generator.stat().st_mtime <= manifest.stat().st_mtime:
        return None
    return (f"{manifest} is older than {generator}.\n"
            f"The manifest was produced by a previous version of the "
            f"extractor; regenerate it first:\n"
            f"    python3 {generator} . --out {manifest}\n"
            f"Pass --allow-stale to select from it anyway.")


def ensure_arch_coverage(selected, pool):
    """
    Guarantee both architectures appear whenever the pool holds both.

    Per-category quotas cannot express a global invariant. At N == 12 every
    category gets a single slot, and a slot can hold only one architecture, so
    whichever rule decides that slot decides the whole corpus: spending every
    one on the scarce architecture inverts the split (9 x86_64 to 3 x86), and
    spending every one on the larger group erases the scarce architecture
    entirely (12 x86, 0 x86_64). Both are wrong for the same reason -- the
    harness has two code paths and the corpus has to exercise both.

    So the split stays proportional by default and this pass repairs the
    corner: if an architecture is missing outright, swap one selected record
    for a pool record of the missing architecture, preferring a swap inside
    the same category so category coverage is preserved. N and the per-category
    counts are unchanged.
    """
    chosen = {r["path"] for r in selected}
    for missing in ("x86_64", "x86"):
        if any(r["arch"] == missing for r in selected):
            continue
        available = [x for x in pool if x["arch"] == missing]
        if not available:
            continue                      # pool genuinely has none; nothing to fix
        for i, r in enumerate(selected):
            same_cat = sorted(
                (x for x in available
                 if x["category"] == r["category"] and x["path"] not in chosen),
                key=lambda x: (x["doc_ratio"], x["path"]))
            if same_cat:
                chosen.discard(r["path"])
                selected[i] = same_cat[0]
                chosen.add(same_cat[0]["path"])
                break
        else:
            # No selected category has material in the missing architecture.
            # Take the best available and displace a record from the largest
            # category, which can most afford to lose one.
            counts = Counter(r["category"] for r in selected)
            victim = max(range(len(selected)),
                         key=lambda i: counts[selected[i]["category"]])
            best = sorted(available, key=lambda x: (x["doc_ratio"], x["path"]))[0]
            selected[victim] = best
    return selected


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", default="manifest.json")
    ap.add_argument("--out", default="corpus.json")
    ap.add_argument("-n", type=int, default=60)
    ap.add_argument("--root", default=".")
    ap.add_argument("--allow-stale", action="store_true",
                    help="select even if the manifest predates the extractor")
    args = ap.parse_args()

    complaint = check_fresh(Path(args.manifest),
                            Path(__file__).parent / "manifest.py")
    if complaint and not args.allow_stale:
        raise SystemExit(f"REFUSING: {complaint}")

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
        q = quota[c]
        if q == 0:
            continue
        if q == 1:
            # One slot cannot hold both architectures. Take from whichever
            # group is larger, preferring x86 on a tie. An earlier version
            # always spent a single slot on x86_64 to guarantee the scarce
            # architecture appeared, which inverted the global split: at
            # N == 12 every category has a quota of 1, and the nine holding
            # 64-bit material each yielded 64-bit only, giving 9 x86_64 to
            # 3 x86 out of a pool that is roughly 90% x86.
            want_wide = 1 if len(wide) > len(rest) else 0
        else:
            # At two slots or more, both architectures appear whenever the
            # category has material for both.
            want_wide = min(len(wide), q // 2)
        want_rest = min(len(rest), q - want_wide)
        want_wide = min(len(wide), q - want_rest)   # absorb any shortfall
        selected.extend(spread(wide, want_wide) + spread(rest, want_rest))

    ensure_arch_coverage(selected, pool)
    selected.sort(key=lambda r: r["path"])          # deterministic on disk
    Path(args.out).write_text(json.dumps(selected, indent=2) + "\n")

    # summary
    if excluded:
        print(f"EXCLUDED {len(excluded)} record(s) -- upstream extraction "
              f"defects in manifest.py, see implausible():")
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
