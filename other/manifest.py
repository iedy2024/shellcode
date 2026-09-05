#!/usr/bin/env python3
"""
manifest.py
------------
Builds manifest.json in the exact shape docs/schema.md freezes for
validate(bytes, arch, os, claimed_effect). This file follows that schema,
not the other way around -- if something here disagrees with schema.md,
schema.md wins and this file is wrong.

Field-by-field, per schema.md:
  path            -- repo-relative path. THE primary key (schema.md is
                     explicit: no separate id, because no path in the
                     mirror has a space in it, so path is already safe as
                     a whitespace-delimited field everywhere).
  bytes           -- lowercase hex string, no 0x, no separators, even
                     length. This is the ONLY place hex ever appears --
                     schema.md is explicit that neither harness parses
                     hex, so whatever we hand off here has to already be
                     in exactly this form.
  arch            -- exactly "x86" or "x86_64". The directory on disk is
                     literally "Linux/x86-64" with a HYPHEN -- schema.md
                     calls this out specifically because it's an easy
                     mismatch to introduce by accident (copy the folder
                     name verbatim and you've violated the schema on the
                     first field). Normalised here, once, so nothing
                     downstream ever sees the hyphen form.
  os              -- exactly "linux" or "windows", lowercase, always.
                     Directory names on disk are "Linux"/"Windows"
                     (capitalised) -- lowercased here for the same reason
                     as arch: normalise at the one place bytes leave this
                     script, not in every consumer.
  claimed_effect  -- schema.md's own example for this field is written
                     WITH the .c extension and WITH underscores intact
                     ("setuid(0)_&_chmod_(-etc-passwd,_0777)_&_exit(0).c"),
                     i.e. the raw filename, unmodified. Took that
                     literally instead of guessing at a "nicer" de-slugged
                     form -- schema.md's whole ethos is measured, not
                     assumed, so this doesn't invent a transformation the
                     schema doesn't ask for.
  length          -- len(bytes), computed, never trusted from an in-file
                     "N bytes" comment (schema.md: those are frequently
                     per-instruction comments, not payload length).

Byte extraction, per docs/recon.md's format table:
  F1 (char[] hex array)         -> handled, same declaration-based
                                    extraction as before.
  F2 (asm + loose \\x.. blob,
      no array)                 -> NEW in this pass. recon.md named the
                                    exact gap: classify.py buckets these
                                    as "asm" (correct, as a *format*
                                    label), but the old extractor read
                                    that bucket as "no bytes available"
                                    and stopped there. Fixed by scanning
                                    for a long run of \\x escapes with no
                                    quotes required around them at all --
                                    see extract_loose_hex_blob().
  F3 (asm source, no bytes)     -> still genuinely nothing to extract.
                                    Correctly stays unsupported.
  F4 (ascii payload)            -> handled, unchanged.
  F5 (unmatched by classify.py) -> not fixed in this pass. recon.md notes
                                    7 of 8 of these do contain recoverable
                                    hex; left as a follow-up, not silently
                                    claimed done here.

Usage:
    python3 scripts/manifest.py <path-to-corpus> [--out manifest.json]
"""
import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from classify import classify

DECL = re.compile(r"""
(?s)
(unsigned\s+char|char)
\s+
(\w+\s*\[\s*\]|\*\s*\w+)
\s*=\s*
(?:
    (?:
          /\*.*?\*/
        | //[^\n]*
        | \\
        | \{
    )
    \s*
)*
(?P<body>"(?:\\.|[^"\\])*"(?:\s*"(?:\\.|[^"\\])*")*)
""", re.VERBOSE)

STRING_LITERAL = re.compile(r'"((?:\\.|[^"\\])*)"', re.DOTALL)
HEX_ESCAPE = re.compile(r"\\x([0-9a-fA-F]{2})")

# F2 fix: a run of \xNN escapes with NO quotes required at all -- the
# blob in these files sits bare after a "Shellcode:" label (see
# Linux/x86-64/Read_-etc-passwd.c, recon.md's named example). Threshold
# of 8+ consecutive escapes so an isolated \xNN mentioned in prose
# somewhere doesn't get mistaken for a real payload -- a real blob here
# runs to dozens of bytes, a stray mention in a comment doesn't.
LOOSE_HEX_RUN = re.compile(r"(?:\\x[0-9a-fA-F]{2}){8,}")

COMMENT_BLOCK = re.compile(r"/\*.*?\*/", re.DOTALL)
COMMENT_LINE = re.compile(r"//[^\n]*")

KNOWN_ARCH_DIRS = {
    "x86", "x86-64", "32bits", "arm", "strongarm", "mips", "sparc", "ppc",
}

# schema.md's enum is only x86/x86_64 (Linux-side scope is those two only,
# per docs/scope.md). Everything else still gets extracted into
# manifest.json -- scope.md: "Everything else in the mirror is extracted
# into manifest.json but never validated" -- so we normalise those too,
# for consistency, even though they're outside the frozen enum.
ARCH_NORMALISE = {
    "x86-64": "x86_64",
    "32bits": "x86",
}


def strip_comments(text: str) -> str:
    """Strip C comments before hunting for a declaration -- a comment
    between two concatenated string literals stops naive concatenation
    dead (found on Bind_TCP_Port.c: a trailing /* port number */ comment
    truncated extraction from 103 bytes to 4). Comments are removed
    first so that trap can't happen."""
    text = COMMENT_BLOCK.sub(" ", text)
    text = COMMENT_LINE.sub(" ", text)
    return text


def extract_bytes_for_bucket(text: str, bucket: str) -> bytes:
    text = strip_comments(text)

    if bucket == "hex":
        m = DECL.search(text)
        if not m:
            return b""
        chunks = []
        for lit in STRING_LITERAL.finditer(m.group("body")):
            chunks.append(bytes(int(h, 16) for h in HEX_ESCAPE.findall(lit.group(1))))
        return b"".join(chunks)

    if bucket == "ascii":
        m = DECL.search(text)
        if not m:
            return b""
        chunks = []
        for lit in STRING_LITERAL.finditer(m.group("body")):
            chunks.append(lit.group(1).encode("latin-1", errors="replace"))
        return b"".join(chunks)

    if bucket == "asm":
        # F2 fix (see module docstring): classify.py is right that this
        # is asm *format*, but recon.md's point stands -- "asm" must
        # never silently mean "no bytes". Look for a bare \x run before
        # giving up.
        runs = LOOSE_HEX_RUN.findall(text)
        if not runs:
            return b""
        longest = max(runs, key=len)
        return bytes(int(h, 16) for h in HEX_ESCAPE.findall(longest))

    return b""  # other / empty -- genuinely nothing to extract


def resolve_arch_os(relative_path: Path):
    parts = relative_path.parts
    os_name = parts[0].lower()  # schema.md: lowercase, always
    arch = None
    if len(parts) > 2 and parts[1].lower() in KNOWN_ARCH_DIRS:
        raw_arch = parts[1].lower()
        arch = ARCH_NORMALISE.get(raw_arch, raw_arch)
    return os_name, arch


def build_record(root: Path, path: Path) -> dict:
    text = path.read_text(errors="replace")
    bucket = classify(path)
    data = extract_bytes_for_bucket(text, bucket)
    rel = path.relative_to(root)
    os_name, arch = resolve_arch_os(rel)

    return {
        "path": str(rel),
        "bucket": bucket,
        "os": os_name,
        "arch": arch,
        "length": len(data),
        "bytes": data.hex() if data else None,  # lowercase, no 0x, per schema.md
        "claimed_effect": path.name,  # raw filename, per schema.md's own example
        "supported": len(data) > 0,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("root", help="path to the cloned corpus")
    parser.add_argument("--out", default="manifest.json")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    records = []
    for p in sorted(root.rglob("*.c")):
        if ".git" in p.parts:
            continue
        records.append(build_record(root, p))

    Path(args.out).write_text(json.dumps(records, indent=2))

    supported = sum(1 for r in records if r["supported"])
    print(f"{len(records)} files scanned, {supported} with extracted bytes "
          f"(manifest written to {args.out})")

    from collections import Counter
    print(Counter(r["bucket"] for r in records))

    in_scope = [r for r in records if r["os"] == "linux" and r["arch"] in ("x86", "x86_64")]
    in_scope_supported = sum(1 for r in in_scope if r["supported"])
    print(f"in-scope (linux, x86/x86_64): {len(in_scope)} files, "
          f"{in_scope_supported} with bytes")


if __name__ == "__main__":
    main()