#!/usr/bin/env python3
"""
manifest.py
------------
Builds on classify.py (which only decides the *bucket* a file falls into)
to actually pull the bytes out and produce the Stage 1 manifest:

    {bytes, arch, OS, claimed_effect, source_file}

Per bucket:
  hex    -> real extraction. Find the same char[] / *ptr declaration
            classify.py detected, pull every \\xNN out of it in order.
  ascii  -> the string literal IS the payload (alphanumeric shellcode,
            no \\x anywhere) -- take the raw chars as bytes, no decoding.
  asm    -> no bytes yet. Needs an assembler (nasm/etc) to turn source
            into bytes -- that's follow-up work, not this script's job.
            Left as null so nothing downstream mistakes "not attempted"
            for "attempted and empty".
  other/empty -> no bytes, flagged unsupported, same reasoning as asm.

arch / OS come from the path, not the file content: this repo is laid
out as System/Architecture/name.c (Linux/x86-64/foo.c) for most
systems, but some have no arch subfolder at all (Windows/foo.c,
Cisco_IOS/foo.c) -- those get arch=None rather than a guess.

claimed_effect is the thing Stage 2 checks the emulated syscalls
against. The plan says it "comes from the shell-storm title" -- the
most reliable place we actually have that title is the filename itself
(that's literally what scrape.py turned it into), so we derive it from
there instead of parsing comments. Comment formats are all over the
place (see other/file_format), filenames aren't.

Usage:
    python3 other/manifest.py <path-to-corpus> [--out manifest.json]
"""
import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from classify import classify  # bucket decision stays classify.py's job, not ours

# Same declaration shape classify.py's DECL looks for, but this time we
# capture the actual quoted payload (as `body`) instead of just checking
# a match exists. Comments are stripped from the whole file BEFORE this
# runs (see strip_comments) -- more on why below.
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

COMMENT_BLOCK = re.compile(r"/\*.*?\*/", re.DOTALL)
COMMENT_LINE = re.compile(r"//[^\n]*")


def strip_comments(text: str) -> str:
    """Strip C comments BEFORE looking for the declaration.

    Found the hard way on Linux/x86/Bind_TCP_Port.c: the shellcode is
    written as several concatenated string literals, and one of them
    has a trailing comment before the next literal starts --

        "\\x2b\\x67" /* <- Port number 11111 (2 bytes) */ "\\x6a\\x66..."

    C string concatenation happily skips over that comment (the
    preprocessor removes it before concatenation ever happens), but a
    regex that only allows whitespace between literals stops dead
    right there. Without this stripping step we silently pulled 4
    bytes out of a 103-byte shellcode -- no error, no crash, just a
    truncated payload with a perfectly normal-looking record. Classic
    "off by a comment" trap, same flavor as the Add_root one.
    """
    text = COMMENT_BLOCK.sub(" ", text)
    text = COMMENT_LINE.sub(" ", text)
    return text


# Folders that mean "this is an architecture", i.e. System/Architecture/
# name.c. Anything else is a system with no arch subfolder at all
# (System/name.c directly) -- those get arch=None, we don't guess.
KNOWN_ARCH_DIRS = {
    "x86", "x86-64", "32bits", "arm", "strongarm", "mips", "sparc", "ppc",
}


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
            # no \x here by definition of this bucket -- the literal
            # characters, as-is, ARE the shellcode bytes.
            chunks.append(lit.group(1).encode("latin-1", errors="replace"))
        return b"".join(chunks)

    return b""  # asm / other / empty -- no bytes in this pass, see module docstring


def resolve_arch_os(relative_path: Path):
    parts = relative_path.parts
    os_name = parts[0]
    if len(parts) > 2 and parts[1].lower() in KNOWN_ARCH_DIRS:
        return os_name, parts[1].lower()
    return os_name, None


def claimed_effect_from_filename(name: str) -> str:
    # Turn "Bind_TCP_Port.c" into "Bind TCP Port". Keeps parens/commas
    # as-is since those usually carry real parameter info in the
    # original shell-storm titles (e.g. "setreuid(0,0)").
    stem = name.rsplit(".", 1)[0]
    text = stem.replace("_", " ")
    text = re.sub(r"\s+", " ", text).strip()
    return text


def build_record(root: Path, path: Path) -> dict:
    text = path.read_text(errors="replace")
    bucket = classify(path)
    data = extract_bytes_for_bucket(text, bucket)
    rel = path.relative_to(root)
    os_name, arch = resolve_arch_os(rel)

    return {
        "source_file": str(rel),
        "bucket": bucket,
        "os": os_name,
        "arch": arch,
        "byte_count": len(data),
        "bytes_hex": data.hex() if data else None,
        "claimed_effect": claimed_effect_from_filename(path.name),
        # bucket says "hex"/"ascii" doesn't guarantee we actually got
        # bytes out of it -- a few files classify as "hex" but the only
        # \x in them turns out to live inside a documentation comment
        # for an asm file, not a real array (extraction correctly
        # returns 0 bytes for those; this flag is what downstream
        # stages should actually check, not `bucket` alone).
        "supported": bucket in ("hex", "ascii") and len(data) > 0,
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


if __name__ == "__main__":
    main()