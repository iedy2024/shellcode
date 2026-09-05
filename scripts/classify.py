#!/usr/bin/env python3
"""
Router: classify each shellcode file into ONE byte-acquisition bucket.
Final format: {bytes, arch, OS, claimed_effect, source_file}

Order:
  empty  -> no usable content            (0 bytes can't lie -> runs first)

  asm    -> assembler source             (must beat hex, or a `db 0x..,0x..`
                                          line in asm gets falsely extracted
                                          -- the Add_root trap)
  ascii  -> char[] whose string IS the   (alphanumeric shellcode; disjoint
            payload, NO \\x in it          from `hex` by construction)

  hex    -> char[] "\\xNN" array          (the common case; safe as fallback
                                          because empty/asm already excluded)
  other  -> matched nothing              (don't guess -- surface it, go cat it)

"""
import re
import sys
from collections import Counter
from pathlib import Path

def classify(path: Path) -> str:
    text = path.read_text(errors="replace")

    # 1. empty — can't lie, runs first
    if not text.strip():
        return "empty"

    # 2. hex — a REAL array declaration: char name[] = "  (\s* spans the
    #    newline, because we search the whole-file string, not lines).
    #    MUST come before asm: files carry asm source in a COMMENT plus a
    #    real \x array below. If asm ran first, return "asm" fires and these
    #    bytes are never read. The array declaration is the honest signal;
    #    a ;\x48 comment has no `char x[] =` in front of it, so it won't match.
    #    Between `=` and the opening `"` we skip any run of: /* */ or // comments
    #    and `\` line-continuations (the `char *SC = /* ... */ "\x.."` variant).
    #    (?s) so a /* */ block comment can span newlines.
    DECL = re.compile(r"""
    (?s)                          # DOTALL: '.' also matches newlines
                                  #   (so a multi-line /* */ comment is skipped whole)

    (unsigned\s+char | char)      # the type:  'unsigned char'  or  'char'
    \s+

    (\w+\s*\[\s*\] | \*\s*\w+ )   # arry format: name[] OR *name

    \s* = \s*                     # the '='  (whitespace either side)

    (?:                           # then any run of "gap junk", zero or more times:
        (?:
              /\* .*? \*/         #   a  /* block comment */   (lazy: stops at first */)
            | // [^\n]*           #   or a  // line comment   (to end of line)
            | \\                  #   or a line-continuation backslash
            | {                   #   or a stray '{'
        )
        \s*
    )*

    "                             # ...until the opening quote of the byte string
""", re.VERBOSE)
    if re.search(DECL, text):
        if re.search(r"\\x[0-9a-fA-F]{2}", text):
            return "hex"
        else:
            return "ascii"        # char[] present, no \x -> the chars ARE the bytes

    # 3. asm — only reached if there's NO real array. asm structure, anchored
    #    to line-start (?m)^ so a directive quoted mid-comment doesn't count.
    if re.search(r"(?m)^\s*(section\s+\.text|\.?globl\s+_start|global\s+_start|_start:|BITS\s+64)", text):
        return "asm"

    # 4. nothing matched — don't guess, surface it
    return "other"

def main(root: str) -> None:
    total = Counter()
    others = []
    for p in sorted(Path(root).rglob("*.c")):
        if ".git" in p.parts:
            continue
        bucket = classify(p)
        total[bucket] += 1
        if bucket == "other":
            others.append(p)

    for bucket, n in total.most_common():
        print(f"{bucket:6} {n}")
    print(f"{'TOTAL':6} {sum(total.values())}")

    if others:
        print("\n-- OTHER (go cat these) --")
        for p in others:
            print(p)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else ".")

