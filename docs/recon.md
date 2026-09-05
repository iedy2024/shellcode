# Repo recon — Linux/x86 and Linux/x86_64

Measured, not assumed. Re-run the commands at the bottom to refresh these
numbers.

## Layout

Flat `OS/arch/` tree, one file per shellcode. **Every file has a `.c`
extension regardless of what it actually contains** — the scrape could not
recover the real filetype. Many are assembly, one is empty.

In-scope pool is **283 files**: `Linux/x86` (245) and `Linux/x86-64` (38).

## Byte-storage formats

The mirror has five, not one. Ids are used by the extractor's dispatch.

| id | format | count | extractable | rule |
|----|--------|-------|-------------|------|
| F1 | C hex array — `unsigned char code[] = "\x31\xc0…"` | 244 | yes | the common case |
| F2 | asm source + loose `\x..` blob, in no array | 8 | yes | blob usually follows a `Shellcode:` line |
| F3 | asm source only, no bytes present | 15 | **no** | excluded from N; assembling is out of scope |
| F4 | alphanumeric/ASCII payload — the string *is* the bytes | 1 | yes | no `\x` by construction |
| F5 | unmatched by the current router | 8 | 7 of 8 | contain hex the `char[]` regex misses |

Plus 6 files with a `char[]` declaration but fewer than 8 `\x` escapes, and 1
empty file.

Totals: **259 files carry hex**, 1 more is ASCII-payload, and **23 yield no
bytes**. 260 extractable candidates against a target of N ≈ 60 — comfortable
headroom, so selection can be made on spread rather than on availability.

**`other/classify.py` has a known gap here.** It returns `asm` for F2 files
that carry both assembly source and a usable hex blob —
`Linux/x86-64/Read_-etc-passwd.c` is the clean example, 82 bytes sitting after
the assembly, bucketed `asm`. The bucket name is fine as a *format* label, but
the extractor must never read `asm` as "no bytes".

## Where the metadata lives

There is **no consistent title line**. Only 10 of 283 files carry a
shell-storm-style `Linux/x86 - … - N bytes` header. This determines the
record shape:

- **`arch` / `os` — from the directory path.** The only reliable source. Note
  the directory is `Linux/x86-64` with a hyphen; the extractor normalises to
  `x86_64` with an underscore per `docs/schema.md`, and nothing downstream
  ever sees the hyphen form.
- **`claimed_effect` — from the filename.** The filename is the shell-storm
  title, slugged (`/` → `-`, space → `_`), and is rich and specific:
  `setuid(0)_&_chmod_(-etc-passwd,_0777)_&_exit(0).c`. Not recoverable from
  file contents in the general case.
- **`length` — computed from the extracted bytes.** 207 files mention
  "N bytes" somewhere, but in incompatible contexts: `; 16 bytes from buf` is
  a per-instruction comment, not a payload length. Any in-file claim is a
  cross-check that raises a flag on mismatch, never the source.
- **`path` is the primary key.** No separate id — see `docs/schema.md` for
  why.

## Character safety

**No file in the entire mirror has a space in its path.** Paths are therefore
safe as whitespace-delimited fields in the `RESULT` line and safe under shell
word-splitting.

In-scope filenames do use `! & ( ) + , - . ; = @ [ ] ^ _ { }`. These are inert
to grep and awk, which work on lines rather than shell syntax, but any path
substituted into a shell command in the workflow must be quoted. Longest
in-scope path is 84 characters.

## Commands used

```sh
find Linux/x86 Linux/x86-64 -type f | wc -l
find . -path ./.venv -prune -o -type f -name '* *' -print   # space check
find Linux/x86 Linux/x86-64 -type f -printf '%f\n' | grep -o '[^A-Za-z0-9]' | sort -u
python other/classify.py Linux/x86
```
