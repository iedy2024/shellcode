# Interface schema

```
validate(bytes, arch, os, claimed_effect) -> {verdict, syscalls, reason}
```

This signature is frozen. The Linux harness and the Windows harness return
objects that are literally interchangeable. If something here turns out to be
wrong, it is changed in this document first and in both implementations
together — never on one side alone.

Every vocabulary below is **enumerated, not described**. A value not on a list
is a bug, not a variant.

---

## Inputs

### `bytes`

Raw bytes. Python `bytes`, not `str`, not a hex string. Not length-prefixed —
the payload length is `len(bytes)` and nothing else.

Hex only appears at the storage boundary: `manifest.json` and `corpus.json`
carry the payload as a **lowercase hex string, no `0x`, no separators, no
whitespace, even number of characters**. The caller decodes before calling
`validate()`. Neither harness ever parses hex.

### `arch`

Exactly one of:

- `"x86"`
- `"x86_64"`

Not `i386`. Not `x86-64`. Not `amd64`. Not `x64`. The mirror's directory is
literally named `Linux/x86-64` with a hyphen; the extractor normalises it to
`x86_64` with an underscore and nothing downstream ever sees the hyphen form.

### `os`

Exactly one of:

- `"linux"`
- `"windows"`

Lowercase. Always.

### `claimed_effect`

Free text. This is the one field that is deliberately unstructured — it is the
human claim being tested, taken from the mirror, and the mirror's claims are
prose. Derived from the filename, which is the shell-storm title slugged
(`/` → `-`, space → `_`), because only 10 of 283 in-scope files carry a usable
title line in their contents.

The harness does not parse it. It is echoed for reporting and read by a human
when a verdict is disputed. Matching a payload's behaviour against its claim is
done by the per-effect check the harness selects, not by string analysis of
this field.

---

## Outputs

### `verdict`

Exactly one of:

- `"pass"`
- `"fail"`
- `"inconclusive"`

**The fail/inconclusive boundary.** Both harnesses use this rule and it is the
single most important line in this document:

> `fail` means the harness got a trustworthy observation and the observation
> contradicts the claim.
> `inconclusive` means the harness could not get a trustworthy observation.

`fail` is a statement about the shellcode. `inconclusive` is a statement about
the harness. When in doubt, return `inconclusive` — a false `fail` is a bug
report filed against an innocent payload, and those are expensive to unwind.

Concretely, `inconclusive` covers: emulator setup error; timeout; the payload
blocking on a peer that will never connect; a syscall the emulator does not
implement; self-modifying or egghunter code that needs memory the harness did
not stage; any crash the harness cannot attribute to the payload itself.

`fail` covers: the payload ran to a clean end and the expected syscall sequence
did not occur; it faulted on its own bytes (bad opcode, unmapped access from
its own addressing); it executed a materially different effect from the one
claimed.

### `syscalls`

An **ordered list**, chronological, one entry per syscall actually invoked.
Order is part of the data — `socket` then `bind` then `listen` is the claim
being tested, so an unordered set would throw away the evidence.

Each entry:

```json
{"n": 59, "name": "execve", "args": ["/bin/sh", ["/bin/sh"], null], "ret": 0}
```

- `n` — integer syscall number, as seen on that arch. Note the same name has
  different numbers on x86 and x86_64 (`execve` is 11 on x86, 59 on x86_64);
  `n` is the raw number, never normalised.
- `name` — lowercase, no `sys_` prefix, no `SYS_` prefix. `"unknown"` if the
  number is not in the table for that arch.
- `args` — included. Best-effort: pointers are dereferenced to strings where
  the harness can do so safely, otherwise the integer value is kept. A payload
  that calls `execve` on the wrong path is a `fail` we can only see if the args
  are here.
- `ret` — integer return value, or `null` if the call did not return.

Empty list is legal and meaningful: it means the payload invoked no syscalls.

### `reason`

**A machine-parseable code from a fixed vocabulary. Not free text.** Harness
output is parsed with grep/awk in the CI workflow, and prose here makes that
harder for no gain.

On `pass`:

- `ok`

On `fail`:

- `no_syscalls` — payload ran, invoked nothing
- `wrong_syscall` — expected call absent, different one present
- `wrong_args` — right syscall, arguments contradict the claim
- `bad_opcode` — undecodable instruction in the payload's own bytes
- `segv` — fault attributable to the payload
- `effect_mismatch` — ran cleanly, observed effect is not the claimed one

On `inconclusive`:

- `timeout`
- `blocked_on_peer` — bind/reverse shell waiting on a connection that will
  never arrive
- `unsupported_syscall`
- `emulator_error` — setup or internal emulator failure
- `needs_staging` — egghunter or self-modifying code needing memory the
  harness did not prepare
- `unknown`

If a code is needed that is not on this list, add it to this document first
and to both implementations. Do not emit an unlisted code.

---

## Result line format

One line per shellcode on stdout, so the CI workflow has a stable thing to
cut on:

```
RESULT <path> <verdict> <reason> <syscall_count>
```

Whitespace-separated, prefix is literally `RESULT`. Everything else the harness
prints is diagnostics and is not parsed.

`path` is the repo-relative path of the shellcode file, and it is the primary
key everywhere — manifest, corpus, results. There is deliberately no separate
`id` field: no file in the mirror contains a space in its path, so the path is
safe as a whitespace-delimited field, and a derived id would be duplicated
state that goes stale on exactly the renames that change the path anyway.

Filenames do contain `; & ( ) ! { }`. These are inert to grep and awk, which
work on lines rather than shell syntax, but any path substituted into a shell
command in the workflow must be quoted.

This document specifies only what the harness emits. How that output is
consumed is outside its scope.
