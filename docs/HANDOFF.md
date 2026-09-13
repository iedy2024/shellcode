# Shellcode Validator — Handoff Document

**Team:** Stefan Bibirus, Eduard Rusu
**Repository:** [github.com/iedy2024/shellcode](https://github.com/iedy2024/shellcode)

---

## 1. Problem statement

The corpus at [7feilee/shellcode](https://github.com/7feilee/shellcode) contains roughly 480 shellcode samples, each with a filename or comment claiming a specific effect (`execve_-bin-sh.c`, `Bind_TCP_Port.c`, `setuid(0)_&_reboot.c`, and so on). Nothing in the corpus verifies these claims. A file could be mislabeled, corrupted during archival, target an OS old enough that the technique no longer applies, or simply be wrong.

The goal of this practicum was to build an **automated framework that runs each shellcode and checks whether its real, observed behaviour matches its claim** — not just whether it "looks like" valid code, but whether it actually does the specific thing it says it does.

## 2. Scope

The frozen scope, recorded in [`docs/scope.md`](scope.md), is:

- **OS:** Linux
- **Architecture:** x86 and x86-64
- **Selection size:** N≈60, hand-curated for category diversity (not a random sample)

This scope was chosen because Linux's `int 0x80` / `syscall` ABI is well-documented, Qiling has mature Linux support, and a hand-curated 60-file set is large enough to be meaningful while small enough to manually verify every category assignment — the one part of the pipeline that cannot be automated away.

Everything beyond this — Windows, FreeBSD, a partial macOS investigation — was built after the frozen scope was already working, as extended coverage. It is documented honestly as *extra*, not as fulfilling additional requirements nobody asked for.

## 3. Methodology

### 3.1 The three-verdict system

Every validation result is exactly one of three verdicts, defined in [`docs/schema.md`](schema.md):

- **`pass`** — observed behaviour matches the claim.
- **`fail`** — the harness obtained a trustworthy observation, and that observation contradicts the claim. This is a statement about the **shellcode**.
- **`inconclusive`** — the harness could not obtain a trustworthy observation (a timeout, an emulator crash, a syscall the emulator doesn't implement, a category with no checker written for it). This is a statement about the **harness**, not the shellcode.

Keeping these separate matters: a `fail` should mean the payload is genuinely broken or mislabeled, not that the harness gave up. Conflating the two would produce a report that looks precise but isn't — a shellcode wrongly marked `fail` because the harness timed out is a false accusation against a payload that may be entirely correct.

### 3.2 Pipeline

```
corpus (482 files)
  -> manifest.py    (extract raw bytes, 401/482 succeed)
  -> classify.py    (bucket by extraction format)
  -> corpus.py      (hand-select ~60 Linux files, assign category by reading each one)
  -> harness.py     (run each payload in Qiling, compare observed syscalls to category)
  -> CI (GitHub Actions)
```

`corpus.py`'s output (`corpus.json`) is the one artifact in this whole pipeline that required a human to actually read every file and decide what it claims. Nothing downstream is more trustworthy than that step.

### 3.3 Why Qiling, and where it stops being enough

Qiling wraps Unicorn (pure CPU emulation) with an OS layer that implements real POSIX syscalls. That OS layer is what makes it useful — hooking `int 0x80`/`syscall` and comparing raw numbers only tells you *that* a syscall happened, not what it actually did (a real `execve` with a corrupted path argument and a real `execve` with a legitimate one both look identical at the interception point unless the argument itself is inspected).

The same OS layer is also the danger: Qiling's syscalls are **real host operations** by default. `bind()`, `connect()`, `accept()`, even `read()` on a redirected file descriptor, will genuinely touch the host's network stack and file descriptors unless explicitly intercepted and replaced. This was not a hypothetical risk — the Linux harness genuinely hung on a real `accept()` call during development, confirmed via a wall-clock-timed test that exceeded its own timeout, before the relevant syscalls were caught and replaced with fakes (see `DANGEROUS_SYSCALLS` in `harness.py`).

## 4. Key findings

### 4.1 Linux (frozen scope)

- Full harness (`Recorder`, `verdict_for`, 10 category checkers, `self_test` ground-truth gate) implemented and passing self-test.
- Curated 60-file run and a full 259-file in-scope run both pass through CI — see [`test-linux.yml`](../.github/workflows/test-linux.yml) for current numbers.
- **Root-cause bug found and fixed:** on x86 (32-bit), every socket operation multiplexes through a single syscall (`socketcall`, number 102) rather than separate named syscalls. The first implementation only intercepted `socket`/`bind`/`connect`/etc. by name, which is silently a no-op on x86 — the real syscall Qiling ever sees there is `socketcall`. This alone was responsible for most of an early batch's timeouts and false `wrong_syscall` failures on files that were actually behaving correctly. Fixed by decoding the sub-operation code and recording the real operation name.
- **A second, related bug:** `QL_INTERCEPT.CALL` handlers (used to replace dangerous syscalls with fakes) do not receive real arguments through Qiling's normal argument-passing mechanism — confirmed empirically, not assumed. Fixed by reading arguments directly from the ABI's argument registers instead of relying on the handler's Python arguments.
- A heuristic, filename-keyword-based categoriser (`guess_category()`) extends coverage to the full 259-file in-scope set beyond the hand-verified 60. It is explicitly **not** a substitute for manual verification and is labelled as such everywhere it's used.

### 4.2 Windows (extended, not required)

No single tool covers Windows shellcode validation:

- **Speakeasy** (Win32 API emulation) works for a small fraction of the corpus — most Windows shellcode resolves API addresses via PEB-walking or a hand-rolled export-table walk, which Speakeasy cannot intercept.
- **Native execution** on real `windows-latest` GitHub Actions runners, inside a minimal C loader, observed via Procmon, with network blocked in both directions (inbound too, since bind-shells listen rather than connect). All 44 Windows files ran; most crash — confirmed genuine, not a harness artifact, via `WerFault.exe` (Windows' own crash handler) appearing in the Procmon trace — because they hardcode addresses calibrated to a specific old Windows build (XP or 7) that no longer matches modern `kernel32.dll`.

### 4.3 FreeBSD (extended, not required)

- Qiling supports FreeBSD only on x86-64, and only as of a specific pinned version (1.4.6 — 1.4.11, the newest release, has a confirmed regression that breaks this exact path).
- FreeBSD/x86 has **no** Qiling support at all, on any version checked back to 1.2.4 — confirmed directly in source, not assumed. A raw-Unicorn engine was built from scratch for this architecture, implementing FreeBSD's own syscall calling convention (arguments passed on the stack, not in registers — the opposite of Linux) directly.
- Result: 20/27 pass, 1/27 legitimate fail, remainder inconclusive (extraction failures and genuine coverage gaps, documented individually in `freebsd_harness.py`).

### 4.4 macOS (investigated, explicitly not a deliverable)

12 of 17 macOS files are PowerPC, unsupported by any tool used in this project. Of the remaining 5, two real bugs in Qiling's macOS loader (missing `entry_point`/`load_address` attributes in raw-shellcode mode) were patched from outside Qiling, and Qiling's name-based syscall interception was found not to fire at all for macOS — worked around by hooking the `syscall` instruction directly via Unicorn instead. This was confirmed to correctly observe a real sample's `setuid`+`execve` sequence, matching its documented behaviour, but was **not** built into a full harness — no category checkers, no CI, no `self_test`. It is documented here as a reproducible starting point for anyone continuing this work, explicitly not claimed as working coverage.

## 5. Known limitations

- **Heuristic categorisation** (`guess_category()`) is filename-keyword matching, not manual review. It measurably improves coverage (raised the full-set pass count substantially once bugs in it were fixed) but should never be cited as equivalent evidence to the hand-verified 60.
- **Native execution costs real CI minutes** and depends on Sysinternals' Procmon being reachable at build time — if that download ever breaks, the Windows native path breaks with it. No fallback was built for this.
- **Qiling bugs were worked around, not fixed upstream.** A missing `posix_open_flags` name in `ql_syscall_creat`, macOS's `code=` loader, FreeBSD's incomplete syscall table, and the 1.4.11 regression are all real, reproducible issues that would be worth filing against the Qiling project directly.

## 6. Recommendations for continuation

In rough priority order, for anyone picking this project up after submission:

1. **Extract the shared vocabulary module.** Low effort, removes a real drift risk (a `REASONS` entry added to one harness and not the others would silently diverge).
2. **Manually verify a sample of the heuristically-guessed categories** in the full 259-file Linux run, to get a real (not estimated) accuracy figure for `guess_category()`.
3. **Build the macOS harness properly** — the hard parts (loader bugs, syscall interception) are already solved and documented in this handoff; what's missing is `CHECKERS`, `self_test`, and CI wiring, mirroring `freebsd_harness.py`'s structure.
4. **File the Qiling bugs upstream** (listed in §5) — confirmed, reproducible, and would help the next people using this same framework.


## 7. Team contribution summary

- **Stefan Bibirus:** `manifest.py` extraction (and its many format-specific fixes), all four language harnesses (Linux, Windows, FreeBSD, macOS investigation), all CI pipelines, native Windows execution infrastructure.
- **Eduard Rusu:** `classify.py`, `corpus.py` and the curated 60-file selection with hand-verified categories, `harness.py`'s original scaffolding and Qiling API research notes (documented directly in the module header).
