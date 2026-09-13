# Shellcode Validator

Academic practicum project — automated framework for validating whether shellcode samples in a public corpus actually do what their filenames/comments claim.

**Team:** Stefan Bibirus, Eduard Rusu
**Deadline:** 18 September 2026 (freeze: 16 September)
**Corpus source:** [7feilee/shellcode](https://github.com/7feilee/shellcode) (mirror of the shell-storm database)
**Repo:** [iedy2024/shellcode](https://github.com/iedy2024/shellcode)

## What this project does

The corpus contains ~480 shellcode files, each claiming an effect via its filename (`execve_-bin-sh.c`, `Bind_TCP_Port.c`, etc.) or a comment. Filenames and comments are not proof — a file could be mislabeled, broken, or simply not do what it says. This project runs each shellcode in an emulator (or, where emulation isn't trustworthy, real hardware) and checks whether the *actual observed behaviour* (the syscalls it made) matches the claim.

Every result is one of three verdicts, defined in [`docs/schema.md`](docs/schema.md):

| Verdict | Meaning |
|---|---|
| `pass` | Observed behaviour matches the claim |
| `fail` | The harness got a trustworthy observation, and it contradicts the claim — a statement about the **shellcode** |
| `inconclusive` | The harness could not get a trustworthy observation — a statement about the **harness**, not the shellcode |

The scope frozen in [`docs/scope.md`](docs/scope.md) is **Linux, x86/x86-64, N≈60 curated files**. Everything else in this repo (Windows, FreeBSD, a partial macOS investigation) is validated extra coverage beyond that frozen scope, not a requirement.

## Repo layout

```
scripts/
  manifest.py          -- extracts raw bytes from every corpus file (482 -> 401 with bytes)
  classify.py           -- buckets files by extraction format (hex/asm/ascii/other/empty)
  corpus.py              -- builds the curated N=60 Linux selection (corpus.json)
  harness.py             -- Linux validator (Qiling)
  windows_harness.py     -- Windows validator (Speakeasy emulation)
  freebsd_harness.py     -- FreeBSD validator (Qiling x86_64 + raw Unicorn x86 hybrid)

windows_native/
  run_all.ps1             -- native Windows execution, single shellcode (loader + Procmon)
  run_batch.ps1           -- native Windows execution, whole batch, shared Procmon session

.github/workflows/
  test-linux.yml
  test-windows-native.yml
  test-windows-native-batch.yml
  test-freebsd.yml

docs/
  schema.md               -- frozen validate() interface, verdict/reason vocabulary
  scope.md                -- frozen scope decision (N, architectures, what's excluded)

manifest.json              -- extraction output, all 482 corpus files
corpus.json                -- the curated ~60-file Linux selection, hand-assigned categories
```

## Results summary

### Linux (the frozen scope)

Two runs, both against `manifest.py`'s x86/x86-64 extraction:

| Run | Files | Pass | Fail | Inconclusive |
|---|---|---|---|---|
| Curated (`corpus.json`, hand-verified categories) | 60 | 23 | 20 | 17 |
| Full in-scope set (`manifest.json`, heuristic categories) | 259 | 116 | 70 | 73 |

The curated run is the one that matters for the frozen scope — every category there was assigned by hand, reading the actual file. The full-set run is extra coverage: most of its categories are guessed from filename keywords (`--guess-categories`, see `harness.py`'s `guess_category()` docstring) and are **not** manually verified — useful for breadth, not a substitute for the curated 60.


### Windows (extended coverage, not in frozen scope)

Two validation paths, since no single tool covers it:

- **Speakeasy emulation** (`windows_harness.py`) — works for a small minority of files; most Windows shellcode resolves Win32 APIs via PEB-walking or hand-rolled export-table parsing, which Speakeasy can't intercept.
- **Native execution** (`windows_native/`) — runs the real bytes on real `windows-latest` runners inside a loader, captured with Procmon, network blocked in both directions. All 44 Windows files (including the separately-tagged `Windows-64` set) ran; most crash confirmed via `WerFault.exe` (hardcoded XP-era addresses, verified against modern Windows), a handful show real, complete effects (spawned `cmd.exe`, wrote a file, created a registry key).

### FreeBSD (extended coverage, not in frozen scope)

27 files, two engines depending on architecture:

- **x86-64 (5 files):** Qiling, pinned to version 1.4.6 (1.4.11 has a confirmed regression for this exact path)
- **x86 (22 files):** Qiling has no x86 support for FreeBSD at all (confirmed against every version back to 1.2.4) — a raw-Unicorn engine built from scratch, decoding FreeBSD's own syscall ABI directly

Current result: 20/27 pass, 1/27 legitimate fail, rest inconclusive (2 extraction failures, 4 genuine gaps).

### macOS (investigated, not a working harness)

12 of 17 files are PowerPC, which neither Qiling nor this project's raw-Unicorn approach supports. Of the remaining 5 (4 x86-64, 1 x86), Qiling's `code=` (raw shellcode) loader has two real bugs (missing `entry_point`/`load_address` attributes) that were patched from outside, and Qiling's name-based syscall interception silently does not fire for macOS — confirmed working instead by hooking the raw `syscall` instruction directly via Unicorn. This got as far as correctly observing `setuid`+`execve` on a real sample, matching its documented behaviour, but was not built into a full harness (no `CHECKERS`, no CI). Documented here as a confirmed, reproducible path for anyone continuing this work, not as a deliverable.

## Running things locally

Each harness follows the same pattern:

```bash
# Linux
pip install qiling
python3 scripts/harness.py --self-test                                    # ground-truth gate
python3 scripts/harness.py --corpus corpus.json --skip-self-test          # curated 60
python3 scripts/harness.py --manifest manifest.json --corpus corpus.json \
    --skip-self-test --guess-categories                                    # full in-scope set

# FreeBSD (needs Qiling pinned to 1.4.6 specifically)
pip install "qiling==1.4.6"
python3 scripts/freebsd_harness.py --self-test
python3 scripts/freebsd_harness.py --manifest manifest.json --skip-self-test --guess-categories

# Windows (Speakeasy path, any OS)
pip install speakeasy-emulator
python3 scripts/windows_harness.py --self-test

# Windows (native path, Windows only, elevated PowerShell)
.\windows_native\run_batch.ps1 -ManifestPath manifest.json -MaxFiles 0
```

Every harness refuses to run its corpus if `--self-test` fails — a harness that can't validate its own ground truth is not trustworthy enough to validate anything else.

## Known limitations (see also `docs/scope.md`)

- **Heuristic categories** (`guess_category()` in both `harness.py` and `freebsd_harness.py`) are filename-keyword guesses, not manual verification — always check which files came from `corpus.json` (verified) versus a guess before treating a `fail` as a real finding about the payload.
- **Several genuine Qiling bugs** were found and worked around rather than fixed upstream (a missing `posix_open_flags` name in `ql_syscall_creat`, macOS's `code=` loader, FreeBSD's x86 syscall table, a v1.4.11 regression in FreeBSD's profile loading) — worth filing upstream if anyone has time after the deadline.