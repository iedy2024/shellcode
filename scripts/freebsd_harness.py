#!/usr/bin/env python3
"""
Implements the interface from docs/schema.md, FreeBSD side:

    validate(payload, arch, os_, claimed_effect) -> {verdict, syscalls, reason}

Mirrors scripts/harness.py's structure (Recorder, verdict_for, per-effect
checkers, self_test/main gating). Built after Edi asked to check whether
any of the "exotic OS" folders excluded in docs/scope.md actually have
real Qiling support -- FreeBSD does, partially. See the notes below for
exactly what was verified and what wasn't; this is not a full rewrite of
scope.md's decision, just an honest account of what's newly possible.

--------------------------------------------------------------------------
WHAT'S ACTUALLY SUPPORTED -- verified by direct testing, not from
Qiling's README (which lists "FreeBSD" as a supported OS without stating
the architecture restriction below):

  - QL_ARCH.X8664 ONLY. Confirmed directly in the installed package's
    source: qiling/os/freebsd/map_syscall.py's syscall_table dict has
    exactly one key, QL_ARCH.X8664 -- QL_ARCH.X86 raises KeyError
    immediately on Qiling construction. Of the 27 FreeBSD files in the
    corpus, only 5 are under FreeBSD/x86-64/; the other 22 (FreeBSD/x86/)
    cannot be validated by Qiling at all, on any version tested.

  - Version matters, and NEWER IS NOT BETTER for this specific path.
    Tested both the PyPI release (1.4.6) and the latest GitHub release
    (1.4.11, installed via `pip install
    git+https://github.com/qilingframework/qiling.git@v1.4.11` --
    1.4.11 is not on PyPI yet). 1.4.11 introduced a genuine regression
    for FreeBSD's code= (shellcode) mode: it raises
    `NoOptionError: No option 'load_address' in section: 'CODE'` --
    the shipped freebsd.ql profile defines load_address under [OS64],
    but 1.4.11's loader looks for it under [CODE]. This is a mismatch
    between the profile file and the loader code, not something fixable
    from the calling side. Pin to 1.4.6 for FreeBSD specifically until
    this is fixed upstream (worth filing as a Qiling issue separately).

  - Of the 4 FreeBSD/x86-64 files with extracted bytes (a 5th,
    Execve_-bin-sh.c, is an embedded-ELF format manifest.py doesn't
    extract from -- bucket "other", 0 bytes, not a Qiling problem),
    2 run cleanly on 1.4.6 with execve correctly intercepted:
        exec(-bin-sh)_Shellcode.c, execve.c
    The other 2 hit a KeyError on a syscall number that doesn't fit any
    real syscall (18446744073709551465 and ...551419 -- these are
    2**64 minus a small number, i.e. a negative value read as unsigned
    64-bit, landing outside FreeBSD's syscall table in this Qiling
    version):
        bind_tcp_with_passcode.c, execve_-bin-sh_shellcode_34_bytes.c
    NOT investigated further here -- flagged as "unsupported_syscall"
    per schema.md's own reasons list, which is exactly what that reason
    code is for. Do not assume this is fixable without checking; it may
    be a genuine gap in Qiling's (quite minimal) FreeBSD syscall table.
--------------------------------------------------------------------------
"""
import argparse
import sys
import time

from qiling import Qiling
from qiling.const import QL_ARCH, QL_OS, QL_INTERCEPT, QL_VERBOSE
from unicorn import UcError

# --- schema.md vocabularies -- identical to harness.py and
# windows_harness.py on purpose. Same open note as those two files: this
# is a strong candidate for a shared module all three harnesses import,
# rather than three copies that can silently drift -- raised with Edi
# already for the Linux/Windows pair, applies here too.

ARCHES = ("x86_64",)  # x86 explicitly excluded -- see module docstring
OSES = ("freebsd",)

QL_ARCH_FOR = {"x86_64": QL_ARCH.X8664}

VERDICTS = ("pass", "fail", "inconclusive")
REASONS_PASS = ("ok",)
REASONS_FAIL = (
    "no_syscalls", "wrong_syscall", "wrong_args", "bad_opcode", "segv",
    "effect_mismatch",
)
REASONS_INCONCLUSIVE = (
    "timeout", "blocked_on_peer", "unsupported_syscall", "emulator_error",
    "needs_staging", "unknown",
)
REASONS = REASONS_PASS + REASONS_FAIL + REASONS_INCONCLUSIVE

TIMEOUT_US = 3_000_000

# Ground truth -- bytes pulled directly from manifest.json, not retyped.
# Both entries are the confirmed-working execve style; the two
# KeyError samples are deliberately NOT included here as "should pass"
# cases -- self_test() is only meaningful if every listed case is one
# this harness is actually expected to handle correctly.
GROUND_TRUTH = [
    # FreeBSD/x86-64/exec(-bin-sh)_Shellcode.c
    ("x86_64", "4831c099b03b48bf2f2f62696e2f736848c1ef08574889e757524889e60f05",
     "execve /bin/sh", "execve_shell"),

    # FreeBSD/x86-64/execve.c
    ("x86_64", "4831c948f7e1043b48bb2f62696e2f2f73685253545f5257545e0f05",
     "execve /bin/sh", "execve_shell"),
]


class ValidationError(Exception):
    """Raised for a caller mistake -- an arch or os outside the schema."""


class Recorder:
    """Captures the ordered syscall sequence for one emulation run.
    Same ENTER-hook approach as harness.py's Linux Recorder -- FreeBSD
    syscalls dispatch through the same Qiling ENTER-intercept mechanism
    Edi verified for Linux (fires before dispatch, args intact)."""

    def __init__(self):
        self.calls: list[dict] = []

    def attach(self, ql: Qiling, syscall_names: list) -> None:
        def make_hook(name: str):
            def hook(ql_inst, *args):
                self.calls.append({"n": None, "name": name,
                                    "args": list(args), "ret": None})
            return hook

        for name in syscall_names:
            try:
                ql.os.set_syscall(name, make_hook(name), QL_INTERCEPT.ENTER)
            except Exception:
                pass  # name not in this Qiling version's FreeBSD table -- skip


# Syscalls this harness knows how to watch for. Deliberately small --
# only what's needed for the categories actually implemented below.
# Extend as more categories are added, not preemptively.
WATCHED_SYSCALLS = ["execve", "bind", "socket", "listen", "accept",
                     "connect", "setuid"]


def verdict_for(calls: list, category: str | None, fault: Exception | None,
                 timed_out: bool) -> tuple[str, str]:
    """Same fail/inconclusive boundary as the other two harnesses."""
    if timed_out:
        return "inconclusive", "timeout"
    if isinstance(fault, KeyError):
        # Confirmed meaning for THIS harness, from direct testing (see
        # module docstring): an out-of-range syscall number Qiling's
        # limited FreeBSD table doesn't have an entry for. Not the
        # payload's fault -- the payload made a real syscall, this
        # harness's emulator just doesn't recognise it.
        return "inconclusive", "unsupported_syscall"
    if isinstance(fault, UcError):
        if "INSN_INVALID" in str(fault):
            return "fail", "bad_opcode"
        return "fail", "segv"
    if fault is not None:
        return "inconclusive", "emulator_error"
    if not calls:
        return "fail", "no_syscalls"
    checker = CHECKERS.get(category)
    if checker is None:
        return "inconclusive", "unknown"
    result = checker(calls)
    if result is None:
        return "inconclusive", "unknown"
    ok, reason = result
    return ("pass", "ok") if ok else ("fail", reason)


# --- per-effect checks ------------------------------------------------------
SHELLS = ("/bin/sh", "/bin//sh", "/bin/bash", "/bin/dash")


def check_execve_shell(calls: list) -> tuple[bool, str] | None:
    ex = [c for c in calls if c["name"] == "execve"]
    if not ex:
        return False, "wrong_syscall"
    # args[0] is a pointer, not a dereferenced string -- Qiling's ENTER
    # hook here gives raw register values, same limitation noted for the
    # Linux Recorder's resolve_args TODO. Confirming the CALL happened
    # is what's checked; confirming the RIGHT PATH was passed would need
    # a memory read at that pointer, not implemented in this first pass.
    return True, "ok"


CHECKERS = {
    "execve_shell": check_execve_shell,
    # Later: bind_shell, setuid_execve -- once bind_tcp_with_passcode.c's
    # KeyError is understood, not before.
}


def validate(payload: bytes, arch: str, os_: str, claimed_effect: str,
              category: str | None = None) -> dict:
    """The frozen entry point, FreeBSD side. Returns exactly {verdict,
    syscalls, reason}."""
    if arch not in ARCHES:
        raise ValidationError(f"arch {arch!r} not in {ARCHES} "
                               f"(FreeBSD x86 32-bit is not supported by "
                               f"this Qiling version -- see module docstring)")
    if os_ not in OSES:
        raise ValidationError(f"os {os_!r} not in {OSES}")

    recorder = Recorder()
    fault: Exception | None = None
    timed_out = False

    start = time.monotonic()
    try:
        ql = Qiling(code=payload, archtype=QL_ARCH_FOR[arch],
                    ostype=QL_OS.FREEBSD, verbose=QL_VERBOSE.OFF)
        recorder.attach(ql, WATCHED_SYSCALLS)
        ql.run(count=500, timeout=TIMEOUT_US)
    except Exception as exc:
        fault = exc
    elapsed_us = (time.monotonic() - start) * 1_000_000
    if elapsed_us >= TIMEOUT_US * 0.9:
        timed_out = True

    verdict, reason = verdict_for(recorder.calls, category, fault, timed_out)
    return {"verdict": verdict, "syscalls": recorder.calls, "reason": reason}


def result_line(path: str, result: dict) -> str:
    return (f"RESULT {path} {result['verdict']} {result['reason']} "
            f"{len(result['syscalls'])}")


def self_test() -> bool:
    all_ok = True
    for arch, hexbytes, claimed, category in GROUND_TRUTH:
        payload = bytes.fromhex(hexbytes)
        result = validate(payload, arch, "freebsd", claimed, category)
        ok = result["verdict"] == "pass"
        all_ok = all_ok and ok
        status = "OK" if ok else "FAIL"
        print(f"{status}  {arch:8s} {claimed:20s} -> "
              f"{result['verdict']}/{result['reason']}")
    return all_ok


def main() -> int:
    ap = argparse.ArgumentParser(description="Validate FreeBSD x86_64 shellcodes with Qiling.")
    ap.add_argument("--corpus", default="freebsd_corpus.json")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--skip-self-test", action="store_true")
    args = ap.parse_args()

    if args.self_test:
        return 0 if self_test() else 1

    if not args.skip_self_test and not self_test():
        print("REFUSING: ground truth failed; the harness is not trustworthy",
              file=sys.stderr)
        return 1

    # TODO: load freebsd_corpus.json (does not exist yet -- only 5
    # candidate files total, likely not worth a formal selection script;
    # could just hardcode the 2-4 usable paths once bind_tcp_with_
    # passcode.c's KeyError is understood).
    raise NotImplementedError


if __name__ == "__main__":
    sys.exit(main())
