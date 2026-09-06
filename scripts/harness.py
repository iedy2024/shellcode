#!/usr/bin/env python3
"""
Implements the interface from docs/schema.md:

    validate(payload, arch, os_, claimed_effect) -> {verdict, syscalls, reason}

--------------------------------------------------------------------------
Qiling API notes -- verified by probe against qiling 1.4.6, not from memory.
Two of these are traps that cost an afternoon if hit the obvious way.

1. Do NOT capture syscalls with ql.hook_intno() or ql.hook_insn(). They fire
   AFTER Qiling dispatches the syscall, so the number register already holds
   the RETURN VALUE. Measured: eax == 0xFFFFFFFF where 11 (execve) was
   expected. Use QL_INTERCEPT.ENTER, which fires before dispatch with the
   number and arguments intact.

2. ql.os.set_syscall() has no catch-all -- it takes one target at a time. The
   full handler list enumerates from qiling.os.posix.syscall as the 142
   ql_syscall_* functions, and all 142 register without error.

3. A TIMEOUT DOES NOT RAISE. ql.run(timeout=...) on an infinite loop (ebfe)
   returns normally with zero syscalls, which by exception is identical to a
   clean exit -- but schema.md needs timeout to be `inconclusive` while a
   clean no-syscall run is `fail`/`no_syscalls`. Detect it by wall clock.
   Measured on a 1_000_000us budget: 8021us and 240us for real payloads
   against 1_000_279us for a hang. ql.run(timeout=) is in MICROSECONDS.

4. ql.os.stats.syscalls already records every dispatched call with named
   params, `retval` and a `position` for ordering. Use it for return values;
   use the ENTER hooks for number, name, args and order.

5. Faults surface as unicorn.UcError. UC_ERR_INSN_INVALID is a bad opcode.
--------------------------------------------------------------------------
"""
import argparse
import json
import sys
import time
from pathlib import Path

from qiling import Qiling
from qiling.const import QL_ARCH, QL_INTERCEPT, QL_OS, QL_VERBOSE
from qiling.os.posix import syscall as _syscall_module
from unicorn import UcError

# --- schema.md vocabularies -- these are the contract, not preferences -------

ARCHES = ("x86", "x86_64")
OSES = ("linux",)

QL_ARCH_FOR = {"x86": QL_ARCH.X86, "x86_64": QL_ARCH.X8664}

# Register holding the syscall number, per architecture. Also note pointer
# width differs (4 vs 8), which matters when walking a NULL-terminated argv.
SYSCALL_NUM_REG = {"x86": "eax", "x86_64": "rax"}
POINTER_WIDTH = {"x86": 4, "x86_64": 8}

VERDICTS = ("pass", "fail", "inconclusive")

REASONS_PASS = ("ok",)
REASONS_FAIL = (
    "no_syscalls",      # payload ran, invoked nothing
    "wrong_syscall",    # expected call absent, different one present
    "wrong_args",       # right syscall, arguments contradict the claim
    "bad_opcode",       # undecodable instruction in the payload's own bytes
    "segv",             # fault attributable to the payload
    "effect_mismatch",  # ran cleanly, observed effect is not the claimed one
)
REASONS_INCONCLUSIVE = (
    "timeout",
    "blocked_on_peer",      # bind/reverse shell waiting on a peer that never comes
    "unsupported_syscall",
    "emulator_error",       # setup or internal emulator failure
    "needs_staging",        # egghunter / self-modifying code needing staged memory
    "unknown",
)
REASONS = REASONS_PASS + REASONS_FAIL + REASONS_INCONCLUSIVE

# Budget for one payload, microseconds. Anything at or above TIMEOUT_FRACTION
# of this is treated as a hang
TIMEOUT_US = 1_000_000
TIMEOUT_FRACTION = 0.9

# All syscall handler names Qiling knows
SYSCALL_NAMES = [
    n[len("ql_syscall_"):]
    for n in dir(_syscall_module)
    if n.startswith("ql_syscall_")
]

# We test 5 good shellcodes separatly to see if they pass. This
# will tell us if our setup is wrong or if it is just the shellcode.

GROUND_TRUTH = [
    # Linux/x86/execve_-bin-sh_shellcode.c
    ("x86", "31c050682f2f7368682f62696e89e3505389e1b00bcd80", "execve //bin/sh"),

    # Linux/x86_64/execve(-bin-sh);.c
    ("x86_64", "4831d248bb2f2f62696e2f736848c1eb08534889e750574889e6b03b0f05",
     "execve //bin/sh"),

    # Linux/x86_64/setuid(0)_+_execve(-bin-sh)_49_bytes.c
    ("x86_64", "4831ffb0690f054831d248bbff2f62696e2f736848c1eb08534889e74831c050574889e6b03b0f056a015f6a3c580f05",
     "setuid 0 + execve //bin/sh"),

    #
    ("x86", "6a175831dbcd80b00b6a0b58b00b9952682f2f7368682f62696e89e3cd80",
     "setuid 0 + execve //bin/sh, 0"),

    #
    ("x86", "31db8d431799cd8031c951686e2f7368682f2f62698d410b89e3cd80",
     "setuid 0 + execve //bin/sh, 0, 0")
]


class ValidationError(Exception):
    """Raised for a caller mistake -- an arch or os outside the schema."""


class Recorder:
    """
    Captures the ordered syscall sequence for one emulation run.

    Produces the `syscalls` field of the schema: an ordered list, one entry per
    syscall invoked, each {n, name, args, ret}. Order is part of the data --
    socket then bind then listen is the claim being tested.
    """

    def __init__(self, arch: str):
        self.arch = arch
        self.calls: list[dict] = []

    def attach(self, ql: Qiling) -> None:
        """
        Register an ENTER hook on every name in SYSCALL_NAMES.

        TODO: for each name, ql.os.set_syscall(name, handler, QL_INTERCEPT.ENTER).
        The handler must append {n, name, args, ret} to self.calls, reading the
        number from ql.arch.regs via SYSCALL_NUM_REG[self.arch] and the args
        from the handler's positional arguments. `ret` is not known yet -- see
        collect_returns().

        Remember the closure trap: build the handler in a factory so each one
        captures its own name rather than the last value of the loop variable.
        """
        raise NotImplementedError

    def resolve_args(self, ql: Qiling, args: tuple) -> list:
        """
        Best-effort dereference of pointer arguments.

        schema.md requires args, because a payload that execve's the WRONG path
        is a fail that is only visible if the arguments are read. Without this,
        the `wrong_args` reason is unreachable and a corrupted-path payload
        passes.

        TODO: dereference C strings with ql.os.utils.read_cstring, and walk
        NULL-terminated pointer arrays with ql.mem.read_ptr using
        POINTER_WIDTH[self.arch]. Keep the integer when a pointer cannot be
        safely read -- never let a bad dereference take down the run.
        """
        raise NotImplementedError

    def collect_returns(self, ql: Qiling) -> None:
        """
        Fill in `ret` on each recorded call from ql.os.stats.syscalls.

        That dict is keyed by handler name and holds, per call, the named
        params, `retval` and a `position`. Match on position -- see API note 4.

        TODO: implement. Leave ret as None for a call that did not return.
        """
        raise NotImplementedError


def verdict_for(calls: list, claimed_effect: str, category: str | None,
                fault: Exception | None, timed_out: bool) -> tuple[str, str]:
    """
    Map an observed run onto (verdict, reason) per docs/schema.md.

    The boundary, which both halves of the project must implement identically:

        fail          the harness got a trustworthy observation and the
                      observation contradicts the claim. A statement about the
                      SHELLCODE.
        inconclusive  the harness could not get a trustworthy observation. A
                      statement about the HARNESS.

    When in doubt return inconclusive. A false `fail` is a bug report filed
    against an innocent payload and those are expensive to unwind.

    TODO: implement the mapping. The cases, roughly in precedence order:
      timed_out                              -> inconclusive / timeout
      fault is UcError UC_ERR_INSN_INVALID   -> fail / bad_opcode
      fault is any other UcError             -> fail / segv
      fault is anything else                 -> inconclusive / emulator_error
      not calls                              -> fail / no_syscalls
      category has no checker                -> inconclusive / unknown
      checker says yes                       -> pass / ok
      checker says no                        -> fail / wrong_syscall | wrong_args

    Return only codes from REASONS. An unlisted code is a bug; if a new one is
    needed it goes into docs/schema.md first and into both harnesses.
    """
    raise NotImplementedError


# --- per-effect checks ------------------------------------------------------
# Selected by corpus.json's `category` field. schema.md is explicit that the
# check is chosen by the harness rather than derived by string analysis of
# claimed_effect.
#
# Day 3 implements execve_shell ONLY. Every other category must return None,
# meaning "no checker", which becomes inconclusive/unknown. A stub that guessed
# would poison the failure taxonomy, and the taxonomy is the deliverable.

SHELLS = ("/bin/sh", "/bin//sh", "/bin/bash", "/bin/dash", "/bin/zsh",
          "/bin/ksh", "/bin/csh", "/bin/ash")


def check_execve_shell(calls: list) -> tuple[bool, str] | None:
    """
    True if the run execve'd a recognised shell.

    TODO: find an execve in calls; if absent return (False, "wrong_syscall").
    If present but its path argument is not in SHELLS, return
    (False, "wrong_args"). Otherwise (True, "ok").
    """
    raise NotImplementedError


CHECKERS = {
    "execve_shell": check_execve_shell,
    # Days 4-5: add_user, bind_shell, reverse_shell, chmod_chown, file_op,
    # egghunter, encoder, proc_kill, net_other, system_state, uncategorised.
}


def validate(payload: bytes, arch: str, os_: str, claimed_effect: str,
             category: str | None = None) -> dict:
    """
    The frozen entry point. Returns exactly {verdict, syscalls, reason}.

    `payload` is raw bytes, never a hex string -- hex exists only in
    manifest.json and corpus.json, and the caller decodes before calling here.

    TODO: build the Qiling instance with code=payload and
    QL_ARCH_FOR[arch], attach a Recorder, time the run against TIMEOUT_US,
    catch UcError, then hand everything to verdict_for().

    Keep the returned dict to exactly three keys. Anything else breaks
    interchangeability with the Windows half.
    """
    if arch not in ARCHES:
        raise ValidationError(f"arch {arch!r} not in {ARCHES}")
    if os_ not in OSES:
        raise ValidationError(f"os {os_!r} not in {OSES}")
    raise NotImplementedError


def result_line(path: str, result: dict) -> str:
    """One stdout line per shellcode, per docs/schema.md."""
    return (f"RESULT {path} {result['verdict']} {result['reason']} "
            f"{len(result['syscalls'])}")


def self_test() -> bool:
    """
    Run GROUND_TRUTH and require every entry to pass.

    Nothing from the corpus should be believed until this does. TODO: run each
    entry through validate() and report which failed.
    """
    raise NotImplementedError


def main() -> int:
    ap = argparse.ArgumentParser(description="Validate shellcodes with Qiling.")
    ap.add_argument("--corpus", default="corpus.json")
    ap.add_argument("--self-test", action="store_true",
                    help="run ground truth only and exit")
    ap.add_argument("--skip-self-test", action="store_true",
                    help="run the corpus without the ground-truth gate")
    args = ap.parse_args()

    if args.self_test:
        return 0 if self_test() else 1

    # Ground truth gates the corpus, the same way corpus.py refuses a stale
    # manifest. A corpus run on an unverified harness produces confident
    # nonsense.
    if not args.skip_self_test and not self_test():
        print("REFUSING: ground truth failed; the harness is not trustworthy",
              file=sys.stderr)
        return 1

    # TODO: load corpus.json, call validate() per record, print result_line().
    raise NotImplementedError


if __name__ == "__main__":
    sys.exit(main())
