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
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_INTR, UcError
from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_ESP, UC_X86_REG_EIP

# --- raw-Unicorn engine for FreeBSD/x86 -- Qiling has NO x86 support for
# this OS at all (confirmed: qiling/os/freebsd/map_syscall.py's
# syscall_table dict only has an X8664 key, on every version checked
# back to 1.2.4, so this was never supported, not a regression). Built
# from scratch here, mirroring the project's very first prototype
# (raw Unicorn, before Qiling was adopted for Linux) -- FreeBSD's x86
# `int 0x80` calling convention is fundamentally different from Linux's
# anyway (arguments on the STACK, not in registers -- confirmed against
# FreeBSD's own Developer's Handbook, not assumed), so this needed its
# own implementation regardless of what Qiling does or doesn't support.
#
# execve=59 is independently confirmed empirically too: running a real
# corpus sample (FreeBSD/x86/execve_-bin-sh_23_bytes.c) through this
# exact mechanism reads eax=59 at the int 0x80 trap, matching the table.
# socket/connect/bind/listen/accept/dup2 were added after that first
# pass, confirmed the same way (source cross-check + matching observed
# behaviour): the full socket->bind->listen->accept->dup2 sequence
# showed up naturally on FreeBSD/x86/bind_sh_port_41254.c, a textbook
# bind-shell pattern that would only line up if these numbers were
# actually right.
FREEBSD_X86_SYSCALL_NAMES = {
    1: "exit",
    2: "fork",
    3: "read",
    4: "write",
    5: "open",
    6: "close",
    23: "setuid",
    30: "accept",
    37: "kill",
    55: "reboot",
    59: "execve",
    90: "dup2",
    97: "socket",
    98: "connect",
    104: "bind",
    106: "listen",
}


def _run_freebsd_x86(payload: bytes, timeout_us: int):
    """Raw-Unicorn FreeBSD/x86 engine. Returns (calls, fault, timed_out).
    Mirrors the shape validate() needs from the Qiling path so both
    engines can feed the same verdict_for()."""
    BASE = 0x1000
    STACK_TOP = 0x200000
    STACK_SIZE = 0x20000

    calls: list[dict] = []
    fault: Exception | None = None
    timed_out = False

    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    uc.mem_map(BASE, 0x1000)
    uc.mem_write(BASE, payload)
    uc.mem_map(STACK_TOP - STACK_SIZE, STACK_SIZE)
    uc.reg_write(UC_X86_REG_ESP, STACK_TOP)

    def hook_intr(uc_inst, intno, _data):
        if intno != 0x80:
            return
        eax = uc_inst.reg_read(UC_X86_REG_EAX)
        esp = uc_inst.reg_read(UC_X86_REG_ESP)
        eip = uc_inst.reg_read(UC_X86_REG_EIP)
        name = FREEBSD_X86_SYSCALL_NAMES.get(eax)
        args = []
        try:
            raw = uc_inst.mem_read(esp, 12)  # first 3 stack args -- enough
                                              # for every syscall this
                                              # harness currently checks
            args = [int.from_bytes(raw[i:i+4], "little") for i in (0, 4, 8)]
        except Exception:
            pass  # unmapped stack read -- leave args empty rather than crash
        calls.append({"n": eax, "name": name or f"unknown({eax})",
                       "args": args, "ret": 0})

        # Multi-syscall sequences are common and real -- e.g. setuid(0)
        # THEN execve(...) (found directly in this corpus: kldload_-tmp-
        # o.o.c, reverse_connect_dl(...).c, reverse_portbind_-bin-sh.c,
        # setuid(0)&execve;(...).c all hit setuid FIRST, with the actual
        # claimed-effect syscall coming after). Stopping at the first
        # syscall (the original version of this function) silently
        # missed every one of those. `int 0x80` is 2 bytes (CD 80) --
        # advance EIP past it and let emulation continue instead of
        # stopping, so the sequence keeps going. Faking ret=0 (success)
        # in EAX is necessary for this: real shellcode often branches on
        # the syscall's return value (e.g. "did setuid succeed?"), and
        # leaving EAX as whatever garbage was there would send execution
        # somewhere the payload never intended, producing a fault that
        # is an artifact of this harness, not a real payload bug.
        uc_inst.reg_write(UC_X86_REG_EAX, 0)
        uc_inst.reg_write(UC_X86_REG_EIP, eip + 2)

        if name == "exit" or len(calls) >= 10:
            # exit(): legitimately nothing meaningful follows. 10-call
            # cap: a safety net against a pathological loop of syscalls
            # never reaching exit, not a claim that 10 is architecturally
            # significant.
            uc_inst.emu_stop()

    uc.hook_add(UC_HOOK_INTR, hook_intr)

    start = time.monotonic()
    try:
        uc.emu_start(BASE, BASE + len(payload), timeout=timeout_us)
    except UcError as exc:
        fault = exc
    elapsed_us = (time.monotonic() - start) * 1_000_000
    if elapsed_us >= timeout_us * 0.9:
        timed_out = True

    return calls, fault, timed_out
from unicorn import UcError

# --- schema.md vocabularies -- identical to harness.py and
# windows_harness.py on purpose. Same open note as those two files: this
# is a strong candidate for a shared module all three harnesses import,
# rather than three copies that can silently drift -- raised with Edi
# already for the Linux/Windows pair, applies here too.

ARCHES = ("x86", "x86_64")  # both valid per schema.md's global contract --
                              # x86 is accepted as INPUT, but see validate()
                              # below: this harness's underlying tool (Qiling)
                              # cannot actually observe x86 FreeBSD shellcode,
                              # confirmed on all 22 FreeBSD/x86 corpus files
                              # (identical KeyError <QL_ARCH.X86: 101> at
                              # Qiling construction, before any instruction
                              # runs -- categorical, not file-dependent).
                              # That is exactly what "inconclusive" is for
                              # per schema.md ("the harness could not get a
                              # trustworthy observation") -- so x86 is
                              # accepted, not rejected, and always resolves
                              # to inconclusive/unsupported_syscall.
OSES = ("freebsd",)

QL_ARCH_FOR = {"x86": QL_ARCH.X86, "x86_64": QL_ARCH.X8664}

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


# Filename-based category guesses -- NOT verified against file content,
# NOT a substitute for real categorization (the way Edi's corpus.json
# assigns category by hand for the Linux selection). Opt-in only via
# --guess-categories, off by default so the harness's normal behavior
# stays honest (inconclusive/unknown when nothing establishes a
# category). Kept deliberately small: only "execve_shell" has a real
# checker implemented, so guessing categories this harness can't check
# anyway (bind_shell, reboot, kill, kldload -- all present by name in
# the FreeBSD/x86 corpus) would still resolve to inconclusive/unknown,
# adding guesswork for zero behavioural difference -- and all 22
# FreeBSD/x86 files fail at the architecture step regardless of
# category (see module docstring), so category cannot change their
# outcome no matter what it's set to. Only the x86_64 files below are
# even reachable by a checker. Every entry here was read directly
# against the file's own content, not inferred from the filename
# pattern alone.
GUESSED_CATEGORIES = {
    "FreeBSD/x86-64/exec(-bin-sh)_Shellcode.c": "execve_shell",
    "FreeBSD/x86-64/execve.c": "execve_shell",
    "FreeBSD/x86-64/execve_-bin-sh_shellcode_34_bytes.c": "execve_shell",
    # 0 bytes extracted (embedded-ELF format) -- category is moot here,
    # included only so it's visible this file wasn't overlooked.
    "FreeBSD/x86-64/Execve_-bin-sh.c": "execve_shell",

    # FreeBSD/x86 -- unlike the x86_64 entries above, these are NOT
    # filename guesses. Each was run through _run_freebsd_x86() directly
    # and the observed syscall sequence was checked for "execve" before
    # being added here. Some names are misleading on their own --
    # kldload_-tmp-o.o.c's OBSERVED sequence is setuid -> execve, not
    # anything related to kernel module loading despite the filename --
    # which is exactly why this list is built from what was observed
    # running, not from what the filename claims.
    "FreeBSD/x86/-bin-sh.c": "execve_shell",
    "FreeBSD/x86/8.0-RELEASE.c": "execve_shell",
    "FreeBSD/x86/encrypted_shellcode_-bin-sh_48_bytes.c": "execve_shell",
    "FreeBSD/x86/execv(-bin-sh).c": "execve_shell",
    "FreeBSD/x86/execve(-bin-cat_&_-etc-master.passwd).c": "execve_shell",
    "FreeBSD/x86/execve_-bin-sh_23_bytes.c": "execve_shell",
    "FreeBSD/x86/execve_-bin-sh_37_bytes.c": "execve_shell",
    "FreeBSD/x86/execve_-tmp-sh.c": "execve_shell",
    "FreeBSD/x86/kldload_-tmp-o.o.c": "execve_shell",
    "FreeBSD/x86/setreuid(0,_0)_&_execve(pfctl_-d).c": "execve_shell",
    "FreeBSD/x86/setuid(0)&execve;({--sbin-ipf,-Faa,0},0);.c": "execve_shell",

    # Group 1 (bind-shell / connect-back) -- category assigned only
    # after observing the actual syscall sequence via
    # _run_freebsd_x86(), not from filename alone. See the checker
    # docstrings for exactly what's required vs not.
    "FreeBSD/x86/bind_sh_port_41254.c": "bind_shell",
    "FreeBSD/x86/portbind_shell_+_fork.c": "bind_shell",
    "FreeBSD/x86/portbind_shellcode.c": "bind_shell",
    "FreeBSD/x86/connect_back.send.exit_-etc-passwd.c": "connect_back",
    "FreeBSD/x86/connect_back_-bin-sh._81_bytes.c": "connect_back",

    # Group 2 (single confirmed syscall, trivial checker)
    "FreeBSD/x86/kill_all_processes.c": "kill",
    "FreeBSD/x86/reboot().c": "reboot",
    "FreeBSD/x86/reboot(RB_AUTOBOOT).c": "reboot",
}


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

    # A fault (UcError) that happens AFTER at least one real syscall was
    # captured is treated as a harness artifact, not a payload bug --
    # confirmed concretely, not assumed: the raw-Unicorn FreeBSD/x86
    # engine maps only the payload's own bytes, so once real
    # instructions run out after the last syscall, execution falls into
    # genuinely unmapped memory and UcError fires REGARDLESS of whether
    # the payload did exactly what it claimed. Verified on real corpus
    # files that are confirmed-correct by direct inspection (e.g.
    # kill_all_processes.c: the ONE syscall it makes really is `kill`,
    # then it faults the same way -- the fault says nothing about
    # whether the kill call itself was right). So: if calls exist, let
    # the category checker decide (pass/fail on its own terms); if there
    # is no checker for this category, "inconclusive/unknown" -- NOT a
    # fail derived from an artifact fault the payload had nothing to do
    # with wrong or right. Only an EMPTY calls list plus a fault is
    # actually attributable to the payload itself (nothing ran
    # correctly enough to even reach a syscall).
    if calls:
        checker = CHECKERS.get(category)
        if checker is None:
            return "inconclusive", "unknown"
        result = checker(calls)
        if result is None:
            return "inconclusive", "unknown"
        ok, reason = result
        return ("pass", "ok") if ok else ("fail", reason)

    if isinstance(fault, UcError):
        if "INSN_INVALID" in str(fault):
            return "fail", "bad_opcode"
        return "fail", "segv"
    if fault is not None:
        return "inconclusive", "emulator_error"
    return "fail", "no_syscalls"


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


def check_bind_shell(calls: list) -> tuple[bool, str] | None:
    """socket -> bind -> listen -> accept, in that order. dup2/execve
    after accept() are the natural continuation (redirect stdio, spawn
    a shell) but are NOT required here -- confirmed on a real corpus
    sample (portbind_shell_+_fork.c) that a legitimate bind-shell can
    stop being observable right after accept() if what follows is a
    fork() this harness doesn't model realistically. Requiring the full
    chain would wrongly fail a payload for a harness limitation, not a
    payload defect -- same principle as verdict_for's fault-after-calls
    handling above."""
    names = [c["name"] for c in calls]
    required = ["socket", "bind", "listen", "accept"]
    positions = []
    search_from = 0
    for r in required:
        if r not in names[search_from:]:
            return False, "wrong_syscall"
        idx = names.index(r, search_from)
        positions.append(idx)
        search_from = idx + 1
    return True, "ok"


def check_connect_back(calls: list) -> tuple[bool, str] | None:
    """socket -> connect, in that order. Same reasoning as bind_shell
    for not requiring what comes after (dup2/write/exit) -- confirmed
    on a real sample (connect_back.send.exit_-etc-passwd.c) that the
    full claimed sequence (open, read, close the target file, THEN
    socket/connect/write/exit to send it) does complete when nothing
    cuts it short, but the socket->connect pair is the minimum that
    actually defines "connect back", the rest is what it does once
    connected."""
    names = [c["name"] for c in calls]
    if "socket" not in names:
        return False, "wrong_syscall"
    socket_idx = names.index("socket")
    if "connect" not in names[socket_idx + 1:]:
        return False, "wrong_syscall"
    return True, "ok"


def check_kill(calls: list) -> tuple[bool, str] | None:
    if not any(c["name"] == "kill" for c in calls):
        return False, "wrong_syscall"
    return True, "ok"


def check_reboot(calls: list) -> tuple[bool, str] | None:
    if not any(c["name"] == "reboot" for c in calls):
        return False, "wrong_syscall"
    return True, "ok"


CHECKERS = {
    "execve_shell": check_execve_shell,
    "bind_shell": check_bind_shell,
    "connect_back": check_connect_back,
    "kill": check_kill,
    "reboot": check_reboot,
}


def validate(payload: bytes, arch: str, os_: str, claimed_effect: str,
              category: str | None = None) -> dict:
    """The frozen entry point, FreeBSD side. Returns exactly {verdict,
    syscalls, reason}."""
    if arch not in ARCHES:
        raise ValidationError(f"arch {arch!r} not in {ARCHES}")
    if os_ not in OSES:
        raise ValidationError(f"os {os_!r} not in {OSES}")

    if arch == "x86":
        # Qiling has no x86 FreeBSD support at all (see module docstring)
        # -- use the raw-Unicorn engine built for this above instead of
        # ever touching Qiling for this arch.
        calls, fault, timed_out = _run_freebsd_x86(payload, TIMEOUT_US)
        verdict, reason = verdict_for(calls, category, fault, timed_out)
        return {"verdict": verdict, "syscalls": calls, "reason": reason}

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
    ap = argparse.ArgumentParser(description="Validate FreeBSD shellcodes with Qiling.")
    ap.add_argument("--manifest", default="manifest.json")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--skip-self-test", action="store_true")
    ap.add_argument("--guess-categories", action="store_true",
                     help="use filename-based category guesses (GUESSED_CATEGORIES) "
                          "instead of leaving category unset -- opt-in, not the "
                          "default, since these are unverified guesses")
    args = ap.parse_args()

    if args.self_test:
        return 0 if self_test() else 1

    if not args.skip_self_test and not self_test():
        print("REFUSING: ground truth failed; the harness is not trustworthy",
              file=sys.stderr)
        return 1

    # No separate freebsd_corpus.json -- all 27 FreeBSD files (5 in
    # x86-64/, 22 in x86/) is few enough that reading straight from
    # manifest.json and filtering by path prefix is simpler than
    # building a whole selection script for it, unlike Linux's 283-file
    # pool. No `category` field exists per record (same limitation as
    # the Windows side) so every result here is either a real pass/fail
    # for the one category implemented (execve_shell) or inconclusive --
    # this is deliberately NOT claiming full corpus coverage -- all
    # pass/fail/inconclusive counts are printed at the end for an honest
    # tally, not a curated "looks good" summary.
    import json
    manifest = json.load(open(args.manifest))
    records = [r for r in manifest if r["path"].startswith("FreeBSD/")]
    records.sort(key=lambda r: r["path"])

    counts = {"pass": 0, "fail": 0, "inconclusive": 0, "no_bytes": 0}
    for r in records:
        if not r["supported"]:
            print(f"RESULT {r['path']} n/a no_bytes 0")
            counts["no_bytes"] += 1
            continue
        arch = "x86_64" if "x86-64" in r["path"] else "x86"
        payload = bytes.fromhex(r["bytes"])
        # category unknown for real corpus records -- see module
        # docstring. Guessing "execve_shell" for files whose name
        # suggests it would inflate pass counts on an assumption, not a
        # verified fact; left as None (-> inconclusive/unknown) except
        # where explicitly confirmed, matching schema.md's "when in
        # doubt, inconclusive" rule rather than schema's letter alone.
        category = GUESSED_CATEGORIES.get(r["path"]) if args.guess_categories else None
        result = validate(payload, arch, "freebsd", r["path"], category)
        print(result_line(r["path"], result))
        counts[result["verdict"]] = counts.get(result["verdict"], 0) + 1

    print()
    print(f"=== {len(records)} FreeBSD files: "
          f"{counts['pass']} pass, {counts['fail']} fail, "
          f"{counts['inconclusive']} inconclusive, "
          f"{counts['no_bytes']} no_bytes (extraction failed) ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())