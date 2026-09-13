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
import os
import re
import signal
import sys
import time
from pathlib import Path

from qiling import Qiling
from qiling.const import QL_ARCH, QL_INTERCEPT, QL_OS, QL_VERBOSE
from qiling.os.posix import syscall as _syscall_module
from unicorn import UcError

ARCHES = ("x86", "x86_64")
OSES = ("linux",)

QL_ARCH_FOR = {"x86": QL_ARCH.X86, "x86_64": QL_ARCH.X8664}

SYSCALL_NUM_REG = {"x86": "eax", "x86_64": "rax"}
POINTER_WIDTH = {"x86": 4, "x86_64": 8}

# Argument registers for a syscall, in order, per the real Linux ABI --
# needed because QL_INTERCEPT.CALL handlers do NOT receive the syscall's
# real arguments through their Python *args (confirmed directly: a CALL
# handler on socketcall received args=() every time, even though the
# syscall genuinely takes 2 arguments). ENTER handlers DO get real args
# (confirmed too -- this whole harness's execve/socket-name capture
# relies on it), so this is specific to CALL. Reading straight from
# these registers is the workaround.
SYSCALL_ARG_REGS = {
    "x86": ("ebx", "ecx", "edx", "esi", "edi", "ebp"),
    "x86_64": ("rdi", "rsi", "rdx", "r10", "r8", "r9"),
}


def read_syscall_args(ql, arch: str, count: int) -> list:
    """Read the first `count` syscall arguments directly from the ABI's
    argument registers. Use this inside CALL-intercept handlers, where
    Qiling does not pass real arguments through Python's *args."""
    regs = SYSCALL_ARG_REGS[arch]
    return [getattr(ql.arch.regs, regs[i]) for i in range(count)]

VERDICTS = ("pass", "fail", "inconclusive")

REASONS_PASS = ("ok",)
REASONS_FAIL = (
    "no_syscalls",
    "wrong_syscall",
    "wrong_args",
    "bad_opcode",
    "segv",
    "effect_mismatch",
)
REASONS_INCONCLUSIVE = (
    "timeout",
    "blocked_on_peer",
    "unsupported_syscall",
    "emulator_error",
    "needs_staging",
    "unknown",
)
REASONS = REASONS_PASS + REASONS_FAIL + REASONS_INCONCLUSIVE

TIMEOUT_US = 1_000_000
TIMEOUT_FRACTION = 0.9

# Confirmed real, not theoretical: the corpus.json run hung on the third
# file (Bind_TCP_stager_with_egghunter.c, category bind_shell) well past
# TIMEOUT_US, because Qiling's socket/bind/listen/accept/connect
# syscalls are REAL host operations by default -- ql.run(timeout=...)
# only bounds emulated-instruction time, not a genuinely blocking
# accept() the underlying Python socket call makes on the real host.
# This is the exact danger this whole project flagged from its very
# first prototype onward (raw Unicorn is inert; Qiling is not). These
# MUST be overridden to log-and-fake-return before any corpus file with
# a bind_shell/reverse_shell-shaped category runs, not just the ones
# confirmed to hang -- a payload's real behaviour is not knowable in
# advance of running it, that's the whole point of this harness.
DANGEROUS_SYSCALLS = ("socket", "bind", "listen", "accept", "accept4",
                       "connect", "fork", "vfork", "clone", "read",
                       "socketcall", "ioctl")
# ioctl joins this list for a narrower but real reason: found on a real
# corpus file that Qiling's OWN ioctl implementation does
# `ql.os.fd[fd]` to check for a few network-related ioctls
# (SIOCGIFADDR/SIOCGIFNETMASK) -- but this harness's faked socket() (see
# below) never registers its fake fd in Qiling's actual fd table, so a
# real ioctl() call on that fd hits Qiling's own IndexError. Faking
# ioctl entirely (always return 0) avoids this without needing to fully
# simulate Qiling's internal fd bookkeeping just for this one check.
# socketcall is the BIG one, found from real corpus data, not guessed in
# advance: on x86 (32-bit) Linux, EVERY socket operation multiplexes
# through this ONE syscall (eax=102) -- confirmed directly in Qiling's
# own qiling/os/posix/syscall/net.py (ql_syscall_socketcall dispatches
# by a `call` code to the real ql_syscall_connect/bind/accept/etc
# internally). Registering CALL-intercepts on "connect"/"accept"/etc BY
# NAME, as done for the other dangerous syscalls, is silently a no-op on
# x86 -- the real syscall Qiling ever sees there is "socketcall", never
# "connect" by itself. This was the root cause behind several real,
# confusing failures found running the full manifest: OSError "Network
# is unreachable" (a real connect() actually dispatching), most of the
# SIGALRM timeouts (real accept() blocking), and category checkers
# failing with wrong_syscall on files that DID do the right thing (their
# calls list had "socketcall", never "connect"/"bind"/etc by name, so
# check_bind_shell/check_connect_back never matched). See
# make_call_handler's socketcall branch for the fix: decode the
# sub-operation code and record THAT name instead of "socketcall", so
# the existing checkers keep working unchanged.
SOCKETCALL_NAMES = {
    1: "socket", 2: "bind", 3: "connect", 4: "listen", 5: "accept",
    18: "accept4",
}
# read() is in DANGEROUS_SYSCALLS for a related reason: found on a real
# corpus file (Bind_TCP_stager_with_egghunter.c) that a bind-shell's
# read(0, buf, N) after dup2'ing a socket onto fd 0 tries to read REAL
# data from whatever fd 0 actually is -- with no real client connected,
# that's a genuine unbounded block, confirmed via a wall-clock-timed
# hang. Means a payload's read() calls never see real file content --
# acceptable since no current checker depends on read()'s return data.
# execve is deliberately NOT in this list -- it needs different handling
# from the others, found the hard way: routing it through
# QL_INTERCEPT.CALL (like socket/bind/etc) came back with args=() empty
# every time, the same "CALL doesn't pass positional args the way ENTER
# does" behaviour observed on socket/bind/accept -- but unlike those,
# execve's args ARE the whole point of the execve_shell check (the shell
# path). Confirmed instead: registering execve with QL_INTERCEPT.ENTER
# (which DOES get real args, per point 1 above) and calling
# ql.emu_stop() from INSIDE that same ENTER handler, right after
# recording, stops cleanly before the real dispatch causes whatever
# hang/crash prompted this whole list -- verified directly (0.01s,
# correct pointer args, no hang) rather than assumed. See
# make_enter_handler's execve special-case below.

SYSCALL_NAMES = [
    n[len("ql_syscall_"):]
    for n in dir(_syscall_module)
    if n.startswith("ql_syscall_")
]

GROUND_TRUTH = [
    ("x86", "31c050682f2f7368682f62696e89e3505389e1b00bcd80", "execve //bin/sh"),
    ("x86_64", "4831d248bb2f2f62696e2f736848c1eb08534889e750574889e6b03b0f05",
     "execve //bin/sh"),
    ("x86_64", "4831ffb0690f054831d248bbff2f62696e2f736848c1eb08534889e74831c050574889e6b03b0f056a015f6a3c580f05",
     "setuid 0 + execve //bin/sh"),
    ("x86", "6a175831dbcd80b00b6a0b58b00b9952682f2f7368682f62696e89e3cd80",
     "setuid 0 + execve //bin/sh, 0"),
    ("x86", "31db8d431799cd8031c951686e2f7368682f2f62698d410b89e3cd80",
     "setuid 0 + execve //bin/sh, 0, 0")
]


class ValidationError(Exception):
    """Raised for a caller mistake -- an arch or os outside the schema."""


class Recorder:
    def __init__(self, arch: str):
        self.arch = arch
        self.calls: list[dict] = []

    def attach(self, ql: Qiling) -> None:
        """ENTER hook (observe-only) on every known syscall name EXCEPT
        the ones in DANGEROUS_SYSCALLS, which get QL_INTERCEPT.CALL
        (REPLACE) instead -- confirmed the hard way, not assumed: a
        first attempt using ENTER for socket/bind/listen/accept still
        let the REAL accept() block on this host, confirmed via a
        wall-clock-timed test that hung past its own timeout (measured
        exit code 124). Verified directly in Qiling's own source
        (QlOsPosix.set_syscall docstring): QL_INTERCEPT.ENTER runs
        "before the target syscall is called" (the real one still
        runs after); QL_INTERCEPT.CALL runs "instead of the existing
        target implementation" -- CALL is the one that actually
        prevents real dispatch, matching this whole project's very
        first prototype's core lesson (Qiling's POSIX syscalls are real
        host operations unless explicitly replaced)."""
        def make_enter_handler(name: str):
            def handler(ql_inst, *args):
                num_reg = SYSCALL_NUM_REG[self.arch]
                n = getattr(ql_inst.arch.regs, num_reg)
                resolved_args = self.resolve_args(ql_inst, args)
                self.calls.append({"n": n, "name": name,
                                    "args": resolved_args, "ret": None})
                if name == "execve":
                    # ENTER (not CALL) specifically for execve, so args
                    # resolve correctly (see DANGEROUS_SYSCALLS comment
                    # for why CALL came back empty here) -- emu_stop()
                    # called from inside this same ENTER handler, right
                    # after recording, verified directly to stop cleanly
                    # before the real dispatch causes trouble (0.01s,
                    # correct args, no hang -- not assumed).
                    ql_inst.emu_stop()
            return handler

        def make_call_handler(name: str):
            def handler(ql_inst, *args):
                num_reg = SYSCALL_NUM_REG[self.arch]
                n = getattr(ql_inst.arch.regs, num_reg)
                fake_ret = 0
                effective_name = name
                if name == "socketcall":
                    # Real args, not the (empty) *args this handler
                    # receives -- see SYSCALL_ARG_REGS comment. ebx/rdi
                    # holds `call` (the sub-operation code), ecx/rsi
                    # holds a pointer to the real per-call argument
                    # block -- read call_code directly; the pointer
                    # itself isn't dereferenced here (would need a
                    # per-sub-op arg count to know how many words to
                    # read, not implemented -- args stays coarse for
                    # socketcall specifically).
                    call_code = read_syscall_args(ql_inst, self.arch, 1)[0]
                    effective_name = SOCKETCALL_NAMES.get(call_code, name)
                    resolved_args = [call_code]
                else:
                    # Fixed count of 4 -- covers every DANGEROUS_SYSCALLS
                    # entry's real arity (accept4 needs the most, at 4)
                    # with a little headroom; reading a couple of extra
                    # registers for a 2-arg syscall like listen() is
                    # harmless (resolve_args just won't find a valid
                    # string/pointer in the unused ones).
                    real_args = read_syscall_args(ql_inst, self.arch, 4)
                    resolved_args = self.resolve_args(ql_inst, real_args)
                if effective_name == "socket":
                    fake_ret = 3  # a plausible-looking fake fd, not a
                                   # real one -- nothing opens a real
                                   # socket, so this number is never
                                   # backed by an actual descriptor
                self.calls.append({"n": n, "name": effective_name,
                                    "args": resolved_args, "ret": fake_ret})
                return fake_ret
            return handler

        for name in SYSCALL_NAMES:
            if name in DANGEROUS_SYSCALLS:
                try:
                    ql.os.set_syscall(name, make_call_handler(name), QL_INTERCEPT.CALL)
                except Exception:
                    pass
                continue
            try:
                ql.os.set_syscall(name, make_enter_handler(name), QL_INTERCEPT.ENTER)
            except Exception:
                pass

    def resolve_args(self, ql: Qiling, args: tuple) -> list:
        """Best-effort dereference. Every arg here is a raw register
        value -- there's no static way to know which positions are C
        strings vs plain integers vs pointer arrays from the handler
        args alone, so this tries read_cstring on anything that looks
        like a plausible pointer and falls back to the raw int
        otherwise. A bad dereference must never take the run down."""
        resolved = []
        for a in args:
            if not isinstance(a, int) or a <= 0:
                resolved.append(a)
                continue
            try:
                # maxlen is critical, not cosmetic: confirmed the hard
                # way that without it (default maxlen=0, unbounded),
                # this hung for many seconds on a read()'s OUTPUT buffer
                # argument -- read()'s buf is uninitialised/garbage at
                # the moment this ENTER hook fires (the real read()
                # hasn't written into it yet), so scanning for a null
                # terminator with no cap can run through a very long
                # stretch of mapped memory before finding one, or never
                # find one within a length that matters. 256 is a
                # generous bound for anything this harness cares about
                # (paths, shell commands) without risking that hang.
                s = ql.os.utils.read_cstring(a, maxlen=256)
                if s and all(32 <= ord(c) < 127 or c in "\t\n" for c in s):
                    resolved.append(s)
                    continue
            except Exception:
                pass
            resolved.append(a)
        return resolved

    def collect_returns(self, ql: Qiling) -> None:
        """Fill in `ret` from ql.os.stats.syscalls. Verified directly
        (module header, point 4): keyed by "ql_syscall_<name>" WITH the
        prefix (SYSCALL_NAMES strips it, stats.syscalls does not), each
        value a LIST of per-call records in invocation order. Match
        self.calls (already in invocation order from the ENTER hooks)
        against that list by occurrence count per name."""
        seen_count: dict[str, int] = {}
        for call in self.calls:
            if call["ret"] is not None:
                continue  # already set by the CALL-intercept fake handler
                          # for a dangerous syscall -- don't let a real
                          # stats lookup (which may not even exist, since
                          # the real implementation never actually ran)
                          # clobber the fake, intentional value
            key = f"ql_syscall_{call['name']}"
            records = ql.os.stats.syscalls.get(key, [])
            idx = seen_count.get(call["name"], 0)
            seen_count[call["name"]] = idx + 1
            if idx < len(records):
                call["ret"] = records[idx].get("retval")


def verdict_for(calls: list, claimed_effect: str, category: str | None,
                fault: Exception | None, timed_out: bool) -> tuple[str, str]:
    """Same fail/inconclusive boundary documented in this file's own
    docstring TODO -- implemented exactly as specified there."""
    if timed_out:
        return "inconclusive", "timeout"
    if isinstance(fault, UcError) or "UC_ERR_" in str(fault):
        # Qiling's own internal syscall implementations (e.g.
        # ql_syscall_execve, ql_syscall_access reading a garbage
        # pathname pointer) can raise a real UcError from WITHIN
        # load_syscall's try/except, which re-wraps it -- confirmed
        # directly on real corpus files where the traceback showed a
        # genuine unicorn.UcError ("Invalid memory read
        # (UC_ERR_READ_UNMAPPED)") that nonetheless didn't satisfy a
        # plain isinstance() check here, landing in emulator_error
        # instead of the more accurate fail/segv. Checking the message
        # string as a fallback catches this without needing to chase
        # down every wrapper type Qiling might use.
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


SHELLS = ("/bin/sh", "/bin//sh", "//bin/sh", "/bin/bash", "/bin/dash",
          "/bin/zsh", "/bin/ksh", "/bin/csh", "/bin/ash")


def _names(calls: list) -> list:
    return [c["name"] for c in calls]


def _args_contain(calls: list, name: str, substr: str) -> bool:
    """True if any call named `name` has a string arg containing substr
    (case-insensitive). Used throughout below for path/command checks."""
    substr = substr.lower()
    for c in calls:
        if c["name"] != name:
            continue
        for a in c["args"]:
            if isinstance(a, str) and substr in a.lower():
                return True
    return False


def _any_args_contain(calls: list, substr: str) -> bool:
    """Same as _args_contain but across ALL calls, not just one name --
    used for broad execve-argument-substring categories (proc_kill,
    system_state) where the claim is closer to "ran a command whose
    name/args suggest X" than "called a specific syscall"."""
    substr = substr.lower()
    for c in calls:
        for a in c["args"]:
            if isinstance(a, str) and substr in a.lower():
                return True
    return False


def check_execve_shell(calls: list) -> tuple[bool, str] | None:
    ex = [c for c in calls if c["name"] == "execve"]
    if not ex:
        return False, "wrong_syscall"
    for c in ex:
        if not c["args"]:
            continue
        path = c["args"][0]
        if not isinstance(path, str):
            continue
        # Normalise repeated slashes -- confirmed on a real corpus file
        # (setreud(getuid...)_&_execve(-bin-sh).c uses "////bin/bash",
        # which is functionally identical to "/bin/bash" but didn't
        # match SHELLS on an exact string comparison). Collapsing runs
        # of "/" is safe and standard (POSIX treats them as equivalent).
        normalized = re.sub(r"/+", "/", path)
        if normalized in SHELLS:
            return True, "ok"
    return False, "wrong_args"


def check_bind_shell(calls: list) -> tuple[bool, str] | None:
    """socket -> bind -> listen, in that order. accept/dup2/execve after
    are the natural continuation but not required -- same reasoning
    used for the FreeBSD harness's bind_shell checker: a real bind-shell
    can legitimately stop being observable right after listen() if what
    follows blocks on a peer that never connects (schema.md's own
    blocked_on_peer case) or forks."""
    names = _names(calls)
    required = ["socket", "bind", "listen"]
    search_from = 0
    for r in required:
        if r not in names[search_from:]:
            return False, "wrong_syscall"
        search_from = names.index(r, search_from) + 1
    return True, "ok"


def check_reverse_shell(calls: list) -> tuple[bool, str] | None:
    """socket -> connect, in that order. Same "don't require what comes
    after" reasoning as bind_shell."""
    names = _names(calls)
    if "socket" not in names:
        return False, "wrong_syscall"
    socket_idx = names.index("socket")
    if "connect" not in names[socket_idx + 1:]:
        return False, "wrong_syscall"
    return True, "ok"


def check_chmod_chown(calls: list) -> tuple[bool, str] | None:
    """chmod/fchmod/chown/fchown/lchown present. NOTE: at least two
    corpus.json entries labelled chmod_chown (setuid(0)_&_reboot.c,
    setreuid()_+_exec_-usr-bin-python.c) do NOT actually call any of
    these based on their claimed effect (reboot, running python) --
    likely a real mislabel in corpus.json, not something to design a
    workaround for here. Checking the syscall that the category name
    actually says, and reporting fail/wrong_syscall honestly on a
    mismatch, is correct behaviour -- it surfaces the mislabel instead
    of hiding it."""
    if any(n in ("chmod", "fchmod", "fchmodat") for n in _names(calls)):
        return True, "ok"
    if any(n in ("chown", "fchown", "lchown", "fchownat") for n in _names(calls)):
        return True, "ok"
    return False, "wrong_syscall"


def check_file_op(calls: list) -> tuple[bool, str] | None:
    """A plain filesystem operation happened: open/openat, mkdir, rmdir,
    unlink, rename -- the category is broad by nature (corpus.json shows
    "add a hosts entry", "mkdir", "rmdir", "open /dev/cdrom" all under
    file_op), so this checks for ANY of the common file-touching
    syscalls rather than one specific one."""
    file_syscalls = {"open", "openat", "mkdir", "mkdirat", "rmdir",
                      "unlink", "unlinkat", "rename", "renameat"}
    if any(n in file_syscalls for n in _names(calls)):
        return True, "ok"
    return False, "wrong_syscall"


def check_add_user(calls: list) -> tuple[bool, str] | None:
    """Broad by corpus evidence: writing to /etc/passwd or /etc/shadow
    (open+write), reading them via execve(cat, [...,/etc/passwd]), or
    chmod'ing them -- all appear under this category in corpus.json.
    Checks for "passwd" or "shadow" appearing in the args of open OR
    execve OR chmod, rather than requiring one specific syscall."""
    for name in ("open", "openat", "execve", "chmod", "fchmod"):
        if _args_contain(calls, name, "passwd") or _args_contain(calls, name, "shadow"):
            return True, "ok"
    return False, "wrong_syscall"


def check_egghunter(calls: list) -> tuple[bool, str] | None:
    """Egghunters work by repeatedly probing memory with a syscall that
    faults safely on unmapped pages (classically access() on Linux) --
    checked as 2+ calls to the SAME probe syscall, since a single call
    doesn't distinguish this from any other payload that happens to
    call access() once for an unrelated reason."""
    names = _names(calls)
    for probe in ("access", "sigaction", "rt_sigaction"):
        if names.count(probe) >= 2:
            return True, "ok"
    return False, "wrong_syscall"


def check_proc_kill(calls: list) -> tuple[bool, str] | None:
    """kill()/tgkill() directly, OR execve of a process-stopping command
    (killall, shutdown, reboot) -- corpus.json shows both patterns under
    this category (sys_kill(-1,9).c calls kill() directly;
    shutdown_-h_now.c execve's /sbin/shutdown instead)."""
    if any(n in ("kill", "tgkill", "tkill") for n in _names(calls)):
        return True, "ok"
    for kw in ("killall", "shutdown", "reboot"):
        if _args_contain(calls, "execve", kw):
            return True, "ok"
    return False, "wrong_syscall"


def check_net_other(calls: list) -> tuple[bool, str] | None:
    """Broad: any socket-family syscall, not specifically bind or
    connect (those have their own categories) -- covers raw sockets,
    stagers that recv() into a jump target, etc."""
    net_syscalls = {"socket", "recv", "recvfrom", "send", "sendto"}
    if any(n in net_syscalls for n in _names(calls)):
        return True, "ok"
    return False, "wrong_syscall"


def check_system_state(calls: list) -> tuple[bool, str] | None:
    """Broad, matching corpus.json evidence: sethostname() directly, a
    write into /proc/sys (ASLR toggle, ip_forward), or execve of a
    system-configuration tool (iptables)."""
    if "sethostname" in _names(calls):
        return True, "ok"
    for name in ("open", "openat", "write"):
        if _args_contain(calls, name, "/proc/sys"):
            return True, "ok"
    if _args_contain(calls, "execve", "iptables"):
        return True, "ok"
    return False, "wrong_syscall"


CHECKERS = {
    "execve_shell": check_execve_shell,
    "bind_shell": check_bind_shell,
    "reverse_shell": check_reverse_shell,
    "chmod_chown": check_chmod_chown,
    "file_op": check_file_op,
    "add_user": check_add_user,
    "egghunter": check_egghunter,
    "proc_kill": check_proc_kill,
    "net_other": check_net_other,
    "system_state": check_system_state,
    # "encoder" and "uncategorised" deliberately have NO checker -- see
    # module notes: encoder's real effect is whatever runs AFTER the
    # self-decode stub, which isn't derivable from the decoder's own
    # syscalls (there typically are none until decoding finishes), and
    # uncategorised has no claim to check by definition. Both correctly
    # resolve to inconclusive/unknown rather than a guessed check.
}


def _alarm_handler(signum, frame):
    raise TimeoutError("hard wall-clock cutoff (SIGALRM)")


def validate(payload: bytes, arch: str, os_: str, claimed_effect: str,
             category: str | None = None) -> dict:
    if arch not in ARCHES:
        raise ValidationError(f"arch {arch!r} not in {ARCHES}")
    if os_ not in OSES:
        raise ValidationError(f"os {os_!r} not in {OSES}")

    recorder = Recorder(arch)
    fault: Exception | None = None
    timed_out = False

    # Hard backstop, on top of Qiling's own timeout= parameter -- found
    # necessary the hard way, not preemptively: individual dangerous
    # syscalls (socket/bind/accept/connect/read on fd 0) were fixed one
    # at a time as each was discovered hanging the corpus run, but
    # chasing every possible blocking syscall this way doesn't scale and
    # there is no guarantee the list is complete (a corpus of real,
    # varied shellcode WILL eventually call something not yet
    # discovered). SIGALRM forcibly interrupts Python execution after a
    # real wall-clock number of seconds regardless of what's blocking --
    # Qiling's own timeout= only bounds emulated-instruction time, which
    # is exactly the gap that let read(0,...) and accept() hang past it
    # in the first place. 3 seconds is generous relative to
    # TIMEOUT_US (1s) -- if Qiling's own mechanism is working, this
    # should essentially never fire; it exists for the cases where it
    # doesn't.
    old_handler = signal.signal(signal.SIGALRM, _alarm_handler)
    signal.alarm(3)

    start = time.monotonic()
    try:
        ql = Qiling(code=payload, archtype=QL_ARCH_FOR[arch],
                    ostype=QL_OS.LINUX, verbose=QL_VERBOSE.OFF)
        recorder.attach(ql)
        ql.run(count=2000, timeout=TIMEOUT_US)
        recorder.collect_returns(ql)
    except UcError as exc:
        fault = exc
    except TimeoutError:
        timed_out = True
    except Exception as exc:
        fault = exc
    finally:
        signal.alarm(0)  # cancel -- must always run, even on the
                          # success path, or the NEXT validate() call
                          # inherits a countdown that started here
        signal.signal(signal.SIGALRM, old_handler)
    elapsed_us = (time.monotonic() - start) * 1_000_000
    if elapsed_us >= TIMEOUT_US * TIMEOUT_FRACTION:
        timed_out = True

    verdict, reason = verdict_for(recorder.calls, claimed_effect, category,
                                   fault, timed_out)
    return {"verdict": verdict, "syscalls": recorder.calls, "reason": reason}


def guess_category(path: str, claimed_effect: str) -> str | None:
    """Keyword-based category guess for files outside corpus.json's
    curated ~60 -- NOT manually verified like Edi's real category
    assignments, an explicit heuristic used only when --guess-categories
    is passed. Checked in priority order: specific, checker-backed
    categories first, "encoder" (which has no real checker -- see
    CHECKERS' comment -- always resolves to inconclusive/unknown
    regardless of being guessed correctly) checked last, so a file that
    could match a real, actionable category doesn't get misrouted into
    one that can never produce a verdict either way."""
    s = (path + " " + claimed_effect).lower()

    def has(*kws):
        return any(k in s for k in kws)

    if has("egghunter", "egg_hunter", "egg hunter", "egg-hunter"):
        return "egghunter"
    if has("bind") and has("shell", "tcp", "port", "tcp-", "tcp_"):
        return "bind_shell"
    if has("reverse", "connect_back", "connectback", "back-connect",
           "back_connect", "backconnect"):
        return "reverse_shell"
    if has("adduser", "add_user", "add root user", "add new",
           "useradd", "add_root", "-etc-passwd") and has(
           "add", "new", "creat"):
        return "add_user"
    if has("chmod", "chown", "fchmod", "fchown"):
        return "chmod_chown"
    if has("kill", "reboot", "shutdown", "sync") and not has("killall5"):
        return "proc_kill"
    if has("mkdir", "rmdir", "unlink", "file_reader", "file reader",
           "copy_", "writeable", "-etc-passwd", "-etc-shadow", "file_op",
           "file unlinker"):
        return "file_op"
    if has("http", "download", "socket", "-dev-dsp", "ifconfig", "wget",
           "ftp", "proxy"):
        return "net_other"
    if has("iptables", "aslr", "randomize", "sethostname", "hostname",
           "ip_forward", "proc-sys", "proc/sys"):
        return "system_state"
    if has("execve", "exec_", "-exec", "-sh.c", "-bin-sh",
           "/bin/sh", "bin-sh"):
        return "execve_shell"
    if has("polymorphic", "encoder", "encrypted", "obfuscated",
           "alphanumeric", "mutated", "decoder", "encoded", "null-free",
           "nullfree"):
        return "encoder"
    return None


def result_line(path: str, result: dict) -> str:
    return (f"RESULT {path} {result['verdict']} {result['reason']} "
            f"{len(result['syscalls'])}")


def self_test() -> bool:
    all_ok = True
    for arch, hexbytes, claimed in GROUND_TRUTH:
        payload = bytes.fromhex(hexbytes)
        result = validate(payload, arch, "linux", claimed, "execve_shell")
        ok = result["verdict"] == "pass"
        all_ok = all_ok and ok
        status = "OK" if ok else "FAIL"
        print(f"{status}  {arch:6s} {claimed:35s} -> "
              f"{result['verdict']}/{result['reason']}")
    return all_ok


def write_step_summary(section_title: str, all_results: list, counts: dict,
                        extra_note: str = "") -> None:
    """Append a markdown table to GITHUB_STEP_SUMMARY, same pattern used
    for the Windows and FreeBSD pipelines -- shows up directly on the
    Actions run page, no artifact download needed."""
    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if not step_summary:
        return
    lines = [f"## {section_title}", ""]
    if extra_note:
        lines.append(extra_note)
        lines.append("")
    lines.append("| | Count |")
    lines.append("|---|---|")
    lines.append(f"| Total | {sum(counts.values())} |")
    lines.append(f"| Pass | {counts.get('pass', 0)} |")
    lines.append(f"| Fail | {counts.get('fail', 0)} |")
    lines.append(f"| Inconclusive | {counts.get('inconclusive', 0)} |")
    lines.append("")
    lines.append("<details><summary>Full results</summary>")
    lines.append("")
    lines.append("| Path | Verdict | Reason | Syscalls |")
    lines.append("|---|---|---|---|")
    icon = {"pass": "✅", "fail": "❌", "inconclusive": "❓"}
    for path, verdict, reason, n_syscalls in all_results:
        lines.append(f"| {path} | {icon.get(verdict, '')} {verdict} "
                      f"| {reason} | {n_syscalls} |")
    lines.append("")
    lines.append("</details>")
    lines.append("")
    with open(step_summary, "a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def main() -> int:
    ap = argparse.ArgumentParser(description="Validate shellcodes with Qiling.")
    ap.add_argument("--corpus", default="corpus.json",
                     help="curated file with 'category' per record "
                          "(corpus.json) -- gives real pass/fail verdicts")
    ap.add_argument("--manifest",
                     help="raw extraction file (manifest.json) -- no "
                          "'category' field, so every record resolves to "
                          "inconclusive/unknown UNLESS its path is also in "
                          "--corpus (in which case that category is used). "
                          "Runs against every in-scope Linux x86/x86_64 "
                          "record, not just the curated ~60 -- use this for "
                          "raw syscall-capture coverage across the whole "
                          "corpus, not for a verdict count.")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--skip-self-test", action="store_true")
    ap.add_argument("--guess-categories", action="store_true",
                     help="for --manifest records with no known category "
                          "(not in --corpus), guess one from filename "
                          "keywords via guess_category() instead of "
                          "leaving it unset. Heuristic, NOT manually "
                          "verified -- may misclassify. Off by default.")
    args = ap.parse_args()

    if args.self_test:
        return 0 if self_test() else 1

    if not args.skip_self_test and not self_test():
        print("REFUSING: ground truth failed; the harness is not trustworthy",
              file=sys.stderr)
        return 1

    if args.manifest:
        # The full in-scope set, not the curated ~60 -- most records
        # here have no known category (corpus.json only covers the
        # curated subset), so most resolve to inconclusive/unknown. That
        # is still useful: it proves the harness can construct, run and
        # capture syscalls for every in-scope file, not just the ones
        # someone already hand-picked. category_by_path lets a record
        # that DOES also appear in corpus.json (by path) borrow its real
        # category rather than being treated as unknown twice over.
        category_by_path = {}
        if Path(args.corpus).exists():
            for rec in json.loads(Path(args.corpus).read_text()):
                category_by_path[rec["path"]] = rec.get("category")

        manifest = json.loads(Path(args.manifest).read_text())
        records = [r for r in manifest
                   if r.get("os") == "linux" and r.get("arch") in ARCHES
                   and r.get("supported")]
        counts = {"pass": 0, "fail": 0, "inconclusive": 0}
        all_results = []
        for rec in records:
            payload = bytes.fromhex(rec["bytes"])
            category = category_by_path.get(rec["path"])
            if category is None and args.guess_categories:
                category = guess_category(rec["path"], rec["claimed_effect"])
            result = validate(payload, rec["arch"], rec["os"],
                               rec["claimed_effect"], category)
            print(result_line(rec["path"], result))
            counts[result["verdict"]] = counts.get(result["verdict"], 0) + 1
            all_results.append((rec["path"], result["verdict"],
                                 result["reason"], len(result["syscalls"])))
        guessed_count = sum(1 for r in records if r["path"] not in category_by_path
                            and args.guess_categories
                            and guess_category(r["path"], r["claimed_effect"]) is not None)
        print()
        print(f"=== {len(records)} in-scope Linux files (manifest.json): "
              f"{counts['pass']} pass, {counts['fail']} fail, "
              f"{counts['inconclusive']} inconclusive "
              f"({len(category_by_path)} have a manually-verified category "
              f"via corpus.json; {guessed_count} more got a heuristic "
              f"filename-based guess via --guess-categories; the rest "
              f"had no keyword match and resolve to inconclusive/unknown) ===")
        write_step_summary(
            "Linux harness -- full in-scope manifest", all_results, counts,
            extra_note=(f"{len(category_by_path)} manually-verified categories "
                        f"(corpus.json), {guessed_count} heuristic guesses "
                        f"(--guess-categories), rest unknown."))
        return 0

    corpus = json.loads(Path(args.corpus).read_text())
    counts = {"pass": 0, "fail": 0, "inconclusive": 0}
    all_results = []
    for rec in corpus:
        payload = bytes.fromhex(rec["bytes"])
        result = validate(payload, rec["arch"], rec["os"],
                           rec["claimed_effect"], rec.get("category"))
        print(result_line(rec["path"], result))
        counts[result["verdict"]] = counts.get(result["verdict"], 0) + 1
        all_results.append((rec["path"], result["verdict"],
                             result["reason"], len(result["syscalls"])))

    print()
    print(f"=== {len(corpus)} files: {counts['pass']} pass, "
          f"{counts['fail']} fail, {counts['inconclusive']} inconclusive ===")
    write_step_summary("Linux harness -- curated corpus (corpus.json)",
                        all_results, counts)
    return 0


if __name__ == "__main__":
    sys.exit(main())