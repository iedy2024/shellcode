#!/usr/bin/env python3
"""
Implements the interface from docs/schema.md, Windows side:

    validate(payload, arch, os_, claimed_effect) -> {verdict, syscalls, reason}

Mirrors scripts/harness.py's structure (Recorder, verdict_for, per-effect
checkers, self_test/main gating) so the two halves stay "literally
interchangeable" per schema.md.

--------------------------------------------------------------------------
WHY SPEAKEASY, NOT QILING -- this section exists because the first attempt
at this file used Qiling and hit a wall worth recording so nobody re-walks
into it.

Qiling's QL_OS.WINDOWS mode, even in pure `code=` shellcode mode, tries to
load real kernel32.dll/user32.dll/ntdll.dll PE files from a rootfs and run
their actual DllMain initialisation routines as part of constructing the
Qiling object -- before any hook we register gets a chance to run. Modern
(Windows 10/11) system DLLs pull in a long chain of `api-ms-win-core-*.dll`
forwarder stubs plus KERNELBASE.dll/win32u.dll/GDI32.dll, and even with all
of those present (collected via Qiling's own dllscollector.bat, run as
Administrator on real Windows), DllMain still called internal APIs Qiling
does not implement (`UserClientDllInitialize`, `RtlInitializeCriticalSection`)
and "bailed" -- confirmed to be a known, general Qiling limitation, not
specific to this setup (github.com/qilingframework/qiling issues #1323 and
#1175 show the identical failure pattern on unrelated programs). Attempting
to pre-register no-op stubs for the missing APIs via `ql.os.set_api()` after
construction had no effect at all, because the failing calls happen DURING
`Qiling(...)`, before that call is even reachable.

Speakeasy (mandiant/speakeasy, MIT licensed, the actively-maintained
successor to FireEye's original shellcode emulation work) avoids this
entirely by design: it does not load real DLL files or run real DllMain at
all. Windows APIs are modelled directly in Python, and shellcode's
PEB-walk / GetProcAddress-style resolution is caught by "doping" the
export-table addresses it expects to find, switching into a Python handler
the moment the shellcode's own resolution logic reads them. No rootfs, no
DLL collection, no registry export -- confirmed by direct testing against
three real samples from manifest.json, no setup beyond `pip install
speakeasy-emulator`.

Verified against real corpus samples, not assumed:
  - Windows/Allwin_WinExec_cmd.exe_+_ExitProcess_Shellcode.c: full, correct,
    ordered API trace with named args --
    GetProcAddress(hKernel32, "WinExec") -> WinExec("cmd", 0x5) ->
    GetProcAddress(hKernel32, "ExitProcess"). Exactly what the file claims.
  - Windows/XP_SP3_English_MessageBoxA.c and
    Windows/sp3_(Tr)_MessageBoxA_Shellcode.c: BOTH fail with an
    `invalid_fetch` error, apis=[]. Real, reproducible pattern, not a fluke
    -- both use a hand-rolled PE export-table walk instead of ever calling
    a nameable "GetProcAddress"-style function, so there is no import/export
    table ACCESS for Speakeasy's doping mechanism to intercept. This is a
    genuine gap in what Speakeasy can observe for THIS resolution style, not
    an infrastructure problem the way the Qiling rootfs/DllMain issue was.
    Samples using straightforward named-API resolution are far more likely
    to produce a usable trace than samples using obfuscated/manual
    resolution -- expect this split to keep showing up across the corpus,
    not just these three files.
--------------------------------------------------------------------------
"""
import argparse
import json
import sys
import time
from pathlib import Path

import speakeasy

# --- schema.md vocabularies -- identical to the Linux harness, on purpose.
# Same note as before: worth raising with Edi whether this should be a
# shared module both harnesses import, rather than two copies that can
# silently drift.

ARCHES = ("x86", "x86_64")
OSES = ("windows",)

SPEAKEASY_ARCH = {"x86": "x86", "x86_64": "amd64"}

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

TIMEOUT_SECONDS = 5.0

# Ground truth, same gating role as the Linux side's GROUND_TRUTH and the
# earlier Qiling-based attempt at this file. Bytes pulled directly from
# manifest.json. Left BOTH the working and the currently-failing samples
# in here on purpose -- self_test() gates on ALL of them passing, so this
# accurately reflects "not trustworthy yet" rather than hiding the gap by
# only listing the sample that happens to work.
GROUND_TRUTH = [
    ("x86",
     "fc33d2b23064ff325a8b520c8b52148b722833c9b11833ff33c0ac3c617c022c20"
     "c1cf0d03f8e2f081ff5bbc4a6a8b5a108b1275da8b533c03d3ff72348b527803d3"
     "8b722003f333c941ad03c381384765745075f4817804726f634175eb8178086464"
     "726575e2498b722403f3668b0c4e8b721c03f38b148e03d3526878656301fe4c24"
     "036857696e455453ffd268636d6401fe4c24036a0533c98d4c240451ffd0686573"
     "73018bdffe4c24036850726f63684578697454ff742420ff54242057ffd0",
     "WinExec cmd.exe + ExitProcess", "winexec_cmd"),

    # Both currently fail with invalid_fetch (hand-rolled export-table
    # walk, no nameable API call for Speakeasy to intercept) -- kept in
    # GROUND_TRUTH deliberately so self_test() honestly reports "not
    # trustworthy yet" instead of quietly excluding the harder cases.
    ("x86",
     "31c031db31c931d251686c6c20206833322e64687573657289e1bb7b1d807c51ffd3"
     "b95e6730ef81c111111111516861676542684d65737389e15150bb40ae807cffd3"
     "89e131d252515152ffd031c050b812cb817cffd0",
     "MessageBoxA popup", "messagebox_a"),

    ("x86",
     "31c031db31d931d2eb355988510abb7b1d807c51ffd3eb375931d288510b5150bb"
     "30ae807cffd3eb375931d288510752525152ffd031d250b8faca817cffd0e8c6ff"
     "ffff7573657233322e646c6c4ee8c4ffffff4d657373616765426f78414ee8c4ff"
     "ffff697473206f6b21ff",
     "MessageBoxA popup", "messagebox_a"),
]


class ValidationError(Exception):
    """Raised for a caller mistake -- an arch or os outside the schema."""


class Recorder:
    """
    Wraps a Speakeasy run's API trace into the schema's `syscalls` shape.

    Unlike the Linux/Qiling side, Speakeasy already returns a structured,
    ordered list of {api_name, args, ret_val} per entry point via
    get_json_report() -- confirmed directly (see module docstring). This
    class's job is just reshaping that into schema.md's {n, name, args,
    ret} form, not re-implementing hook plumbing from scratch.
    """

    def __init__(self):
        self.calls: list[dict] = []
        self.error: dict | None = None

    def load_from_report(self, report: dict) -> None:
        entry_points = report.get("entry_points", [])
        if not entry_points:
            return
        ep = entry_points[0]
        for call in ep.get("apis", []):
            self.calls.append({
                "n": None,  # no numeric syscall-number equivalent for a
                            # named Win32 API call -- left null rather than
                            # invented, same principle as the Qiling
                            # attempt's Recorder docstring stated
                "name": call.get("api_name"),
                "args": call.get("args", []),
                "ret": call.get("ret_val"),
            })
        self.error = ep.get("error")


def verdict_for(calls: list, claimed_effect: str, category: str | None,
                 fault: Exception | None, timed_out: bool,
                 speakeasy_error: dict | None) -> tuple[str, str]:
    """
    Identical mapping logic to the Linux harness's verdict_for -- see that
    file's docstring for why this is written as a port rather than a fresh
    implementation. speakeasy_error is the extra Windows-specific input:
    Speakeasy reports its own faults (invalid_fetch, unsupported_api, etc)
    inside the JSON report rather than as a raised Python exception, so
    they need a mapping too.
    """
    if timed_out:
        return "inconclusive", "timeout"
    if fault is not None:
        return "inconclusive", "emulator_error"
    if not calls:
        # Only treat Speakeasy's own internal error as the reason when
        # there's truly nothing to evaluate. Found the ordering bug the
        # hard way: the WinExec ground-truth sample gets a FULL correct
        # 3-call trace (GetProcAddress -> WinExec -> GetProcAddress) AND
        # a trailing "unsupported_api" from something it calls right
        # after -- checking speakeasy_error first was reporting
        # "inconclusive" on a sample that actually had everything needed
        # to verdict as pass. A late, incidental error after the claim-
        # relevant calls already happened is not the same as "no
        # trustworthy observation".
        if speakeasy_error is not None:
            err_type = speakeasy_error.get("type", "")
            if err_type == "unsupported_api":
                return "inconclusive", "unsupported_syscall"
            return "inconclusive", "emulator_error"
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

def check_winexec_cmd(calls: list) -> tuple[bool, str] | None:
    winexec = [c for c in calls if c["name"] == "kernel32.WinExec"]
    if not winexec:
        return False, "wrong_syscall"
    args = winexec[0]["args"]
    cmdline = str(args[0]) if args else ""
    if "cmd" not in cmdline.lower():
        return False, "wrong_args"
    return True, "ok"


def check_messagebox_a(calls: list) -> tuple[bool, str] | None:
    mb = [c for c in calls if c["name"] in
          ("user32.MessageBoxA", "user32.MessageBoxW")]
    if not mb:
        return False, "wrong_syscall"
    return True, "ok"


CHECKERS = {
    "winexec_cmd": check_winexec_cmd,
    "messagebox_a": check_messagebox_a,
    # Later: add_admin, bind_shell_win, reverse_shell_win, rdp_enable,
    # firewall_stop, download_exec -- coordinate names with Edi/
    # docs/classes.md.
}


def validate(payload: bytes, arch: str, os_: str, claimed_effect: str,
              category: str | None = None) -> dict:
    """
    The frozen entry point, Windows side. Returns exactly {verdict,
    syscalls, reason}.
    """
    if arch not in ARCHES:
        raise ValidationError(f"arch {arch!r} not in {ARCHES}")
    if os_ not in OSES:
        raise ValidationError(f"os {os_!r} not in {OSES}")

    recorder = Recorder()
    fault: Exception | None = None
    timed_out = False

    start = time.monotonic()
    try:
        se = speakeasy.Speakeasy()
        sc_addr = se.load_shellcode("payload.bin", SPEAKEASY_ARCH[arch],
                                     data=payload)
        se.run_shellcode(sc_addr, offset=0)
        report = json.loads(se.get_json_report())
        recorder.load_from_report(report)
    except Exception as exc:
        fault = exc
    elapsed = time.monotonic() - start
    if elapsed >= TIMEOUT_SECONDS:
        timed_out = True

    verdict, reason = verdict_for(recorder.calls, claimed_effect, category,
                                   fault, timed_out, recorder.error)
    return {"verdict": verdict, "syscalls": recorder.calls, "reason": reason}


def result_line(path: str, result: dict) -> str:
    return (f"RESULT {path} {result['verdict']} {result['reason']} "
            f"{len(result['syscalls'])}")


def self_test() -> bool:
    all_ok = True
    for arch, hexbytes, claimed, category in GROUND_TRUTH:
        payload = bytes.fromhex(hexbytes)
        result = validate(payload, arch, "windows", claimed, category)
        ok = result["verdict"] == "pass"
        all_ok = all_ok and ok
        status = "OK" if ok else "FAIL"
        print(f"{status}  {arch:6s} {claimed:30s} -> "
              f"{result['verdict']}/{result['reason']}")
    return all_ok


def main() -> int:
    ap = argparse.ArgumentParser(description="Validate Windows shellcodes with Speakeasy.")
    ap.add_argument("--corpus", default="windows_corpus.json")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--skip-self-test", action="store_true")
    args = ap.parse_args()

    if args.self_test:
        return 0 if self_test() else 1

    if not args.skip_self_test and not self_test():
        print("REFUSING: ground truth failed; the harness is not trustworthy",
              file=sys.stderr)
        return 1

    # TODO: load windows_corpus.json (does not exist yet -- see the Qiling
    # attempt's equivalent TODO; unchanged by the Speakeasy switch).
    raise NotImplementedError


if __name__ == "__main__":
    sys.exit(main())