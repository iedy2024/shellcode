#!/usr/bin/env python3
"""
Manual x86 (32-bit) Qiling smoke test -- the 32-bit counterpart to
testshellcode.py, to answer whether x86 needs different setup from x86_64
before the harness is written. 46 of the 60 selected shellcodes are x86.

Payload: Linux/x86/execve_-bin-sh_shellcode.c, 23 bytes, null-free.
The textbook Aleph One execve("/bin//sh", ["/bin//sh"], NULL):

    31c0         xor    eax, eax
    50           push   eax
    682f2f7368   push   0x68732f2f      ; "//sh"
    682f62696e   push   0x6e69622f      ; "/bin"
    89e3         mov    ebx, esp        ; ebx = path
    50           push   eax
    53           push   ebx
    89e1         mov    ecx, esp        ; ecx = argv
    b00b         mov    al, 0xb         ; __NR_execve = 11 on x86
    cd80         int    0x80

Chosen as ground truth because it is the most documented payload in the
mirror: if this does not come out clean, the Qiling setup is wrong, not the
shellcode.

NOTE: this payload never zeroes edx, and edx is execve's third argument
(envp). It relies on edx being 0 on entry. Qiling zeroes registers at start
so it works here -- but that implicit dependency is worth knowing, because it
is exactly the kind of thing that behaves differently on real hardware than
under emulation.
"""
from qiling import Qiling
from qiling.const import QL_ARCH, QL_OS, QL_VERBOSE

# Linux/x86/execve_-bin-sh_shellcode.c
X86_EXECVE = bytes.fromhex("31c050682f2f7368682f62696e89e3505389e1b00bcd80")

# For contrast: Linux/x86/sys_exit(0).c -- the simplest possible smoke test.
# If this does not produce a clean exit, nothing else is worth trying.
X86_EXIT = bytes.fromhex("31c0b001cd80")

code = X86_EXECVE

ql = Qiling(
    code=code,
    archtype=QL_ARCH.X86,      # <- the only required change from X8664
    ostype=QL_OS.LINUX,
    verbose=QL_VERBOSE.DEBUG,
)

# Record the syscalls rather than reading a hardcoded address. testshellcode.py
# did `ql.mem.read(0x11feff8, 16)`, which is a stack address that happened to
# be right for that x86_64 run; it is not portable across architectures and
# the harness needs the syscall sequence anyway.
seen = []


def on_execve(ql, path, argv, envp, *args):
    # The hook receives raw guest pointers. Dereference them -- a verdict of
    # "execve happened" is not ground truth, "execve of /bin//sh with argv
    # [/bin//sh]" is. This is the shape the harness needs for schema.md's
    # syscalls field, where wrong-path payloads must come out as wrong_args.
    path_s = ql.os.utils.read_cstring(path) if path else None
    args_l = []
    if argv:
        while True:                       # argv is a NULL-terminated pointer array
            ptr = ql.mem.read_ptr(argv + 4 * len(args_l), 4)
            if not ptr:
                break
            args_l.append(ql.os.utils.read_cstring(ptr))
    seen.append(("execve", path_s, args_l, envp))
    ql.os.stop()               # nothing to exec into -- stop at the observation
    return 0


ql.os.set_syscall("execve", on_execve)

ql.run()

print("\n--- observed ---")
for entry in seen:
    print("  ", entry)
print("  esp at exit:", hex(ql.arch.regs.arch_sp))
