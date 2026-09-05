# Scope

Cut made 4 Sep 2026. Frozen. Do not silently re-expand — changes are a
conversation, not a commit.

## In scope

- **N ≈ 60** shellcodes, hand-picked from `corpus.json`.
- **Linux only**, **x86** and **x86_64** only.
- Selection pool is the 283 files under `Linux/x86` (245) and `Linux/x86-64`
  (38). Everything else in the mirror is extracted into `manifest.json` but
  never validated.
- **Bind and reverse shells are in N.** They are verdicted on the observed
  syscall sequence alone (socket/bind/listen/accept/dup2/execve). The harness
  does not stand up a listener and no peer ever connects. A payload that
  blocks waiting for a peer returns `inconclusive`, not `fail`.

## Out of scope

- All non-Linux OSes on the Linux side (Windows is Stefan's half; FreeBSD,
  Solaris, OSX, BSD, AIX, HP-UX, IRIX, NetBSD, OpenBSD, Cisco IOS, Alpha, Cso
  are nobody's).
- All non-x86 architectures: ARM, StrongARM, mips, ppc, sparc, SuperH.
- Exotic OSes needing full-system emulation. Hosted GitHub runners have no KVM.
- The ~15 in-scope files that contain assembly source and no extracted bytes.
  Assembling them is not in the budget; they are excluded from N by the
  extractor, not by hand.

## Repair cap

**10–15 shellcodes maximum.** Repairs happen **14–15 Sep only**, not before,
and stop at the freeze regardless of count.

## Dates

- **16 Sep** — freeze. README, architecture diagram, hand-off doc. Nothing new
  lands after this.
- **18 Sep** — hard deadline.

## Priority under time pressure

Cut N. Never cut the CI layer. A hundred validated shellcodes with no pipeline
is the worse project; the pipeline is the point.
