# mount-nocanonicalize-symlink-refusal

Characterizes exactly when `util-linux` `mount` refuses, versus follows, a
symlink involved in a bind mount -- with and without `--no-canonicalize` and
its mount-option sibling `X-mount.nocanonicalize`. The headline results:

- For a symlinked bind TARGET, `--no-canonicalize` / `X-mount.nocanonicalize`
  refuse exactly ONE shape -- a directory symlink named by its exact path. A
  trailing `/` or `/.` defeats the refusal, and a file symlink is not refused.
- For a symlinked bind SOURCE, the two forms are NOT equivalent:
  `X-mount.nocanonicalize` refuses it while `--no-canonicalize` follows it.

This repository is the durable, self-checking proof of that envelope.

Tested: `util-linux 2.41.5` on Debian GNU/Linux 13 (trixie), inside a mount
namespace. This behavior is VERSION-SPECIFIC (see "Version dependence" below):
the refusal exists in util-linux 2.41.x but not in 2.39.3, so CI runs the
reproduction inside a Debian trixie container (util-linux 2.41.x) on every push,
not directly on the older-util-linux runner. Captured evidence is in `results/`.

## This is NOT a mount bug

`mount` is behaving as documented; `man mount` says `--no-canonicalize`
disables path canonicalization and refers to the `X-mount.nocanonicalize`
option. This repository is EVIDENCE characterizing that behavior, not a bug
report. Nothing here is filed upstream; there is nothing to fix in util-linux.

## Threat model

A Qubes DisposableVM boots from a clone of its DVM-Template, so the home
directory (and anything the unprivileged user can write) is attacker-influenced
before any root service runs. If a root service later does
`mount --bind SRC /some/attacker-writable/target`, the unprivileged user can
pre-plant a symlink at `target` pointing at a victim path. If `mount` follows
that symlink, the root bind lands on the victim instead -- a CWE-59 symlink-
follow local privilege escalation.

`--no-canonicalize` (or `X-mount.nocanonicalize`) refusing an exact
directory-symlink target makes it useful as a mount-layer BACKSTOP. It is NOT a
general symlink guard -- as the envelope below shows, a trailing slash/dot and
a file symlink are not refused, and it does not cover intermediate path
components -- so it must not be the sole defense. A robust consumer rejects the
attacker-influenced path up front (before mounting) and orders the mount before
any unprivileged process can run (pre-session), with `--no-canonicalize` /
`X-mount.nocanonicalize` as the mount-layer backstop. This repository exists to
pin down precisely how much that backstop does and does not cover.

## Proven envelope

Each row is asserted by `driver.sh`. `SRC` is the bind source, `tgt` is a
symlink the attacker planted.

### Symlinked bind TARGET

| form                     | symlink kind | target  | rc | verdict                 |
|--------------------------|--------------|---------|----|-------------------------|
| plain `--bind`           | directory    | `tgt`   | 0  | FOLLOWED_VULNERABLE     |
| `--no-canonicalize`      | directory    | `tgt`   | 32 | REFUSED_SAFE            |
| `X-mount.nocanonicalize` | directory    | `tgt`   | 32 | REFUSED_SAFE            |
| `--no-canonicalize`      | directory    | `tgt/`  | 0  | FOLLOWED_VULNERABLE     |
| `X-mount.nocanonicalize` | directory    | `tgt/`  | 0  | FOLLOWED_VULNERABLE     |
| `--no-canonicalize`      | directory    | `tgt/.` | 0  | FOLLOWED_VULNERABLE     |
| `X-mount.nocanonicalize` | directory    | `tgt/.` | 0  | FOLLOWED_VULNERABLE     |
| `--no-canonicalize`      | file         | `tgt`   | 0  | MOUNTED_ON_SYMLINK_NODE |
| `X-mount.nocanonicalize` | file         | `tgt`   | 0  | MOUNTED_ON_SYMLINK_NODE |

### Symlinked bind SOURCE (the forms are NOT equivalent)

| form                     | source      | rc | verdict             |
|--------------------------|-------------|----|---------------------|
| plain `--bind`           | dir symlink | 0  | FOLLOWED_VULNERABLE |
| `--no-canonicalize`      | dir symlink | 0  | FOLLOWED_VULNERABLE |
| `X-mount.nocanonicalize` | dir symlink | 32 | REFUSED_SAFE        |

Verdicts:

- `FOLLOWED_VULNERABLE` -- the bind landed on the symlink's target (the source
  content appeared where the symlink pointed).
- `REFUSED_SAFE` -- `mount` refused (rc 32); the target was untouched.
- `MOUNTED_ON_SYMLINK_NODE` -- `mount` succeeded but bound on the symlink node
  itself, leaving the victim untouched (not refused, not a follow either).

Takeaways:

- For the TARGET, `--no-canonicalize` and `X-mount.nocanonicalize` behave the
  same: they refuse only the exact directory-symlink target (`tgt`, no trailing
  separator). A trailing `/` or `/.` makes the kernel resolve THROUGH the
  symlink at `mount(2)` time, so the bind FOLLOWS -- the guard only stops
  `mount(8)` userspace canonicalization, not kernel path resolution. A file
  symlink is not refused; the bind lands on the symlink node.
- For the SOURCE they DIFFER: `X-mount.nocanonicalize` applies
  `AT_SYMLINK_NOFOLLOW` to the source and refuses a symlinked source, while
  `--no-canonicalize` follows it. So the option is the stricter of the two.
- The guard never protects an intermediate path component (only the final
  component is subject to the no-canonicalize handling).

## Version dependence

The refusal is NOT present in all util-linux versions. On `util-linux 2.39.3`
(for example Ubuntu 24.04), every row above FOLLOWS -- `--no-canonicalize` and
`X-mount.nocanonicalize` do not refuse the symlinked target or source at all;
they behave like a plain `--bind`. The refusals shown here were added in a later
util-linux and are present in `2.41.5` (Debian trixie, the platform this
evidence targets). So the mount-layer backstop only exists on new enough
util-linux; on an older release it provides nothing, which is why a consumer
must not rely on it as the sole defense, and why CI pins a trixie container
rather than trusting the runner's util-linux.

## Run

Prerequisites: a Linux host with `util-linux` `mount` and `unshare`. Each case
runs in its OWN mount namespace so the binds never touch the host; run it in a
disposable VM anyway.

- As root (recommended, works everywhere):

      sudo ./driver.sh

- Unprivileged, where unprivileged user namespaces are enabled:

      ./driver.sh

`driver.sh` auto-selects the namespace form from the effective UID -- root uses
`unshare --mount`, unprivileged uses `unshare --map-root-user --mount` -- so
there is no flag to remember. It runs every row above, asserts each verdict, and
exits:

- `RESULT: PASS` (exit 0) when the whole envelope matches.
- `RESULT: FAIL` (exit non-zero) if any verdict changes -- the regression
  signal.

## CI

`.github/workflows/repro.yml` runs the reproduction on every push (and on pull
requests and manual dispatch). Because the behavior is util-linux-version-
specific, the job does not run `./driver.sh` directly on the `ubuntu-24.04`
runner (util-linux 2.39.3); it runs it inside a privileged Debian `trixie`
container (util-linux 2.41.x), the platform this evidence targets. The `push:`
trigger is deliberate: this org has no required status checks, so a
pull-request-only workflow would never fire. A util-linux behavior change that
moved any verdict would turn this job red.

## Files

- `driver.sh` -- runs the full envelope, each case in its own namespace, and
  asserts the verdicts.
- `probe_one.sh` -- one case (`form where kind suffix`); plants the symlink,
  attempts the bind, and reports a `VERDICT=` line.
- `results/` -- captured evidence of a real run (environment + full output).
- `.github/workflows/repro.yml` -- the CI regression guard.

## Provenance

Empirically confirmed in a sandbox VM on util-linux 2.41.5 (trixie) inside a
mount namespace, then re-confirmed on GitHub `ubuntu-24.04` CI. The narrow
scope of the refusal -- that a trailing slash/dot and a file-symlink target are
not refused, and that the flag and option differ on a symlinked source -- was
surfaced during AI code review and verified before being recorded here. This
repository is the record of that behavior; it does not file anything upstream.

AI-Assisted.
