#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Drive the symlinked-bind probe across the full behavior envelope, each case
## in its OWN mount namespace, and ASSERT the verdicts. Self-checking regression
## guard: exits non-zero if util-linux ever changes behavior.
##
## Envelope summary:
##   TARGET symlink:
##     - plain bind follows it (the LPE).
##     - --no-canonicalize and X-mount.nocanonicalize REFUSE the exact
##       directory-symlink target, but a trailing "/" or "/." defeats them
##       (the kernel resolves through the symlink at mount(2) time), and a FILE
##       symlink is not refused (the bind lands on the symlink node).
##   SOURCE symlink (the two forms are NOT equivalent here):
##     - --no-canonicalize FOLLOWS a symlinked source.
##     - X-mount.nocanonicalize REFUSES it (AT_SYMLINK_NOFOLLOW on the source).
##
## Mount namespace: as root the probe runs under `unshare --mount`; unprivileged
## under `unshare --map-root-user --mount` (where unprivileged user namespaces
## are enabled). The form is auto-selected from the effective UID, so both
## `sudo ./driver.sh` and a plain `./driver.sh` work -- nothing to recall.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

cd "$(dirname "$0")"

## form | where | kind | target-suffix | expected-verdict | description
cases=(
  "plain|tgt|dir||FOLLOWED_VULNERABLE|plain bind, dir-symlink target, exact"
  "flag|tgt|dir||REFUSED_SAFE|--no-canonicalize, dir-symlink target, exact"
  "opt|tgt|dir||REFUSED_SAFE|X-mount.nocanonicalize, dir-symlink target, exact"
  "flag|tgt|dir|/|FOLLOWED_VULNERABLE|--no-canonicalize, dir-symlink target, TRAILING SLASH (defeats guard)"
  "opt|tgt|dir|/|FOLLOWED_VULNERABLE|X-mount.nocanonicalize, dir-symlink target, TRAILING SLASH (defeats guard)"
  "flag|tgt|dir|/.|FOLLOWED_VULNERABLE|--no-canonicalize, dir-symlink target, TRAILING /. (defeats guard)"
  "opt|tgt|dir|/.|FOLLOWED_VULNERABLE|X-mount.nocanonicalize, dir-symlink target, TRAILING /. (defeats guard)"
  "flag|tgt|file||MOUNTED_ON_SYMLINK_NODE|--no-canonicalize, FILE-symlink target (not refused; victim untouched)"
  "opt|tgt|file||MOUNTED_ON_SYMLINK_NODE|X-mount.nocanonicalize, FILE-symlink target (not refused; victim untouched)"
  "plain|src|dir||FOLLOWED_VULNERABLE|plain bind, symlinked SOURCE"
  "flag|src|dir||FOLLOWED_VULNERABLE|--no-canonicalize FOLLOWS a symlinked SOURCE"
  "opt|src|dir||REFUSED_SAFE|X-mount.nocanonicalize REFUSES a symlinked SOURCE"
)

if [ "$(id -u)" -eq 0 ]; then
  ns=(unshare --mount --)
else
  ns=(unshare --map-root-user --mount --)
fi

printf '%s\n' '=== util-linux ==='
mount --version
printf '%s\n' '=== namespace form ===' "${ns[*]}"

fail=0
for entry in "${cases[@]}"; do
  IFS='|' read -r form where kind suffix expected desc <<< "${entry}"
  printf '%s\n' '' "===== ${form} / ${where} / ${kind} / '${suffix}' (expect ${expected}) =====" "  ${desc}"
  out=''
  if ! out="$("${ns[@]}" ./probe_one.sh "${form}" "${where}" "${kind}" "${suffix}")"; then
    printf '%s\n' 'ERROR: could not run the probe in a mount namespace.' \
      'Need root (sudo) or an enabled unprivileged user namespace.'
    exit 2
  fi
  printf '%s\n' "${out}"
  verdict="$(printf '%s\n' "${out}" | sed -n 's/^VERDICT=//p')"
  if [ "${verdict}" = "${expected}" ]; then
    printf '%s\n' "ok   ${form}/${where}/${kind}/'${suffix}': ${verdict}"
  else
    printf '%s\n' "FAIL ${form}/${where}/${kind}/'${suffix}': got ${verdict:-<none>}, want ${expected}"
    fail=1
  fi
done

printf '%s\n' ''
if [ "${fail}" -ne 0 ]; then
  printf '%s\n' 'RESULT: FAIL (util-linux mount symlink behavior changed; see above)'
  exit 1
fi
printf '%s\n' 'RESULT: PASS (envelope holds: no-canonicalize refuses an exact dir-symlink target and a symlinked source; trailing slash/dot and file-symlink targets are not refused)'
