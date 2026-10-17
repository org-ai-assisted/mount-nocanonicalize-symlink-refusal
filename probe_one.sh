#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## One symlinked-bind test case, run inside its own mount namespace.
## Threat model: an unprivileged user pre-plants a symlink at a path a later
## root `mount --bind` touches; if mount FOLLOWS it, the bind lands on the
## symlink's target -- the CWE-59 symlink-follow local privilege escalation.
##
## Arguments:
##   form   : plain | flag | opt
##            plain = no guard; flag = --no-canonicalize;
##            opt = -o X-mount.nocanonicalize
##   where  : tgt | src          (which side of the bind is the symlink)
##   kind   : dir | file         (what the symlink points at; src is always dir)
##   suffix : appended to the target path, e.g. "" or "/" or "/."
##
## Output: a machine-readable VERDICT= line (plus mount_rc / mount_stderr),
## consumed by driver.sh. Always exits 0; the VERDICT is the signal.
##
## FOLLOWED is decided by OBSERVING the filesystem (did the source content
## appear where the symlink pointed), which is ground truth, and takes priority
## over mount's exit code: a bind can attach and still return non-zero (libmount
## MNT_EX_* when a flag could not be applied), so a follow must never be
## mislabelled a refusal. Assumes it can mount (driver.sh guarantees privilege
## via unshare); the driver's plain case fails loudly if mount cannot run.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

form="${1:-}"
where="${2:-}"
kind="${3:-}"
suffix="${4:-}"

base="$(mktemp -d)"

if [ "${where}" = src ]; then
  ## Symlinked bind SOURCE; the target is an ordinary directory.
  mkdir -p "${base}/real_src" "${base}/dst"
  printf '%s\n' 'SRC' > "${base}/real_src/marker"
  ln -s "${base}/real_src" "${base}/src_link"
  bind_src="${base}/src_link"
  tgt="${base}/dst${suffix}"
  observe="${base}/dst/marker"
else
  ## Symlinked bind TARGET pointing at a victim.
  if [ "${kind}" = dir ]; then
    mkdir -p "${base}/src" "${base}/victim"
    printf '%s\n' 'SRC' > "${base}/src/marker"
    bind_src="${base}/src"
    ln -s "${base}/victim" "${base}/tgt"
    observe="${base}/victim/marker"
  else
    printf '%s\n' 'SRC' > "${base}/src"
    printf '%s\n' 'VICTIM' > "${base}/victim"
    bind_src="${base}/src"
    ln -s "${base}/victim" "${base}/tgt"
    observe="__FILE__"
  fi
  tgt="${base}/tgt${suffix}"
fi

## Keep bind effects inside this namespace.
mount --make-rprivate / 2>/dev/null || true

err="$(mktemp)"
rc=0
case "${form}" in
  plain)
    mount --bind -o nosuid,nodev -- "${bind_src}" "${tgt}" 2>"${err}" || rc=$?
    ;;
  flag)
    mount --no-canonicalize --bind -o nosuid,nodev -- "${bind_src}" "${tgt}" 2>"${err}" || rc=$?
    ;;
  opt)
    mount --bind -o nosuid,nodev,X-mount.nocanonicalize -- "${bind_src}" "${tgt}" 2>"${err}" || rc=$?
    ;;
  *)
    printf '%s\n' "unknown form ${form}"
    exit 2
    ;;
esac

printf '%s\n' "mount_rc=${rc}"
printf '%s\n' "mount_stderr=$(cat "${err}")"

## Did the source content appear where the symlink pointed?
followed=no
if [ "${observe}" = '__FILE__' ]; then
  ## file-symlink target: the victim FILE now reads the source content.
  if [ "$(cat "${base}/victim")" = 'SRC' ]; then
    followed=yes
  fi
else
  if [ -e "${observe}" ]; then
    followed=yes
  fi
fi

if [ "${followed}" = yes ]; then
  ## bind landed on the symlink's target => the symlink was followed.
  printf '%s\n' 'VERDICT=FOLLOWED_VULNERABLE'
elif [ "${rc}" -ne 0 ]; then
  ## mount refused the symlink; the target was untouched.
  printf '%s\n' 'VERDICT=REFUSED_SAFE'
else
  ## mount succeeded but bound on the symlink node itself; target untouched.
  printf '%s\n' 'VERDICT=MOUNTED_ON_SYMLINK_NODE'
fi
