# mount-nocanonicalize-symlink-refusal
Evidence: util-linux mount --no-canonicalize (and the equivalent X-mount.nocanonicalize option) REFUSES a symlinked bind target; plain --bind follows it. Mount-namespace repro + CI regression guard.
