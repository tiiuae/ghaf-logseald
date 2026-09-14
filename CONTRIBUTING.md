<!--
SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Development

This repository owns the application, protocol, verifier, tests and Nix package.
Ghaf owns VM placement, systemd hardening, credential provisioning, persistence,
firewall policy and NixOS integration tests. Changes crossing that boundary need
validation in both repositories.

## Checks

```sh
nix fmt -- --fail-on-change
nix develop --command reuse --no-multiprocessing lint
nix develop --command go test -p 1 -count=1 ./...
nix develop --command go vet -p 1 ./...
nix flake check --max-jobs 1 --cores 2
```

Both x86_64-linux and aarch64-linux are supported. Native ARM tests require an
ARM runner; cross-compilation alone is not runtime validation. Keep CI dependency
revisions pinned. Tests must not require real signing keys or deployment access.

Make scoped changes, describe assumptions and define a verification step before
implementation. Preserve wire-format and stored-evidence compatibility unless
an explicit migration is reviewed. Keep historical fixtures and recovery tests.

## Commits

Follow Ghaf's conventional format: `type(scope): imperative description`, with
an optional lowercase scope. Use lowercase descriptions without a final period.
Wrap the subject and prose body at 75 characters. The body explains what and why,
and identifies interface changes; avoid file lists and implementation narration.
Make commits atomic and fold fixes into the change they correct. Sign off using
`git commit -s`. Code uses Apache-2.0; documentation uses CC-BY-SA-4.0. Keep SPDX
attribution and include license texts for any new license.
