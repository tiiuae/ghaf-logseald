<!--
SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors
SPDX-License-Identifier: Apache-2.0
-->

# Agent instructions

Follow [CONTRIBUTING.md](CONTRIBUTING.md) for changes, validation and commits.
Read [SECURITY.md](SECURITY.md) before changing security-sensitive behavior.
State assumptions, make the smallest scoped change, and preserve existing style.
Do not refactor unrelated code or add speculative interfaces.
Comments explain non-obvious constraints only, in one or two lines; avoid
function preambles, edit narration and decorative sections. Preserve SPDX headers.

Do not commit or push unless explicitly requested. Never reset persisted
evidence, rotate keys, or change the protocol as an incidental cleanup.
Keep memory use bounded: run Go tests with `-p 1` and Nix with `--max-jobs 1`.
Report unrun tests and unresolved security limitations accurately.
