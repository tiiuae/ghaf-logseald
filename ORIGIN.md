<!--
SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Source provenance

The initial application and tests were extracted from
`tiiuae/ghaf`, directory `packages/pkgs-by-name/logseald`, as present in commit
`92da6ad5ffe154b31a1c1bbff54ae4d772364f81` on the development branch.
The Go module/import path was renamed from `github.com/tiiuae/ghaf/logseald`
to `github.com/tiiuae/ghaf-logseald`. Runtime logic, protocol identifiers,
CLI defaults and stored evidence encoding were preserved.

Original SPDX attribution and license texts are retained. Source development
history remains in Ghaf; this repository records the extraction boundary rather
than importing unrelated platform history. Ghaf's deployment configuration and
integration tests remain in Ghaf, including the socket-group fix in this baseline.
