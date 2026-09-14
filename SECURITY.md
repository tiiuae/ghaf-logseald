<!--
SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Security boundaries

Treat journal records, request bodies, persisted evidence and peer responses as
untrusted. Validate canonical encoding, sizes, hashes, sequence/predecessor links,
authenticated chain identity, signing-key binding and signatures before acceptance.
Persist queued blocks before advancing cursors; persist seals before acknowledging
or removing queued evidence. Identical retries must preserve the accepted history.
Keep resource bounds and fail-closed behavior at capacity and on malformed input.

The sealer's GIVC identity and CA anchor initial trust. Its separate Ed25519 key
signs evidence. The default clock-independent TLS mode does not enforce current
certificate expiry; explicit revocation requires policy deployment and restart.

## Known limits

- No forward-secure signing-key evolution, hardware signing or full-state rollback
  resistance; an independently retained reference is needed to detect some losses.
- No proof of truthful or complete event reporting, and no log-content encryption.
- Ghaf GUI/app VM users can access shared GIVC keys and impersonate producers.
  Private systemd credential copies do not solve that provisioning limitation.
- Bounded queues and finite evidence capacity; no automatic evidence pruning.
  Long outages can leave records unsigned or lost to journal retention.
- Deployment permissions and sandboxing are part of the security boundary and
  must be tested in Ghaf, including access to the Unix socket and signing key.

This implementation is not a claim of FSS-equivalent security or an external
cryptographic audit. Coordinate suspected vulnerabilities privately with the
TII/Ghaf maintainers before publishing exploit details; do not upload device keys
or sensitive logs to public issues.
