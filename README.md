<!--
SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# logseald

## Build and development

```sh
nix build .#logseald --max-jobs 1 --cores 2
nix develop --command go test -p 1 ./...
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for checks and commit conventions,
[SECURITY.md](SECURITY.md) for security boundaries, and [ORIGIN.md](ORIGIN.md)
for extraction provenance. This repository owns the application and package;
[Ghaf](https://github.com/tiiuae/ghaf) owns the deployment modules and VM tests.
The deployment settings below describe Ghaf integration, not a NixOS module
exported by this repository. The package supports x86_64-linux and aarch64-linux;
downstream consumers can use `lib.mkPackage { pkgs = ...; }` with their own Nixpkgs.

`logseald` provides clock-independent tamper evidence for Ghaf journals. A
producer on each logging-enabled host and virtual machine builds a local block
chain. A central sealer in `admin-vm` validates and signs those blocks.

Log sealing is independent of journal forwarding and systemd journal Forward
Secure Sealing (FSS). It does not change the journal format or prevent logs from
appearing in Grafana.

## Architecture

| Role     | Location                          | Responsibility                                                                                                    |
| -------- | --------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| Producer | Host and every logging-enabled VM | Read local journal records, build chained blocks, queue them durably, and verify returned seals                   |
| Sealer   | `admin-vm`                        | Authenticate producers, validate complete blocks, enforce chain order, sign seals, and persist signed chain heads |

The producer reads the journal export stream and preserves duplicate and binary
fields. It creates a canonical encoding for each record, calculates a Merkle
root, and includes the previous block identifier in the next block. The journal
cursor advances only after the complete block is stored in the durable queue.

The producer submits the complete block over mutually authenticated TLS. The
sealer decodes the records and recomputes the Merkle root and block identifier.
It also checks the producer sequence and predecessor against the authenticated
chain head. Accepted blocks receive a device-wide seal sequence and an Ed25519
signature. The sealer atomically persists a signed checkpoint of the current
chain heads before returning the seal. Full block contents are validated in
memory but are not retained centrally.

The sealer certifies its Ed25519 signing key with the authenticated GIVC
transport key. The producer verifies this binding against the GIVC certificate
from the TLS connection before it pins the signing key or accepts a seal. It
then stores the sealed artifact and removes the queued request. Repeated
delivery of the latest request for a chain returns its original seal, including
after restart. Older requests are rejected rather than signed again. Producers
submit pending blocks in order, one at a time. Other chains cannot evict this
last-response retry state.

## Offline and Clock-Independent Operation

Block order, block closure, chaining, and signatures do not use wall-clock
time. If `admin-vm` is unavailable, each producer continues to create blocks in
its local queue. At the configured queue limit, the producer stops consuming
new journal entries and retries delivery. Journald remains the source for
records that the producer has not consumed.

The default `static-cert` TLS policy verifies the GIVC certificate authority,
peer identity, signatures, and key usage without trusting the system clock. It
does not enforce certificate expiration. A configured offline leaf-SPKI denylist
enforces explicit revocation in both TLS modes. Deploy the list to every peer
and restart the services to load it and terminate established connections.

## Identity and Keys

Logseald uses the existing GIVC certificate authority and node identity:

- `/etc/givc/ca-cert.pem`
- `/etc/givc/cert.pem`
- `/etc/givc/key.pem`

The NixOS module passes these files to the unprivileged services through systemd
credentials. The SHA-256 fingerprint of the authenticated certificate public
key identifies the producer chain.

GUI and app-VM GIVC clients also receive this private key with user-readable
permissions. Such users can impersonate logseald; private systemd credential
copies do not remove that access. The current identity authenticates a VM key
holder, not exclusively the producer service. Separate root-only producer
credentials and an explicit chain migration are required to close this boundary;
this module does not provision them.

The GIVC CA and the `admin-vm` certificate identity are the initial root of
trust. The GIVC transport key is separate from the Ed25519 log-signing key at
`/var/lib/logseald/sealer/sealer.key`. The transport key authenticates the node
and signs the key-binding statement once per sealer start. The Ed25519 key signs
the log seals.

PID 1 owns configurable TCP port `59631` on the internal `admin-vm` address and
passes traffic through an unprivileged socket proxy to the sealer's protected
Unix socket. The TCP port remains reserved while the sealer stops or restarts.
The Ghaf firewall admits the port only from configured internal node addresses;
mTLS remains the producer authentication boundary.

The sealer runs as user `logseald-sealer` with process group `logseald-proxy`.
Its runtime directory is `0750` and its socket is `0660`, both assigned to that
group without relying on setgid inheritance. The private state directory stays
`0700` and the signing key `0600`; the proxy cannot read them.

## Configuration

Logseald is enabled when global logging is enabled. Disable it without removing
its stored state with:

```nix
ghaf.global-config.logging.logseald.enable = false;
```

The port is also configurable:

```nix
ghaf.global-config.logging.logseald.port = 59631;
```

The local service module exposes block size, block interval, offline queue
depth, retry interval, endpoint, TLS policy, and state directory options under
`ghaf.logging.logseald`.

## Resource and Retention Policy

Live ingestion bounds canonical records to 256 KiB and blocks to 1 MiB. A valid
oversized export entry becomes an explicit `oversize-export-digest-v1` marker
containing its cursor, boot ID, raw-export SHA-256 and export byte count (including
binary framing and the terminating blank line). The original values are not
stored in that marker. Malformed framing is rejected; normal journal forwarding
is unchanged. Batches close on byte, count, duration or boot-ID boundaries.

The sealer admits one body at a time, limits HTTP bodies to 2 MiB and uses a
16-connection proxy. Producers retain up to 20000 sealed blocks by default
(`--window-entries`), within their 256 MiB evidence budget and 100000-entry
limit. Byte pressure may shorten that window. At one block every five seconds,
20000 blocks is approximately 28 hours, not a guaranteed time period. Expiry
uses sequence numbers and byte counts, never wall time or Internet connectivity.

Only acknowledged sealed blocks expire. Before removing an old block, the
producer durably stores its signed receipt as the chain boundary. At least one
sealed block is retained for cursor recovery. Pending blocks are never expired,
and admission reserves room for their receipts. When pending evidence or a
single block cannot fit, ingestion still stops with status 75. Journald may
rotate unconsumed records during a prolonged outage.

The sealer's default `--compact-state=true` keeps one signed head/last receipt
per chain in a signed atomic checkpoint, capped at 256 identities and 1 MiB.
Atomic replacement temporarily requires a second copy, and the configured byte
budget must cover both. Old identities are not automatically forgotten: doing
so would allow replay of their initial chains. Reaching the identity cap rejects
new identities but existing chains continue. Key rotation therefore requires
planned identity/state management. Per-chain legacy byte/entry limits apply
during migration only, not to the lifetime number of compact-mode seals.

This is bounded retained evidence, not unlimited audit history. Once blocks
expire, their contents cannot be verified or recovered locally. The boundary
commits to their history but does not archive it. Grafana visibility is not an
archive acknowledgment, and log forwarding does not control expiry. Keeping
older verifiable evidence requires separately archiving records, receipts and
trusted references before expiry.

Upgrade automatically verifies the legacy ledger, persists the compact
checkpoint, then removes legacy full-block entries. Producers automatically
expire acknowledged history to their configured window. Back up evidence before
upgrading if historical verification is required. This storage migration is
one-way: do not restart the old binary against migrated state. Wire block/seal
formats remain v1, keys and counters are preserved, and state survives reboots.
Use `--window-entries=0` to disable further producer expiry. That cannot recover
expired evidence. Existing compact state remains compact even if the legacy
mode flag is later selected.

Quotas cover evidence content bytes, not filesystem allocation overhead. Producer
boundary/pin/lock metadata and temporary atomic-replacement files require
additional bounded headroom. Runtime writers are exclusive, and verification
takes a shared state lock so it cannot race window cleanup. Verification does
not migrate, prune, reset counters or create signing keys.

Systemd producer `MemoryHigh`/`MemoryMax` are 192/256 MiB (including journalctl);
sealer limits are 256/384 MiB, with swap disabled for both. These are containment
limits, not measurements or reservations. Go soft GC targets are 128/192 MiB.

Archival v1 decoding remains compatible. Drain pre-existing queued blocks above
1 MiB before upgrade; large historical artifacts may need offline verification
with higher memory limits. Service startup also re-verifies these artifacts:
offline verification is not enough. Before upgrading large historical stores,
measure startup on a suitably sized system and configure producer/sealer
`memoryMaxMiB` (defaults 256/384) with headroom above the observed peak. Increase
VM RAM accordingly, allowing space for other services; retain that cap while
the artifacts remain active. Stores above capacity require explicit provisioning.
CLI verification accepts the same storage limit overrides as the services.

Set `ghaf.global-config.logging.logseald.revokedPeerKeys` to a list of
`spki-sha256:<64 lowercase hex characters>` identities. This denies peer leaf
keys, including renewed certificates with the same key, without requiring time
or network services. Removing a CA requires updating trust bundles. Key changes
also change chain identity; never silently reset an existing chain during rotation.

## Services and State

| Component         | Service                                                   | State directory                     |
| ----------------- | --------------------------------------------------------- | ----------------------------------- |
| Host producer     | `logseald-producer.service`                               | `/persist/common/logseald/producer` |
| VM producer       | `logseald-producer.service`                               | `/var/lib/logseald/producer`        |
| Admin VM sealer   | `logseald-sealer.service`                                 | `/var/lib/logseald/sealer`          |
| Admin VM listener | `logseald-sealer.socket`, `logseald-sealer-proxy.service` | `/run/logseald-sealer/sealer.sock`  |

Producer state contains queued requests, sealed artifacts, and the pinned
sealer public key, and a signed boundary receipt after expiry. Sealer state
contains the signing key and compact signed chain checkpoint.

## Verification

Verify the producer on the host:

```console
sudo logseald verify-producer \
  --state-dir /persist/common/logseald/producer \
  --cert /etc/givc/cert.pem \
  --source ghaf-host
```

Verify a VM producer:

```console
sudo logseald verify-producer \
  --state-dir /var/lib/logseald/producer \
  --cert /etc/givc/cert.pem \
  --source net-vm
```

Verify the compact checkpoint in `admin-vm`:

For other producers, use the `--source` and state directory from
`systemctl show logseald-producer.service -p ExecStart --no-pager`.
The runtime hostname can differ from the configured source name.

```console
sudo logseald verify-sealer --state-dir /var/lib/logseald/sealer
```

The commands fail if canonical block decoding, the Merkle root, a chain
predecessor, a sequence, a pinned key, or a signature is invalid.

## Security Properties and Limitations

Logseald detects modification, insertion, reordering, gaps, and forks within
the retained producer evidence. Compact sealer verification checks the signed
checkpoint and current chain heads, not expired blocks or an entire global log. Mutual TLS prevents an unauthenticated
node from claiming another producer chain. Durable writes and idempotent retries
preserve a single accepted history across process failures.

Logseald does not encrypt journal contents, prove that a producer emitted every
event, prove that an event is truthful, or prevent a compromised producer from
stopping. The software signing key and ledger do not provide hardware-backed
rollback resistance. Restoring or deleting a complete trailing state can escape
local detection. Static certificate verification does not enforce expiration or
fetch online revocation data. The producer verification report distinguishes retained sealed blocks, pending
blocks and expired history. A valid boundary does not prove that an attacker
has not removed a longer prefix or rolled back the entire retained state.
An independently retained recent reference is needed to detect such losses.

Compromise of the Admin VM GIVC private key or CA can authorize a different
signing-key binding. Port reservation depends on PID 1 and the socket unit; an
administrator that stops the socket unit can release the port.

The cryptographic format is specific to Ghaf and has not received an external
cryptographic audit.

## References

- [Cryptographic Support for Secure Logs on Untrusted Machines](https://www.usenix.org/conference/7th-usenix-security-symposium/cryptographic-support-secure-logs-untrusted-machines)
- [Efficient Data Structures for Tamper-Evident Logging](https://www.usenix.org/conference/usenixsecurity09/technical-sessions/presentation/efficient-data-structures-tamper-evident)
- [RFC 9162: Certificate Transparency Version 2.0](https://www.rfc-editor.org/rfc/rfc9162.html)
