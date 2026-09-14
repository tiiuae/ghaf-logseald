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
| Sealer   | `admin-vm`                        | Authenticate producers, validate complete blocks, enforce chain order, sign seals, and persist the central ledger |

The producer reads the journal export stream and preserves duplicate and binary
fields. It creates a canonical encoding for each record, calculates a Merkle
root, and includes the previous block identifier in the next block. The journal
cursor advances only after the complete block is stored in the durable queue.

The producer submits the complete block over mutually authenticated TLS. The
sealer decodes the records and recomputes the Merkle root and block identifier.
It also checks the producer sequence and predecessor against the authenticated
chain head. Accepted blocks receive a device-wide seal sequence and an Ed25519
signature. The sealer writes the ledger entry to durable storage before it
returns the seal.

The sealer certifies its Ed25519 signing key with the authenticated GIVC
transport key. The producer verifies this binding against the GIVC certificate
from the TLS connection before it pins the signing key or accepts a seal. It
then stores the sealed artifact and removes the queued request. Repeated
delivery of the same request returns the original seal. A request identifier
reused with different content is rejected.

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
16-connection proxy. State bodies are read one at a time; history/replay indexes
have bounded entry counts. Producer `maxStateBytes`/`maxStateEntries` default to
256 MiB/100000; sealer defaults to 1 GiB/100000, with `maxChainBytes` and
`maxChainEntries` of 128 MiB/20000 per producer. Producer admission reserves space
for seal persistence. A producer at evidence capacity stops with exit status 75
(no automatic restart); the sealer rejects new work but preserves identical
retries. Journald may rotate unsealed records during a prolonged pause.

There is no automatic pruning or checkpoint protocol. Provision disk capacity
and increase limits before they fill, then restart. Do not delete active evidence
or reset keys/counters. These quotas cover evidence file bytes, not filesystem
overhead or other services. At one block every five seconds, 20000 blocks covers
only about 28 hours, less under heavier traffic. Monitor both bytes and entries.

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
sealer public key. Sealer state contains the signing key and append-only ledger.

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

Verify the central ledger in `admin-vm`:

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
the retained producer and sealer evidence. Mutual TLS prevents an unauthenticated
node from claiming another producer chain. Durable writes and idempotent retries
preserve a single accepted history across process failures.

Logseald does not encrypt journal contents, prove that a producer emitted every
event, prove that an event is truthful, or prevent a compromised producer from
stopping. The software signing key and ledger do not provide hardware-backed
rollback resistance. Restoring or deleting a complete trailing state can escape
local detection. Static certificate verification does not enforce expiration or
fetch online revocation data. Evidence retains records or oversized-entry markers and
has no automatic pruning policy.

Compromise of the Admin VM GIVC private key or CA can authorize a different
signing-key binding. Port reservation depends on PID 1 and the socket unit; an
administrator that stops the socket unit can release the port.

The cryptographic format is specific to Ghaf and has not received an external
cryptographic audit.

## References

- [Cryptographic Support for Secure Logs on Untrusted Machines](https://www.usenix.org/conference/7th-usenix-security-symposium/cryptographic-support-secure-logs-untrusted-machines)
- [Efficient Data Structures for Tamper-Evident Logging](https://www.usenix.org/conference/usenixsecurity09/technical-sessions/presentation/efficient-data-structures-tamper-evident)
- [RFC 9162: Certificate Transparency Version 2.0](https://www.rfc-editor.org/rfc/rfc9162.html)
