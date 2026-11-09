# Architecture

`findarat` is a Linux-first Rust application organized around a shared
application layer. The CLI is the primary interface. The TUI reuses the same
scan request, scan runner, inventory, import, and export code.

## Design constraints

- **Unprivileged by default.** Discovery uses ordinary UDP/TCP sockets and
  Linux kernel tables (`/proc/net/arp`, `/proc/net/route`). No raw sockets,
  packet injection, deauthentication, or AP management.
- **Evidence over guesses.** Inferred properties are stored with a source,
  confidence, and evidence kind. Unknown remains a valid answer.
- **One implementation, two interfaces.** The TUI must not fork business
  logic. Both interfaces call the same services and models.
- **Bounded work.** Discovery providers have per-provider timeouts, TCP scans
  have a concurrency window, an optional rate limit, and a host cap.
- **Failures are local.** A provider failure is recorded in the scan report and
  does not abort other providers.
- **Schema safety.** Database and export schemas are versioned. Newer data is
  rejected rather than silently corrupted.

## Module map

```text
src/
  main.rs              clap parsing, error-to-exit-code mapping
  lib.rs               public modules, tool/schema version constants
  cli/                 argument parsing, table/JSON rendering, command wiring
  tui/                 ratatui screens, input handling, background scan task
  app/                 scan orchestration shared by CLI and TUI
  config/              XDG paths, TOML loading, defaults, validation
  network/             interfaces, default route, subnet arithmetic
  discovery/           ARP, mDNS, SSDP, NetBIOS providers and result merging
    dns.rs             minimal DNS wire parser/builder used by mDNS/NetBIOS
  scanner/             port-spec parsing and bounded TCP connect scanning
  fingerprint/         OUI, hostname, device-type, OS, and service heuristics
  inventory/           identity matching, SQLite persistence, history/changes
  io/                  JSON/CSV/SQLite export and JSON/SQLite import
  models/              Device, evidence, observations, sessions, changes
  error.rs             stable error categories and exit codes
```

Dependencies flow inward:

```text
main -> cli -> app -> discovery / scanner / fingerprint / inventory
                   \-> config / network / models
tui  -> app, inventory, io, models, config
io   -> inventory, models, error
```

`models` and `error` do not depend on the interface layers. `app` does not
depend on `cli` or `tui`.

## Scan pipeline

`app::run_scan` is the single scan implementation. It accepts a fully resolved
`ScanRequest`, a mutable `Database`, and an optional progress channel.

1. **Detect the network.** `NetworkContext::detect` lists interfaces, finds the
   default route, and selects the requested or default-route interface. An
   explicit subnet may override the interface subnet.
2. **Discover hosts.** Enabled providers run concurrently in a `JoinSet`, each
   wrapped in its own timeout. Results are merged by IP or MAC. Conflicting
   names become evidence instead of overwriting the primary value.
3. **Resolve missing names.** Reverse DNS is attempted only for hosts without
   an advertised hostname, unless disabled.
4. **Build device snapshots.** `app::build_device` creates in-memory `Device`
   values from merged discovery results, including identifiers and
   observations.
5. **Scan TCP ports.** If enabled, the unique IPv4 host list is capped by
   `max_hosts`, then scanned with bounded concurrency and optional rate
   limiting. Open ports are attached to the corresponding devices.
6. **Fingerprint.** `fingerprint::apply` adds services and evidence, infers
   device type and OS, and sets display properties only when evidence supports
   them.
7. **Persist.** A scan session is created, devices are upserted, changes are
   recorded, and disappeared devices are marked when at least one discovery
   provider succeeded.
8. **Report.** The final `ScanReport` is authoritative. Progress events are
   advisory and may arrive before persistence finishes.

`ScanEvent` messages are emitted over an unbounded Tokio channel. The CLI
ignores them; the TUI uses them to update progress, provider status, and the
final result without blocking the UI thread.

### Provider contract

Each provider implements `DiscoveryProvider`:

```rust
#[async_trait]
pub trait DiscoveryProvider: Send + Sync {
    fn name(&self) -> &'static str;
    async fn discover(&self, context: &DiscoveryContext) -> anyhow::Result<ProviderOutput>;
}
```

Providers return `DiscoveredHost` values and never write to the database. This
keeps discovery testable and lets the merge layer preserve conflicts.

### TCP scanner

`scanner::scan_hosts` scans the cartesian product of hosts and ports. A
`JoinSet` bounds the number of in-flight connection attempts. The optional rate
limiter serializes start times with a shared `Instant`. Results contain only
open ports; connection refusal, timeout, and unreachable outcomes are not
recorded as open.

Banner collection is deliberately conservative:

- Plaintext HTTP: minimal `HEAD` request, parse response headers.
- Greeting services such as SSH/SMTP: passive read.
- TLS and binary protocols: no plaintext probe.

## Identity and persistence

`inventory::identity` owns the matching rules independently of SQLite:

- MAC match: high confidence, medium for locally administered MACs.
- Hostname match: medium confidence, unique normalised names only.
- IP match: low confidence, no MAC conflict, sighting within seven days.

`Database::find_match` supplies candidates; `identity::choose` ranks them.
`Database::upsert_device_with_options` then merges identifiers, observations,
evidence, ports, services, and changes in one transaction. The device row is a
last-known snapshot; the child tables are the historical record.

The schema uses `schema_meta.schema_version` for compatibility checks. Opening
a database from a newer build fails with an upgrade message. See
[data-model.md](data-model.md).

## CLI

`cli::run` handles one special case before loading configuration:
`config init` must work even when the existing config is invalid. All other
commands load and validate configuration first, then dispatch.

The global `--format` flag controls command output. Import and export file
formats are separate flags. Output is either human-readable tables or
pretty-printed JSON. Errors are mapped to stable exit codes in `main.rs`.

## TUI

The TUI uses `ratatui` with `crossterm`. It has eight screens: Dashboard,
Devices, Details, Scan, History, Import/Export, Settings, and Help.

- Scans run in a background Tokio task that opens its own `Database`
  connection. WAL mode and the busy timeout allow concurrent reads.
- Progress arrives through a channel and is drained between frames.
- The event loop polls crossterm for 50 ms, redraws, drains scan events, and
  repeats.
- `ratatui::try_init` / `ratatui::try_restore` ensure terminal restoration on
  both success and error paths.

State transitions and key handling are unit-tested without a real terminal.

## Import/export

Exports read complete device snapshots, scan sessions, and changes from the
database.

- **JSON** uses `ExportEnvelope`, a versioned document with tool/version
  metadata.
- **CSV** is a flat device report with a fixed header.
- **SQLite** uses the SQLite backup API to produce a consistent snapshot.

Imports validate before writing:

- JSON accepts an envelope or a bare device array.
- SQLite is opened read-only; importing a database into itself is rejected.
- Schema versions outside the supported range are rejected.
- Devices without any identity are skipped with a warning.
- `--dry-run` never writes.
- Matching devices are merged unless `--no-merge` is set.
- Changes are re-linked to local device and session ids; unlinkable history is
  reported as a warning.

## Error handling

Fallible application functions return `anyhow::Result` for context chains. A
small `FindaratError` enum carries stable categories used for process exit
codes:

| Category | Exit code |
| --- | --- |
| Generic/I/O | `1` |
| Clap usage | `2` |
| Device not found | `3` |
| Validation/config | `4` |
| Permission required | `5` |
| Database | `6` |

Production paths avoid `unwrap()` and `expect()`. Warnings are not suppressed.

## Extension points

- **New discovery provider:** implement `DiscoveryProvider`, add it to
  `run_discovery`, add an enable flag to `DiscoveryOptions` and config, and add
  merge/evidence tests.
- **New fingerprint rule:** add a module under `fingerprint/`, return findings
  with a source and confidence, and let `fingerprint::apply` record evidence.
- **New migration:** bump `SCHEMA_VERSION`, add an ordered migration step, keep
  forward-compatibility checks, and test opening an older database.
- **New export format:** add a variant to `ExportFormat`, implement the writer,
  and document whether it is a complete backup or a report.
