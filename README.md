# findarat

Linux-first local network discovery and device intelligence, with a CLI-first
design and an optional terminal UI.

<img width="500" height="300" alt="find-a-rat-banner" src="https://github.com/user-attachments/assets/f91fd2b0-efb4-405d-a962-060c45d63666" />


`findarat` discovers hosts on your local IPv4 network, records what it actually
observed, infers device properties from attributable evidence, and keeps a
historical SQLite inventory. Every inference carries a confidence level and a
source. When the data does not support a conclusion, the answer stays
`unknown`.

The CLI and TUI use the same application services and the same database. The
TUI is a presentation layer, not a separate implementation.

## Status

This is a working pre-1.0 implementation. The current milestone covers:

- Unprivileged IPv4 discovery over ARP, mDNS/DNS-SD, SSDP/UPnP, and NetBIOS.
- Bounded TCP port scanning with optional banner collection.
- Evidence-based fingerprinting: vendor, hostname, device type, and OS.
- SQLite inventory with identity matching, observations, evidence, history,
  and detected changes.
- JSON, CSV, and SQLite export; JSON and SQLite import with validation,
  dry-run, merge, and skip behavior.
- CLI and TUI access to the same inventory and scan pipeline.

Access-point management (deauthentication, AP configuration, or other
disruptive wireless operations) is intentionally not implemented.

## Requirements

- Linux. Network discovery reads `/proc/net/arp`, `/proc/net/route`, and uses
  Linux interface naming.
- Rust 1.88 or newer to build.
- IPv4 local networks. IPv6 discovery is not implemented.
- No root privileges. All operations use ordinary UDP/TCP sockets and local
  kernel tables.

`findarat` never performs deauthentication, packet injection, exploit
delivery, or other disruptive network operations. It only sends normal
discovery traffic and TCP connection attempts.

## Build and install

From the repository:

```sh
cargo build --release
./target/release/findarat --help
```

Install into `~/.cargo/bin`:

```sh
cargo install --path .
```

Or copy the release binary wherever you prefer:

```sh
install -Dm755 target/release/findarat ~/.local/bin/findarat
```

## Quick start

```sh
# Show interfaces and the current network summary.
findarat interfaces
findarat

# Scan the active network, save results, and print a table.
findarat scan

# Scan without TCP port scanning for a fast, quiet first pass.
findarat scan --no-tcp --timeout-ms 800

# Inspect what was found.
findarat devices
findarat devices --active --search printer
findarat device 192.168.1.10
findarat history
findarat changes --kind device_added

# Export and re-import.
findarat export inventory.json
findarat export inventory.csv --export-format csv
findarat export snapshot.db --export-format sqlite
findarat import inventory.json --dry-run
findarat import inventory.json

# Open the TUI.
findarat tui
```

## Commands

Global options apply to every subcommand:

| Option | Meaning |
| --- | --- |
| `--config <PATH>` | Use a specific TOML configuration file. |
| `--database <PATH>` | Override the SQLite inventory path. |
| `--format <table\|json>` | Output format. Overrides `general.default_output`. |

`--format` controls command output. It is separate from the import/export file
formats, which are selected with `--import-format` and `--export-format`.

Running `findarat` with no subcommand shows the overview. Explicit
`findarat overview` does the same.

### `scan`

Discover hosts, optionally scan TCP ports, fingerprint devices, and persist the
result. A scan creates a history session and records changes such as new
devices, disappeared devices, IP changes, and opened or closed ports.

```text
findarat scan [OPTIONS]

  --interface <NAME>        Interface to scan (default: default-route interface)
  --subnet <CIDR>           Explicit IPv4 CIDR instead of the interface subnet
  --ports <SPEC>            common, all, 22,80,443, or 1-1024
  --no-tcp                  Skip TCP port scanning
  --no-arp                  Disable ARP discovery
  --no-mdns                 Disable mDNS discovery
  --no-ssdp                 Disable SSDP discovery
  --no-netbios              Disable NetBIOS discovery
  --timeout-ms <MS>         Per-provider discovery timeout (200..=30000)
  --scan-timeout-ms <MS>    TCP connect timeout (50..=60000)
  --concurrency <N>         Simultaneous TCP attempts (1..=1024)
  --rate-limit <N>          TCP attempts started per second (0 = unlimited)
  --no-resolve              Skip reverse DNS for hosts without a name
  --max-hosts <N>           Host cap for probing and TCP scanning (1..=65534)
```

`--ports` and `--no-tcp` conflict. The port specification accepts `common`,
`all`, a single port, a range, or a comma-separated combination:

```sh
findarat scan --ports 22,80,443,8000-8100
findarat scan --ports 1-1024 --concurrency 64 --rate-limit 200
```

Discovery providers run concurrently. A provider that fails or times out is
reported as failed while the remaining providers continue. If no discovery
provider succeeds, disappeared-device detection is skipped and a warning is
included in the report.

Scan output includes per-provider status, the discovered devices, and any
changes. With `--format json`, the report is a single JSON object containing
the session, devices, changes, provider reports, warnings, and elapsed time.

### `devices`

```text
findarat devices [--active] [--search TEXT] [--sort FIELD] [--limit N]
```

`--sort` accepts `last_seen`, `first_seen`, `ip`, `name`, `type`, `vendor`, or
`id`. Search is case-insensitive across names, addresses, vendor, type, OS, and
interface.

### `device <TARGET>`

Show one device, including identifiers, ports, services, evidence, and recent
observations. `TARGET` may be a device id, IP address, MAC address, or
hostname. A missing device exits with code `3`.

### `history`

List scan sessions, including interface, subnet, status, device count, and
per-provider outcomes. `--limit N` limits the number of sessions.

### `changes`

```text
findarat changes [--device TARGET] [--kind KIND] [--limit N]
```

Change kinds are `device_added`, `device_disappeared`, `ip_changed`,
`hostname_changed`, `service_added`, `service_removed`, `port_opened`, and
`port_closed`. An unknown kind is a validation error.

### `export <PATH>`

```text
findarat export <PATH> [--export-format auto|json|csv|sqlite] [--force]
```

The format is inferred from the extension unless `--export-format` is given.
`.json` produces a versioned export envelope. `.csv` produces a device table
with a fixed header. `.db`, `.sqlite`, and `.sqlite3` produce a consistent
SQLite snapshot via the SQLite backup API. Existing files are not overwritten
without `--force`.

CSV columns:

```text
id, last_ip, mac, hostname, vendor, device_type, os, interface,
first_seen, last_seen, active, open_ports, services, identifiers,
evidence_count, observation_count
```

CSV is an interchange/reporting format for devices. It does not contain scan
sessions or change history; use JSON or SQLite for a complete backup.

### `import <PATH>`

```text
findarat import <PATH> [--import-format auto|json|sqlite] [--dry-run] [--no-merge]
```

JSON imports accept either a versioned export envelope or a bare array of
device objects. SQLite imports read an existing findarat database in read-only
mode and reject importing a database into itself.

Before writing, the import validates the schema version and device identities.
`--dry-run` reports what would happen without modifying the destination.
Devices that match an existing identity are merged by default; `--no-merge`
skips them. Changes are re-linked to the imported devices, and history that
cannot be linked is reported as a warning.

### `interfaces`

List interfaces with kind, state, IPv4 address, MAC address, and whether the
interface carries the default route. This is useful when `scan` needs an
explicit `--interface`.

### `config`

```text
findarat config show          # effective configuration as TOML
findarat config paths         # config file, data dir, and database paths
findarat config init [--force]
```

`config init` writes the documented default template. It refuses to replace an
existing file unless `--force` is supplied. Because `init` is handled before
normal configuration loading, it can recover from an invalid config file.

### `tui`

Open the terminal interface. Scans run in a background Tokio task and report
progress through a channel. The TUI reads and writes the same SQLite database
as the CLI.

## Configuration

Default locations follow the XDG base directory specification:

| Item | Default |
| --- | --- |
| Config file | `$XDG_CONFIG_HOME/findarat/config.toml` (usually `~/.config/findarat/config.toml`) |
| Data directory | `$XDG_DATA_HOME/findarat` (usually `~/.local/share/findarat`) |
| Database | `$XDG_DATA_HOME/findarat/findarat.db` |

If no configuration file exists, built-in defaults are used. Unknown keys are
ignored; invalid values are rejected with an actionable error. Relative
`storage.database` paths are resolved against the config file's directory, and
`~` is expanded.

Generate the documented template with:

```sh
findarat config init
```

The effective configuration is:

```toml
[general]
# interface = "wlan0"
default_output = "table"       # table | json
log_level = "warn"             # error | warn | info | debug | trace

[discovery]
arp = true
mdns = true
ssdp = true
netbios = true
timeout_ms = 2500              # per-provider timeout
resolve_hostnames = true       # reverse DNS for hosts without an advertised name

[scanner]
default_ports = "common"       # common | all | 1-1024 | 22,80,443
timeout_ms = 1000              # TCP connect timeout
concurrency = 100              # simultaneous connection attempts
rate_limit_per_sec = 0         # 0 = no explicit rate limit
banner_grab = true
max_hosts = 4096               # safety cap for one TCP scan

[storage]
database = "~/.local/share/findarat/findarat.db"

[tui]
show_colors = true
refresh_interval_ms = 1000
```

Validation ranges:

- `discovery.timeout_ms`: 200 to 30000.
- `scanner.timeout_ms`: 50 to 60000.
- `scanner.concurrency`: 1 to 1024.
- `scanner.rate_limit_per_sec`: at most 100000.
- `scanner.max_hosts`: 1 to 65534.
- `tui.refresh_interval_ms`: 100 to 60000.
- `general.log_level`: `error`, `warn`, `info`, `debug`, or `trace`.
- `scanner.default_ports` must be a valid port specification.

`RUST_LOG` can override the configured log filter for diagnostics. Logs are
written to stderr.

## Output and exit codes

Commands support `--format table` (the default) and `--format json`. JSON output
is pretty-printed and stable enough for scripting; exported files use their own
versioned schema.

| Exit code | Meaning |
| --- | --- |
| `0` | Success. |
| `1` | Generic failure or I/O error. |
| `2` | Command-line usage error (reported by clap). |
| `3` | Requested device not found. |
| `4` | Invalid input or configuration. |
| `5` | Permission required (reserved for a required privilege). |
| `6` | Database error. |

## Identity, evidence, and confidence

An IP address alone is not an identity. Matching uses this order:

1. **MAC address** — high confidence, or medium when the MAC is locally
   administered (randomised).
2. **Hostname** — medium confidence, and only when the normalised name is
   unique and not generic (`localhost`, `gateway`, an IP literal, and similar
   names are rejected).
3. **IP address** — low confidence, only when neither side already has a
   conflicting MAC and the previous sighting is within seven days.

Confidence values describe *why* a value is believed:

- `high`: directly observed or produced by an authoritative local source.
- `medium`: a strong inference or stable database match.
- `low`: a weak heuristic or ambiguous match.
- `unknown`: the value exists but its reliability is not established.

Every inferred property is stored as evidence with a source and an evidence
kind: `direct_observation`, `database_inference`, `probabilistic_inference`, or
`user_provided`. Conflicting observations are preserved rather than silently
discarded. For example, a conflicting advertised hostname is recorded as
low-confidence evidence while the primary name is retained.

Vendor names come from an embedded snapshot of the public IEEE MA-L OUI
registry (`data/oui.tsv`). An OUI identifies the organisation that registered a
MAC prefix. It does not identify a device model, and it is unreliable for
randomised MAC addresses.

## Discovery providers

| Provider | Method | Notes |
| --- | --- | --- |
| ARP | UDP priming to port 9, then `/proc/net/arp` | Unprivileged. Only hosts that respond to kernel neighbour resolution appear. |
| mDNS | Multicast DNS-SD queries on 5353 | Custom DNS wire parser; does not require Avahi. |
| SSDP | M-SEARCH to 239.255.255.250:1900 | Fetches a bounded number of UPnP descriptions. |
| NetBIOS | NBNS node-status query on UDP 137 | Often disabled on modern networks; no response is normal. |

Reverse DNS is attempted only for discovered hosts that do not already have an
advertised name. It can be disabled with `--no-resolve` or
`discovery.resolve_hostnames = false`.

## TCP scanning and fingerprinting

TCP scanning uses ordinary `connect()` attempts, bounded by a concurrency
window and an optional rate limit. It never sends exploit payloads. Banner
collection is conservative: a minimal HTTP `HEAD` request for plaintext HTTP,
a passive read for services that greet clients, and no plaintext probe for TLS
or binary protocols.

Fingerprinting combines:

- OUI vendor lookup (database inference).
- Hostname patterns (probabilistic inference).
- mDNS service types and SSDP device types/manufacturer/model.
- Open ports and service banners.
- Gateway and NetBIOS presence hints.

Direct observations are never overwritten by guesses. When multiple rules
disagree, the strongest evidence wins for the displayed value and the
alternatives remain visible as evidence.

## Data storage

The inventory is a SQLite database in WAL mode with foreign keys enabled and a
five-second busy timeout. Schema versioning is stored in `schema_meta`. The
current schema version is `1`. A database created by a newer build is rejected
with an upgrade message instead of being modified.

The last-known device row is a convenience snapshot. The observation, evidence,
port, service, session, and change tables are the historical record. See
[docs/data-model.md](docs/data-model.md) for the schema and invariants.

## TUI keys

| Key | Action |
| --- | --- |
| `Tab` / `Shift+Tab` | Next / previous screen. |
| `1` … `8` | Jump to a screen. |
| `q` or `Ctrl+C` | Quit. |
| `?` | Help. |
| `↑` / `↓` | Move or scroll. |
| `Enter` | Open details, start a scan, or confirm an action. |
| `/` | Search devices. |
| `s` | Cycle sort mode (Devices) or start a scan (Scan). |
| `r` | Refresh or reload. |
| `e` / `i` | Export / import using the current path. |
| `p` | Edit the import/export path. |
| `x` | Toggle import dry-run. |
| `Esc` | Go back or leave an input mode. |

Terminal state is restored on every exit path, including errors.

## Documentation

- [Architecture](docs/architecture.md)
- [Data model](docs/data-model.md)
- [Development](docs/development.md)

## Limitations

- IPv4 only.
- Discovery depends on what the local network exposes. Silent hosts, client
  isolation, firewalls, and disabled protocols legitimately produce no result.
- OUI data identifies a registered organisation, not a model or operating
  system.
- Fingerprinting is heuristic. Confidence levels are part of the result;
  absence of evidence is not evidence of absence.
- Scans are safety-capped by `scanner.max_hosts` and the configured
  concurrency/rate limits.
- Access-point management and disruptive wireless testing are out of scope.

## License

MIT. See [LICENSE](LICENSE).
