# Data model

`findarat` stores a historical inventory in SQLite and exports the same domain
objects as JSON. The database schema and the export envelope are both versioned
independently of the application version.

Current versions:

- SQLite schema: `1` (`schema_meta.schema_version`).
- Export/import envelope: `1` (`ExportEnvelope.schema_version`).
- Application version: reported separately as `tool_version`.

## Design principles

- **A device is an identity, not an address.** IP, MAC, hostname, and NetBIOS
  names are identifiers with confidence and observation times.
- **History is authoritative.** The `devices` row is a last-known snapshot.
  Observations, evidence, ports, services, sessions, and changes preserve what
  was seen over time.
- **Unknown is a value.** `device_type = 'unknown'` and null optional fields are
  legitimate results, not missing data to be guessed.
- **Conflicts are preserved.** When two sources disagree, the primary value is
  retained and the alternative is stored as evidence.
- **Deduplication is deterministic.** Stable keys prevent duplicate
  observations, services, and changes when the same scan data is written or
  imported twice.

## Entity relationships

```text
scan_sessions 1 ─── n observations
              1 ─── n changes
devices       1 ─── n identifiers
              1 ─── n observations
              1 ─── n evidence
              1 ─── n ports
              1 ─── n services
              1 ─── n changes
```

All child tables reference `devices(id)` with `ON DELETE CASCADE`.
`observations.scan_id` and `changes.scan_id` reference `scan_sessions(id)` with
`ON DELETE SET NULL`.

## SQLite schema

### `schema_meta`

Key/value metadata. The only required key is `schema_version`.

```sql
CREATE TABLE schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
```

On open, `findarat` reads the version, refuses versions newer than the build,
applies the idempotent schema, and inserts version `1` for a new database.
Existing databases are not downgraded or rewritten silently.

### `scan_sessions`

One row per scan attempt.

```sql
CREATE TABLE scan_sessions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at    TEXT NOT NULL,
    finished_at   TEXT,
    interface     TEXT,
    subnet        TEXT,
    status        TEXT NOT NULL,
    device_count  INTEGER NOT NULL DEFAULT 0,
    providers_json TEXT NOT NULL DEFAULT '[]'
);
```

- Timestamps are RFC 3339 UTC strings.
- `status` is `running`, `completed`, or `failed`.
- `providers_json` is a serialized array of per-provider reports
  (`name`, `status`, `hosts_found`, `error`, `duration_ms`).
- Provider failures are recorded per provider; they do not invalidate the
  session.

### `devices`

Last-known snapshot used for list and detail views.

```sql
CREATE TABLE devices (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    last_ip       TEXT,
    last_mac      TEXT,
    last_hostname TEXT,
    vendor        TEXT,
    device_type   TEXT NOT NULL DEFAULT 'unknown',
    os            TEXT,
    interface     TEXT,
    active        INTEGER NOT NULL DEFAULT 1,
    first_seen    TEXT NOT NULL,
    last_seen     TEXT NOT NULL
);
```

Indexed by `last_seen` and `interface`. `active` is `1` for devices seen in the
most recent completed scan and `0` after disappeared-device detection.

The device row is not the source of truth for identity. `last_ip`, `last_mac`,
and `last_hostname` are display conveniences; use `identifiers` and
`observations` for history.

### `identifiers`

Historical identity values attached to a device.

```sql
CREATE TABLE identifiers (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id  INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL,
    value      TEXT NOT NULL,
    confidence TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen  TEXT NOT NULL,
    UNIQUE(device_id, kind, value)
);
```

- `kind`: `mac`, `ip`, `hostname`, or `netbios_name`.
- `value` is normalised: MACs are uppercase colon-separated, hostnames are
  lowercased and stripped of a trailing `.local`.
- Indexed by `(kind, value)` for identity lookup.
- An old IP remains attached after DHCP assigns a new one.

### `observations`

Point-in-time observations by a discovery source.

```sql
CREATE TABLE observations (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id       INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    scan_id         INTEGER REFERENCES scan_sessions(id) ON DELETE SET NULL,
    observed_at     TEXT NOT NULL,
    source          TEXT NOT NULL,
    interface       TEXT,
    ip              TEXT,
    mac             TEXT,
    hostname        TEXT,
    details         TEXT,
    observation_key TEXT NOT NULL,
    UNIQUE(device_id, observation_key)
);
```

- `source` is the provider or subsystem (`arp`, `mdns`, `ssdp`, `netbios`,
  `tcp_scan`, and so on).
- `details` is optional JSON for provider-specific data.
- `observation_key` is a deterministic hash over the observation timestamp,
  source, interface, addresses, hostname, and details. The unique constraint
  makes re-imports idempotent.
- Indexed by `(device_id, observed_at)`.

### `evidence`

Attributable support for a property value.

```sql
CREATE TABLE evidence (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id      INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    observation_id INTEGER REFERENCES observations(id) ON DELETE SET NULL,
    property       TEXT NOT NULL,
    value          TEXT NOT NULL,
    source         TEXT NOT NULL,
    confidence     TEXT NOT NULL,
    kind           TEXT NOT NULL,
    observed_at    TEXT NOT NULL,
    note           TEXT,
    UNIQUE(device_id, property, value, source)
);
```

- `property`: `mac`, `vendor`, `hostname`, `device_type`, `operating_system`,
  `open_port`, `service`, and similar names.
- `confidence`: `high`, `medium`, `low`, or `unknown`.
- `kind`: `direct_observation`, `database_inference`,
  `probabilistic_inference`, or `user_provided`.
- `note` explains conflicts or rule details.
- The unique constraint keeps one row per device/property/value/source. If the
  same claim is observed again, the existing row is reused rather than
  duplicated.

Evidence is additive. A stronger value does not delete weaker or conflicting
evidence.

### `ports`

Open port observations.

```sql
CREATE TABLE ports (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id  INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    ip         TEXT NOT NULL,
    port       INTEGER NOT NULL,
    protocol   TEXT NOT NULL,
    state      TEXT NOT NULL,
    service    TEXT,
    version    TEXT,
    banner     TEXT,
    confidence TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen  TEXT NOT NULL,
    UNIQUE(device_id, ip, port, protocol)
);
```

- An open port is a direct observation.
- The service name and version are separate, less certain claims. Their
  confidence is stored in the same row.
- `state` supports `open`, `closed`, and `filtered`, but the scanner currently
  records open ports only.
- Indexed by `device_id`.

### `services`

Services advertised by discovery or inferred from banners.

```sql
CREATE TABLE services (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id   INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    port        INTEGER,
    protocol    TEXT NOT NULL,
    version     TEXT,
    source      TEXT NOT NULL,
    active      INTEGER NOT NULL DEFAULT 1,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    service_key TEXT NOT NULL,
    UNIQUE(device_id, service_key)
);
```

- `service_key` is `name|port|protocol|source`.
- `active = 0` marks a previously seen TCP service that was absent in the
  latest scan. Discovery-advertised services are not deactivated by TCP scan
  absence.
- Indexed by `device_id`.

### `changes`

Detected changes between scans.

```sql
CREATE TABLE changes (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id      INTEGER REFERENCES scan_sessions(id) ON DELETE SET NULL,
    device_id    INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    kind         TEXT NOT NULL,
    old_value    TEXT,
    new_value    TEXT,
    detected_at  TEXT NOT NULL,
    device_label TEXT,
    change_key   TEXT NOT NULL UNIQUE
);
```

Change kinds:

| Kind | Meaning |
| --- | --- |
| `device_added` | A new identity entered the inventory. |
| `device_disappeared` | A previously active device was not seen. |
| `ip_changed` | The device's current IP changed. |
| `hostname_changed` | The normalised hostname changed. |
| `service_added` | A service claim appeared. |
| `service_removed` | A service claim disappeared. |
| `port_opened` | An open port was newly observed. |
| `port_closed` | A previously open port was no longer observed. |

`device_label` is a denormalised display name captured when the change was
recorded, so history remains readable if the device is renamed later.
`change_key` is a deterministic hash of device, kind, old/new values, and
timestamp; it prevents duplicate change rows on re-import.

Indexed by `detected_at` and `(device_id, detected_at)`.

## Identity matching

Identity matching is implemented in `inventory/identity.rs` and applied by
`Database::find_match`.

Candidate order:

1. **MAC** — exact normalised match. `high` confidence normally, `medium` when
   the MAC is locally administered (randomised).
2. **Hostname** — exact normalised match, `medium` confidence, only when the
   name is unique and not generic. Names rejected as identity keys include
   `localhost`, `localhost.localdomain`, `unknown`, `_gateway`, `gateway`, and
   IP literals. A trailing `.local` is removed.
3. **IP** — exact match, `low` confidence, only when:
   - the existing device and the observed device do not both have a MAC, and
   - the previous sighting is at most seven days old.

When multiple candidates exist, the highest confidence wins. Ties prefer MAC,
then hostname, then IP. An IP address alone never proves identity.

## Domain model and JSON export

`Device` is the aggregate used by the CLI, TUI, and JSON export:

```json
{
  "id": 1,
  "last_ip": "192.168.1.10",
  "mac": "AA:BB:CC:DD:EE:01",
  "vendor": "Example Vendor",
  "hostname": "printer",
  "device_type": "printer",
  "os": "Linux",
  "interface": "wlan0",
  "first_seen": "2026-01-01T00:00:00Z",
  "last_seen": "2026-01-02T00:00:00Z",
  "active": true,
  "identifiers": [],
  "evidence": [],
  "ports": [],
  "services": [],
  "observations": []
}
```

Optional fields are omitted when absent. Empty vectors are omitted. `active`
defaults to `true` when absent, so a minimal imported device is treated as
active.

Enumerations serialize as snake_case strings:

- `device_type`: `router`, `access_point`, `smartphone`, `laptop`, `desktop`,
  `server`, `printer`, `smart_tv`, `iot`, `unknown`.
- `confidence`: `high`, `medium`, `low`, `unknown`.
- `kind` (evidence): `direct_observation`, `database_inference`,
  `probabilistic_inference`, `user_provided`.
- `identifier kind`: `mac`, `ip`, `hostname`, `netbios_name`.
- `protocol`: `tcp`, `udp`.
- `port state`: `open`, `closed`, `filtered`.
- `scan status`: `running`, `completed`, `failed`.
- `provider status`: `ok`, `failed`, `skipped`.

## JSON export envelope

JSON export is a complete inventory document:

```json
{
  "schema_version": 1,
  "tool": "findarat",
  "tool_version": "0.1.0",
  "exported_at": "2026-01-02T03:04:05Z",
  "devices": [],
  "scan_sessions": [],
  "changes": []
}
```

Import accepts this envelope or a bare JSON array of device objects. A bare
array is treated as devices with no sessions or changes. Envelope versions
outside `1..=SCHEMA_VERSION` are rejected.

## CSV export

CSV is a flat device report, not a complete backup. The header is:

```text
id,last_ip,mac,hostname,vendor,device_type,os,interface,
first_seen,last_seen,active,open_ports,services,identifiers,
evidence_count,observation_count
```

- `open_ports` is a comma-separated list of open TCP port numbers.
- `services` is a human-readable service summary.
- `identifiers` is `kind=value` pairs separated by `; `.
- `evidence_count` and `observation_count` are counts, not full records.
- Scan sessions and change history are not included.

## Import behavior

1. Read and validate the source. JSON errors are reported with the file path.
   SQLite sources are opened read-only and must contain a findarat schema.
2. Reject unsupported schema versions.
3. Reject importing a database into itself.
4. Import scan sessions, matching existing sessions by exact `started_at`.
5. For each device:
   - Skip devices with no IP, MAC, hostname, or identifier.
   - Match against local identities.
   - Merge by default; skip with `--no-merge`.
   - Create when no identity matches.
6. Re-link changes to local device and session ids. Changes whose device was
   skipped are reported once as a warning.
7. In `--dry-run` mode, perform matching and report counts without writing any
   device, session, evidence, or change rows.

Imports preserve historical timestamps. They do not synthesize observations
and do not run change detection for imported snapshots.

## Migration policy

- `SCHEMA_VERSION` is bumped only for incompatible changes.
- The schema application is idempotent (`CREATE TABLE IF NOT EXISTS`).
- Opening a database from a newer build fails with a database error instead of
  attempting a downgrade.
- Adding a migration requires:
  1. bumping `SCHEMA_VERSION`,
  2. adding an ordered migration step,
  3. updating the export/import version checks if the document shape changes,
  4. adding a test that opens an older database and verifies the upgrade.
