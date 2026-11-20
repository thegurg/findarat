# Development

## Toolchain

- Linux
- Rust 1.88 or newer (`rust-version` in `Cargo.toml`)
- A C toolchain for the bundled SQLite build (`rusqlite` with the `bundled`
  feature)

The project uses the 2021 edition and a thin-LTO, stripped release profile.

## Build and run

```sh
cargo build
cargo run -- --help
cargo run -- interfaces
cargo run -- scan --no-tcp --timeout-ms 500
cargo run -- tui
```

Use a temporary inventory while developing to avoid touching your real data:

```sh
cargo run -- --database /tmp/findarat-dev.db scan --no-tcp
cargo run -- --database /tmp/findarat-dev.db devices
```

Isolate XDG paths in scripts and tests:

```sh
XDG_CONFIG_HOME=/tmp/findarat-test/config \
XDG_DATA_HOME=/tmp/findarat-test/data \
cargo run -- config paths
```

## Required checks

Run all three before considering a change complete:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

During development, `cargo fmt --all` applies formatting. Clippy warnings are
treated as errors; do not suppress them with `#[allow]` unless there is a
specific, documented reason.

The full suite currently consists of library unit tests and end-to-end CLI
tests. A passing run looks like:

```text
running 136 tests ... test result: ok
running 9 tests ... test result: ok
```

## Test layout

### Unit tests

Unit tests live next to the code they exercise (`#[cfg(test)] mod tests`).
Coverage includes:

- Subnet parsing and address arithmetic.
- Interface/MAC normalisation.
- Configuration defaults, partial TOML, and validation failures.
- Port-spec parsing and canonicalisation.
- DNS wire parsing and mDNS/SSDP/NetBIOS parsing helpers.
- Identity ranking, hostname normalisation, and IP-match rules.
- Evidence and confidence serialization.
- Change detection rules.
- SQLite schema creation, upserts, identity merges, duplicates, conflicts,
  history, and migrations.
- JSON/CSV/SQLite export and JSON/SQLite import, including dry-run, merge,
  skip, schema rejection, and bare-array imports.
- TUI state transitions and key handling without a real terminal.

Prefer pure functions for rules so they can be tested without sockets or a
database. Network providers should keep parsing and merge logic separate from
socket I/O.

### CLI integration tests

`tests/cli.rs` runs the real binary with isolated `XDG_CONFIG_HOME` and
`XDG_DATA_HOME` directories and a temporary database. It covers:

- Help and version output.
- Overview and interface JSON.
- Missing-device exit code.
- Invalid sort and change-kind validation.
- Config initialization and overwrite refusal.
- Import dry-run not writing.
- Import, list, export, and re-import round trips.

Add an integration test when a change affects command behavior, exit codes, or
file formats. Use `TempDir` and explicit paths; never depend on the developer's
real network or inventory.

### Network-dependent tests

Unit tests must not require a live network. The one environment-sensitive test
in `network::tests` only asserts that local interface listing includes `lo`.
Live scans are a manual smoke test, not part of the automated suite.

## Manual smoke test

A bounded scan validates orchestration without scanning a large network or
waiting on many timeouts:

```sh
cargo run -- --database /tmp/findarat-smoke.db scan \
  --no-tcp --timeout-ms 300 --max-hosts 8
```

Then inspect the result and history:

```sh
cargo run -- --database /tmp/findarat-smoke.db devices
cargo run -- --database /tmp/findarat-smoke.db history
cargo run -- --database /tmp/findarat-smoke.db changes
```

A quiet or isolated network may legitimately return zero devices. That is not
a failure; check the per-provider status in the scan output.

For a TCP smoke test, use a small explicit port list and rate limit:

```sh
cargo run -- --database /tmp/findarat-smoke.db scan \
  --ports 22,80,443 --scan-timeout-ms 300 --concurrency 16 --rate-limit 50
```

## Code style

- Keep the CLI and TUI as presentation layers. Put shared behavior in `app`,
  `inventory`, or `io`.
- Return `anyhow::Result` with context at application boundaries. Use
  `FindaratError` for stable categories that map to exit codes.
- Avoid `unwrap()` and `expect()` in production paths. Tests may use them for
  fixtures and assertions.
- Do not suppress warnings. If a lint is genuinely wrong, document why.
- Preserve conflicts as evidence instead of overwriting observations.
- Keep output stable and script-friendly. Table output is for humans; JSON
  output is for automation.
- Use snake_case for serialized enum values. Existing exported names are part
  of the schema.
- Add comments for non-obvious protocol handling, safety caps, and confidence
  decisions, not for self-evident code.

## Adding a discovery provider

1. Create `src/discovery/<name>.rs` implementing `DiscoveryProvider`.
2. Return `DiscoveredHost` values with sources, services, and evidence. Do not
   write to the database.
3. Keep socket I/O bounded and respect `DiscoveryContext::timeout` and
   `max_hosts`.
4. Add enable flags to `DiscoveryOptions`, `Config`, and the CLI.
5. Register the provider in `run_discovery`.
6. Add parsing/merge tests using captured or synthetic data.
7. Update the README provider table and `docs/architecture.md`.

## Adding a fingerprint rule

1. Add a module under `src/fingerprint/` or extend an existing one.
2. Return findings with a value, source, confidence, and evidence kind.
3. Record every finding as evidence in `fingerprint::apply`.
4. Only set a display property when the finding is strong enough. Direct
   observations must not be overwritten by guesses.
5. Add tests for positive, negative, and conflicting cases.
6. Update `docs/data-model.md` if the rule introduces a new property name.

## Changing the database schema

1. Bump `SCHEMA_VERSION` in `src/inventory/database.rs` and `src/lib.rs` only
   for incompatible changes.
2. Add an ordered migration step. Keep the base schema idempotent.
3. Keep the newer-version rejection behavior.
4. Update `ExportEnvelope` and import validation if the document shape changes.
5. Add a test that opens a database at the previous version and verifies the
   upgrade.
6. Update `docs/data-model.md`.

Never edit a released migration in place; add a new step.

## Refreshing OUI data

Vendor lookup uses `data/oui.tsv`, embedded at compile time with
`include_str!`. The file has one entry per line:

```text
<six-hex-digit-prefix>\t<registered organisation>
```

It is a snapshot of the public IEEE MA-L registry
(`https://standards-oui.ieee.org/oui/oui.csv`). To refresh it, download the
current CSV and convert the `Assignment` and `Organization Name` columns to
tab-separated uppercase prefixes. Keep the table sorted only if convenient;
lookup uses a hash map. Rebuild and run the fingerprint tests afterward:

```sh
cargo test fingerprint::oui
```

OUI data identifies a registered organisation, not a device model, and should
not be used as strong evidence for randomised MAC addresses.

## Debugging

- Set `RUST_LOG=debug` (or `trace`) for internal diagnostics on stderr.
- Use `findarat config show` to confirm the effective configuration and
  `findarat config paths` to locate the database.
- Use `findarat interfaces` when a scan cannot find an active interface.
- A provider that times out is reported as `failed`; other providers continue.
- If no discovery provider succeeds, disappeared-device detection is skipped
  and the scan report includes a warning.
- SQLite runs in WAL mode with a five-second busy timeout. Remove stale
  `-wal`/`-shm` files only when no findarat process is using the database.

## Release checklist

1. Update the version in `Cargo.toml`.
2. Run `cargo fmt --all -- --check`.
3. Run `cargo clippy --all-targets --all-features -- -D warnings`.
4. Run `cargo test`.
5. Run a bounded live smoke scan.
6. Build with `cargo build --release`.
7. Verify `findarat --version`, `findarat config paths`, and an export/import
   round trip.
8. Update README/docs for any behavior changes.
9. Tag the release and attach the binary and checksum.

## License

MIT. Contributions are accepted under the same license.
