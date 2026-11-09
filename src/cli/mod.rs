//! Command-line interface.
//!
//! The CLI is the primary interface. It owns argument parsing, output
//! formatting, and exit codes; all network and storage work happens in the
//! shared [`crate::app`] and [`crate::inventory`] layers.

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
use std::time::Duration;

use crate::app::{self, ScanRequest};
use crate::config::{self, LoadedConfig, OutputFormat};
use crate::error::FindaratError;
use crate::inventory::Database;
use crate::io::{self, ExportFormat, ImportFormat, ImportOptions, ImportReport};
use crate::models::{ChangeKind, Device, ScanSession};
use crate::network::interface::list_interfaces;

#[derive(Debug, Parser)]
#[command(
    name = "findarat",
    version = crate::VERSION,
    about = "Linux-first local network discovery and device intelligence",
    long_about = "Discover devices on your local IPv4 network, record evidence-based \
identities in a SQLite inventory, and inspect history from the CLI or TUI.\n\n\
findarat is unprivileged by default and never performs disruptive network operations."
)]
pub struct Cli {
    /// Configuration file (defaults to $XDG_CONFIG_HOME/findarat/config.toml).
    #[arg(long, global = true, value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// Override the SQLite inventory path.
    #[arg(long, global = true, value_name = "PATH")]
    pub database: Option<PathBuf>,

    /// Output format. Defaults to general.default_output from the config.
    #[arg(long, global = true, value_enum, value_name = "FORMAT")]
    pub format: Option<FormatArg>,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum FormatArg {
    Table,
    Json,
}

impl From<FormatArg> for OutputFormat {
    fn from(value: FormatArg) -> Self {
        match value {
            FormatArg::Table => OutputFormat::Table,
            FormatArg::Json => OutputFormat::Json,
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Discover devices, scan ports, fingerprint, and save the inventory.
    Scan(ScanArgs),
    /// List known devices.
    Devices(DevicesArgs),
    /// Show one device, its evidence, ports, and observations.
    Device {
        /// Device id, IP address, MAC address, or hostname.
        target: String,
    },
    /// List scan sessions.
    History(HistoryArgs),
    /// List detected changes.
    Changes(ChangesArgs),
    /// Export the inventory to JSON, CSV, or SQLite.
    Export(ExportArgs),
    /// Import devices and history from JSON or SQLite.
    Import(ImportArgs),
    /// List network interfaces.
    Interfaces,
    /// Inspect or create the configuration.
    Config(ConfigArgs),
    /// Open the terminal user interface.
    Tui,
    /// Show a short status overview (the default command).
    Overview,
}

#[derive(Debug, Args)]
pub struct ScanArgs {
    /// Interface to scan (default: interface carrying the default route).
    #[arg(long, value_name = "NAME")]
    pub interface: Option<String>,

    /// Scan an explicit IPv4 CIDR instead of the interface subnet.
    #[arg(long, value_name = "CIDR")]
    pub subnet: Option<String>,

    /// TCP ports: common, all, 22,80,443, or 1-1024.
    #[arg(long, value_name = "SPEC", conflicts_with = "no_tcp")]
    pub ports: Option<String>,

    /// Skip TCP port scanning.
    #[arg(long)]
    pub no_tcp: bool,

    #[arg(long)]
    pub no_arp: bool,

    #[arg(long)]
    pub no_mdns: bool,

    #[arg(long)]
    pub no_ssdp: bool,

    #[arg(long)]
    pub no_netbios: bool,

    /// Per-provider discovery timeout in milliseconds.
    #[arg(long, value_name = "MS")]
    pub timeout_ms: Option<u64>,

    /// TCP connect timeout in milliseconds.
    #[arg(long, value_name = "MS")]
    pub scan_timeout_ms: Option<u64>,

    /// Maximum simultaneous TCP connection attempts.
    #[arg(long, value_name = "N")]
    pub concurrency: Option<usize>,

    /// Maximum TCP connection attempts started per second (0 = unlimited).
    #[arg(long, value_name = "N")]
    pub rate_limit: Option<u32>,

    /// Do not perform reverse DNS for hosts without an advertised name.
    #[arg(long)]
    pub no_resolve: bool,

    /// Safety cap for hosts probed or port-scanned.
    #[arg(long, value_name = "N")]
    pub max_hosts: Option<usize>,
}

#[derive(Debug, Args)]
pub struct DevicesArgs {
    /// Only show devices seen in the most recent scan (active).
    #[arg(long)]
    pub active: bool,

    /// Case-insensitive search across names, addresses, vendor, type, and OS.
    #[arg(long, value_name = "TEXT")]
    pub search: Option<String>,

    /// Sort by last_seen, first_seen, ip, name, type, vendor, or id.
    #[arg(long, default_value = "last_seen", value_name = "FIELD")]
    pub sort: String,

    /// Maximum number of rows.
    #[arg(long, value_name = "N")]
    pub limit: Option<usize>,
}

#[derive(Debug, Args)]
pub struct HistoryArgs {
    #[arg(long, value_name = "N")]
    pub limit: Option<usize>,
}

#[derive(Debug, Args)]
pub struct ChangesArgs {
    /// Limit to one device (id, IP, MAC, or hostname).
    #[arg(long, value_name = "DEVICE")]
    pub device: Option<String>,

    /// Limit to a change kind (device_added, ip_changed, port_opened, ...).
    #[arg(long, value_name = "KIND")]
    pub kind: Option<String>,

    #[arg(long, value_name = "N")]
    pub limit: Option<usize>,
}

#[derive(Debug, Args)]
pub struct ExportArgs {
    /// Destination path. Extension selects the default format.
    pub path: PathBuf,

    /// json, csv, sqlite, or auto (infer from the extension).
    #[arg(long, default_value = "auto", value_name = "FORMAT")]
    pub export_format: String,

    /// Replace an existing destination file.
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct ImportArgs {
    /// Source file (JSON export or findarat SQLite database).
    pub path: PathBuf,

    /// json, sqlite, or auto (infer from the extension).
    #[arg(long, default_value = "auto", value_name = "FORMAT")]
    pub import_format: String,

    /// Validate and report without writing.
    #[arg(long)]
    pub dry_run: bool,

    /// Skip devices that match an existing identity instead of merging.
    #[arg(long)]
    pub no_merge: bool,
}

#[derive(Debug, Args)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub command: Option<ConfigCommand>,
}

#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    /// Print the effective configuration.
    Show,
    /// Print configuration and database paths.
    Paths,
    /// Write the documented default configuration template.
    Init {
        #[arg(long)]
        force: bool,
    },
}

/// Parse and run the CLI. `main` maps the returned error to an exit code.
pub async fn run(cli: Cli) -> Result<()> {
    if let Some(Command::Config(args)) = &cli.command {
        return run_config(args, &cli);
    }

    let loaded = LoadedConfig::load(cli.config.as_deref(), cli.database.as_deref())?;
    init_tracing(&loaded.config.general.log_level);
    for warning in &loaded.warnings {
        eprintln!("warning: {warning}");
    }
    let format = cli
        .format
        .map(OutputFormat::from)
        .unwrap_or(loaded.config.general.default_output);

    match cli.command.unwrap_or(Command::Overview) {
        Command::Scan(args) => run_scan(args, &loaded, format).await,
        Command::Devices(args) => run_devices(args, &loaded, format),
        Command::Device { target } => run_device(&target, &loaded, format),
        Command::History(args) => run_history(args, &loaded, format),
        Command::Changes(args) => run_changes(args, &loaded, format),
        Command::Export(args) => run_export(args, &loaded, format),
        Command::Import(args) => run_import(args, &loaded, format),
        Command::Interfaces => run_interfaces(format),
        Command::Config(_) => unreachable!("config is handled before configuration loading"),
        Command::Tui => crate::tui::run(&loaded.config, loaded.database_path()).await,
        Command::Overview => run_overview(&loaded, format),
    }
}

fn init_tracing(level: &str) {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}

fn open_database(loaded: &LoadedConfig) -> Result<Database> {
    Database::open(loaded.database_path()).with_context(|| {
        format!(
            "failed to open inventory {}",
            loaded.database_path().display()
        )
    })
}

async fn run_scan(args: ScanArgs, loaded: &LoadedConfig, format: OutputFormat) -> Result<()> {
    let mut request = ScanRequest::from_config(&loaded.config)?;
    if let Some(interface) = args.interface {
        request.interface = Some(interface);
    }
    request.subnet = app::parse_subnet(args.subnet.as_deref())?;
    if args.no_arp {
        request.discovery.arp = false;
    }
    if args.no_mdns {
        request.discovery.mdns = false;
    }
    if args.no_ssdp {
        request.discovery.ssdp = false;
    }
    if args.no_netbios {
        request.discovery.netbios = false;
    }
    if let Some(timeout_ms) = args.timeout_ms {
        if !(200..=30_000).contains(&timeout_ms) {
            return Err(FindaratError::Validation(
                "discovery timeout must be between 200 and 30000 ms".into(),
            )
            .into());
        }
        request.discovery.timeout = Duration::from_millis(timeout_ms);
    }
    if let Some(timeout_ms) = args.scan_timeout_ms {
        if !(50..=60_000).contains(&timeout_ms) {
            return Err(FindaratError::Validation(
                "TCP timeout must be between 50 and 60000 ms".into(),
            )
            .into());
        }
        request.scan_options.timeout = Duration::from_millis(timeout_ms);
    }
    if let Some(concurrency) = args.concurrency {
        if !(1..=1024).contains(&concurrency) {
            return Err(
                FindaratError::Validation("concurrency must be between 1 and 1024".into()).into(),
            );
        }
        request.scan_options.concurrency = concurrency;
    }
    if let Some(rate_limit) = args.rate_limit {
        request.scan_options.rate_limit_per_sec = rate_limit;
    }
    if args.no_resolve {
        request.resolve_hostnames = false;
    }
    if let Some(max_hosts) = args.max_hosts {
        if !(1..=65_534).contains(&max_hosts) {
            return Err(
                FindaratError::Validation("max_hosts must be between 1 and 65534".into()).into(),
            );
        }
        request.max_hosts = max_hosts;
    }
    if args.no_tcp {
        request.ports = None;
    } else if let Some(spec) = args.ports {
        request.ports = Some(
            crate::scanner::parse_ports(&spec)
                .map_err(|error| FindaratError::Validation(format!("invalid --ports: {error}")))?,
        );
    }

    let mut database = open_database(loaded)?;
    let report = app::run_scan(&request, &mut database, None).await?;

    match format {
        OutputFormat::Json => print_json(&serde_json::json!({
            "session": &report.session,
            "session_id": report.session_id,
            "interface": &report.interface,
            "subnet": &report.subnet,
            "devices": &report.devices,
            "changes": &report.changes,
            "providers": &report.reports,
            "open_ports": report.open_ports,
            "elapsed_ms": report.elapsed.as_millis().min(u128::from(u64::MAX)) as u64,
            "warnings": &report.warnings,
        }))?,
        OutputFormat::Table => print_scan_report(&report),
    }
    Ok(())
}

fn print_scan_report(report: &app::ScanReport) {
    println!("{}", app::summarise_report(report));
    if let (Some(interface), Some(subnet)) = (&report.interface, &report.subnet) {
        println!("network: {interface} | {subnet}");
    }
    for warning in &report.warnings {
        eprintln!("warning: {warning}");
    }
    println!();
    let mut rows = Vec::new();
    for provider in &report.reports {
        rows.push(vec![
            provider.name.clone(),
            provider.status.to_string(),
            provider.hosts_found.to_string(),
            format!("{} ms", provider.duration_ms),
            provider.error.clone().unwrap_or_default(),
        ]);
    }
    print_table(&["Provider", "Status", "Hosts", "Time", "Note"], rows);
    println!();
    let rows: Vec<Vec<String>> = report
        .devices
        .iter()
        .map(|device| {
            vec![
                device
                    .id
                    .map(|id| id.to_string())
                    .unwrap_or_else(|| "-".to_string()),
                device.display_name(),
                device
                    .last_ip
                    .map(|ip| ip.to_string())
                    .unwrap_or_else(|| "—".to_string()),
                device.mac.clone().unwrap_or_else(|| "—".to_string()),
                device.device_type.label().to_string(),
                device.vendor.clone().unwrap_or_else(|| "—".to_string()),
                app::port_list(&device.ports),
            ]
        })
        .collect();
    print_table(
        &["ID", "Name", "IP", "MAC", "Type", "Vendor", "Open ports"],
        rows,
    );
    if !report.changes.is_empty() {
        println!();
        println!("changes:");
        print_changes_table(&report.changes);
    }
}

fn run_devices(args: DevicesArgs, loaded: &LoadedConfig, format: OutputFormat) -> Result<()> {
    let database = open_database(loaded)?;
    let mut devices = database.list_devices()?;
    if args.active {
        devices.retain(|device| device.active);
    }
    if let Some(search) = args.search.as_deref() {
        let needle = search.to_ascii_lowercase();
        devices.retain(|device| device_matches(device, &needle));
    }
    sort_devices(&mut devices, &args.sort)?;
    if let Some(limit) = args.limit {
        devices.truncate(limit);
    }

    match format {
        OutputFormat::Json => print_json(&devices)?,
        OutputFormat::Table => {
            let rows: Vec<Vec<String>> = devices
                .iter()
                .map(|device| {
                    vec![
                        device
                            .id
                            .map(|id| id.to_string())
                            .unwrap_or_else(|| "-".to_string()),
                        device.display_name(),
                        device
                            .last_ip
                            .map(|ip| ip.to_string())
                            .unwrap_or_else(|| "—".to_string()),
                        device.mac.clone().unwrap_or_else(|| "—".to_string()),
                        device.device_type.label().to_string(),
                        device.vendor.clone().unwrap_or_else(|| "—".to_string()),
                        app::port_list(&device.ports),
                        device.last_seen.format("%Y-%m-%d %H:%M").to_string(),
                        if device.active { "yes" } else { "no" }.to_string(),
                    ]
                })
                .collect();
            print_table(
                &[
                    "ID",
                    "Name",
                    "IP",
                    "MAC",
                    "Type",
                    "Vendor",
                    "Open ports",
                    "Last seen",
                    "Active",
                ],
                rows,
            );
        }
    }
    Ok(())
}

fn run_device(target: &str, loaded: &LoadedConfig, format: OutputFormat) -> Result<()> {
    let database = open_database(loaded)?;
    let device = database
        .find_device(target)?
        .ok_or_else(|| FindaratError::DeviceNotFound(target.to_string()))?;

    match format {
        OutputFormat::Json => print_json(&device)?,
        OutputFormat::Table => print_device_detail(&device),
    }
    Ok(())
}

fn print_device_detail(device: &Device) {
    println!("{}", device.display_name());
    println!(
        "id: {}",
        device
            .id
            .map(|id| id.to_string())
            .unwrap_or_else(|| "-".to_string())
    );
    println!(
        "ip: {}",
        device
            .last_ip
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "unknown".to_string())
    );
    println!("mac: {}", device.mac.as_deref().unwrap_or("unknown"));
    println!("vendor: {}", device.vendor.as_deref().unwrap_or("unknown"));
    println!("type: {}", device.device_type.label());
    println!("os: {}", device.os.as_deref().unwrap_or("unknown"));
    println!(
        "interface: {}",
        device.interface.as_deref().unwrap_or("unknown")
    );
    println!("first seen: {}", device.first_seen.to_rfc3339());
    println!("last seen: {}", device.last_seen.to_rfc3339());
    println!("active: {}", device.active);

    if !device.identifiers.is_empty() {
        println!();
        println!("identifiers:");
        let rows = device
            .identifiers
            .iter()
            .map(|identifier| {
                vec![
                    identifier.kind.to_string(),
                    identifier.value.clone(),
                    identifier.confidence.to_string(),
                    identifier.first_seen.format("%Y-%m-%d %H:%M").to_string(),
                    identifier.last_seen.format("%Y-%m-%d %H:%M").to_string(),
                ]
            })
            .collect();
        print_table(
            &["Kind", "Value", "Confidence", "First seen", "Last seen"],
            rows,
        );
    }

    if !device.ports.is_empty() {
        println!();
        println!("ports:");
        let rows = device
            .ports
            .iter()
            .map(|port| {
                vec![
                    format!("{}/{}", port.protocol, port.port),
                    port.state.to_string(),
                    port.service.clone().unwrap_or_else(|| "—".to_string()),
                    port.version.clone().unwrap_or_else(|| "—".to_string()),
                    port.confidence.to_string(),
                ]
            })
            .collect();
        print_table(&["Port", "State", "Service", "Version", "Confidence"], rows);
    }

    if !device.services.is_empty() {
        println!();
        println!("services:");
        let rows = device
            .services
            .iter()
            .map(|service| {
                vec![
                    service.name.clone(),
                    service
                        .port
                        .map(|port| format!("{}/{}", service.protocol, port))
                        .unwrap_or_else(|| "—".to_string()),
                    service.version.clone().unwrap_or_else(|| "—".to_string()),
                    service.source.clone(),
                ]
            })
            .collect();
        print_table(&["Service", "Port", "Version", "Source"], rows);
    }

    if !device.evidence.is_empty() {
        println!();
        println!("evidence:");
        let rows = device
            .evidence
            .iter()
            .map(|evidence| {
                vec![
                    evidence.property.clone(),
                    evidence.value.clone(),
                    evidence.source.clone(),
                    evidence.confidence.to_string(),
                    evidence.kind.to_string(),
                    evidence.note.clone().unwrap_or_default(),
                ]
            })
            .collect();
        print_table(
            &["Property", "Value", "Source", "Confidence", "Kind", "Note"],
            rows,
        );
    }

    if !device.observations.is_empty() {
        println!();
        println!("observations (most recent first):");
        let rows = device
            .observations
            .iter()
            .take(50)
            .map(|observation| {
                vec![
                    observation
                        .observed_at
                        .format("%Y-%m-%d %H:%M:%S")
                        .to_string(),
                    observation.source.clone(),
                    observation
                        .ip
                        .map(|ip| ip.to_string())
                        .unwrap_or_else(|| "—".to_string()),
                    observation.mac.clone().unwrap_or_else(|| "—".to_string()),
                    observation
                        .hostname
                        .clone()
                        .unwrap_or_else(|| "—".to_string()),
                ]
            })
            .collect();
        print_table(&["Observed", "Source", "IP", "MAC", "Hostname"], rows);
    }
}

fn run_history(args: HistoryArgs, loaded: &LoadedConfig, format: OutputFormat) -> Result<()> {
    let database = open_database(loaded)?;
    let sessions = database.list_scan_sessions(args.limit)?;
    match format {
        OutputFormat::Json => print_json(&sessions)?,
        OutputFormat::Table => print_sessions_table(&sessions),
    }
    Ok(())
}

fn print_sessions_table(sessions: &[ScanSession]) {
    let rows = sessions
        .iter()
        .map(|session| {
            let providers = session
                .providers
                .iter()
                .map(|provider| format!("{}:{}", provider.name, provider.status))
                .collect::<Vec<_>>()
                .join(", ");
            vec![
                session
                    .id
                    .map(|id| id.to_string())
                    .unwrap_or_else(|| "-".to_string()),
                session.started_at.format("%Y-%m-%d %H:%M:%S").to_string(),
                session
                    .finished_at
                    .map(|finished| finished.format("%H:%M:%S").to_string())
                    .unwrap_or_else(|| "—".to_string()),
                session.interface.clone().unwrap_or_else(|| "—".to_string()),
                session.subnet.clone().unwrap_or_else(|| "—".to_string()),
                session.status.to_string(),
                session.device_count.to_string(),
                providers,
            ]
        })
        .collect();
    print_table(
        &[
            "ID",
            "Started",
            "Finished",
            "Interface",
            "Subnet",
            "Status",
            "Devices",
            "Providers",
        ],
        rows,
    );
}

fn run_changes(args: ChangesArgs, loaded: &LoadedConfig, format: OutputFormat) -> Result<()> {
    let database = open_database(loaded)?;
    let kind = match args.kind.as_deref() {
        Some(value) => Some(
            value
                .parse::<ChangeKind>()
                .map_err(FindaratError::Validation)?,
        ),
        None => None,
    };
    let mut changes = if let Some(target) = args.device.as_deref() {
        let device = database
            .find_device(target)?
            .ok_or_else(|| FindaratError::DeviceNotFound(target.to_string()))?;
        database.device_changes(
            device
                .id
                .ok_or_else(|| FindaratError::Database("device has no id".into()))?,
            None,
        )?
    } else {
        database.list_changes(None)?
    };
    if let Some(kind) = kind {
        changes.retain(|change| change.kind == kind);
    }
    if let Some(limit) = args.limit {
        changes.truncate(limit);
    }
    match format {
        OutputFormat::Json => print_json(&changes)?,
        OutputFormat::Table => print_changes_table(&changes),
    }
    Ok(())
}

fn print_changes_table(changes: &[crate::models::Change]) {
    let rows = changes
        .iter()
        .map(|change| {
            vec![
                change.detected_at.format("%Y-%m-%d %H:%M:%S").to_string(),
                change.kind.label().to_string(),
                change
                    .device_label
                    .clone()
                    .unwrap_or_else(|| change.device_id.to_string()),
                change.old_value.clone().unwrap_or_else(|| "—".to_string()),
                change.new_value.clone().unwrap_or_else(|| "—".to_string()),
            ]
        })
        .collect();
    print_table(&["When", "Change", "Device", "Old", "New"], rows);
}

fn run_export(args: ExportArgs, loaded: &LoadedConfig, format: OutputFormat) -> Result<()> {
    let export_format = match args.export_format.trim().to_ascii_lowercase().as_str() {
        "auto" => ExportFormat::from_path(&args.path),
        other => ExportFormat::parse(other)?,
    };
    let database = open_database(loaded)?;
    let report = io::export(export_format, &args.path, &database, args.force)?;
    match format {
        OutputFormat::Json => print_json(&serde_json::json!({
            "path": report.path.display().to_string(),
            "format": report.format.as_str(),
            "devices": report.devices,
            "sessions": report.sessions,
            "changes": report.changes,
            "bytes": report.bytes,
        }))?,
        OutputFormat::Table => println!(
            "exported {} device(s), {} session(s), {} change(s) to {} ({})",
            report.devices,
            report.sessions,
            report.changes,
            report.path.display(),
            report.format.as_str()
        ),
    }
    Ok(())
}

fn run_import(args: ImportArgs, loaded: &LoadedConfig, format: OutputFormat) -> Result<()> {
    let import_format = match args.import_format.trim().to_ascii_lowercase().as_str() {
        "auto" => ImportFormat::from_path(&args.path),
        other => ImportFormat::parse(other)?,
    };
    let mut database = open_database(loaded)?;
    let report = io::import(
        import_format,
        &args.path,
        &mut database,
        ImportOptions {
            dry_run: args.dry_run,
            merge: !args.no_merge,
        },
    )?;
    match format {
        OutputFormat::Json => print_json(&report)?,
        OutputFormat::Table => print_import_report(&report),
    }
    Ok(())
}

fn print_import_report(report: &ImportReport) {
    println!("{}", report.summary());
    if !report.outcomes.is_empty() {
        let rows = report
            .outcomes
            .iter()
            .map(|outcome| {
                vec![
                    outcome.action.as_str().to_string(),
                    outcome.label.clone(),
                    outcome
                        .device_id
                        .map(|id| id.to_string())
                        .unwrap_or_else(|| "—".to_string()),
                    outcome.matched_by.clone().unwrap_or_default(),
                ]
            })
            .collect();
        print_table(&["Action", "Device", "Local ID", "Matched by"], rows);
    }
    for warning in &report.warnings {
        eprintln!("warning: {warning}");
    }
}

fn run_interfaces(format: OutputFormat) -> Result<()> {
    let interfaces = list_interfaces();
    match format {
        OutputFormat::Json => print_json(&interfaces)?,
        OutputFormat::Table => {
            let rows = interfaces
                .iter()
                .map(|interface| {
                    vec![
                        interface.name.clone(),
                        interface.kind.label().to_string(),
                        interface.state.clone(),
                        if interface.up { "yes" } else { "no" }.to_string(),
                        interface
                            .ipv4
                            .first()
                            .map(|ip| match interface.subnet {
                                Some(subnet) => format!("{ip}/{}", subnet.prefix_len()),
                                None => ip.to_string(),
                            })
                            .unwrap_or_else(|| "—".to_string()),
                        interface.mac.clone().unwrap_or_else(|| "—".to_string()),
                        if interface.is_default { "yes" } else { "no" }.to_string(),
                    ]
                })
                .collect();
            print_table(
                &["Name", "Kind", "State", "Up", "IPv4", "MAC", "Default"],
                rows,
            );
        }
    }
    Ok(())
}

fn run_config(args: &ConfigArgs, cli: &Cli) -> Result<()> {
    let paths = config::ConfigPaths::resolve(cli.config.as_deref(), cli.database.as_deref());
    let command = args.command.as_ref().unwrap_or(&ConfigCommand::Show);
    match command {
        ConfigCommand::Init { force } => {
            LoadedConfig::write_default_template(&paths.config_file, *force)?;
            println!("wrote {}", paths.config_file.display());
        }
        ConfigCommand::Paths => {
            let value = serde_json::json!({
                "config_file": paths.config_file.display().to_string(),
                "data_dir": paths.data_dir.display().to_string(),
                "database": paths.database.display().to_string(),
            });
            match cli.format.map(OutputFormat::from) {
                Some(OutputFormat::Json) => print_json(&value)?,
                _ => {
                    println!("config file: {}", paths.config_file.display());
                    println!("data dir:    {}", paths.data_dir.display());
                    println!("database:    {}", paths.database.display());
                }
            }
        }
        ConfigCommand::Show => {
            let loaded = LoadedConfig::load(cli.config.as_deref(), cli.database.as_deref())?;
            match cli.format.map(OutputFormat::from) {
                Some(OutputFormat::Json) => print_json(&loaded.config)?,
                _ => {
                    print!("{}", config::render_effective(&loaded.config)?);
                    if let Some(source) = &loaded.source {
                        eprintln!("# source: {}", source.display());
                    } else {
                        eprintln!("# source: built-in defaults (no config file)");
                    }
                }
            }
        }
    }
    Ok(())
}

fn run_overview(loaded: &LoadedConfig, format: OutputFormat) -> Result<()> {
    let database = open_database(loaded)?;
    let total = database.count_devices()?;
    let active = database.count_active_devices()?;
    let sessions = database.list_scan_sessions(Some(1))?;
    let changes = database.list_changes(Some(5))?;
    let network = app::network_summary(&loaded.config)?;

    match format {
        OutputFormat::Json => print_json(&serde_json::json!({
            "version": crate::VERSION,
            "network": &network,
            "database": loaded.database_path().display().to_string(),
            "devices": { "total": total, "active": active },
            "last_scan": sessions.first(),
            "recent_changes": &changes,
        }))?,
        OutputFormat::Table => {
            println!("findarat {}", crate::VERSION);
            println!("network:  {}", network.summary());
            println!("database: {}", loaded.database_path().display());
            println!("devices:  {total} total, {active} active");
            match sessions.first() {
                Some(session) => println!(
                    "last scan: #{} {} | {} device(s) | {}",
                    session
                        .id
                        .map(|id| id.to_string())
                        .unwrap_or_else(|| "-".to_string()),
                    session.started_at.format("%Y-%m-%d %H:%M"),
                    session.device_count,
                    session.status
                ),
                None => println!("last scan: none"),
            }
            if !changes.is_empty() {
                println!();
                println!("recent changes:");
                print_changes_table(&changes);
            }
            if let Some(source) = &loaded.source {
                println!();
                println!("config:   {}", source.display());
            }
        }
    }
    Ok(())
}

fn device_matches(device: &Device, needle: &str) -> bool {
    let fields = [
        device.display_name(),
        device.last_ip.map(|ip| ip.to_string()).unwrap_or_default(),
        device.mac.clone().unwrap_or_default(),
        device.hostname.clone().unwrap_or_default(),
        device.vendor.clone().unwrap_or_default(),
        device.os.clone().unwrap_or_default(),
        device.device_type.as_str().to_string(),
        device.interface.clone().unwrap_or_default(),
    ];
    fields
        .iter()
        .any(|field| field.to_ascii_lowercase().contains(needle))
}

fn sort_devices(devices: &mut [Device], field: &str) -> Result<()> {
    match field.trim().to_ascii_lowercase().as_str() {
        "last_seen" | "last-seen" => {
            devices.sort_by_key(|device| std::cmp::Reverse(device.last_seen))
        }
        "first_seen" | "first-seen" => devices.sort_by_key(|device| device.first_seen),
        "ip" => devices.sort_by_key(|device| device.last_ip),
        "name" => devices.sort_by_key(|device| device.display_name().to_ascii_lowercase()),
        "type" => devices.sort_by_key(|device| device.device_type.as_str()),
        "vendor" => devices.sort_by_key(|device| {
            device
                .vendor
                .as_deref()
                .unwrap_or("")
                .to_ascii_lowercase()
        }),
        "id" => devices.sort_by_key(|device| device.id),
        other => {
            return Err(FindaratError::Validation(format!(
                "invalid sort field {other:?}; expected last_seen, first_seen, ip, name, type, vendor, or id"
            ))
            .into())
        }
    }
    Ok(())
}

fn print_json<T: serde::Serialize>(value: &T) -> Result<()> {
    let text = serde_json::to_string_pretty(value).context("failed to serialize JSON output")?;
    println!("{text}");
    Ok(())
}

fn print_table(headers: &[&str], rows: Vec<Vec<String>>) {
    let mut widths: Vec<usize> = headers
        .iter()
        .map(|header| header.chars().count())
        .collect();
    for row in &rows {
        for (index, cell) in row.iter().enumerate() {
            if index >= widths.len() {
                widths.push(0);
            }
            widths[index] = widths[index].max(cell.chars().count());
        }
    }
    print_row(
        &headers
            .iter()
            .map(|header| header.to_string())
            .collect::<Vec<_>>(),
        &widths,
    );
    let separator: Vec<String> = widths.iter().map(|width| "-".repeat(*width)).collect();
    print_row(&separator, &widths);
    for row in rows {
        print_row(&row, &widths);
    }
}

fn print_row(cells: &[String], widths: &[usize]) {
    let mut line = String::new();
    for (index, cell) in cells.iter().enumerate() {
        if index > 0 {
            line.push_str("  ");
        }
        let width = widths.get(index).copied().unwrap_or(0);
        line.push_str(cell);
        line.push_str(&" ".repeat(width.saturating_sub(cell.chars().count())));
    }
    println!("{}", line.trim_end());
}

/// Path helper used by tests and future shell completion.
pub fn config_path(cli: &Cli) -> PathBuf {
    config::ConfigPaths::resolve(cli.config.as_deref(), cli.database.as_deref()).config_file
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use clap::CommandFactory;

    fn device(ip: &str, hostname: &str, device_type: crate::models::DeviceType) -> Device {
        let now = Utc::now();
        let mut device = Device::new(now, now);
        device.id = Some(1);
        device.last_ip = Some(ip.parse().unwrap());
        device.hostname = Some(hostname.to_string());
        device.device_type = device_type;
        device
    }

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn parses_scan_flags() {
        let cli = Cli::try_parse_from([
            "findarat",
            "scan",
            "--interface",
            "wlan0",
            "--no-mdns",
            "--no-tcp",
            "--ports",
            "22,80",
        ])
        .unwrap_err();
        assert!(cli.to_string().contains("cannot be used with"));
        let cli = Cli::try_parse_from([
            "findarat",
            "scan",
            "--interface",
            "wlan0",
            "--no-mdns",
            "--ports",
            "22,80",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Scan(args)) => {
                assert_eq!(args.interface.as_deref(), Some("wlan0"));
                assert!(args.no_mdns);
                assert_eq!(args.ports.as_deref(), Some("22,80"));
            }
            _ => panic!("expected scan command"),
        }
    }

    #[test]
    fn default_command_is_none_and_maps_to_overview() {
        let cli = Cli::try_parse_from(["findarat"]).unwrap();
        assert!(cli.command.is_none());
    }

    #[test]
    fn sorts_devices_by_name_and_ip() {
        let mut devices = vec![
            device("192.168.1.20", "beta", crate::models::DeviceType::Laptop),
            device("192.168.1.10", "alpha", crate::models::DeviceType::Printer),
        ];
        sort_devices(&mut devices, "name").unwrap();
        assert_eq!(devices[0].hostname.as_deref(), Some("alpha"));
        sort_devices(&mut devices, "ip").unwrap();
        assert_eq!(devices[0].last_ip.unwrap().to_string(), "192.168.1.10");
        assert!(sort_devices(&mut devices, "nope").is_err());
    }

    #[test]
    fn search_matches_multiple_fields() {
        let device = device("192.168.1.10", "alpha", crate::models::DeviceType::Printer);
        assert!(device_matches(&device, "alpha"));
        assert!(device_matches(&device, "192.168"));
        assert!(device_matches(&device, "printer"));
        assert!(!device_matches(&device, "beta"));
    }

    #[test]
    fn table_rows_are_rendered_without_panicking() {
        print_table(
            &["A", "B"],
            vec![vec!["one".to_string(), "two".to_string()]],
        );
    }

    #[test]
    fn config_path_is_absolute() {
        let cli = Cli::try_parse_from(["findarat", "config", "paths"]).unwrap();
        assert!(config_path(&cli).is_absolute());
    }
}
