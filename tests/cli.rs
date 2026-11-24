//! End-to-end CLI tests. These exercise the real binary with isolated XDG
//! directories and a temporary SQLite inventory.

use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_findarat")
}

fn command(directory: &Path) -> Command {
    let mut command = Command::new(binary());
    command
        .env("XDG_CONFIG_HOME", directory.join("config"))
        .env("XDG_DATA_HOME", directory.join("data"))
        .env("RUST_LOG", "off");
    command
}

fn run(directory: &Path, args: &[&str]) -> Output {
    command(directory)
        .args(args)
        .output()
        .expect("failed to run findarat")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

fn database(directory: &Path) -> PathBuf {
    directory.join("inventory.db")
}

fn write_devices(directory: &Path) -> PathBuf {
    let path = directory.join("devices.json");
    fs::write(
        &path,
        r#"[
            {
                "last_ip": "192.168.1.10",
                "mac": "AA:BB:CC:DD:EE:01",
                "hostname": "alpha",
                "vendor": "Example Vendor",
                "device_type": "printer",
                "first_seen": "2026-01-01T00:00:00Z",
                "last_seen": "2026-01-02T00:00:00Z",
                "active": true
            }
        ]"#,
    )
    .expect("failed to write fixture");
    path
}

#[test]
fn help_and_version_work() {
    let directory = TempDir::new().unwrap();
    let output = run(directory.path(), &["--help"]);
    assert!(output.status.success());
    assert!(stdout(&output).contains("scan"));
    assert!(stdout(&output).contains("tui"));

    let output = run(directory.path(), &["--version"]);
    assert!(output.status.success());
    assert!(stdout(&output).contains("findarat"));
}

#[test]
fn overview_and_interfaces_emit_json() {
    let directory = TempDir::new().unwrap();
    let db = database(directory.path());
    let output = run(
        directory.path(),
        &[
            "--database",
            db.to_str().unwrap(),
            "--format",
            "json",
            "overview",
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    let value: Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(value["devices"]["total"], 0);
    assert!(value["database"]
        .as_str()
        .unwrap()
        .ends_with("inventory.db"));

    let output = run(
        directory.path(),
        &[
            "--database",
            db.to_str().unwrap(),
            "--format",
            "json",
            "interfaces",
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    let value: Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert!(value
        .as_array()
        .unwrap()
        .iter()
        .any(|interface| { interface["name"].as_str() == Some("lo") }));
}

#[test]
fn import_list_export_and_reimport() {
    let directory = TempDir::new().unwrap();
    let db = database(directory.path());
    let fixture = write_devices(directory.path());
    let fixture = fixture.to_str().unwrap();

    let output = run(
        directory.path(),
        &[
            "--database",
            db.to_str().unwrap(),
            "import",
            fixture,
            "--import-format",
            "json",
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stdout(&output).contains("imported"));

    let output = run(
        directory.path(),
        &[
            "--database",
            db.to_str().unwrap(),
            "--format",
            "json",
            "devices",
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    let devices: Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(devices.as_array().unwrap().len(), 1);
    assert_eq!(devices[0]["hostname"], "alpha");

    let export = directory.path().join("export.json");
    let output = run(
        directory.path(),
        &[
            "--database",
            db.to_str().unwrap(),
            "export",
            export.to_str().unwrap(),
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(export.exists());
    let envelope: Value = serde_json::from_str(&fs::read_to_string(&export).unwrap()).unwrap();
    assert_eq!(envelope["schema_version"], 2);
    assert_eq!(envelope["devices"].as_array().unwrap().len(), 1);

    let second = directory.path().join("second.db");
    let output = run(
        directory.path(),
        &[
            "--database",
            second.to_str().unwrap(),
            "import",
            export.to_str().unwrap(),
            "--import-format",
            "json",
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    let output = run(
        directory.path(),
        &[
            "--database",
            second.to_str().unwrap(),
            "--format",
            "json",
            "devices",
        ],
    );
    let devices: Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(devices.as_array().unwrap().len(), 1);
}

#[test]
fn dry_run_import_does_not_create_the_database() {
    let directory = TempDir::new().unwrap();
    let db = database(directory.path());
    let fixture = write_devices(directory.path());
    let output = run(
        directory.path(),
        &[
            "--database",
            db.to_str().unwrap(),
            "import",
            fixture.to_str().unwrap(),
            "--import-format",
            "json",
            "--dry-run",
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stdout(&output).contains("would import"));
    assert!(
        !db.exists(),
        "dry-run import created a database at {}",
        db.display()
    );

    let output = run(
        directory.path(),
        &[
            "--database",
            db.to_str().unwrap(),
            "--format",
            "json",
            "devices",
        ],
    );
    let devices: Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert!(devices.as_array().unwrap().is_empty());
}

#[test]
fn dry_run_import_does_not_modify_an_existing_database() {
    let directory = TempDir::new().unwrap();
    let db = database(directory.path());
    let fixture = write_devices(directory.path());

    let output = run(
        directory.path(),
        &[
            "--database",
            db.to_str().unwrap(),
            "import",
            fixture.to_str().unwrap(),
            "--import-format",
            "json",
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    let before = fs::read(&db).unwrap();

    let output = run(
        directory.path(),
        &[
            "--database",
            db.to_str().unwrap(),
            "import",
            fixture.to_str().unwrap(),
            "--import-format",
            "json",
            "--dry-run",
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(fs::read(&db).unwrap(), before);
}

#[test]
fn config_paths_uses_the_configured_database() {
    let directory = TempDir::new().unwrap();
    let config = directory.path().join("config.toml");
    fs::write(&config, "[storage]\ndatabase = \"custom.db\"\n").unwrap();

    let output = run(
        directory.path(),
        &[
            "--config",
            config.to_str().unwrap(),
            "--format",
            "json",
            "config",
            "paths",
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    let value: Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(
        value["database"].as_str().unwrap(),
        directory.path().join("custom.db").to_str().unwrap()
    );
}

#[test]
fn config_show_and_paths_honor_default_output() {
    let directory = TempDir::new().unwrap();
    let config = directory.path().join("config.toml");
    fs::write(&config, "[general]\ndefault_output = \"json\"\n").unwrap();

    let output = run(
        directory.path(),
        &["--config", config.to_str().unwrap(), "config", "show"],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    let value: Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(value["general"]["default_output"], "json");

    let output = run(
        directory.path(),
        &["--config", config.to_str().unwrap(), "config", "paths"],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    let value: Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert!(value["database"].is_string());
}

#[test]
fn missing_device_uses_documented_exit_code() {
    let directory = TempDir::new().unwrap();
    let db = database(directory.path());
    let output = run(
        directory.path(),
        &[
            "--database",
            db.to_str().unwrap(),
            "device",
            "does-not-exist",
        ],
    );
    assert_eq!(output.status.code(), Some(3));
    assert!(stderr(&output).contains("device not found"));
}

#[test]
fn invalid_sort_is_a_validation_error() {
    let directory = TempDir::new().unwrap();
    let db = database(directory.path());
    let output = run(
        directory.path(),
        &[
            "--database",
            db.to_str().unwrap(),
            "devices",
            "--sort",
            "nonsense",
        ],
    );
    assert_eq!(output.status.code(), Some(4));
    assert!(stderr(&output).contains("invalid sort field"));
}

#[test]
fn config_init_refuses_to_overwrite_without_force() {
    let directory = TempDir::new().unwrap();
    let config = directory.path().join("config.toml");
    let output = run(
        directory.path(),
        &["--config", config.to_str().unwrap(), "config", "init"],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(config.exists());

    let output = run(
        directory.path(),
        &["--config", config.to_str().unwrap(), "config", "init"],
    );
    assert_eq!(output.status.code(), Some(4));
    assert!(stderr(&output).contains("already exists"));

    let output = run(
        directory.path(),
        &[
            "--config",
            config.to_str().unwrap(),
            "config",
            "init",
            "--force",
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
}

#[test]
fn config_show_reads_the_written_template() {
    let directory = TempDir::new().unwrap();
    let config = directory.path().join("config.toml");
    let output = run(
        directory.path(),
        &["--config", config.to_str().unwrap(), "config", "init"],
    );
    assert!(output.status.success());
    let output = run(
        directory.path(),
        &["--config", config.to_str().unwrap(), "config", "show"],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stdout(&output).contains("[discovery]"));
}

#[test]
fn changes_filters_are_validated() {
    let directory = TempDir::new().unwrap();
    let db = database(directory.path());
    let output = run(
        directory.path(),
        &[
            "--database",
            db.to_str().unwrap(),
            "changes",
            "--kind",
            "not-a-change",
        ],
    );
    assert_eq!(output.status.code(), Some(4));
    assert!(stderr(&output).contains("invalid change kind"));
}

#[test]
fn annotations_explain_timeline_and_filters_work() {
    let directory = TempDir::new().unwrap();
    let db = database(directory.path());
    let db = db.to_str().unwrap();
    let fixture = write_devices(directory.path());
    let fixture = fixture.to_str().unwrap();
    let output = run(
        directory.path(),
        &[
            "--database",
            db,
            "import",
            fixture,
            "--import-format",
            "json",
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));

    let output = run(
        directory.path(),
        &[
            "--database",
            db,
            "annotate",
            "alpha",
            "--name",
            "Office Printer",
            "--notes",
            "second floor",
            "--tag",
            "Office",
            "--tag",
            "Printer",
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stdout(&output).contains("Office Printer"));
    assert!(stdout(&output).contains("office, printer"));

    let output = run(
        directory.path(),
        &[
            "--database",
            db,
            "--format",
            "json",
            "devices",
            "--tag",
            "OFFICE",
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    let devices: Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(devices.as_array().unwrap().len(), 1);
    assert_eq!(devices[0]["label"], "Office Printer");

    let output = run(
        directory.path(),
        &[
            "--database",
            db,
            "annotate",
            "alpha",
            "--ignore",
            "--untag",
            "office",
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stdout(&output).contains("ignored: true"));

    let output = run(
        directory.path(),
        &[
            "--database",
            db,
            "--format",
            "json",
            "devices",
            "--exclude-ignored",
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    let devices: Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert!(devices.as_array().unwrap().is_empty());

    let output = run(
        directory.path(),
        &["--database", db, "--format", "json", "explain", "alpha"],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    let explanation: Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(explanation["label"], "Office Printer");
    assert!(explanation["ignored"].as_bool().unwrap());
    assert!(explanation["properties"].as_array().is_some());

    let output = run(
        directory.path(),
        &["--database", db, "--format", "json", "timeline", "alpha"],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    let timeline: Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert!(timeline["events"].as_array().is_some());
    assert!(timeline["observation_count"].as_u64().is_some());
    assert_eq!(timeline["name"], "Office Printer");

    let output = run(
        directory.path(),
        &["--database", db, "annotate", "alpha", "--clear"],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    let output = run(
        directory.path(),
        &["--database", db, "--format", "json", "devices"],
    );
    let devices: Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert!(devices[0]["label"].is_null());
    assert!(devices[0].get("tags").is_none());
    assert!(devices[0].get("ignored").is_none());
}

#[test]
fn nmap_and_arpscan_imports_work() {
    let directory = TempDir::new().unwrap();
    let db = database(directory.path());
    let db = db.to_str().unwrap();

    let xml = directory.path().join("scan.xml");
    fs::write(
        &xml,
        r#"<?xml version="1.0"?>
<nmaprun start="1700000000">
  <host>
    <status state="up"/>
    <address addr="192.168.1.20" addrtype="ipv4"/>
    <address addr="AA:BB:CC:DD:EE:20" addrtype="mac" vendor="Example Vendor"/>
    <hostname name="printer.local"/>
    <ports>
      <port protocol="tcp" portid="631">
        <state state="open"/>
        <service name="ipp" product="CUPS" version="2.4" devicetype="printer"/>
      </port>
    </ports>
    <os><osmatch name="Linux 5.0"/></os>
  </host>
</nmaprun>
"#,
    )
    .unwrap();
    let output = run(
        directory.path(),
        &[
            "--database",
            db,
            "--format",
            "json",
            "import",
            xml.to_str().unwrap(),
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    let report: Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(report["format"], "nmap");

    let arp = directory.path().join("scan.arp");
    fs::write(&arp, "192.168.1.30\taa:bb:cc:dd:ee:30\tExample Vendor\n").unwrap();
    let output = run(
        directory.path(),
        &[
            "--database",
            db,
            "--format",
            "json",
            "import",
            arp.to_str().unwrap(),
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    let report: Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(report["format"], "arp-scan");

    let output = run(
        directory.path(),
        &["--database", db, "--format", "json", "devices"],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    let devices: Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(devices.as_array().unwrap().len(), 2);
}

#[test]
fn annotate_rejects_conflicting_flags() {
    let directory = TempDir::new().unwrap();
    let db = database(directory.path());
    let db = db.to_str().unwrap();
    let fixture = write_devices(directory.path());
    let fixture = fixture.to_str().unwrap();
    let output = run(
        directory.path(),
        &[
            "--database",
            db,
            "import",
            fixture,
            "--import-format",
            "json",
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));

    let output = run(
        directory.path(),
        &["--database", db, "annotate", "alpha", "--clear", "--ignore"],
    );
    assert_eq!(output.status.code(), Some(4));
    assert!(stderr(&output).contains("--clear"));

    let output = run(
        directory.path(),
        &[
            "--database",
            db,
            "annotate",
            "alpha",
            "--name",
            "x",
            "--clear-name",
        ],
    );
    assert_eq!(output.status.code(), Some(4));
}
