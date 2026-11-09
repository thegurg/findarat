//! Terminal user interface.
//!
//! The TUI is deliberately thin: it uses the same [`crate::app::ScanRequest`]
//! and [`crate::inventory::Database`] as the CLI. Scans run in a background
//! Tokio task and report progress through a channel, so the interface stays
//! responsive.

use anyhow::{Context, Result};
use chrono::Utc;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Cell, Gauge, Paragraph, Row, Table, Tabs, Wrap};
use ratatui::{DefaultTerminal, Frame};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::app::{self, ScanEvent, ScanRequest};
use crate::config::Config;
use crate::inventory::Database;
use crate::io::{self, ExportFormat, ImportFormat, ImportOptions};
use crate::models::{Change, Device, ProviderReport, ScanSession};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Screen {
    Dashboard,
    Devices,
    Details,
    Scan,
    History,
    ImportExport,
    Settings,
    Help,
}

impl Screen {
    const ALL: [Screen; 8] = [
        Screen::Dashboard,
        Screen::Devices,
        Screen::Details,
        Screen::Scan,
        Screen::History,
        Screen::ImportExport,
        Screen::Settings,
        Screen::Help,
    ];

    fn index(self) -> usize {
        Self::ALL
            .iter()
            .position(|screen| *screen == self)
            .unwrap_or(0)
    }

    fn label(self) -> &'static str {
        match self {
            Self::Dashboard => "Dashboard",
            Self::Devices => "Devices",
            Self::Details => "Details",
            Self::Scan => "Scan",
            Self::History => "History",
            Self::ImportExport => "Import/Export",
            Self::Settings => "Settings",
            Self::Help => "Help",
        }
    }

    fn next(self) -> Self {
        let index = (self.index() + 1) % Self::ALL.len();
        Self::ALL[index]
    }

    fn previous(self) -> Self {
        let index = (self.index() + Self::ALL.len() - 1) % Self::ALL.len();
        Self::ALL[index]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SortMode {
    LastSeen,
    Name,
    Ip,
    Type,
    Vendor,
}

impl SortMode {
    fn next(self) -> Self {
        match self {
            Self::LastSeen => Self::Name,
            Self::Name => Self::Ip,
            Self::Ip => Self::Type,
            Self::Type => Self::Vendor,
            Self::Vendor => Self::LastSeen,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::LastSeen => "last seen",
            Self::Name => "name",
            Self::Ip => "IP",
            Self::Type => "type",
            Self::Vendor => "vendor",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ScanState {
    Idle,
    Running,
    Completed,
    Failed(String),
}

impl ScanState {
    fn label(&self) -> String {
        match self {
            Self::Idle => "idle".to_string(),
            Self::Running => "running".to_string(),
            Self::Completed => "completed".to_string(),
            Self::Failed(error) => format!("failed: {error}"),
        }
    }
}

struct TuiApp {
    config: Config,
    database: Database,
    database_path: PathBuf,
    screen: Screen,
    devices: Vec<Device>,
    selected: usize,
    search: String,
    search_mode: bool,
    sort: SortMode,
    changes: Vec<Change>,
    sessions: Vec<ScanSession>,
    network_summary: String,
    scan_state: ScanState,
    scan_progress: Option<(usize, usize)>,
    scan_reports: Vec<ProviderReport>,
    scan_result: Option<String>,
    scan_rx: Option<mpsc::UnboundedReceiver<ScanEvent>>,
    scan_task: Option<JoinHandle<()>>,
    status: String,
    io_path: String,
    path_input_mode: bool,
    import_dry_run: bool,
    details_scroll: u16,
    history_scroll: u16,
    settings_scroll: u16,
    help_scroll: u16,
    settings_text: String,
    should_quit: bool,
}

impl TuiApp {
    fn new(config: Config, database_path: PathBuf) -> Result<Self> {
        let database = Database::open(&database_path)?;
        Self::with_database(config, database, database_path)
    }

    fn with_database(config: Config, database: Database, database_path: PathBuf) -> Result<Self> {
        let network_summary = match app::network_summary(&config) {
            Ok(context) => context.summary(),
            Err(error) => format!("unavailable ({error:#})"),
        };
        let settings_text = crate::config::render_effective(&config)
            .unwrap_or_else(|error| format!("failed to render configuration: {error:#}"));
        let io_path = database_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(format!(
                "findarat-export-{}.json",
                Utc::now().format("%Y%m%d-%H%M%S")
            ))
            .display()
            .to_string();
        let mut app = Self {
            config,
            database,
            database_path,
            screen: Screen::Dashboard,
            devices: Vec::new(),
            selected: 0,
            search: String::new(),
            search_mode: false,
            sort: SortMode::LastSeen,
            changes: Vec::new(),
            sessions: Vec::new(),
            network_summary,
            scan_state: ScanState::Idle,
            scan_progress: None,
            scan_reports: Vec::new(),
            scan_result: None,
            scan_rx: None,
            scan_task: None,
            status: "ready — press ? for help".to_string(),
            io_path,
            path_input_mode: false,
            import_dry_run: false,
            details_scroll: 0,
            history_scroll: 0,
            settings_scroll: 0,
            help_scroll: 0,
            settings_text,
            should_quit: false,
        };
        app.refresh_all()?;
        Ok(app)
    }

    fn refresh_all(&mut self) -> Result<()> {
        self.devices = self.database.list_devices()?;
        self.changes = self.database.list_changes(Some(200))?;
        self.sessions = self.database.list_scan_sessions(Some(100))?;
        self.clamp_selection();
        Ok(())
    }

    fn filtered_indices(&self) -> Vec<usize> {
        let needle = self.search.to_ascii_lowercase();
        let mut indices: Vec<usize> = self
            .devices
            .iter()
            .enumerate()
            .filter(|(_, device)| needle.is_empty() || device_matches(device, &needle))
            .map(|(index, _)| index)
            .collect();
        match self.sort {
            SortMode::LastSeen => {
                indices.sort_by(|left, right| {
                    self.devices[*right]
                        .last_seen
                        .cmp(&self.devices[*left].last_seen)
                });
            }
            SortMode::Name => {
                indices
                    .sort_by_key(|index| self.devices[*index].display_name().to_ascii_lowercase());
            }
            SortMode::Ip => {
                indices.sort_by_key(|index| self.devices[*index].last_ip);
            }
            SortMode::Type => {
                indices.sort_by_key(|index| self.devices[*index].device_type.as_str());
            }
            SortMode::Vendor => {
                indices.sort_by_key(|index| {
                    self.devices[*index]
                        .vendor
                        .as_deref()
                        .unwrap_or("")
                        .to_ascii_lowercase()
                });
            }
        }
        indices
    }

    fn selected_device(&self) -> Option<&Device> {
        self.filtered_indices()
            .get(self.selected)
            .and_then(|index| self.devices.get(*index))
    }

    fn clamp_selection(&mut self) {
        let count = self.filtered_indices().len();
        if count == 0 {
            self.selected = 0;
        } else if self.selected >= count {
            self.selected = count - 1;
        }
    }

    fn move_selection(&mut self, delta: isize) {
        let count = self.filtered_indices().len();
        if count == 0 {
            self.selected = 0;
            return;
        }
        let next = self.selected as isize + delta;
        self.selected = next.clamp(0, count as isize - 1) as usize;
    }

    fn handle_key(&mut self, key: KeyEvent) {
        if key.kind != KeyEventKind::Press {
            return;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && matches!(key.code, KeyCode::Char('c')) {
            self.should_quit = true;
            return;
        }

        if self.search_mode {
            self.handle_search_key(key);
            return;
        }
        if self.path_input_mode {
            self.handle_path_key(key);
            return;
        }

        match key.code {
            KeyCode::Char('q') => {
                self.should_quit = true;
                return;
            }
            KeyCode::Tab => {
                self.screen = self.screen.next();
                return;
            }
            KeyCode::BackTab => {
                self.screen = self.screen.previous();
                return;
            }
            KeyCode::Char(character @ '1'..='8') => {
                if let Some(index) = character.to_digit(10) {
                    if let Some(screen) = Screen::ALL.get(index as usize - 1) {
                        self.screen = *screen;
                    }
                }
                return;
            }
            KeyCode::Char('?') => {
                self.screen = Screen::Help;
                return;
            }
            _ => {}
        }

        match self.screen {
            Screen::Devices => self.handle_devices_key(key),
            Screen::Details => self.handle_details_key(key),
            Screen::Scan => self.handle_scan_key(key),
            Screen::History => self.handle_history_key(key),
            Screen::ImportExport => self.handle_io_key(key),
            Screen::Settings => self.handle_settings_key(key),
            Screen::Help => self.handle_help_key(key),
            Screen::Dashboard => {
                if matches!(key.code, KeyCode::Char('r')) {
                    self.reload();
                }
            }
        }
    }

    fn handle_search_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc | KeyCode::Enter => {
                self.search_mode = false;
                self.clamp_selection();
            }
            KeyCode::Backspace => {
                self.search.pop();
                self.clamp_selection();
            }
            KeyCode::Up => self.move_selection(-1),
            KeyCode::Down => self.move_selection(1),
            KeyCode::Char(character) => {
                self.search.push(character);
                self.clamp_selection();
            }
            _ => {}
        }
    }

    fn handle_path_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => self.path_input_mode = false,
            KeyCode::Enter => {
                self.path_input_mode = false;
                self.status = format!("path set: {}", self.io_path);
            }
            KeyCode::Backspace => {
                self.io_path.pop();
            }
            KeyCode::Char(character) => self.io_path.push(character),
            _ => {}
        }
    }

    fn handle_devices_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up => self.move_selection(-1),
            KeyCode::Down => self.move_selection(1),
            KeyCode::PageUp => self.move_selection(-10),
            KeyCode::PageDown => self.move_selection(10),
            KeyCode::Enter => {
                if self.selected_device().is_some() {
                    self.details_scroll = 0;
                    self.screen = Screen::Details;
                }
            }
            KeyCode::Char('/') => {
                self.search_mode = true;
                self.status = "search: type to filter, Enter/Esc to finish".to_string();
            }
            KeyCode::Char('s') => {
                self.sort = self.sort.next();
                self.status = format!("sorted by {}", self.sort.label());
                self.clamp_selection();
            }
            KeyCode::Char('r') => self.reload(),
            _ => {}
        }
    }

    fn handle_details_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc | KeyCode::Backspace => self.screen = Screen::Devices,
            KeyCode::Up => self.details_scroll = self.details_scroll.saturating_sub(1),
            KeyCode::Down => self.details_scroll = self.details_scroll.saturating_add(1),
            KeyCode::PageUp => self.details_scroll = self.details_scroll.saturating_sub(10),
            KeyCode::PageDown => self.details_scroll = self.details_scroll.saturating_add(10),
            _ => {}
        }
    }

    fn handle_scan_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Enter | KeyCode::Char('s') => self.start_scan(),
            KeyCode::Char('r') => self.reload(),
            _ => {}
        }
    }

    fn handle_history_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up => self.history_scroll = self.history_scroll.saturating_sub(1),
            KeyCode::Down => self.history_scroll = self.history_scroll.saturating_add(1),
            KeyCode::PageUp => self.history_scroll = self.history_scroll.saturating_sub(10),
            KeyCode::PageDown => self.history_scroll = self.history_scroll.saturating_add(10),
            KeyCode::Char('r') => self.reload(),
            _ => {}
        }
    }

    fn handle_io_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('p') => {
                self.path_input_mode = true;
                self.status = "edit path, Enter to save, Esc to cancel".to_string();
            }
            KeyCode::Char('e') => self.export_to_path(),
            KeyCode::Char('i') => self.import_from_path(),
            KeyCode::Char('x') => {
                self.import_dry_run = !self.import_dry_run;
                self.status = format!(
                    "import dry-run {}",
                    if self.import_dry_run { "on" } else { "off" }
                );
            }
            KeyCode::Char('r') => self.reload(),
            _ => {}
        }
    }

    fn handle_settings_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up => self.settings_scroll = self.settings_scroll.saturating_sub(1),
            KeyCode::Down => self.settings_scroll = self.settings_scroll.saturating_add(1),
            KeyCode::PageUp => self.settings_scroll = self.settings_scroll.saturating_sub(10),
            KeyCode::PageDown => self.settings_scroll = self.settings_scroll.saturating_add(10),
            KeyCode::Char('r') => {
                self.settings_text = crate::config::render_effective(&self.config)
                    .unwrap_or_else(|error| format!("failed to render configuration: {error:#}"));
            }
            _ => {}
        }
    }

    fn handle_help_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up => self.help_scroll = self.help_scroll.saturating_sub(1),
            KeyCode::Down => self.help_scroll = self.help_scroll.saturating_add(1),
            KeyCode::PageUp => self.help_scroll = self.help_scroll.saturating_sub(10),
            KeyCode::PageDown => self.help_scroll = self.help_scroll.saturating_add(10),
            KeyCode::Esc => self.screen = Screen::Dashboard,
            _ => {}
        }
    }

    fn reload(&mut self) {
        match self.refresh_all() {
            Ok(()) => self.status = "inventory reloaded".to_string(),
            Err(error) => self.status = format!("reload failed: {error:#}"),
        }
    }

    fn start_scan(&mut self) {
        if matches!(self.scan_state, ScanState::Running) {
            self.status = "a scan is already running".to_string();
            return;
        }
        let request = match ScanRequest::from_config(&self.config) {
            Ok(request) => request,
            Err(error) => {
                self.scan_state = ScanState::Failed(format!("{error:#}"));
                self.status = format!("scan configuration error: {error:#}");
                return;
            }
        };
        let path = self.database_path.clone();
        let (sender, receiver) = mpsc::unbounded_channel();
        self.scan_rx = Some(receiver);
        self.scan_state = ScanState::Running;
        self.scan_progress = None;
        self.scan_reports.clear();
        self.scan_result = None;
        self.status = "scan started".to_string();
        self.scan_task = Some(tokio::spawn(async move {
            let result = async {
                let mut database = Database::open(&path)?;
                app::run_scan(&request, &mut database, Some(sender.clone())).await
            }
            .await;
            if let Err(error) = result {
                let _ = sender.send(ScanEvent::Failed(format!("{error:#}")));
            }
        }));
    }

    fn drain_scan_events(&mut self) {
        let mut finished = false;
        let mut events = Vec::new();
        if let Some(receiver) = &mut self.scan_rx {
            while let Ok(event) = receiver.try_recv() {
                events.push(event);
            }
        }
        for event in events {
            match event {
                ScanEvent::Stage(stage) => self.status = stage,
                ScanEvent::Provider(report) => self.scan_reports.push(report),
                ScanEvent::HostsDiscovered(count) => {
                    self.status = format!("{count} host(s) discovered");
                }
                ScanEvent::PortScan(progress) => self.apply_progress(progress),
                ScanEvent::Persisted { devices, changes } => {
                    self.status = format!("saved {devices} device(s), {changes} change(s)");
                }
                ScanEvent::Finished {
                    devices,
                    open_ports,
                    changes,
                } => {
                    self.scan_state = ScanState::Completed;
                    self.scan_result = Some(format!(
                        "{devices} device(s), {open_ports} open port(s), {changes} change(s)"
                    ));
                    self.status =
                        format!("scan complete: {devices} device(s), {open_ports} open port(s)");
                    finished = true;
                }
                ScanEvent::Failed(error) => {
                    self.scan_state = ScanState::Failed(error.clone());
                    self.status = format!("scan failed: {error}");
                    finished = true;
                }
            }
        }
        if finished {
            self.scan_rx = None;
            self.scan_task = None;
            if let Err(error) = self.refresh_all() {
                self.status = format!("scan finished but reload failed: {error:#}");
            }
        }
    }

    fn apply_progress(&mut self, progress: crate::scanner::ScanProgress) {
        use crate::scanner::ScanProgress;
        match progress {
            ScanProgress::Started { total } => self.scan_progress = Some((0, total)),
            ScanProgress::Progress {
                completed,
                total,
                open_ports,
            } => {
                self.scan_progress = Some((completed, total));
                self.status = format!("port scan: {completed}/{total} probes, {open_ports} open");
            }
            ScanProgress::Finished { total, open_ports } => {
                self.scan_progress = Some((total, total));
                self.status = format!("port scan finished: {open_ports} open port(s)");
            }
        }
    }

    fn export_to_path(&mut self) {
        let path = PathBuf::from(self.io_path.trim());
        if path.as_os_str().is_empty() {
            self.status = "export path is empty".to_string();
            return;
        }
        let format = ExportFormat::from_path(&path);
        match io::export(format, &path, &self.database, true) {
            Ok(report) => {
                self.status = format!(
                    "exported {} device(s) to {} ({})",
                    report.devices,
                    report.path.display(),
                    report.format.as_str()
                );
            }
            Err(error) => self.status = format!("export failed: {error:#}"),
        }
    }

    fn import_from_path(&mut self) {
        let path = PathBuf::from(self.io_path.trim());
        if path.as_os_str().is_empty() {
            self.status = "import path is empty".to_string();
            return;
        }
        let format = ImportFormat::from_path(&path);
        match io::import(
            format,
            &path,
            &mut self.database,
            ImportOptions {
                dry_run: self.import_dry_run,
                merge: true,
            },
        ) {
            Ok(report) => {
                self.status = report.summary();
                if let Err(error) = self.refresh_all() {
                    self.status = format!("{} (reload failed: {error:#})", report.summary());
                }
            }
            Err(error) => self.status = format!("import failed: {error:#}"),
        }
    }

    fn render(&self, frame: &mut Frame) {
        let areas = Layout::vertical([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(frame.area());
        self.render_header(frame, areas[0]);
        match self.screen {
            Screen::Dashboard => self.render_dashboard(frame, areas[1]),
            Screen::Devices => self.render_devices(frame, areas[1]),
            Screen::Details => self.render_details(frame, areas[1]),
            Screen::Scan => self.render_scan(frame, areas[1]),
            Screen::History => self.render_history(frame, areas[1]),
            Screen::ImportExport => self.render_io(frame, areas[1]),
            Screen::Settings => self.render_settings(frame, areas[1]),
            Screen::Help => self.render_help(frame, areas[1]),
        }
        self.render_footer(frame, areas[2]);
    }

    fn render_header(&self, frame: &mut Frame, area: Rect) {
        let titles: Vec<Line> = Screen::ALL
            .iter()
            .map(|screen| Line::from(format!(" {} ", screen.label())))
            .collect();
        let tabs = Tabs::new(titles)
            .select(self.screen.index())
            .highlight_style(
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
            .divider("|")
            .block(Block::bordered().title(format!("findarat — {}", self.network_summary)));
        frame.render_widget(tabs, area);
    }

    fn render_footer(&self, frame: &mut Frame, area: Rect) {
        let hints = match self.screen {
            Screen::Devices => {
                "↑/↓ move · Enter details · / search · s sort · r refresh · Tab screens · q quit"
            }
            Screen::Details => "↑/↓ scroll · Esc back · Tab screens · q quit",
            Screen::Scan => "Enter start scan · r refresh · Tab screens · q quit",
            Screen::History => "↑/↓ scroll · r refresh · Tab screens · q quit",
            Screen::ImportExport => {
                "e export · i import · p path · x dry-run · Tab screens · q quit"
            }
            Screen::Settings => "↑/↓ scroll · r reload config text · Tab screens · q quit",
            Screen::Help => "↑/↓ scroll · Esc dashboard · Tab screens · q quit",
            Screen::Dashboard => "r refresh · Tab screens · q quit · ? help",
        };
        let text = if self.search_mode {
            format!("search: {}▌", self.search)
        } else if self.path_input_mode {
            format!("path: {}▌", self.io_path)
        } else {
            format!("{} · {}", self.status, hints)
        };
        frame.render_widget(
            Paragraph::new(text).style(Style::default().fg(Color::Gray)),
            area,
        );
    }

    fn render_dashboard(&self, frame: &mut Frame, area: Rect) {
        let active = self.devices.iter().filter(|device| device.active).count();
        let last_scan = self.sessions.first().map(|session| {
            format!(
                "#{} {} · {} device(s) · {}",
                session
                    .id
                    .map(|id| id.to_string())
                    .unwrap_or_else(|| "-".to_string()),
                session.started_at.format("%Y-%m-%d %H:%M"),
                session.device_count,
                session.status
            )
        });
        let mut lines = vec![
            Line::from(vec![
                Span::styled("Network:  ", Style::default().fg(Color::Cyan)),
                Span::raw(self.network_summary.clone()),
            ]),
            Line::from(vec![
                Span::styled("Database: ", Style::default().fg(Color::Cyan)),
                Span::raw(self.database_path.display().to_string()),
            ]),
            Line::from(vec![
                Span::styled("Devices:  ", Style::default().fg(Color::Cyan)),
                Span::raw(format!("{} total, {active} active", self.devices.len())),
            ]),
            Line::from(vec![
                Span::styled("Last scan:", Style::default().fg(Color::Cyan)),
                Span::raw(format!(
                    " {}",
                    last_scan.unwrap_or_else(|| "none".to_string())
                )),
            ]),
            Line::from(""),
        ];
        if self.changes.is_empty() {
            lines.push(Line::from("No changes recorded yet."));
        } else {
            lines.push(Line::from(Span::styled(
                "Recent changes",
                Style::default().add_modifier(Modifier::BOLD),
            )));
            for change in self.changes.iter().take(10) {
                lines.push(Line::from(format!(
                    "{}  {}  {}",
                    change.detected_at.format("%Y-%m-%d %H:%M"),
                    change.kind.label(),
                    change
                        .device_label
                        .clone()
                        .unwrap_or_else(|| change.device_id.to_string())
                )));
            }
        }
        frame.render_widget(
            Paragraph::new(lines)
                .block(Block::bordered().title("Dashboard"))
                .wrap(Wrap { trim: false }),
            area,
        );
    }

    fn render_devices(&self, frame: &mut Frame, area: Rect) {
        let indices = self.filtered_indices();
        let rows: Vec<Row> = indices
            .iter()
            .enumerate()
            .map(|(position, index)| {
                let device = &self.devices[*index];
                let style = if position == self.selected {
                    Style::default()
                        .bg(Color::DarkGray)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                };
                Row::new(vec![
                    Cell::from(
                        device
                            .id
                            .map(|id| id.to_string())
                            .unwrap_or_else(|| "-".to_string()),
                    ),
                    Cell::from(device.display_name()),
                    Cell::from(
                        device
                            .last_ip
                            .map(|ip| ip.to_string())
                            .unwrap_or_else(|| "—".to_string()),
                    ),
                    Cell::from(device.mac.clone().unwrap_or_else(|| "—".to_string())),
                    Cell::from(device.device_type.label().to_string()),
                    Cell::from(device.vendor.clone().unwrap_or_else(|| "—".to_string())),
                    Cell::from(app::port_list(&device.ports)),
                    Cell::from(if device.active { "yes" } else { "no" }.to_string()),
                ])
                .style(style)
            })
            .collect();
        let title = if self.search.is_empty() {
            format!(
                "Devices ({} shown, sorted by {})",
                indices.len(),
                self.sort.label()
            )
        } else {
            format!(
                "Devices ({} shown, search {:?}, sorted by {})",
                indices.len(),
                self.search,
                self.sort.label()
            )
        };
        let table = Table::new(
            rows,
            [
                Constraint::Length(5),
                Constraint::Length(20),
                Constraint::Length(16),
                Constraint::Length(18),
                Constraint::Length(13),
                Constraint::Length(18),
                Constraint::Length(16),
                Constraint::Length(6),
            ],
        )
        .header(
            Row::new(vec![
                "ID", "Name", "IP", "MAC", "Type", "Vendor", "Ports", "Active",
            ])
            .style(Style::default().fg(Color::Cyan)),
        )
        .block(Block::bordered().title(title));
        frame.render_widget(table, area);
    }

    fn render_details(&self, frame: &mut Frame, area: Rect) {
        let Some(device) = self.selected_device() else {
            frame.render_widget(
                Paragraph::new("No device selected. Press Tab to open Devices and choose one.")
                    .block(Block::bordered().title("Details"))
                    .wrap(Wrap { trim: false }),
                area,
            );
            return;
        };
        let mut lines = vec![
            Line::from(Span::styled(
                device.display_name(),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(format!(
                "ID: {}   IP: {}   MAC: {}   Active: {}",
                device
                    .id
                    .map(|id| id.to_string())
                    .unwrap_or_else(|| "-".to_string()),
                device
                    .last_ip
                    .map(|ip| ip.to_string())
                    .unwrap_or_else(|| "unknown".to_string()),
                device.mac.as_deref().unwrap_or("unknown"),
                device.active
            )),
            Line::from(format!(
                "Vendor: {}   Type: {}   OS: {}",
                device.vendor.as_deref().unwrap_or("unknown"),
                device.device_type.label(),
                device.os.as_deref().unwrap_or("unknown")
            )),
            Line::from(format!(
                "Interface: {}   First seen: {}   Last seen: {}",
                device.interface.as_deref().unwrap_or("unknown"),
                device.first_seen.format("%Y-%m-%d %H:%M"),
                device.last_seen.format("%Y-%m-%d %H:%M")
            )),
            Line::from(""),
            Line::from(Span::styled(
                "Identifiers",
                Style::default().add_modifier(Modifier::BOLD),
            )),
        ];
        for identifier in &device.identifiers {
            lines.push(Line::from(format!(
                "  {} = {} ({})",
                identifier.kind, identifier.value, identifier.confidence
            )));
        }
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Open ports and services",
            Style::default().add_modifier(Modifier::BOLD),
        )));
        if device.ports.is_empty() {
            lines.push(Line::from("  none observed"));
        } else {
            for port in &device.ports {
                lines.push(Line::from(format!(
                    "  {}/{} {}{}{}",
                    port.protocol,
                    port.port,
                    port.service.as_deref().unwrap_or(""),
                    port.version
                        .as_deref()
                        .map(|version| format!(" ({version})"))
                        .unwrap_or_default(),
                    if port.confidence == crate::models::Confidence::High {
                        String::new()
                    } else {
                        format!(" [{}]", port.confidence)
                    }
                )));
            }
        }
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Evidence (conflicts are preserved)",
            Style::default().add_modifier(Modifier::BOLD),
        )));
        for evidence in &device.evidence {
            lines.push(Line::from(format!(
                "  {} = {} · {} · {}",
                evidence.property, evidence.value, evidence.source, evidence.confidence
            )));
        }
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Recent observations",
            Style::default().add_modifier(Modifier::BOLD),
        )));
        for observation in device.observations.iter().take(20) {
            lines.push(Line::from(format!(
                "  {} · {} · {}{}",
                observation.observed_at.format("%Y-%m-%d %H:%M:%S"),
                observation.source,
                observation
                    .ip
                    .map(|ip| ip.to_string())
                    .unwrap_or_else(|| "no IP".to_string()),
                observation
                    .hostname
                    .as_deref()
                    .map(|hostname| format!(" · {hostname}"))
                    .unwrap_or_default()
            )));
        }
        frame.render_widget(
            Paragraph::new(lines)
                .block(Block::bordered().title("Details"))
                .scroll((self.details_scroll, 0))
                .wrap(Wrap { trim: false }),
            area,
        );
    }

    fn render_scan(&self, frame: &mut Frame, area: Rect) {
        let rows = Layout::vertical([
            Constraint::Length(4),
            Constraint::Length(3),
            Constraint::Min(0),
        ])
        .split(area);
        let status = vec![
            Line::from(vec![
                Span::styled("State: ", Style::default().fg(Color::Cyan)),
                Span::raw(self.scan_state.label()),
            ]),
            Line::from(format!(
                "Ports: {} · Concurrency: {} · Timeout: {} ms",
                self.config.scanner.default_ports,
                self.config.scanner.concurrency,
                self.config.scanner.timeout_ms
            )),
            Line::from(format!(
                "Discovery: arp={} mdns={} ssdp={} netbios={} · resolve={}",
                self.config.discovery.arp,
                self.config.discovery.mdns,
                self.config.discovery.ssdp,
                self.config.discovery.netbios,
                self.config.discovery.resolve_hostnames
            )),
        ];
        frame.render_widget(
            Paragraph::new(status).block(Block::bordered().title("Scan")),
            rows[0],
        );
        let (completed, total) = self.scan_progress.unwrap_or((0, 0));
        let ratio = if total == 0 {
            0.0
        } else {
            completed as f64 / total as f64
        };
        frame.render_widget(
            Gauge::default()
                .block(Block::bordered().title("Progress"))
                .ratio(ratio.clamp(0.0, 1.0))
                .label(format!("{completed}/{total} probes")),
            rows[1],
        );
        let mut lines = Vec::new();
        if let Some(result) = &self.scan_result {
            lines.push(Line::from(vec![
                Span::styled("Last result: ", Style::default().fg(Color::Green)),
                Span::raw(result.clone()),
            ]));
            lines.push(Line::from(""));
        }
        if self.scan_reports.is_empty() {
            lines.push(Line::from(
                "Press Enter to run a scan with the current configuration.",
            ));
        } else {
            lines.push(Line::from(Span::styled(
                "Provider reports",
                Style::default().add_modifier(Modifier::BOLD),
            )));
            for report in &self.scan_reports {
                lines.push(Line::from(format!(
                    "  {:<10} {:<8} {:>4} host(s) {:>6} ms  {}",
                    report.name,
                    report.status.to_string(),
                    report.hosts_found,
                    report.duration_ms,
                    report.error.clone().unwrap_or_default()
                )));
            }
        }
        frame.render_widget(
            Paragraph::new(lines)
                .block(Block::bordered().title("Reports"))
                .wrap(Wrap { trim: false }),
            rows[2],
        );
    }

    fn render_history(&self, frame: &mut Frame, area: Rect) {
        let columns = Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(area);
        let mut session_lines = Vec::new();
        if self.sessions.is_empty() {
            session_lines.push(Line::from("No scan sessions yet."));
        } else {
            for session in &self.sessions {
                session_lines.push(Line::from(format!(
                    "#{} {} · {} · {} device(s) · {}",
                    session
                        .id
                        .map(|id| id.to_string())
                        .unwrap_or_else(|| "-".to_string()),
                    session.started_at.format("%Y-%m-%d %H:%M"),
                    session.status,
                    session.device_count,
                    session.interface.as_deref().unwrap_or("—")
                )));
            }
        }
        frame.render_widget(
            Paragraph::new(session_lines)
                .block(Block::bordered().title("Scan sessions"))
                .scroll((self.history_scroll, 0)),
            columns[0],
        );

        let mut change_lines = Vec::new();
        if self.changes.is_empty() {
            change_lines.push(Line::from("No changes recorded yet."));
        } else {
            for change in &self.changes {
                change_lines.push(Line::from(format!(
                    "{} · {} · {} → {}",
                    change.detected_at.format("%Y-%m-%d %H:%M"),
                    change.kind.label(),
                    change.old_value.as_deref().unwrap_or("—"),
                    change.new_value.as_deref().unwrap_or("—")
                )));
            }
        }
        frame.render_widget(
            Paragraph::new(change_lines)
                .block(Block::bordered().title("Changes"))
                .scroll((self.history_scroll, 0)),
            columns[1],
        );
    }

    fn render_io(&self, frame: &mut Frame, area: Rect) {
        let lines = vec![
            Line::from(Span::styled(
                "Import / Export",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(format!("Path: {}", self.io_path)),
            Line::from(format!(
                "Import mode: {} (x toggles)",
                if self.import_dry_run {
                    "dry run — validate only"
                } else {
                    "merge into the inventory"
                }
            )),
            Line::from(""),
            Line::from("e  export using the path extension (.json, .csv, .db)"),
            Line::from("i  import the path (JSON export or findarat SQLite database)"),
            Line::from("p  edit the path"),
            Line::from("x  toggle import dry-run"),
            Line::from(""),
            Line::from("Exports never include credentials because findarat never collects them."),
            Line::from(""),
            Line::from(format!("Status: {}", self.status)),
        ];
        frame.render_widget(
            Paragraph::new(lines)
                .block(Block::bordered().title("Import/Export"))
                .wrap(Wrap { trim: false }),
            area,
        );
    }

    fn render_settings(&self, frame: &mut Frame, area: Rect) {
        frame.render_widget(
            Paragraph::new(self.settings_text.clone())
                .block(Block::bordered().title("Effective configuration"))
                .scroll((self.settings_scroll, 0)),
            area,
        );
    }

    fn render_help(&self, frame: &mut Frame, area: Rect) {
        let lines = vec![
            Line::from(Span::styled(
                "Keyboard reference",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from("Tab / Shift+Tab   next / previous screen"),
            Line::from("1 … 8             jump directly to a screen"),
            Line::from("q or Ctrl+C       quit"),
            Line::from("?                 open this help"),
            Line::from(""),
            Line::from("Devices: ↑/↓ move, Enter details, / search, s sort, r refresh"),
            Line::from("Details: ↑/↓ scroll, Esc back"),
            Line::from("Scan:    Enter or s start a scan"),
            Line::from("History: ↑/↓ scroll, r refresh"),
            Line::from("I/O:     e export, i import, p edit path, x dry-run"),
            Line::from("Settings:↑/↓ scroll, r reload rendered config"),
            Line::from(""),
            Line::from("findarat is unprivileged and never performs disruptive operations."),
        ];
        frame.render_widget(
            Paragraph::new(lines)
                .block(Block::bordered().title("Help"))
                .scroll((self.help_scroll, 0))
                .wrap(Wrap { trim: false }),
            area,
        );
    }
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

/// Run the TUI until the user quits. Terminal state is restored on every exit
/// path, including errors.
pub async fn run(config: &Config, database_path: &Path) -> Result<()> {
    let mut app = TuiApp::new(config.clone(), database_path.to_path_buf())?;
    let mut terminal = ratatui::try_init().context("failed to initialize terminal")?;
    let result = event_loop(&mut terminal, &mut app).await;
    let restore = ratatui::try_restore();
    if let Err(error) = restore {
        tracing::error!(%error, "failed to restore terminal");
    }
    result
}

async fn event_loop(terminal: &mut DefaultTerminal, app: &mut TuiApp) -> Result<()> {
    loop {
        terminal.draw(|frame| app.render(frame))?;
        while event::poll(Duration::from_millis(0))? {
            if let Event::Key(key) = event::read()? {
                app.handle_key(key);
            }
        }
        app.drain_scan_events();
        if app.should_quit {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::DeviceType;
    use chrono::Utc;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn app_with_devices() -> TuiApp {
        let database = Database::open_in_memory().unwrap();
        let mut app =
            TuiApp::with_database(Config::default(), database, PathBuf::from(":memory:")).unwrap();
        let now = Utc::now();
        for (ip, name, kind) in [
            ("192.168.1.20", "beta", DeviceType::Laptop),
            ("192.168.1.10", "alpha", DeviceType::Printer),
        ] {
            let mut device = Device::new(now, now);
            device.last_ip = Some(ip.parse().unwrap());
            device.hostname = Some(name.to_string());
            device.device_type = kind;
            app.database.upsert_device(&device, None, false).unwrap();
        }
        app.refresh_all().unwrap();
        app
    }

    #[test]
    fn tab_cycles_screens_and_q_quits() {
        let mut app = app_with_devices();
        assert_eq!(app.screen, Screen::Dashboard);
        app.handle_key(key(KeyCode::Tab));
        assert_eq!(app.screen, Screen::Devices);
        app.handle_key(key(KeyCode::BackTab));
        assert_eq!(app.screen, Screen::Dashboard);
        app.handle_key(key(KeyCode::Char('q')));
        assert!(app.should_quit);
    }

    #[test]
    fn search_filters_and_does_not_trigger_global_quit() {
        let mut app = app_with_devices();
        app.screen = Screen::Devices;
        app.handle_key(key(KeyCode::Char('/')));
        assert!(app.search_mode);
        app.handle_key(key(KeyCode::Char('a')));
        assert_eq!(app.search, "a");
        assert!(!app.should_quit);
        app.handle_key(key(KeyCode::Enter));
        assert!(!app.search_mode);
        assert_eq!(app.filtered_indices().len(), 2);
        app.search = "alpha".to_string();
        assert_eq!(app.filtered_indices().len(), 1);
    }

    #[test]
    fn sort_mode_cycles_and_reorders() {
        let mut app = app_with_devices();
        app.screen = Screen::Devices;
        assert_eq!(app.sort, SortMode::LastSeen);
        app.handle_key(key(KeyCode::Char('s')));
        assert_eq!(app.sort, SortMode::Name);
        let indices = app.filtered_indices();
        let first = &app.devices[indices[0]];
        assert_eq!(first.hostname.as_deref(), Some("alpha"));
    }

    #[test]
    fn selection_is_clamped() {
        let mut app = app_with_devices();
        app.move_selection(-1);
        assert_eq!(app.selected, 0);
        app.move_selection(100);
        assert_eq!(app.selected, 1);
        app.search = "does-not-exist".to_string();
        app.clamp_selection();
        assert_eq!(app.selected, 0);
    }

    #[test]
    fn details_navigation_returns_to_devices() {
        let mut app = app_with_devices();
        app.screen = Screen::Devices;
        app.handle_key(key(KeyCode::Enter));
        assert_eq!(app.screen, Screen::Details);
        app.handle_key(key(KeyCode::Esc));
        assert_eq!(app.screen, Screen::Devices);
    }

    #[test]
    fn import_dry_run_toggles() {
        let mut app = app_with_devices();
        app.screen = Screen::ImportExport;
        assert!(!app.import_dry_run);
        app.handle_key(key(KeyCode::Char('x')));
        assert!(app.import_dry_run);
        app.handle_key(key(KeyCode::Char('x')));
        assert!(!app.import_dry_run);
    }

    #[test]
    fn direct_screen_keys_work() {
        let mut app = app_with_devices();
        app.handle_key(key(KeyCode::Char('3')));
        assert_eq!(app.screen, Screen::Details);
        app.handle_key(key(KeyCode::Char('8')));
        assert_eq!(app.screen, Screen::Help);
    }
}
