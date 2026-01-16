//! Shared state for the GUI
//!
//! Uses channels to communicate between the GUI thread and async runtime.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

/// Maximum number of log entries to keep
const MAX_LOG_ENTRIES: usize = 500;

/// Connection status
#[derive(Debug, Clone, PartialEq)]
pub enum ConnectionStatus {
    Disconnected,
    Connecting,
    Connected,
    Error(String),
}

/// A tunnel's runtime status
#[derive(Debug, Clone)]
pub struct TunnelStatus {
    pub name: String,
    pub target: String,
    pub local_port: u16,
    pub active_connections: u32,
    pub bytes_transferred: u64,
}

/// Log entry with timestamp
#[derive(Debug, Clone)]
pub struct LogEntry {
    pub timestamp: String,
    pub level: LogLevel,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LogLevel {
    Info,
    Warn,
    Error,
    Debug,
}

/// Commands from GUI to async runtime
#[derive(Debug)]
pub enum GuiCommand {
    // Server commands
    StartServer {
        tunnels: Vec<(String, String, u16)>, // (name, target_addr, local_port)
    },
    StopServer,
    AddAuthorizedKey {
        node_id: String,
        label: Option<String>,
    },
    RemoveAuthorizedKey {
        node_id: String,
    },

    // Client commands
    Connect {
        ticket: String,
        tunnels: Vec<(String, u16)>, // (name, local_port)
    },
    Disconnect,
}

/// Events from async runtime to GUI
#[derive(Debug, Clone)]
pub enum GuiEvent {
    // Status updates
    StatusChanged(ConnectionStatus),
    NodeIdReady(String),
    TicketReady(String),
    TunnelStatusUpdate(Vec<TunnelStatus>),

    // Logs
    Log(LogEntry),

    // Key management
    AuthorizedKeysUpdated(Vec<(String, Option<String>)>), // (node_id, label)
}

/// Shared application state
pub struct AppState {
    // Connection
    pub status: ConnectionStatus,
    pub node_id: Option<String>,
    pub ticket: Option<String>,

    // Tunnels
    pub tunnel_statuses: Vec<TunnelStatus>,

    // Authorized keys (server mode)
    pub authorized_keys: Vec<(String, Option<String>)>,

    // Logs
    pub logs: VecDeque<LogEntry>,

    // Channels
    pub command_tx: mpsc::UnboundedSender<GuiCommand>,
    pub event_rx: Arc<Mutex<mpsc::UnboundedReceiver<GuiEvent>>>,
}

impl AppState {
    pub fn new(
        command_tx: mpsc::UnboundedSender<GuiCommand>,
        event_rx: mpsc::UnboundedReceiver<GuiEvent>,
    ) -> Self {
        Self {
            status: ConnectionStatus::Disconnected,
            node_id: None,
            ticket: None,
            tunnel_statuses: Vec::new(),
            authorized_keys: Vec::new(),
            logs: VecDeque::with_capacity(MAX_LOG_ENTRIES),
            command_tx,
            event_rx: Arc::new(Mutex::new(event_rx)),
        }
    }

    /// Process pending events from the async runtime
    pub fn process_events(&mut self) {
        let mut rx = self.event_rx.lock().unwrap();
        while let Ok(event) = rx.try_recv() {
            match event {
                GuiEvent::StatusChanged(status) => {
                    self.status = status;
                }
                GuiEvent::NodeIdReady(id) => {
                    self.node_id = Some(id);
                }
                GuiEvent::TicketReady(ticket) => {
                    self.ticket = Some(ticket);
                }
                GuiEvent::TunnelStatusUpdate(statuses) => {
                    self.tunnel_statuses = statuses;
                }
                GuiEvent::Log(entry) => {
                    if self.logs.len() >= MAX_LOG_ENTRIES {
                        self.logs.pop_front();
                    }
                    self.logs.push_back(entry);
                }
                GuiEvent::AuthorizedKeysUpdated(keys) => {
                    self.authorized_keys = keys;
                }
            }
        }
    }

    /// Send a command to the async runtime
    pub fn send_command(&self, cmd: GuiCommand) {
        let _ = self.command_tx.send(cmd);
    }

    /// Add a log entry directly (for GUI-side logging)
    pub fn log(&mut self, level: LogLevel, message: impl Into<String>) {
        let entry = LogEntry {
            timestamp: current_timestamp(),
            level,
            message: message.into(),
        };
        if self.logs.len() >= MAX_LOG_ENTRIES {
            self.logs.pop_front();
        }
        self.logs.push_back(entry);
    }
}

fn current_timestamp() -> String {
    use std::time::SystemTime;
    let duration = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs() % 86400; // seconds since midnight
    let hours = secs / 3600;
    let mins = (secs % 3600) / 60;
    let secs = secs % 60;
    format!("{:02}:{:02}:{:02}", hours, mins, secs)
}
