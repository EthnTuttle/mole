//! Main GUI application

use eframe::egui;
use std::sync::Arc;
use tokio::runtime::Runtime;
use tokio::sync::mpsc;

use super::client_view::ClientView;
use super::server_view::ServerView;
use super::state::{AppState, ConnectionStatus, GuiCommand, GuiEvent, LogEntry, LogLevel, TunnelStatus};

use crate::protocol::{TcpTunnelProtocol, TunnelConfig, TunnelTarget, ALPN};
use crate::security::AuthorizedKeys;

/// Which mode the GUI is in
#[derive(Debug, Clone, Copy, PartialEq)]
enum Mode {
    Server,
    Client,
}

/// Main application struct
struct MoleApp {
    mode: Mode,
    state: AppState,
    server_view: ServerView,
    client_view: ClientView,
    runtime: Arc<Runtime>,
}

impl MoleApp {
    fn new(
        cc: &eframe::CreationContext<'_>,
        mode: Mode,
        state: AppState,
        runtime: Arc<Runtime>,
    ) -> Self {
        // Set up dark theme
        let mut style = (*cc.egui_ctx.style()).clone();
        style.visuals = egui::Visuals::dark();
        cc.egui_ctx.set_style(style);

        Self {
            mode,
            state,
            server_view: ServerView::default(),
            client_view: ClientView::default(),
            runtime,
        }
    }
}

impl eframe::App for MoleApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Process any pending events from async runtime
        self.state.process_events();

        // Request repaint periodically for status updates
        ctx.request_repaint_after(std::time::Duration::from_millis(100));

        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("Mole");
                ui.separator();

                // Mode selector (only when disconnected)
                if self.state.status == ConnectionStatus::Disconnected {
                    ui.selectable_value(&mut self.mode, Mode::Server, "Server");
                    ui.selectable_value(&mut self.mode, Mode::Client, "Client");
                } else {
                    ui.label(match self.mode {
                        Mode::Server => "Server Mode",
                        Mode::Client => "Client Mode",
                    });
                }
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                match self.mode {
                    Mode::Server => self.server_view.ui(ui, &mut self.state),
                    Mode::Client => self.client_view.ui(ui, &mut self.state),
                }
            });
        });
    }
}

/// Run the GUI application
pub fn run_gui(start_mode: Option<&str>) -> anyhow::Result<()> {
    // Create tokio runtime for async operations
    let runtime = Arc::new(Runtime::new()?);

    // Create channels for GUI <-> async communication
    let (command_tx, command_rx) = mpsc::unbounded_channel::<GuiCommand>();
    let (event_tx, event_rx) = mpsc::unbounded_channel::<GuiEvent>();

    // Spawn the async command handler
    let rt = runtime.clone();
    let event_tx_clone = event_tx.clone();
    std::thread::spawn(move || {
        rt.block_on(async_command_handler(command_rx, event_tx_clone));
    });

    // Determine starting mode
    let mode = match start_mode {
        Some("server") => Mode::Server,
        Some("client") => Mode::Client,
        _ => Mode::Server,
    };

    // Get initial node ID
    {
        let event_tx = event_tx.clone();
        runtime.spawn(async move {
            if let Ok(endpoint) = iroh::Endpoint::bind().await {
                let node_id = endpoint.node_id().to_string();
                let _ = event_tx.send(GuiEvent::NodeIdReady(node_id));
                endpoint.close().await;
            }
        });
    }

    // Load authorized keys
    {
        let event_tx = event_tx.clone();
        let _ = event_tx.send(GuiEvent::AuthorizedKeysUpdated(load_authorized_keys()));
    }

    let state = AppState::new(command_tx, event_rx);

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([600.0, 700.0])
            .with_min_inner_size([400.0, 400.0])
            .with_title("Mole - Secure TCP Tunneling"),
        ..Default::default()
    };

    eframe::run_native(
        "Mole",
        options,
        Box::new(move |cc| Ok(Box::new(MoleApp::new(cc, mode, state, runtime)))),
    )
    .map_err(|e| anyhow::anyhow!("GUI error: {}", e))
}

/// Load authorized keys from config
fn load_authorized_keys() -> Vec<(String, Option<String>)> {
    use crate::security;
    
    let path = match security::authorized_keys_path() {
        Ok(p) => p,
        Err(_) => return Vec::new(),
    };

    if !path.exists() {
        return Vec::new();
    }

    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let config: security::AuthorizedKeysConfig = match serde_json::from_str(&content) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    config
        .keys
        .into_iter()
        .map(|k| (k.node_id, k.label))
        .collect()
}

/// Async command handler - processes commands from GUI
async fn async_command_handler(
    mut command_rx: mpsc::UnboundedReceiver<GuiCommand>,
    event_tx: mpsc::UnboundedSender<GuiEvent>,
) {
    use iroh::protocol::Router;
    use iroh::Endpoint;
    use iroh_tickets::{endpoint::EndpointTicket, Ticket};
    use tokio::net::TcpListener;

    // Current server state
    let mut server_router: Option<Router> = None;
    let mut client_endpoint: Option<Endpoint> = None;

    while let Some(cmd) = command_rx.recv().await {
        match cmd {
            GuiCommand::StartServer { tunnels } => {
                log(&event_tx, LogLevel::Info, "Starting server...");
                let _ = event_tx.send(GuiEvent::StatusChanged(ConnectionStatus::Connecting));

                // Build tunnel config
                let mut config = TunnelConfig::new();
                for (name, target_addr, local_port) in &tunnels {
                    config.add_tunnel(TunnelTarget {
                        name: name.clone(),
                        target_addr: target_addr.clone(),
                        description: None,
                        local_port: *local_port,
                    });
                }

                // Load authorized keys
                let authorized_keys = AuthorizedKeys::from_default_config()
                    .unwrap_or_else(|_| AuthorizedKeys::allow_all());

                // Create endpoint
                let endpoint = match Endpoint::builder()
                    .alpns(vec![ALPN.to_vec()])
                    .bind()
                    .await
                {
                    Ok(e) => e,
                    Err(e) => {
                        log(&event_tx, LogLevel::Error, format!("Failed to create endpoint: {}", e));
                        let _ = event_tx.send(GuiEvent::StatusChanged(ConnectionStatus::Error(e.to_string())));
                        continue;
                    }
                };

                // Wait for online
                endpoint.online().await;

                let node_id = endpoint.node_id().to_string();
                let _ = event_tx.send(GuiEvent::NodeIdReady(node_id.clone()));
                log(&event_tx, LogLevel::Info, format!("Node ID: {}", node_id));

                // Generate ticket
                if let Ok(addr) = endpoint.addr().await {
                    let ticket = EndpointTicket::new(addr);
                    let _ = event_tx.send(GuiEvent::TicketReady(ticket.serialize()));
                }

                // Create protocol handler
                let protocol = TcpTunnelProtocol::new(config.clone(), authorized_keys);

                // Build tunnel status for UI
                let statuses: Vec<TunnelStatus> = config
                    .tunnels
                    .values()
                    .map(|t| TunnelStatus {
                        name: t.name.clone(),
                        target: t.target_addr.clone(),
                        local_port: t.local_port,
                        active_connections: 0,
                        bytes_transferred: 0,
                    })
                    .collect();
                let _ = event_tx.send(GuiEvent::TunnelStatusUpdate(statuses));

                // Start router
                let router = Router::builder(endpoint)
                    .accept(ALPN, protocol)
                    .spawn();

                server_router = Some(router);

                log(&event_tx, LogLevel::Info, "Server started. Waiting for connections...");
                let _ = event_tx.send(GuiEvent::StatusChanged(ConnectionStatus::Connected));
            }

            GuiCommand::StopServer => {
                log(&event_tx, LogLevel::Info, "Stopping server...");
                if let Some(router) = server_router.take() {
                    let _ = router.shutdown().await;
                }
                let _ = event_tx.send(GuiEvent::StatusChanged(ConnectionStatus::Disconnected));
                let _ = event_tx.send(GuiEvent::TunnelStatusUpdate(Vec::new()));
                log(&event_tx, LogLevel::Info, "Server stopped");
            }

            GuiCommand::Connect { ticket, tunnels } => {
                log(&event_tx, LogLevel::Info, "Connecting to server...");
                let _ = event_tx.send(GuiEvent::StatusChanged(ConnectionStatus::Connecting));

                // Parse ticket
                let endpoint_ticket = match EndpointTicket::deserialize(&ticket) {
                    Ok(t) => t,
                    Err(e) => {
                        log(&event_tx, LogLevel::Error, format!("Invalid ticket: {}", e));
                        let _ = event_tx.send(GuiEvent::StatusChanged(ConnectionStatus::Error("Invalid ticket".to_string())));
                        continue;
                    }
                };

                let remote_addr = endpoint_ticket.endpoint_addr().clone();
                let remote_node_id = remote_addr.node_id;

                // Create endpoint
                let endpoint = match Endpoint::bind().await {
                    Ok(e) => e,
                    Err(e) => {
                        log(&event_tx, LogLevel::Error, format!("Failed to create endpoint: {}", e));
                        let _ = event_tx.send(GuiEvent::StatusChanged(ConnectionStatus::Error(e.to_string())));
                        continue;
                    }
                };

                let our_node_id = endpoint.node_id().to_string();
                let _ = event_tx.send(GuiEvent::NodeIdReady(our_node_id.clone()));

                // Connect
                log(&event_tx, LogLevel::Info, format!("Connecting to {}...", remote_node_id));
                let connection = match endpoint.connect(remote_addr, ALPN).await {
                    Ok(c) => Arc::new(c),
                    Err(e) => {
                        log(&event_tx, LogLevel::Error, format!("Connection failed: {}", e));
                        let _ = event_tx.send(GuiEvent::StatusChanged(ConnectionStatus::Error(e.to_string())));
                        continue;
                    }
                };

                log(&event_tx, LogLevel::Info, "Connected! Starting tunnel listeners...");

                // Start local listeners for each tunnel
                let mut statuses = Vec::new();
                for (name, local_port) in &tunnels {
                    let bind_addr = format!("127.0.0.1:{}", local_port);
                    match TcpListener::bind(&bind_addr).await {
                        Ok(listener) => {
                            statuses.push(TunnelStatus {
                                name: name.clone(),
                                target: format!("remote:{}", name),
                                local_port: *local_port,
                                active_connections: 0,
                                bytes_transferred: 0,
                            });

                            // Spawn listener task
                            let conn = connection.clone();
                            let tunnel_name = name.clone();
                            let event_tx = event_tx.clone();
                            tokio::spawn(async move {
                                run_client_listener(listener, conn, tunnel_name, event_tx).await;
                            });

                            log(&event_tx, LogLevel::Info, format!("Listening on localhost:{} for {}", local_port, name));
                        }
                        Err(e) => {
                            log(&event_tx, LogLevel::Error, format!("Failed to bind {}: {}", bind_addr, e));
                        }
                    }
                }

                let _ = event_tx.send(GuiEvent::TunnelStatusUpdate(statuses));
                client_endpoint = Some(endpoint);
                let _ = event_tx.send(GuiEvent::StatusChanged(ConnectionStatus::Connected));
            }

            GuiCommand::Disconnect => {
                log(&event_tx, LogLevel::Info, "Disconnecting...");
                if let Some(endpoint) = client_endpoint.take() {
                    endpoint.close().await;
                }
                let _ = event_tx.send(GuiEvent::StatusChanged(ConnectionStatus::Disconnected));
                let _ = event_tx.send(GuiEvent::TunnelStatusUpdate(Vec::new()));
                log(&event_tx, LogLevel::Info, "Disconnected");
            }

            GuiCommand::AddAuthorizedKey { node_id, label } => {
                match crate::security::add_authorized_key(&node_id, label.as_deref()) {
                    Ok(()) => {
                        log(&event_tx, LogLevel::Info, format!("Added authorized key: {}", &node_id[..16.min(node_id.len())]));
                        let _ = event_tx.send(GuiEvent::AuthorizedKeysUpdated(load_authorized_keys()));
                    }
                    Err(e) => {
                        log(&event_tx, LogLevel::Error, format!("Failed to add key: {}", e));
                    }
                }
            }

            GuiCommand::RemoveAuthorizedKey { node_id } => {
                match crate::security::remove_authorized_key(&node_id) {
                    Ok(()) => {
                        log(&event_tx, LogLevel::Info, "Removed authorized key");
                        let _ = event_tx.send(GuiEvent::AuthorizedKeysUpdated(load_authorized_keys()));
                    }
                    Err(e) => {
                        log(&event_tx, LogLevel::Error, format!("Failed to remove key: {}", e));
                    }
                }
            }
        }
    }
}

/// Run a client tunnel listener
async fn run_client_listener(
    listener: TcpListener,
    connection: Arc<iroh::endpoint::Connection>,
    tunnel_name: String,
    event_tx: mpsc::UnboundedSender<GuiEvent>,
) {
    use crate::protocol::{read_tunnel_response, send_tunnel_request, TunnelRequest};
    use tokio::io::AsyncWriteExt;

    loop {
        match listener.accept().await {
            Ok((tcp_stream, _)) => {
                let conn = connection.clone();
                let name = tunnel_name.clone();
                let tx = event_tx.clone();

                tokio::spawn(async move {
                    // Open stream
                    let (mut send, mut recv) = match conn.open_bi().await {
                        Ok(s) => s,
                        Err(e) => {
                            log(&tx, LogLevel::Error, format!("Failed to open stream: {}", e));
                            return;
                        }
                    };

                    // Send tunnel request
                    let request = TunnelRequest { tunnel_name: name.clone() };
                    if let Err(e) = send_tunnel_request(&mut send, &request).await {
                        log(&tx, LogLevel::Error, format!("Failed to send request: {}", e));
                        return;
                    }

                    // Read response
                    let response = match read_tunnel_response(&mut recv).await {
                        Ok(r) => r,
                        Err(e) => {
                            log(&tx, LogLevel::Error, format!("Failed to read response: {}", e));
                            return;
                        }
                    };

                    if !response.accepted {
                        log(&tx, LogLevel::Error, format!("Tunnel rejected: {:?}", response.error));
                        return;
                    }

                    // Bidirectional copy
                    let (mut tcp_read, mut tcp_write) = tcp_stream.into_split();

                    tokio::select! {
                        _ = tokio::io::copy(&mut tcp_read, &mut send) => {}
                        _ = tokio::io::copy(&mut recv, &mut tcp_write) => {}
                    }

                    let _ = send.finish();
                });
            }
            Err(e) => {
                log(&event_tx, LogLevel::Error, format!("Accept error: {}", e));
                break;
            }
        }
    }
}

fn log(tx: &mpsc::UnboundedSender<GuiEvent>, level: LogLevel, message: impl Into<String>) {
    use std::time::SystemTime;
    let duration = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs() % 86400;
    let timestamp = format!("{:02}:{:02}:{:02}", secs / 3600, (secs % 3600) / 60, secs % 60);

    let _ = tx.send(GuiEvent::Log(LogEntry {
        timestamp,
        level,
        message: message.into(),
    }));
}
