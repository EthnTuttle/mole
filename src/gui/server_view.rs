//! Server mode GUI view

use egui::{ScrollArea, Ui};

use super::state::{AppState, ConnectionStatus, GuiCommand, LogLevel};
use super::widgets::{self, section_header};

/// Server configuration UI state
pub struct ServerView {
    /// Tunnel configurations: (name, host, port, local_port)
    pub tunnel_configs: Vec<(String, String, String, String)>,
    /// New authorized key input
    pub new_key_input: String,
    /// New key label input
    pub new_key_label: String,
    /// New chat authorized key input
    pub new_chat_key_input: String,
    /// New chat key label input
    pub new_chat_key_label: String,
    /// Whether to show the QR code popup
    pub show_qr: bool,
    /// Server chat input
    pub chat_input: String,
}

impl Default for ServerView {
    fn default() -> Self {
        Self {
            tunnel_configs: vec![(
                "ssh".to_string(),
                "127.0.0.1".to_string(),
                "22".to_string(),
                "2222".to_string(),
            )],
            new_key_input: String::new(),
            new_key_label: String::new(),
            new_chat_key_input: String::new(),
            new_chat_key_label: String::new(),
            show_qr: false,
            chat_input: String::new(),
        }
    }
}

impl ServerView {
    pub fn ui(&mut self, ui: &mut Ui, state: &mut AppState) {
        // Render QR popup window if open
        if let Some(ticket) = state.ticket.clone() {
            widgets::show_qr_window(ui.ctx(), &mut self.show_qr, "Endpoint QR Code", &ticket);
        }
        // Status section
        section_header(ui, "Server Status");
        ui.horizontal(|ui| {
            widgets::status_indicator(ui, &state.status);

            ui.with_layout(
                egui::Layout::right_to_left(egui::Align::Center),
                |ui| match &state.status {
                    ConnectionStatus::Disconnected | ConnectionStatus::Error(_) => {
                        if ui.button("Start Server").clicked() {
                            self.start_server(state);
                        }
                    }
                    ConnectionStatus::Connected => {
                        if ui.button("Stop Server").clicked() {
                            state.send_command(GuiCommand::StopServer);
                        }
                    }
                    ConnectionStatus::Connecting => {
                        ui.add_enabled(false, egui::Button::new("Starting..."));
                    }
                },
            );
        });

        // Node ID
        if let Some(ref node_id) = state.node_id {
            ui.add_space(4.0);
            widgets::copyable_field(ui, "Node ID", node_id);
        }

        // Connection ticket (endpoint ID)
        if let Some(ticket) = state.ticket.clone() {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label("Endpoint ID:");
                if ui.button("Copy").clicked() {
                    #[cfg(feature = "gui")]
                    if let Ok(mut clipboard) = arboard::Clipboard::new() {
                        let _ = clipboard.set_text(&ticket);
                    }
                    state.log(LogLevel::Info, "Endpoint ID copied to clipboard");
                }
                if ui.button("Show QR").clicked() {
                    self.show_qr = true;
                }
            });
            ui.add_space(2.0);
            ScrollArea::horizontal().max_height(40.0).show(ui, |ui| {
                ui.add(
                    egui::TextEdit::multiline(&mut ticket.as_str())
                        .font(egui::TextStyle::Monospace)
                        .desired_width(f32::INFINITY)
                        .interactive(false),
                );
            });
        }

        // Tunnel configuration
        section_header(ui, "Tunnel Configuration");

        let mut to_remove = None;
        for (i, (name, host, port, local_port)) in self.tunnel_configs.iter_mut().enumerate() {
            if widgets::tunnel_config_row(ui, name, host, port, local_port) {
                to_remove = Some(i);
            }
        }
        if let Some(i) = to_remove {
            self.tunnel_configs.remove(i);
        }

        ui.horizontal(|ui| {
            if ui.button("+ Add Tunnel").clicked() {
                self.tunnel_configs.push((
                    String::new(),
                    "127.0.0.1".to_string(),
                    String::new(),
                    String::new(),
                ));
            }
            if ui.button("+ SSH Default").clicked() {
                self.tunnel_configs.push((
                    "ssh".to_string(),
                    "127.0.0.1".to_string(),
                    "22".to_string(),
                    "2222".to_string(),
                ));
            }
            if ui.button("+ Postgres").clicked() {
                self.tunnel_configs.push((
                    "postgres".to_string(),
                    "127.0.0.1".to_string(),
                    "5432".to_string(),
                    "5432".to_string(),
                ));
            }
        });

        // Active tunnels status
        if !state.tunnel_statuses.is_empty() {
            section_header(ui, "Active Tunnels");
            for tunnel in &state.tunnel_statuses {
                widgets::tunnel_status_row(ui, tunnel);
            }
        }

        // Authorized keys management
        section_header(ui, "Authorized Keys");

        if state.authorized_keys.is_empty() {
            ui.label("No authorized keys. Add keys to allow connections.");
        } else {
            let mut to_remove = None;
            for (node_id, label) in &state.authorized_keys {
                ui.horizontal(|ui| {
                    let display = if let Some(l) = label {
                        format!("{} ({})", l, &node_id[..16])
                    } else {
                        node_id[..32.min(node_id.len())].to_string()
                    };
                    ui.label(&display);
                    if ui.small_button("X").clicked() {
                        to_remove = Some(node_id.clone());
                    }
                });
            }
            if let Some(node_id) = to_remove {
                state.send_command(GuiCommand::RemoveAuthorizedKey { node_id });
            }
        }

        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.new_key_input)
                    .hint_text("Node ID")
                    .desired_width(300.0),
            );
            ui.add(
                egui::TextEdit::singleline(&mut self.new_key_label)
                    .hint_text("Label (optional)")
                    .desired_width(100.0),
            );
            if ui.button("Add Key").clicked() && !self.new_key_input.is_empty() {
                state.send_command(GuiCommand::AddAuthorizedKey {
                    node_id: self.new_key_input.clone(),
                    label: if self.new_key_label.is_empty() {
                        None
                    } else {
                        Some(self.new_key_label.clone())
                    },
                });
                self.new_key_input.clear();
                self.new_key_label.clear();
            }
        });

        // Chat authorized keys management
        section_header(ui, "Chat Authorized Keys");
        ui.label("Keys authorized for chat (separate from tunnel access):");

        if state.chat_authorized_keys.is_empty() {
            ui.label("No chat authorized keys. Add keys to allow chat connections.");
        } else {
            let mut to_remove = None;
            for (node_id, label) in &state.chat_authorized_keys {
                ui.horizontal(|ui| {
                    let display = if let Some(l) = label {
                        format!("{} ({})", l, &node_id[..16])
                    } else {
                        node_id[..32.min(node_id.len())].to_string()
                    };
                    ui.label(&display);
                    if ui.small_button("X").clicked() {
                        to_remove = Some(node_id.clone());
                    }
                });
            }
            if let Some(node_id) = to_remove {
                state.send_command(GuiCommand::RemoveChatAuthorizedKey { node_id });
            }
        }

        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.new_chat_key_input)
                    .hint_text("Node ID")
                    .desired_width(300.0),
            );
            ui.add(
                egui::TextEdit::singleline(&mut self.new_chat_key_label)
                    .hint_text("Label (optional)")
                    .desired_width(100.0),
            );
            if ui.button("Add Chat Key").clicked() && !self.new_chat_key_input.is_empty() {
                state.send_command(GuiCommand::AddChatAuthorizedKey {
                    node_id: self.new_chat_key_input.clone(),
                    label: if self.new_chat_key_label.is_empty() {
                        None
                    } else {
                        Some(self.new_chat_key_label.clone())
                    },
                });
                self.new_chat_key_input.clear();
                self.new_chat_key_label.clear();
            }
        });

        // Chat section (always show when server is running)
        if matches!(state.status, ConnectionStatus::Connected) {
            section_header(ui, "Chat");

            // Messages
            ScrollArea::vertical()
                .max_height(120.0)
                .stick_to_bottom(true)
                .id_salt("server_chat_messages")
                .show(ui, |ui| {
                    if state.chat_messages.is_empty() {
                        ui.label("No messages yet. Waiting for chat connections...");
                    } else {
                        for msg in &state.chat_messages {
                            ui.horizontal(|ui| {
                                ui.label(format!("[{}]", msg.timestamp));
                                if msg.is_self {
                                    ui.colored_label(
                                        egui::Color32::from_rgb(100, 200, 100),
                                        "Server",
                                    );
                                } else {
                                    ui.colored_label(
                                        egui::Color32::from_rgb(100, 150, 255),
                                        if msg.sender.len() > 8 {
                                            &msg.sender[..8]
                                        } else {
                                            &msg.sender
                                        },
                                    );
                                }
                                ui.label(":");
                                ui.label(&msg.text);
                            });
                        }
                    }
                });

            // Chat input
            ui.horizontal(|ui| {
                let response = ui.add(
                    egui::TextEdit::singleline(&mut self.chat_input)
                        .hint_text("Type a message to broadcast...")
                        .desired_width(ui.available_width() - 60.0),
                );

                let send_clicked = ui.button("Send").clicked();
                let enter_pressed =
                    response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));

                if (send_clicked || enter_pressed) && !self.chat_input.is_empty() {
                    state.send_command(GuiCommand::ServerBroadcastChat {
                        text: self.chat_input.clone(),
                    });
                    self.chat_input.clear();
                }
            });
        }

        // Logs
        section_header(ui, "Logs");
        ScrollArea::vertical()
            .max_height(200.0)
            .stick_to_bottom(true)
            .show(ui, |ui| {
                for entry in &state.logs {
                    widgets::log_entry(ui, entry);
                }
            });
    }

    fn start_server(&self, state: &mut AppState) {
        let tunnels: Vec<(String, String, u16)> = self
            .tunnel_configs
            .iter()
            .filter_map(|(name, host, port, local_port)| {
                if name.is_empty() || port.is_empty() {
                    return None;
                }
                let target = format!("{}:{}", host, port);
                let lp: u16 = local_port
                    .parse()
                    .unwrap_or_else(|_| port.parse().unwrap_or(0));
                if lp == 0 {
                    return None;
                }
                Some((name.clone(), target, lp))
            })
            .collect();

        if tunnels.is_empty() {
            state.log(LogLevel::Error, "No valid tunnel configurations");
            return;
        }

        state.send_command(GuiCommand::StartServer { tunnels });
    }
}
