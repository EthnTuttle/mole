//! Client mode GUI view

use egui::{ScrollArea, Ui};

use super::state::{AppState, ConnectionStatus, GuiCommand, LogLevel};
use super::widgets::{self, section_header};

/// Client configuration UI state
pub struct ClientView {
    /// Connection ticket input
    pub ticket_input: String,
    /// Tunnel bindings: (name, local_port)
    pub tunnel_bindings: Vec<(String, String)>,
    /// Chat message input
    pub chat_input: String,
    /// Chat endpoint input (for connecting to chat)
    pub chat_endpoint_input: String,
    /// Whether to show the QR code popup for own node ID
    pub show_qr: bool,
}

impl Default for ClientView {
    fn default() -> Self {
        Self {
            ticket_input: String::new(),
            tunnel_bindings: vec![("ssh".to_string(), "2222".to_string())],
            chat_input: String::new(),
            chat_endpoint_input: String::new(),
            show_qr: false,
        }
    }
}

impl ClientView {
    pub fn ui(&mut self, ui: &mut Ui, state: &mut AppState) {
        // Render QR popup window if open
        if let Some(ref node_id) = state.node_id {
            widgets::show_qr_window(ui.ctx(), &mut self.show_qr, "Your Node ID QR Code", node_id);
        }

        // Status section
        section_header(ui, "Connection Status");
        ui.horizontal(|ui| {
            widgets::status_indicator(ui, &state.status);

            ui.with_layout(
                egui::Layout::right_to_left(egui::Align::Center),
                |ui| match &state.status {
                    ConnectionStatus::Disconnected | ConnectionStatus::Error(_) => {
                        if ui.button("Connect").clicked() {
                            self.connect(state);
                        }
                    }
                    ConnectionStatus::Connected => {
                        if ui.button("Disconnect").clicked() {
                            state.send_command(GuiCommand::Disconnect);
                        }
                    }
                    ConnectionStatus::Connecting => {
                        ui.add_enabled(false, egui::Button::new("Connecting..."));
                    }
                },
            );
        });

        // Node ID
        if let Some(ref node_id) = state.node_id {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                widgets::copyable_field(ui, "Your Node ID", node_id);
                if ui.button("Show QR").clicked() {
                    self.show_qr = true;
                }
            });
            ui.label("Share this with the server admin to get authorized.");
        }

        // Ticket input
        section_header(ui, "Server Ticket");
        ui.horizontal(|ui| {
            if ui.button("Paste").clicked() {
                #[cfg(feature = "gui")]
                if let Ok(mut clipboard) = arboard::Clipboard::new() {
                    if let Ok(text) = clipboard.get_text() {
                        self.ticket_input = text;
                        state.log(LogLevel::Info, "Ticket pasted from clipboard");
                    }
                }
            }
            if ui.button("Clear").clicked() {
                self.ticket_input.clear();
            }
        });
        ui.add_space(2.0);
        ScrollArea::vertical().max_height(60.0).show(ui, |ui| {
            ui.add(
                egui::TextEdit::multiline(&mut self.ticket_input)
                    .hint_text("Paste connection ticket here...")
                    .font(egui::TextStyle::Monospace)
                    .desired_width(f32::INFINITY),
            );
        });

        // Tunnel bindings
        section_header(ui, "Tunnel Bindings");
        ui.label("Configure which tunnels to open and their local ports:");
        ui.add_space(4.0);

        let mut to_remove = None;
        for (i, (name, port)) in self.tunnel_bindings.iter_mut().enumerate() {
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(name)
                        .hint_text("tunnel name")
                        .desired_width(100.0),
                );
                ui.label("-> localhost:");
                ui.add(
                    egui::TextEdit::singleline(port)
                        .hint_text("port")
                        .desired_width(60.0),
                );
                if ui.button("X").clicked() {
                    to_remove = Some(i);
                }
            });
        }
        if let Some(i) = to_remove {
            self.tunnel_bindings.remove(i);
        }

        ui.horizontal(|ui| {
            if ui.button("+ Add Tunnel").clicked() {
                self.tunnel_bindings.push((String::new(), String::new()));
            }
            if ui.button("+ SSH").clicked() {
                self.tunnel_bindings
                    .push(("ssh".to_string(), "2222".to_string()));
            }
            if ui.button("+ Postgres").clicked() {
                self.tunnel_bindings
                    .push(("postgres".to_string(), "5432".to_string()));
            }
            if ui.button("+ Redis").clicked() {
                self.tunnel_bindings
                    .push(("redis".to_string(), "6379".to_string()));
            }
        });

        // Active tunnels status
        if !state.tunnel_statuses.is_empty() {
            section_header(ui, "Active Tunnels");
            for tunnel in &state.tunnel_statuses {
                widgets::tunnel_status_row(ui, tunnel);
            }

            ui.add_space(8.0);
            ui.label("Quick connect commands:");
            for tunnel in &state.tunnel_statuses {
                let cmd = match tunnel.name.as_str() {
                    "ssh" => format!("ssh -p {} localhost", tunnel.local_port),
                    "postgres" => format!("psql -h localhost -p {}", tunnel.local_port),
                    "mysql" => format!("mysql -h 127.0.0.1 -P {}", tunnel.local_port),
                    "redis" => format!("redis-cli -p {}", tunnel.local_port),
                    _ => format!("localhost:{}", tunnel.local_port),
                };
                ui.horizontal(|ui| {
                    ui.label(format!("  {}:", tunnel.name));
                    ui.code(&cmd);
                    if ui.small_button("Copy").clicked() {
                        #[cfg(feature = "gui")]
                        if let Ok(mut clipboard) = arboard::Clipboard::new() {
                            let _ = clipboard.set_text(&cmd);
                        }
                    }
                });
            }
        }

        // Chat section
        section_header(ui, "Chat");

        ui.horizontal(|ui| {
            if state.chat_connected {
                ui.label("Status: Connected");
                if ui.button("Disconnect").clicked() {
                    state.send_command(GuiCommand::DisconnectChat);
                }
            } else {
                ui.label("Status: Disconnected");
            }
        });

        if !state.chat_connected {
            // Chat endpoint input
            ui.horizontal(|ui| {
                ui.label("Endpoint ID:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.chat_endpoint_input)
                        .hint_text("Enter endpoint ID to chat with...")
                        .desired_width(200.0),
                );
                if ui.button("Connect").clicked() && !self.chat_endpoint_input.is_empty() {
                    state.send_command(GuiCommand::ConnectChat {
                        endpoint_id: self.chat_endpoint_input.trim().to_string(),
                    });
                }
            });

            // Quick connect to current tunnel server
            if !self.ticket_input.is_empty() && ui.button("Chat with tunnel server").clicked() {
                state.send_command(GuiCommand::ConnectChat {
                    endpoint_id: self.ticket_input.trim().to_string(),
                });
            }
        } else {
            // Chat messages
            ScrollArea::vertical()
                .max_height(150.0)
                .stick_to_bottom(true)
                .id_salt("chat_messages")
                .show(ui, |ui| {
                    for msg in &state.chat_messages {
                        ui.horizontal(|ui| {
                            ui.label(format!("[{}]", msg.timestamp));
                            if msg.is_self {
                                ui.colored_label(
                                    egui::Color32::from_rgb(100, 200, 100),
                                    &msg.sender,
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
                });

            // Chat input
            ui.horizontal(|ui| {
                let response = ui.add(
                    egui::TextEdit::singleline(&mut self.chat_input)
                        .hint_text("Type a message...")
                        .desired_width(ui.available_width() - 60.0),
                );

                let send_clicked = ui.button("Send").clicked();
                let enter_pressed =
                    response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));

                if (send_clicked || enter_pressed) && !self.chat_input.is_empty() {
                    state.send_command(GuiCommand::SendChatMessage {
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

    fn connect(&self, state: &mut AppState) {
        if self.ticket_input.trim().is_empty() {
            state.log(LogLevel::Error, "Please enter a connection ticket");
            return;
        }

        let tunnels: Vec<(String, u16)> = self
            .tunnel_bindings
            .iter()
            .filter_map(|(name, port)| {
                if name.is_empty() || port.is_empty() {
                    return None;
                }
                let p: u16 = port.parse().ok()?;
                Some((name.clone(), p))
            })
            .collect();

        if tunnels.is_empty() {
            state.log(LogLevel::Error, "No valid tunnel bindings configured");
            return;
        }

        state.send_command(GuiCommand::Connect {
            ticket: self.ticket_input.trim().to_string(),
            tunnels,
        });
    }
}
