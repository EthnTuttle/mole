//! Reusable UI widgets for Mole GUI

use egui::{Color32, RichText, Ui};

use super::state::{ConnectionStatus, LogEntry, LogLevel, TunnelStatus};

/// Status indicator with colored dot
pub fn status_indicator(ui: &mut Ui, status: &ConnectionStatus) {
    let (color, text) = match status {
        ConnectionStatus::Disconnected => (Color32::GRAY, "Disconnected"),
        ConnectionStatus::Connecting => (Color32::YELLOW, "Connecting..."),
        ConnectionStatus::Connected => (Color32::GREEN, "Connected"),
        ConnectionStatus::Error(e) => (Color32::RED, e.as_str()),
    };

    ui.horizontal(|ui| {
        // Colored dot
        let (rect, _) = ui.allocate_exact_size(egui::vec2(12.0, 12.0), egui::Sense::hover());
        ui.painter()
            .circle_filled(rect.center(), 5.0, color);
        ui.label(text);
    });
}

/// Display a tunnel status row
pub fn tunnel_status_row(ui: &mut Ui, tunnel: &TunnelStatus) {
    ui.horizontal(|ui| {
        ui.label(RichText::new(&tunnel.name).strong());
        ui.label("->");
        ui.label(&tunnel.target);
        ui.separator();
        ui.label(format!("localhost:{}", tunnel.local_port));
        ui.separator();
        ui.label(format!("{} conn", tunnel.active_connections));
        ui.separator();
        ui.label(format_bytes(tunnel.bytes_transferred));
    });
}

/// Display a log entry
pub fn log_entry(ui: &mut Ui, entry: &LogEntry) {
    let (color, prefix) = match entry.level {
        LogLevel::Info => (Color32::WHITE, "INFO"),
        LogLevel::Warn => (Color32::YELLOW, "WARN"),
        LogLevel::Error => (Color32::RED, "ERR "),
        LogLevel::Debug => (Color32::GRAY, "DBG "),
    };

    ui.horizontal(|ui| {
        ui.label(RichText::new(&entry.timestamp).color(Color32::DARK_GRAY).monospace());
        ui.label(RichText::new(prefix).color(color).monospace());
        ui.label(RichText::new(&entry.message).monospace());
    });
}

/// Copyable text field with copy button
pub fn copyable_field(ui: &mut Ui, label: &str, value: &str) -> bool {
    let mut copied = false;
    ui.horizontal(|ui| {
        ui.label(format!("{}:", label));
        ui.add(egui::TextEdit::singleline(&mut value.to_string()).interactive(false));
        if ui.button("Copy").clicked() {
            #[cfg(feature = "gui")]
            if let Ok(mut clipboard) = arboard::Clipboard::new() {
                let _ = clipboard.set_text(value);
                copied = true;
            }
        }
    });
    copied
}

/// Editable tunnel configuration row
pub fn tunnel_config_row(
    ui: &mut Ui,
    name: &mut String,
    host: &mut String,
    port: &mut String,
    local_port: &mut String,
) -> bool {
    let mut remove = false;
    ui.horizontal(|ui| {
        ui.add(egui::TextEdit::singleline(name).hint_text("name").desired_width(80.0));
        ui.label(":");
        ui.add(egui::TextEdit::singleline(host).hint_text("host").desired_width(100.0));
        ui.label(":");
        ui.add(egui::TextEdit::singleline(port).hint_text("port").desired_width(50.0));
        ui.label("->");
        ui.add(egui::TextEdit::singleline(local_port).hint_text("local").desired_width(50.0));
        if ui.button("X").clicked() {
            remove = true;
        }
    });
    remove
}

/// Format bytes into human readable format
pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Section header with separator
pub fn section_header(ui: &mut Ui, text: &str) {
    ui.add_space(8.0);
    ui.label(RichText::new(text).strong().size(14.0));
    ui.separator();
}
