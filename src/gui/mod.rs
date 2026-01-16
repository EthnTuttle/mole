//! GUI module for Mole
//!
//! Provides a simple egui-based interface for both server and client modes.

mod app;
mod client_view;
mod server_view;
mod state;
mod widgets;

pub use app::run_gui;
