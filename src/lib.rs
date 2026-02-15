//! Mole - Secure TCP tunneling over Iroh
//!
//! This library provides the core functionality for the Mole tunneling tool.
//! It enables creating encrypted peer-to-peer tunnels to access TCP services
//! on remote machines without exposing ports to the public internet.

pub mod protocol;
pub mod qr;
pub mod security;
