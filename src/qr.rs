//! QR code generation utilities
//!
//! This module provides functions to generate QR codes for endpoint IDs,
//! making it easy to share connection info with mobile devices.

use qrcode::render::unicode;
use qrcode::QrCode;

/// Generate a QR code as a string of Unicode block characters for terminal display
pub fn generate_terminal_qr(data: &str) -> Result<String, String> {
    let code =
        QrCode::new(data.as_bytes()).map_err(|e| format!("Failed to generate QR code: {}", e))?;

    let string = code
        .render::<unicode::Dense1x2>()
        .dark_color(unicode::Dense1x2::Light)
        .light_color(unicode::Dense1x2::Dark)
        .quiet_zone(true)
        .build();

    Ok(string)
}

/// Generate a QR code as a 2D boolean grid (true = dark/black module)
/// This is useful for GUI rendering
pub fn generate_qr_grid(data: &str) -> Result<Vec<Vec<bool>>, String> {
    let code =
        QrCode::new(data.as_bytes()).map_err(|e| format!("Failed to generate QR code: {}", e))?;

    let width = code.width();
    let mut grid = Vec::with_capacity(width);

    for y in 0..width {
        let mut row = Vec::with_capacity(width);
        for x in 0..width {
            // Dark modules are "on" (true)
            row.push(code[(x, y)] == qrcode::Color::Dark);
        }
        grid.push(row);
    }

    Ok(grid)
}

/// Print a QR code to stdout with a label
pub fn print_qr(label: &str, data: &str) {
    println!();
    println!("{}:", label);
    println!();

    match generate_terminal_qr(data) {
        Ok(qr) => {
            println!("{}", qr);
        }
        Err(e) => {
            eprintln!("Error generating QR code: {}", e);
        }
    }

    println!();
    println!("Data: {}", data);
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_terminal_qr() {
        let result = generate_terminal_qr("test data");
        assert!(result.is_ok());
        let qr = result.unwrap();
        assert!(!qr.is_empty());
    }

    #[test]
    fn test_generate_qr_grid() {
        let result = generate_qr_grid("test data");
        assert!(result.is_ok());
        let grid = result.unwrap();
        assert!(!grid.is_empty());
        assert!(!grid[0].is_empty());
        // QR code should be square
        assert_eq!(grid.len(), grid[0].len());
    }
}
