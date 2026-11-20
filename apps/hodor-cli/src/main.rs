//! Operations tool: migrations, bootstrap and tenant management.

use std::io::Write as _;

fn main() -> std::io::Result<()> {
    // Placeholder until the composition root is wired.
    writeln!(
        std::io::stdout(),
        "{} {}",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION")
    )
}
