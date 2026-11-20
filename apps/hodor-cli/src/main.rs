//! Operations tool: migrations, bootstrap and tenant management.

use clap::{Parser, Subcommand};
use hodor_adapters_postgres::PgPool;
use std::error::Error;
use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

/// Operate a Hodor installation.
#[derive(Parser)]
#[command(name = "hodor-cli", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Apply pending database migrations.
    ///
    /// Connects as the role that owns the schema. The server and worker use
    /// a different, less privileged role and never run migrations.
    Migrate {
        /// Connection URL of the schema owner.
        #[arg(long, env = "HODOR_DATABASE_OWNER_URL", hide_env_values = true)]
        database_url: String,
    },

    /// Check a health endpoint and exit non-zero unless it answers 200.
    ///
    /// For container health checks: the runtime image has no shell or HTTP
    /// client of its own.
    Probe {
        /// Address of the operations listener.
        #[arg(long, default_value = "127.0.0.1:9090")]
        addr: SocketAddr,
        /// Path to request.
        #[arg(long, default_value = "/readyz")]
        path: String,
    },
}

/// Performs a minimal HTTP/1.1 GET and reports whether the status is 200.
fn probe(addr: SocketAddr, path: &str) -> Result<bool, std::io::Error> {
    let timeout = Duration::from_secs(3);
    let mut stream = TcpStream::connect_timeout(&addr, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
    )?;
    let mut status_line = [0_u8; 12];
    stream.read_exact(&mut status_line)?;
    Ok(&status_line == b"HTTP/1.1 200")
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    match Cli::parse().command {
        Command::Migrate { database_url } => {
            let pool = PgPool::connect(&database_url).await?;
            hodor_adapters_postgres::migrate(&pool).await?;
            writeln!(std::io::stdout(), "migrations applied")?;
        }
        Command::Probe { addr, path } => {
            if !probe(addr, &path)? {
                return Err(format!("{addr}{path} did not answer 200").into());
            }
        }
    }
    Ok(())
}
