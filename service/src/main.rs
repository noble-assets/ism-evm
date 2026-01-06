mod config;
mod prover;
mod server;

use tonic::transport::Server;
use tracing::info;
use tracing_subscriber::EnvFilter;

use config::Config;
use server::{ProverService, proto::prover_server::ProverServer};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();

    // Initialize tracing subscriber for logging
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "error,prover_service=info".parse().unwrap()),
        )
        .json()
        .init();

    let config = Config::from_env();
    let addr = format!("0.0.0.0:{}", config.port).parse()?;
    let service = ProverService::new(config);

    info!(%addr, "Prover service starting");

    Server::builder()
        .add_service(ProverServer::new(service))
        .serve_with_shutdown(addr, async {
            tokio::signal::ctrl_c().await.ok();
            info!("Shutting down");
        })
        .await?;

    Ok(())
}
