use std::net::SocketAddr;
use tracing_subscriber::EnvFilter;

fn is_port_available(address: SocketAddr) -> bool {
    std::net::TcpListener::bind(address).is_ok()
}

fn pick_address(host: &str, preferred_port: u16) -> SocketAddr {
    let preferred = format!("{host}:{preferred_port}")
        .parse::<SocketAddr>()
        .expect("invalid SIKRYPT_HOST or SIKRYPT_PORT");

    if is_port_available(preferred) {
        return preferred;
    }

    if cfg!(debug_assertions) {
        for port in 3001..=3010 {
            let candidate = format!("{host}:{port}")
                .parse::<SocketAddr>()
                .expect("invalid fallback port");
            if is_port_available(candidate) {
                tracing::warn!(
                    "Port {} is already in use; falling back to https://{}",
                    preferred_port,
                    candidate
                );
                return candidate;
            }
        }
    }

    preferred
}

#[tokio::main]
async fn main() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,tower_http=info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let app = backend::app::create_app();
    let host = std::env::var("SIKRYPT_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port: u16 = std::env::var("SIKRYPT_PORT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(3000);
    let address = pick_address(&host, port);
    let tls_config = backend::tls::load_tls_config()
        .await
        .expect("failed to load TLS configuration");

    tracing::info!("Sikrypt backend listening on https://{address}");
    axum_server::bind_rustls(address, tls_config)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .expect("failed to start Axum server");
}
