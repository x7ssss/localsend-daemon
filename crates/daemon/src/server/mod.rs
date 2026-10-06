//! Headless HTTPS Receiver Server
//!
//! Provides the Axum TLS server loop with strictly pinned HTTP/1.1 transport.

pub mod routes;
pub mod tls;

use axum::Router;
use axum::extract::connect_info::IntoMakeServiceWithConnectInfo;
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tower::Service;

pub use routes::{AppState, create_router};
pub use tls::build_tls_server_config;

/// Headless TLS HTTP/1.1 receiver server.
pub struct ReceiverServer {
    state: AppState,
    tls_acceptor: TlsAcceptor,
}

impl ReceiverServer {
    /// Creates a new ReceiverServer instance.
    pub fn new(state: AppState, tls_config: Arc<rustls::ServerConfig>) -> Self {
        Self {
            state,
            tls_acceptor: TlsAcceptor::from(tls_config),
        }
    }

    /// Run the HTTPS server loop until cancelled.
    pub async fn run(
        self,
        listener: TcpListener,
        cancel_token: CancellationToken,
    ) -> Result<(), std::io::Error> {
        let router = create_router(self.state);
        let mut make_service: IntoMakeServiceWithConnectInfo<Router, SocketAddr> =
            router.into_make_service_with_connect_info();

        loop {
            tokio::select! {
                _ = cancel_token.cancelled() => {
                    tracing::info!("Receiver server shutting down gracefully");
                    break;
                }
                accept_res = listener.accept() => {
                    let (stream, remote_addr) = match accept_res {
                        Ok(val) => val,
                        Err(e) => {
                            tracing::warn!("TCP accept error: {e}");
                            continue;
                        }
                    };

                    let acceptor = self.tls_acceptor.clone();
                    let service = match make_service.call(remote_addr).await {
                        Ok(svc) => svc,
                        Err(e) => {
                            tracing::error!("MakeService error: {e}");
                            continue;
                        }
                    };

                    tokio::spawn(async move {
                        let tls_stream = match acceptor.accept(stream).await {
                            Ok(s) => s,
                            Err(e) => {
                                tracing::debug!("TLS handshake failed from {remote_addr}: {e}");
                                return;
                            }
                        };

                        let io = TokioIo::new(tls_stream);
                        // Strictly enforce HTTP/1.1 server engine
                        let http1 = hyper::server::conn::http1::Builder::new();
                        let hyper_service = hyper_util::service::TowerToHyperService::new(service);
                        if let Err(e) = http1.serve_connection(io, hyper_service).await {
                            tracing::debug!("Connection error with {remote_addr}: {e}");
                        }
                    });
                }
            }
        }

        Ok(())
    }
}
