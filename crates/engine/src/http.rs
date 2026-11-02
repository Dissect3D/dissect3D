//! Authenticated HTTPS composition for the implemented core-service routes.
//!
//! This module owns the loopback listener, TLS acceptor, bounded HTTP/1 parser
//! and route composition. The store remains a separate serialized authority;
//! handlers only send typed operations to it.

mod access;
mod discovery;

use crate::{AuthContext, CorePolicy, Store, StoreIdentity, support::Catalog, tls::TlsMaterial};
use axum::Router;
use dissect3d_api::{DiscoveryCapability, EngineInfo, EnginePhase, PlatformInfo};
use dissect3d_platform::{OwnedRoot, PlatformError};
use hyper::server::conn::http1;
use hyper_util::{rt::TokioIo, service::TowerToHyperService};
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, oneshot};
use tokio::task::JoinSet;
use tokio_rustls::{TlsAcceptor, rustls::ServerConfig};

const MAX_CONNECTIONS: usize = 32;
const MAX_HEADER_BYTES: usize = 16_384;
const MAX_HEADERS: usize = 32;
const HEADER_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_BODY_BYTES: usize = 65_536;
const BODY_TIMEOUT: Duration = Duration::from_secs(4);

/// Ready HTTPS listener and the public trust material carried by discovery.
pub struct HttpServer {
    listener: TcpListener,
    router: Router,
    tls: Arc<ServerConfig>,
    ca_der: Vec<u8>,
    ca_sha256: [u8; 32],
    endpoint: SocketAddr,
    request_timeout: Duration,
}

#[derive(Clone)]
struct ServiceState {
    store: Arc<Store>,
    host: String,
    policy: CorePolicy,
    diagnostic_root: Arc<OwnedRoot>,
    diagnostic_permit: Arc<Semaphore>,
    catalog: Arc<Catalog>,
}

/// Authenticated data placed on a request after the access gate succeeds.
#[derive(Clone)]
pub(crate) struct AuthorizedRequest {
    pub(crate) identity: StoreIdentity,
    pub(crate) context: AuthContext,
}

impl HttpServer {
    /// Bind exactly numeric IPv4 loopback and prepare installation TLS material.
    pub async fn bind(
        root: &OwnedRoot,
        store: Arc<Store>,
        policy: CorePolicy,
    ) -> Result<Self, HttpError> {
        Self::bind_with_catalog(root, store, policy, Arc::new(Catalog::empty())).await
    }

    pub(crate) async fn bind_with_catalog(
        root: &OwnedRoot,
        store: Arc<Store>,
        policy: CorePolicy,
        catalog: Arc<Catalog>,
    ) -> Result<Self, HttpError> {
        let tls = TlsMaterial::load_or_create(root).map_err(|_| HttpError::Tls)?;
        let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .map_err(|_| HttpError::Bind)?;
        let endpoint = listener.local_addr().map_err(|_| HttpError::Bind)?;
        let host = format!("127.0.0.1:{}", endpoint.port());
        let request_timeout = Duration::from_millis(u64::from(policy.request_timeout_ms));
        let diagnostic_root =
            OwnedRoot::open(root.path(), dissect3d_platform::RootPurpose::EngineData)
                .map_err(|_| HttpError::Store)?;
        let state = Arc::new(ServiceState {
            store,
            host,
            policy,
            diagnostic_root: Arc::new(diagnostic_root),
            diagnostic_permit: Arc::new(Semaphore::new(1)),
            catalog,
        });
        let router = access::router(state);
        Ok(Self {
            listener,
            router,
            tls: tls.server,
            ca_der: tls.ca_der,
            ca_sha256: tls.ca_sha256,
            endpoint,
            request_timeout,
        })
    }

    pub fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }

    pub fn base_url(&self) -> String {
        format!("https://127.0.0.1:{}", self.endpoint.port())
    }

    pub fn trust_anchor(&self) -> (&[u8], &[u8; 32]) {
        (&self.ca_der, &self.ca_sha256)
    }

    /// Serve bounded connections until the owner requests shutdown.
    pub async fn run(self, shutdown: oneshot::Receiver<()>) -> Result<(), HttpError> {
        let (deadline_tx, deadline_rx) = oneshot::channel();
        tokio::spawn(async move {
            if shutdown.await.is_ok() {
                let _ = deadline_tx.send(Instant::now() + Duration::from_secs(5));
            }
        });
        self.run_with_ready(deadline_rx, None).await
    }

    /// Start accepting HTTPS requests, signal readiness, then serve until stop.
    pub async fn run_with_ready(
        self,
        mut shutdown: oneshot::Receiver<Instant>,
        ready: Option<oneshot::Sender<()>>,
    ) -> Result<(), HttpError> {
        let acceptor = TlsAcceptor::from(self.tls);
        let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        let mut connections = JoinSet::new();
        if let Some(ready) = ready {
            let _ = ready.send(());
        }
        let drain_deadline = loop {
            while connections.try_join_next().is_some() {}
            let accepted = tokio::select! {
                deadline = &mut shutdown => break deadline.unwrap_or_else(|_| Instant::now()),
                accepted = self.listener.accept() => accepted.map_err(|_| HttpError::Accept)?,
            };
            let (stream, peer) = accepted;
            // Binding to 127.0.0.1 is the primary boundary; reject any socket
            // peer that the OS reports outside that numeric loopback address.
            if peer.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST) {
                continue;
            }
            let Ok(permit) = permits.clone().try_acquire_owned() else {
                drop(stream);
                continue;
            };
            let acceptor = acceptor.clone();
            let router = self.router.clone();
            let request_timeout = self.request_timeout;
            connections.spawn(async move {
                let _permit = permit;
                // One request is served per connection. Start the accepted
                // request budget at socket admission so headers, body,
                // handler work, and the HTTP response share one deadline.
                let _ = tokio::time::timeout(
                    request_timeout,
                    serve_connection(stream, acceptor, router),
                )
                .await;
            });
        };
        // Accepted requests share the intent deadline; no new stage receives
        // a fresh grace period after slow headers or bodies consume the budget.
        // Idle
        // keep-alive connections are disabled, and a final deadline bounds
        // the process lifetime if a peer stalls at the TLS or HTTP boundary.
        while !connections.is_empty() {
            tokio::select! {
                _ = tokio::time::sleep_until(drain_deadline.into()) => {
                    connections.abort_all();
                    break;
                }
                _ = connections.join_next() => {}
            }
        }
        while connections.join_next().await.is_some() {}
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HttpError {
    Catalog,
    Bind,
    Accept,
    Tls,
    Store,
}

async fn serve_connection(stream: TcpStream, acceptor: TlsAcceptor, router: Router) {
    let Ok(Ok(stream)) =
        tokio::time::timeout(Duration::from_secs(5), acceptor.accept(stream)).await
    else {
        return;
    };
    let service = TowerToHyperService::new(router);
    let mut builder = http1::Builder::new();
    builder
        .max_header_size(MAX_HEADER_BYTES)
        .max_headers(MAX_HEADERS)
        .header_read_timeout(HEADER_TIMEOUT)
        .keep_alive(false)
        .timer(hyper_util::rt::TokioTimer::new());
    let _ = builder
        .serve_connection(TokioIo::new(stream), service)
        .await;
}

pub(crate) async fn engine_info(
    identity: StoreIdentity,
    context: AuthContext,
    policy: &CorePolicy,
    stopping: bool,
) -> EngineInfo {
    let supported_operations = vec![
        "engine.info".to_owned(),
        "auth.status".to_owned(),
        "auth.revoke_self".to_owned(),
        "engine.shutdown".to_owned(),
        "operation.show_own".to_owned(),
    ];
    let granted_operations = context
        .granted_operations()
        .iter()
        .filter(|grant| supported_operations.contains(grant))
        .cloned()
        .collect();
    let mut limits = BTreeMap::new();
    limits.insert(
        "store_queue_capacity".to_owned(),
        policy.queue_capacity as u64,
    );
    limits.insert(
        "sqlite_busy_timeout_ms".to_owned(),
        policy.busy_timeout_ms as u64,
    );
    limits.insert(
        "maximum_store_value_bytes".to_owned(),
        policy.maximum_value_bytes as u64,
    );
    limits.insert(
        "control_response_bytes".to_owned(),
        policy.control_response_bytes as u64,
    );
    limits.insert(
        "request_timeout_ms".to_owned(),
        policy.request_timeout_ms as u64,
    );
    limits.insert(
        "shutdown_timeout_ms".to_owned(),
        policy.shutdown_timeout_ms as u64,
    );
    limits.insert("http_header_bytes".to_owned(), MAX_HEADER_BYTES as u64);
    limits.insert("http_header_count".to_owned(), MAX_HEADERS as u64);
    limits.insert("http_body_bytes".to_owned(), MAX_BODY_BYTES as u64);
    limits.insert("http_connections".to_owned(), MAX_CONNECTIONS as u64);
    limits.insert("diagnostic_log_file_bytes".to_owned(), 1_048_576);
    limits.insert("diagnostic_log_files".to_owned(), 3);
    limits.insert(
        "credential_rows".to_owned(),
        crate::store::MAX_CREDENTIAL_ROWS as u64,
    );
    limits.insert(
        "core_operation_rows".to_owned(),
        crate::store::MAX_CORE_OPERATION_ROWS as u64,
    );
    limits.insert("inventory_page_default".to_owned(), 20);
    limits.insert("inventory_page_max".to_owned(), 100);
    limits.insert("catalog_records_max".to_owned(), 1024);
    limits.insert("catalog_bytes_max".to_owned(), 8_388_608);
    limits.insert("inventory_record_bytes_max".to_owned(), 196_608);
    limits.insert("inventory_cursor_bytes_max".to_owned(), 1024);
    limits.insert("inventory_query_bytes_max".to_owned(), 4096);
    limits.insert(
        "recovery_backup_bytes".to_owned(),
        crate::store::RECOVERY_BACKUP_LIMIT_BYTES as u64,
    );
    limits.insert(
        "bootstrap_frame_bytes".to_owned(),
        dissect3d_platform::MAX_BOOTSTRAP_FRAME_BYTES as u64,
    );
    limits.insert(
        "bootstrap_timeout_ms".to_owned(),
        crate::bootstrap::BOOTSTRAP_FRAME_TIMEOUT.as_millis() as u64,
    );
    // The current native server processes one frame at a time, within the
    // accepted admission ceiling. Do not advertise parallel handling it lacks.
    limits.insert("bootstrap_connections".to_owned(), 1);
    EngineInfo {
        api_version: "1.0".to_owned(),
        engine_version: env!("CARGO_PKG_VERSION").to_owned(),
        installation_id: identity.installation_id,
        instance_id: identity.instance_id,
        phase: if stopping {
            EnginePhase::Stopping
        } else {
            EnginePhase::Ready
        },
        supported_operations,
        granted_operations,
        required_features: Vec::new(),
        limits,
        limits_source: Some("built_in".to_owned()),
        platform: PlatformInfo {
            os: std::env::consts::OS.to_owned(),
            architecture: std::env::consts::ARCH.to_owned(),
        },
        discovery: Some(DiscoveryCapability {
            version: "1.0".to_owned(),
            operations: vec![
                "models.list".to_owned(),
                "models.show".to_owned(),
                "runtimes.list".to_owned(),
                "runtimes.show".to_owned(),
                "tasks.list".to_owned(),
                "tasks.show".to_owned(),
            ],
            authorization_grant: "engine.info".to_owned(),
        }),
    }
}

impl From<PlatformError> for HttpError {
    fn from(_: PlatformError) -> Self {
        Self::Tls
    }
}

#[cfg(test)]
mod limit_tests {
    use super::*;
    #[tokio::test]
    async fn engine_info_reports_enforced_policy_and_its_source() {
        let identity = StoreIdentity {
            installation_id: dissect3d_api::InstallationId::parse(
                "ins_0123456789abcdef0123456789abcdef",
            )
            .unwrap(),
            instance_id: dissect3d_api::InstanceId::parse("eng_0123456789abcdef0123456789abcdef")
                .unwrap(),
        };
        let context = AuthContext {
            installation_id: identity.installation_id.clone(),
            client_id: dissect3d_api::ClientId::parse("cli_0123456789abcdef0123456789abcdef")
                .unwrap(),
            granted_operations: Vec::new(),
        };
        let info = engine_info(identity, context, &CorePolicy::default(), false).await;
        assert_eq!(info.limits_source.as_deref(), Some("built_in"));
        for (key, expected) in [
            ("credential_rows", 1024),
            ("core_operation_rows", 16384),
            ("recovery_backup_bytes", 268435456),
            ("bootstrap_frame_bytes", 16384),
            ("bootstrap_timeout_ms", 5000),
            ("bootstrap_connections", 1),
        ] {
            assert_eq!(info.limits[key], expected, "{key}");
        }
    }
}
