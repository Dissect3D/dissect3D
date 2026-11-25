//! Engine lifetime composition from protected root through ready publication.
//!
//! Startup establishes one lease and a recovered store before opening either
//! service channel. Discovery appears only after native bootstrap and HTTPS
//! listeners are bound and the HTTPS accept loop acknowledges readiness.

use crate::{BootstrapServeError, CorePolicy, HttpError, HttpServer, Store};
use dissect3d_api::{
    BootstrapAddress, DiscoveryRecord, MAX_DISCOVERY_BYTES, ProcessReference, decode_json,
};
use dissect3d_platform::{
    AuthorityLease, BootstrapEndpoint, BootstrapListener, OwnedRoot, PlatformError, RelativePath,
    RootPurpose, current_process_identity,
};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot};

const DISCOVERY_FILE: &str = "run/endpoint.json";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartupError {
    Root,
    Authority,
    Store,
    Bootstrap,
    Https,
    Discovery,
    Runtime,
    ShutdownDeadline,
    #[cfg(feature = "test-support")]
    Fixture(crate::submission_fixture::FixtureError),
}

impl StartupError {
    /// Safe, stable diagnostic category suitable for the process error stream.
    pub const fn safe_code(self) -> &'static str {
        match self {
            Self::Root => "protected_storage_unavailable",
            Self::Authority => "authority_unavailable",
            Self::Store => "persistence_unavailable",
            Self::Bootstrap => "bootstrap_unavailable",
            Self::Https => "https_unavailable",
            Self::Discovery => "discovery_unavailable",
            Self::Runtime => "runtime_unavailable",
            Self::ShutdownDeadline => "shutdown_unconfirmed",
            #[cfg(feature = "test-support")]
            Self::Fixture(error) => error.safe_code(),
        }
    }
}

impl From<PlatformError> for StartupError {
    fn from(_: PlatformError) -> Self {
        Self::Root
    }
}

impl From<HttpError> for StartupError {
    fn from(_: HttpError) -> Self {
        Self::Https
    }
}

/// Run one engine instance until its owner asks the process to exit.
pub async fn run_engine(data_root: &Path) -> Result<(), StartupError> {
    run_engine_with_catalog(data_root, crate::support::Catalog::empty()).await
}

/// Isolated synthetic HTTPS host used by connected support-discovery tests.
#[cfg(feature = "test-support")]
pub async fn run_discovery_test_engine(data_root: &Path) -> Result<(), StartupError> {
    let catalog = crate::support::test_support::catalog().map_err(|_| StartupError::Discovery)?;
    run_engine_with_catalog(data_root, catalog).await
}

/// Supplementary ambiguity/pagination host; has no prepared admission fixture.
#[cfg(feature = "test-support")]
pub async fn run_selection_test_engine(data_root: &Path) -> Result<(), StartupError> {
    let catalog =
        crate::support::test_support::selection_catalog().map_err(|_| StartupError::Discovery)?;
    run_engine_with_catalog(data_root, catalog).await
}

/// Isolated host composition backed by an explicitly prepared CPU fixture.
#[cfg(feature = "test-support")]
pub async fn run_submission_test_engine(data_root: &Path) -> Result<(), StartupError> {
    dissect3d_platform::ensure_independent_engine().map_err(|_| StartupError::Runtime)?;
    if !data_root.is_absolute() {
        return Err(StartupError::Root);
    }
    let root = if data_root.exists() {
        OwnedRoot::open(data_root, RootPurpose::EngineData)
    } else {
        OwnedRoot::create_private(data_root, RootPurpose::EngineData)
    }
    .map_err(|_| StartupError::Root)?;
    let diagnostic_path = data_root.to_path_buf();
    let result = async {
        let lease = AuthorityLease::acquire(&root).map_err(|_| StartupError::Authority)?;
        let probe =
            crate::submission_fixture::fixture_probe_sibling().map_err(StartupError::Fixture)?;
        let fixture = crate::submission_fixture::load_prepared_fixture(&root, &probe)
            .map_err(StartupError::Fixture)?;
        run_engine_with_lease(
            data_root,
            root,
            lease,
            Arc::new(fixture.catalog),
            Some(fixture.readiness),
        )
        .await
    }
    .await;
    if let Err(error) = result
        && let Ok(root) = OwnedRoot::open(&diagnostic_path, RootPurpose::EngineData)
    {
        crate::diagnostics::record_startup_failure(&root, error);
    }
    result
}

/// Isolated execution host backed by the explicitly prepared r2 package
/// (WE-P06/WE-P09): prepared admission plus the controller, so accepted jobs
/// dispatch to the contained r2 worker. Never the normal composition.
#[cfg(all(unix, feature = "test-support"))]
pub async fn run_execution_test_engine(data_root: &Path) -> Result<(), StartupError> {
    dissect3d_platform::ensure_independent_engine().map_err(|_| StartupError::Runtime)?;
    if !data_root.is_absolute() {
        return Err(StartupError::Root);
    }
    let root =
        OwnedRoot::open(data_root, RootPurpose::EngineData).map_err(|_| StartupError::Root)?;
    let diagnostic_path = data_root.to_path_buf();
    let result = async {
        let lease = AuthorityLease::acquire(&root).map_err(|_| StartupError::Authority)?;
        let fixture =
            crate::execution_fixture::preparation::load(&root).map_err(StartupError::Fixture)?;
        run_engine_inner(
            data_root,
            root,
            lease,
            Composition::Execution(Box::new(fixture)),
        )
        .await
    }
    .await;
    if let Err(error) = result
        && let Ok(root) = OwnedRoot::open(&diagnostic_path, RootPurpose::EngineData)
    {
        crate::diagnostics::record_startup_failure(&root, error);
    }
    result
}

async fn run_engine_with_catalog(
    data_root: &Path,
    catalog: crate::support::Catalog,
) -> Result<(), StartupError> {
    dissect3d_platform::ensure_independent_engine().map_err(|_| StartupError::Runtime)?;
    if !data_root.is_absolute() {
        return Err(StartupError::Root);
    }
    let root = if data_root.exists() {
        OwnedRoot::open(data_root, RootPurpose::EngineData)
    } else {
        OwnedRoot::create_private(data_root, RootPurpose::EngineData)
    }
    .map_err(|_| StartupError::Root)?;
    let diagnostic_path = data_root.to_path_buf();
    let result = run_engine_with_root(data_root, root, Arc::new(catalog)).await;
    if let Err(error) = result
        && let Ok(root) = OwnedRoot::open(&diagnostic_path, RootPurpose::EngineData)
    {
        crate::diagnostics::record_startup_failure(&root, error);
    }
    result
}

async fn run_engine_with_root(
    data_root: &Path,
    root: OwnedRoot,
    catalog: Arc<crate::support::Catalog>,
) -> Result<(), StartupError> {
    let lease = AuthorityLease::acquire(&root).map_err(|_| StartupError::Authority)?;
    #[cfg(feature = "test-support")]
    return run_engine_with_lease(data_root, root, lease, catalog, None).await;
    #[cfg(not(feature = "test-support"))]
    run_engine_with_lease(data_root, root, lease, catalog).await
}

/// What the HTTP host is composed with.
enum Composition {
    Catalog(Arc<crate::support::Catalog>),
    #[cfg(feature = "test-support")]
    Prepared(
        Arc<crate::support::Catalog>,
        Box<crate::submission_fixture::PreparedReadiness>,
    ),
    #[cfg(all(unix, feature = "test-support"))]
    Execution(Box<crate::execution_fixture::preparation::PreparedExecutionFixture>),
}

pub(crate) async fn run_engine_with_lease(
    data_root: &Path,
    root: OwnedRoot,
    lease: AuthorityLease,
    catalog: Arc<crate::support::Catalog>,
    #[cfg(feature = "test-support")] prepared_readiness: Option<
        crate::submission_fixture::PreparedReadiness,
    >,
) -> Result<(), StartupError> {
    #[cfg(feature = "test-support")]
    let composition = match prepared_readiness {
        Some(readiness) => Composition::Prepared(catalog, Box::new(readiness)),
        None => Composition::Catalog(catalog),
    };
    #[cfg(not(feature = "test-support"))]
    let composition = Composition::Catalog(catalog);
    run_engine_inner(data_root, root, lease, composition).await
}

async fn run_engine_inner(
    data_root: &Path,
    root: OwnedRoot,
    lease: AuthorityLease,
    composition: Composition,
) -> Result<(), StartupError> {
    // Register before publishing readiness so an immediate interrupt is queued.
    #[cfg(unix)]
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .map_err(|_| StartupError::Runtime)?;
    #[cfg(windows)]
    let mut interrupt = tokio::signal::windows::ctrl_c().map_err(|_| StartupError::Runtime)?;
    let (shutdown_intent, mut shutdown_requested) = mpsc::unbounded_channel();
    let store = Arc::new(
        Store::open_with_shutdown(root, lease, &CorePolicy::default(), Some(shutdown_intent))
            .map_err(|_| StartupError::Store)?,
    );
    let identity = store.identity().map_err(|_| StartupError::Store)?;
    let service_root =
        OwnedRoot::open(data_root, RootPurpose::EngineData).map_err(|_| StartupError::Root)?;
    let bootstrap = BootstrapListener::bind(&service_root, identity.instance_id.as_str())
        .map_err(|_| StartupError::Bootstrap)?;
    let bootstrap_endpoint = discovery_bootstrap(bootstrap.endpoint())?;
    // The execution controller, when this host composes one (WE-P07/3).
    #[cfg(all(unix, feature = "test-support"))]
    let mut execution: Option<Arc<crate::execution::controller::ExecutionHandle>> = None;
    let server = match composition {
        Composition::Catalog(catalog) => {
            HttpServer::bind_with_catalog(
                &service_root,
                store.clone(),
                CorePolicy::default(),
                catalog,
            )
            .await
        }
        #[cfg(feature = "test-support")]
        Composition::Prepared(catalog, readiness) => {
            HttpServer::bind_with_prepared_catalog(
                &service_root,
                store.clone(),
                CorePolicy::default(),
                catalog,
                *readiness,
            )
            .await
        }
        #[cfg(all(unix, feature = "test-support"))]
        Composition::Execution(mut fixture) => {
            let catalog = Arc::new(std::mem::replace(
                &mut fixture.catalog,
                crate::support::Catalog::empty(),
            ));
            let readiness = fixture.readiness.clone();
            let attempts_root = Arc::new(
                OwnedRoot::open(data_root, RootPurpose::EngineData)
                    .map_err(|_| StartupError::Root)?,
            );
            // WE-P07/4: earlier workers are reconciled before any dispatch.
            let recovery_store = store.clone();
            tokio::task::spawn_blocking(move || {
                crate::execution::recovery::reconcile(&recovery_store)
            })
            .await
            .map_err(|_| StartupError::Runtime)?
            .map_err(|_| StartupError::Store)?;
            let handle = crate::execution::controller::start(
                crate::execution::controller::ExecutionDependencies {
                    store: store.clone(),
                    root: Arc::clone(&attempts_root),
                    source: Arc::new(crate::execution_fixture::attempts::FixtureAttempts::new(
                        *fixture,
                        attempts_root,
                    )),
                    limits: crate::execution::controller::ExecutionLimits::CONTROLLED,
                },
            );
            let handle = Arc::new(handle);
            execution = Some(Arc::clone(&handle));
            HttpServer::bind_with_execution(
                &service_root,
                store.clone(),
                CorePolicy::default(),
                catalog,
                readiness,
                handle,
            )
            .await
        }
    }
    .map_err(|_| StartupError::Https)?;
    let process = current_process_identity().map_err(|_| StartupError::Runtime)?;
    let service_instance_id = identity.instance_id.clone();
    let (ca_der, ca_sha256) = server.trust_anchor();
    let discovery = DiscoveryRecord {
        discovery_version: "1.0".to_owned(),
        installation_id: identity.installation_id,
        instance_id: identity.instance_id,
        base_url: server.base_url(),
        bootstrap_endpoint,
        process: ProcessReference {
            pid: process.pid,
            start_marker: process.start_marker,
        },
        trust_anchor_der: ca_der.to_vec(),
        trust_anchor_sha256: ca_sha256.to_vec(),
    };
    let encoded = serde_json::to_vec(&discovery).map_err(|_| StartupError::Discovery)?;
    // Never publish a record that clients must refuse to read (CSC-006).
    if encoded.len() > MAX_DISCOVERY_BYTES {
        return Err(StartupError::Discovery);
    }
    let discovery_path =
        RelativePath::parse(DISCOVERY_FILE).map_err(|_| StartupError::Discovery)?;

    let running = Arc::new(AtomicBool::new(true));
    let bootstrap_running = running.clone();
    let native_cancelled = Arc::new(AtomicBool::new(false));
    let bootstrap_cancelled = native_cancelled.clone();
    let bootstrap_store = store.clone();
    let bootstrap_thread = std::thread::Builder::new()
        .name("dissect3d-bootstrap".to_owned())
        .spawn(move || {
            while bootstrap_running.load(Ordering::Acquire) {
                match crate::bootstrap::serve_bootstrap_once_with_cancel(
                    &bootstrap,
                    &bootstrap_store,
                    Duration::from_millis(250),
                    Some(bootstrap_cancelled.clone()),
                ) {
                    Ok(())
                    | Err(BootstrapServeError::Accept | BootstrapServeError::Read)
                    | Err(BootstrapServeError::Encode | BootstrapServeError::Write) => {}
                }
            }
        })
        .map_err(|_| StartupError::Bootstrap)?;

    let (stop_http, stop_http_rx) = oneshot::channel();
    let (http_ready, http_ready_rx) = oneshot::channel();
    let mut http_task = tokio::spawn(server.run_with_ready(stop_http_rx, Some(http_ready)));
    if http_ready_rx.await.is_err() {
        running.store(false, Ordering::Release);
        native_cancelled.store(true, Ordering::Release);
        let _ = stop_http.send(Instant::now());
        let _ = tokio::task::spawn_blocking(move || bootstrap_thread.join()).await;
        let _ = http_task.await;
        return Err(StartupError::Https);
    }
    if service_root
        .write_atomic(&discovery_path, &encoded)
        .is_err()
    {
        running.store(false, Ordering::Release);
        native_cancelled.store(true, Ordering::Release);
        let _ = stop_http.send(Instant::now());
        let _ = tokio::task::spawn_blocking(move || bootstrap_thread.join()).await;
        let _ = http_task.await;
        return Err(StartupError::Discovery);
    }

    let shutdown_request = async {
        tokio::select! {
            signal = interrupt.recv() => {
                signal.ok_or(StartupError::Runtime)?;
                let signal_store = store.clone();
                tokio::task::spawn_blocking(move || signal_store.signal_shutdown(
                    service_instance_id, CorePolicy::default().shutdown_timeout_ms,
                )).await.map_err(|_| StartupError::Runtime)?.map_err(|_| StartupError::Store)
            },
            deadline = shutdown_requested.recv() => deadline.ok_or(StartupError::Store),
        }
    };
    let end = supervise_http(shutdown_request, &mut http_task).await;
    running.store(false, Ordering::Release);
    native_cancelled.store(true, Ordering::Release);
    let drain_deadline = match &end {
        LifetimeEnd::Shutdown(Ok(deadline)) => *deadline,
        _ => Instant::now(),
    };
    let _ = stop_http.send(drain_deadline);
    // WE-005: running attempts stop within the same core deadline, before
    // the final store/session completion. An early end (HTTP failure) still
    // stops them, with a fresh bounded deadline; its result is an error anyway.
    #[cfg(all(unix, feature = "test-support"))]
    let execution_stop = match &execution {
        Some(handle) => {
            let deadline = match &end {
                LifetimeEnd::Shutdown(Ok(deadline)) => *deadline,
                _ => {
                    Instant::now()
                        + Duration::from_millis(u64::from(
                            CorePolicy::default().shutdown_timeout_ms,
                        ))
                }
            };
            handle.shutdown(deadline).await
        }
        None => crate::execution::controller::ShutdownOutcome::Clean,
    };
    // Always stop both channels, including signal/storage and HTTP-task errors.
    let bootstrap_result = tokio::task::spawn_blocking(move || bootstrap_thread.join()).await;
    let result = match end {
        LifetimeEnd::HttpEnded => Err(StartupError::Https),
        LifetimeEnd::Shutdown(result) => match http_task.await {
            Ok(Ok(())) => result.and_then(|deadline| {
                if Instant::now() >= deadline {
                    Err(StartupError::ShutdownDeadline)
                } else {
                    Ok(())
                }
            }),
            Ok(Err(_)) => Err(StartupError::Https),
            Err(_) => Err(StartupError::Runtime),
        },
    };
    let result = result.and({
        if matches!(bootstrap_result, Ok(Ok(()))) {
            Ok(())
        } else {
            Err(StartupError::Runtime)
        }
    });
    // Uncertain worker cleanup is never a clean shutdown (WE-005).
    #[cfg(all(unix, feature = "test-support"))]
    let result = result.and(
        if execution_stop == crate::execution::controller::ShutdownOutcome::Clean {
            Ok(())
        } else {
            Err(StartupError::ShutdownDeadline)
        },
    );
    let result = match result {
        Ok(()) => {
            let completion_store = store.clone();
            let instance = discovery.instance_id.clone();
            tokio::task::spawn_blocking(move || completion_store.complete_shutdown(instance))
                .await
                .map_err(|_| StartupError::Runtime)
                .and_then(|result| result.map_err(|_| StartupError::Store))
        }
        Err(error) => Err(error),
    };
    retire_discovery(&service_root, &discovery_path, &discovery);
    result
}

enum LifetimeEnd {
    Shutdown(Result<Instant, StartupError>),
    HttpEnded,
}

async fn supervise_http(
    shutdown: impl std::future::Future<Output = Result<Instant, StartupError>>,
    http: &mut tokio::task::JoinHandle<Result<(), HttpError>>,
) -> LifetimeEnd {
    tokio::select! {
        result = shutdown => LifetimeEnd::Shutdown(result),
        _ = http => LifetimeEnd::HttpEnded,
    }
}

fn retire_discovery(
    service_root: &OwnedRoot,
    discovery_path: &RelativePath,
    discovery: &DiscoveryRecord,
) {
    if let Ok(bytes) = service_root.read_file(discovery_path, MAX_DISCOVERY_BYTES)
        && let Ok(published) = decode_json::<DiscoveryRecord>(&bytes)
        && published.instance_id == discovery.instance_id
        && published.process.pid == discovery.process.pid
        && published.process.start_marker == discovery.process.start_marker
    {
        let _ = service_root.remove_file(discovery_path);
    }
}

fn discovery_bootstrap(endpoint: &BootstrapEndpoint) -> Result<BootstrapAddress, StartupError> {
    match endpoint {
        BootstrapEndpoint::Unix { path } => Ok(BootstrapAddress::Unix {
            path: path.to_str().ok_or(StartupError::Discovery)?.to_owned(),
        }),
        BootstrapEndpoint::WindowsPipe { name } => {
            Ok(BootstrapAddress::WindowsPipe { name: name.clone() })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn http_failure_is_observed_without_a_shutdown_request() {
        let mut http = tokio::spawn(async { Err(HttpError::Accept) });
        let end = tokio::time::timeout(
            Duration::from_secs(1),
            supervise_http(std::future::pending(), &mut http),
        )
        .await
        .unwrap();
        assert!(matches!(end, LifetimeEnd::HttpEnded));
    }
}
