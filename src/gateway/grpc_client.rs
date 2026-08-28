//! gRPC management client for the SCG gateway.
//!
//! Wraps [`scg_client`] to provision/close UDS and SHM endpoints and probe
//! gateway health via the management API. A lightweight facade so the rest of
//! SESHAT never imports tonic/prost directly.

use std::path::{Path, PathBuf};
use std::time::Duration;

use scg_client::ScgClient;

// Re-export scg-client types for use in transport modules.
pub use scg_client::{Direction, TrafficClass, Transport as ScgTransport};

/// A connected management client.
///
/// Holds only the path to the gateway's management UDS socket; each operation
/// creates a short-lived tokio runtime internally (the `scg-client` pattern).
pub struct MgmtClient {
    socket_path: PathBuf,
}

/// Result of provisioning a UDS endpoint.
pub struct UdsEndpoint {
    pub client: ScgClient,
    pub endpoint_id: u32,
}

/// Result of provisioning a SHM endpoint.
pub struct ShmEndpoint {
    pub client: ScgClient,
    pub endpoint_id: u32,
}

impl MgmtClient {
    /// Create a management client for the given gateway socket path.
    pub fn new(socket_path: &Path) -> Self {
        MgmtClient {
            socket_path: socket_path.to_path_buf(),
        }
    }

    /// Provision a UDS endpoint and return the connected data-plane client.
    pub fn create_uds(
        &self,
        app_id: &str,
        class: TrafficClass,
        direction: Direction,
    ) -> Result<UdsEndpoint, String> {
        let client = ScgClient::connect(
            Some(&self.socket_path),
            app_id,
            ScgTransport::Uds,
            class,
            direction,
        )
        .map_err(|e| format!("UDS endpoint creation failed: {e}"))?;
        let endpoint_id = client.endpoint_id();
        Ok(UdsEndpoint {
            client,
            endpoint_id,
        })
    }

    /// Provision a SHM endpoint and return the connected data-plane client.
    pub fn create_shm(
        &self,
        app_id: &str,
        class: TrafficClass,
        direction: Direction,
        ring_capacity: u64,
    ) -> Result<ShmEndpoint, String> {
        let client = ScgClient::connect_with_capacity(
            Some(&self.socket_path),
            app_id,
            ScgTransport::Shm,
            class,
            direction,
            ring_capacity,
        )
        .map_err(|e| format!("SHM endpoint creation failed: {e}"))?;
        let endpoint_id = client.endpoint_id();
        Ok(ShmEndpoint {
            client,
            endpoint_id,
        })
    }

    /// Close a previously provisioned endpoint by its ID.
    ///
    /// Note: normally endpoints are closed via `ScgClient::close()` (which
    /// deregisters on drop). This method is for forceful cleanup of an endpoint
    /// ID when the ScgClient is no longer held.
    pub fn close_endpoint(&self, endpoint_id: u32) -> Result<(), String> {
        close_endpoint_impl(&self.socket_path, endpoint_id)
    }

    /// Health-check: attempt to list rules (lightweight query). Returns `true`
    /// if the gateway responds without error.
    pub fn health(&self) -> bool {
        // scg-client does not expose a direct health() wrapper — we probe by
        // attempting a minimal gRPC round-trip (create + immediately close an
        // endpoint). Instead, we use the lower-level proto client directly.
        health_probe(&self.socket_path)
    }

    /// List the names of all configured rules on the gateway.
    pub fn list_rules(&self) -> Result<Vec<String>, String> {
        list_rules_impl(&self.socket_path)
    }

    /// Wait until the gateway management API becomes reachable (or timeout).
    pub fn wait_ready(&self, timeout: Duration) -> Result<(), String> {
        let deadline = std::time::Instant::now() + timeout;
        let poll_interval = Duration::from_millis(50);
        while std::time::Instant::now() < deadline {
            if self.health() {
                return Ok(());
            }
            std::thread::sleep(poll_interval);
        }
        Err(format!(
            "gateway management API at {:?} not reachable within {timeout:?}",
            self.socket_path
        ))
    }
}

// --- Low-level gRPC helpers (use a short-lived tokio runtime) ---

fn build_runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime: {e}"))
}

/// Dial the management socket over UDS.
async fn dial(
    path: &Path,
) -> Result<
    scg_proto::v1::management_api_client::ManagementApiClient<tonic::transport::Channel>,
    String,
> {
    use hyper_util::rt::TokioIo;
    use tonic::transport::{Endpoint, Uri};
    use tower::service_fn;

    let path = path.to_path_buf();
    let path_for_err = path.clone();
    let channel = Endpoint::try_from("http://[::]:50051")
        .map_err(|e| format!("endpoint URI: {e}"))?
        .connect_with_connector(service_fn(move |_: Uri| {
            let path = path.clone();
            async move {
                let stream = tokio::net::UnixStream::connect(&path).await?;
                Ok::<_, std::io::Error>(TokioIo::new(stream))
            }
        }))
        .await
        .map_err(|e| format!("gRPC dial {:?}: {e}", path_for_err))?;
    Ok(scg_proto::v1::management_api_client::ManagementApiClient::new(channel))
}

fn health_probe(socket_path: &Path) -> bool {
    let Ok(rt) = build_runtime() else {
        return false;
    };
    rt.block_on(async {
        let Ok(mut client) = dial(socket_path).await else {
            return false;
        };
        client.health(scg_proto::v1::HealthRequest {}).await.is_ok()
    })
}

fn list_rules_impl(socket_path: &Path) -> Result<Vec<String>, String> {
    let rt = build_runtime()?;
    rt.block_on(async {
        let mut client = dial(socket_path).await?;
        let resp = client
            .list_rules(scg_proto::v1::ListRulesRequest {})
            .await
            .map_err(|e| format!("list_rules: {e}"))?
            .into_inner();
        Ok(resp.rules.into_iter().map(|r| r.name).collect())
    })
}

fn close_endpoint_impl(socket_path: &Path, endpoint_id: u32) -> Result<(), String> {
    let rt = build_runtime()?;
    rt.block_on(async {
        let mut client = dial(socket_path).await?;
        client
            .close_endpoint(scg_proto::v1::CloseEndpointRequest { endpoint_id })
            .await
            .map_err(|e| format!("close endpoint {endpoint_id}: {e}"))?;
        Ok(())
    })
}
