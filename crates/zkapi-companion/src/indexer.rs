//! The operator's indexer. Every call is bounded (design §6.4 E0): the
//! indexer is operator-run, and the mutual close and request preparation
//! read it while holding the wallet's locks, which every exit route takes
//! too. A call that connects and never answers, or drips its body, fails
//! after `CALL_TIMEOUT` instead of holding those locks. Note lookups download
//! the same whole-tree snapshot as the browser and derive paths locally;
//! no note ID is sent to the indexer, even if the snapshot is unavailable.

use std::time::{Duration, Instant};

use serde::Deserialize;
use zkapi_core::merkle::MerkleTree;
use zkapi_types::Felt252;

use crate::error::AuthError;

/// E0's `CALL_TIMEOUT`, connect and full body included (shortened in tests,
/// like the exit routes' own bound).
#[cfg(not(test))]
pub(crate) const CALL_TIMEOUT: Duration =
    Duration::from_secs(zkapi_client::exit_policy::CALL_TIMEOUT_SECONDS);
#[cfg(test)]
pub(crate) const CALL_TIMEOUT: Duration = Duration::from_millis(1_500);

// Match clientd's whole-tree response limit, including retired (zero) leaves.
const RESPONSE_LIMIT: usize = 32 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct IndexerClient {
    base_url: String,
    http: reqwest::Client,
    timeout: Duration,
}

#[derive(Debug, Deserialize)]
struct TreeRootResponse {
    root: Felt252,
}

#[derive(Debug, Deserialize)]
struct TreeSnapshotResponse {
    root: Felt252,
    next_note_id: u32,
    leaves: Vec<Felt252>,
}

struct TreeSnapshot {
    tree: MerkleTree,
    next_note_id: u32,
}

impl TreeSnapshotResponse {
    fn verify(self, deadline: Instant) -> Result<TreeSnapshot, AuthError> {
        if self.leaves.len() != self.next_note_id as usize {
            return Err(AuthError::Indexer(
                "tree snapshot leaf count does not match next_note_id".into(),
            ));
        }
        let mut tree = MerkleTree::new();
        for (index, leaf) in self.leaves.into_iter().enumerate() {
            // Reconstruction runs off the async executor. Stop the blocking
            // work too when its caller times out, so a large reply cannot
            // keep doing hashes after the wallet locks have been released.
            if Instant::now() >= deadline {
                return Err(indexer_timeout());
            }
            tree.set_leaf(index as u32, leaf);
        }
        if Instant::now() >= deadline {
            return Err(indexer_timeout());
        }
        if tree.root() != self.root {
            return Err(AuthError::Indexer(
                "tree snapshot root verification failed".into(),
            ));
        }
        Ok(TreeSnapshot {
            tree,
            next_note_id: self.next_note_id,
        })
    }
}

fn indexer_timeout() -> AuthError {
    AuthError::Indexer("the indexer did not answer in time".into())
}

#[derive(Debug, Deserialize)]
struct NextNoteIdResponse {
    next_note_id: u32,
}

impl IndexerClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self::with_timeout(base_url, CALL_TIMEOUT)
    }

    /// An indexer client whose every call (connect and full body) is bounded
    /// by `timeout`.
    pub fn with_timeout(base_url: impl Into<String>, timeout: Duration) -> Self {
        let http = reqwest::Client::builder()
            .connect_timeout(timeout)
            .timeout(timeout)
            .build()
            .unwrap_or_default();
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            http,
            timeout,
        }
    }

    pub async fn root(&self) -> Result<Felt252, AuthError> {
        let payload: TreeRootResponse = self.get(format!("{}/v1/tree/root", self.base_url)).await?;
        Ok(payload.root)
    }

    /// The root and `note_id`'s path from one verified snapshot, within one
    /// call timeout (E0). The note ID is used only locally.
    pub async fn root_and_path(&self, note_id: u32) -> Result<(Felt252, Vec<Felt252>), AuthError> {
        let snapshot = self.snapshot().await?;
        if note_id >= snapshot.next_note_id {
            return Err(AuthError::Indexer(
                "requested note index is inconsistent with the tree snapshot".into(),
            ));
        }
        Ok((
            snapshot.tree.root(),
            snapshot.tree.get_siblings(note_id).to_vec(),
        ))
    }

    pub async fn next_note_id(&self) -> Result<u32, AuthError> {
        let payload: NextNoteIdResponse = self
            .get(format!("{}/v1/tree/next-note-id", self.base_url))
            .await?;
        Ok(payload.next_note_id)
    }

    /// The next deposit slot and its empty path, from the same verified view.
    pub async fn next_deposit_path(&self) -> Result<(u32, Felt252, Vec<Felt252>), AuthError> {
        let snapshot = self.snapshot().await?;
        Ok((
            snapshot.next_note_id,
            snapshot.tree.root(),
            snapshot.tree.get_siblings(snapshot.next_note_id).to_vec(),
        ))
    }

    /// Read a leaf locally from the verified snapshot; zero where no note is.
    pub async fn note_leaf(&self, note_id: u32) -> Result<Felt252, AuthError> {
        Ok(self.snapshot().await?.tree.get_leaf(note_id))
    }

    async fn snapshot(&self) -> Result<TreeSnapshot, AuthError> {
        let deadline = Instant::now() + self.timeout;
        tokio::time::timeout(self.timeout, async {
            let payload: TreeSnapshotResponse = self
                .get(format!("{}/v1/tree/snapshot", self.base_url))
                .await?;
            tokio::task::spawn_blocking(move || payload.verify(deadline))
                .await
                .map_err(|err| AuthError::Indexer(err.to_string()))?
        })
        .await
        .map_err(|_| indexer_timeout())?
    }

    async fn get<T: serde::de::DeserializeOwned>(&self, url: String) -> Result<T, AuthError> {
        let response = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|err| AuthError::Indexer(err.to_string()))?;
        let mut response = response
            .error_for_status()
            .map_err(|err| AuthError::Indexer(err.to_string()))?;
        if response
            .content_length()
            .is_some_and(|length| length > RESPONSE_LIMIT as u64)
        {
            return Err(AuthError::Indexer("indexer response is too large".into()));
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|err| AuthError::Indexer(err.to_string()))?
        {
            if chunk.len() > RESPONSE_LIMIT - body.len() {
                return Err(AuthError::Indexer("indexer response is too large".into()));
            }
            body.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&body).map_err(|err| AuthError::Indexer(err.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use axum::{
        body::Body,
        extract::Request,
        http::{header, StatusCode},
        response::{IntoResponse, Response},
        Router,
    };
    use serde_json::{json, Value};
    use zkapi_core::merkle::compute_root;

    use super::*;

    struct Server {
        client: IndexerClient,
        requests: Arc<Mutex<Vec<String>>>,
        task: tokio::task::JoinHandle<()>,
    }

    impl Drop for Server {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    impl Server {
        async fn new(reply: impl Fn() -> Response + Clone + Send + Sync + 'static) -> Self {
            let requests = Arc::new(Mutex::new(Vec::new()));
            let seen = requests.clone();
            let router = Router::new().fallback(move |request: Request| {
                let seen = seen.clone();
                let reply = reply.clone();
                async move {
                    assert_eq!(request.method(), "GET");
                    seen.lock().unwrap().push(request.uri().to_string());
                    assert!(axum::body::to_bytes(request.into_body(), 0)
                        .await
                        .unwrap()
                        .is_empty());
                    reply()
                }
            });
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let client = IndexerClient::new(format!("http://{}", listener.local_addr().unwrap()));
            let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
            Self {
                client,
                requests,
                task,
            }
        }

        async fn json(value: Value) -> Self {
            Self::new(move || axum::Json(value.clone()).into_response()).await
        }

        fn assert_only_snapshots(&self, count: usize) {
            assert_eq!(
                *self.requests.lock().unwrap(),
                vec!["/v1/tree/snapshot"; count],
                "all lookups must use the same URL, without a note ID or query"
            );
        }
    }

    fn snapshot(leaves: Vec<Felt252>) -> (Value, MerkleTree) {
        let mut tree = MerkleTree::new();
        for (id, leaf) in leaves.iter().enumerate() {
            tree.set_leaf(id as u32, *leaf);
        }
        (
            json!({"root": tree.root(), "next_note_id": leaves.len(), "leaves": leaves}),
            tree,
        )
    }

    #[tokio::test]
    async fn paths_leaves_and_deposits_never_disclose_the_selected_note() {
        let leaves = vec![Felt252::from_u64(41), Felt252::ZERO, Felt252::from_u64(43)];
        let (payload, tree) = snapshot(leaves.clone());
        let server = Server::json(payload).await;
        for (id, leaf) in leaves.iter().enumerate() {
            let (root, siblings) = server.client.root_and_path(id as u32).await.unwrap();
            assert_eq!(root, tree.root());
            assert_eq!(siblings, tree.get_siblings(id as u32));
            assert_eq!(
                compute_root(id as u32, leaf, &siblings.try_into().unwrap()),
                root
            );
            assert_eq!(server.client.note_leaf(id as u32).await.unwrap(), *leaf);
        }
        // The retired leaf stays at its original index; absent leaves are zero.
        assert_eq!(server.client.note_leaf(99).await.unwrap(), Felt252::ZERO);
        let (id, root, siblings) = server.client.next_deposit_path().await.unwrap();
        assert_eq!(id, 3);
        assert_eq!(
            compute_root(id, &Felt252::ZERO, &siblings.try_into().unwrap()),
            root
        );
        assert_eq!(root, tree.root());
        assert!(server.client.root_and_path(3).await.is_err());
        server.assert_only_snapshots(9);
    }

    #[tokio::test]
    async fn empty_snapshot_provides_the_first_deposit_path() {
        let (payload, tree) = snapshot(vec![]);
        let server = Server::json(payload).await;
        let (id, root, siblings) = server.client.next_deposit_path().await.unwrap();
        assert_eq!(id, 0);
        assert_eq!(root, tree.root());
        assert_eq!(siblings, tree.get_siblings(0));
        assert!(server.client.root_and_path(0).await.is_err());
        server.assert_only_snapshots(2);
    }

    #[tokio::test]
    async fn invalid_snapshots_fail_closed_for_every_lookup() {
        let (valid, _) = snapshot(vec![Felt252::ONE]);
        let mut wrong_count = valid.clone();
        wrong_count["next_note_id"] = json!(2);
        let mut wrong_root = valid.clone();
        wrong_root["root"] = json!(Felt252::ONE);
        let mut wrong_leaf = valid.clone();
        wrong_leaf["leaves"][0] = json!(Felt252::from_u64(2));
        let mut noncanonical_leaf = valid;
        noncanonical_leaf["leaves"][0] = json!(zkapi_types::FIELD_MODULUS_HEX);
        for payload in [
            wrong_count,
            wrong_root,
            wrong_leaf,
            noncanonical_leaf,
            json!({}),
        ] {
            let server = Server::json(payload).await;
            assert!(matches!(
                server.client.root_and_path(0).await,
                Err(AuthError::Indexer(_))
            ));
            assert!(matches!(
                server.client.note_leaf(0).await,
                Err(AuthError::Indexer(_))
            ));
            assert!(matches!(
                server.client.next_deposit_path().await,
                Err(AuthError::Indexer(_))
            ));
            server.assert_only_snapshots(3);
        }
    }

    #[tokio::test]
    async fn unavailable_snapshot_never_falls_back_to_note_endpoints() {
        for status in [StatusCode::NOT_FOUND, StatusCode::SERVICE_UNAVAILABLE] {
            let server = Server::new(move || status.into_response()).await;
            assert!(server.client.root_and_path(7).await.is_err());
            assert!(server.client.note_leaf(7).await.is_err());
            assert!(server.client.next_deposit_path().await.is_err());
            server.assert_only_snapshots(3);
        }
    }

    #[tokio::test]
    async fn snapshot_body_read_is_bounded() {
        let server = Server::new(|| {
            let body = Body::from_stream(futures_util::stream::pending::<
                Result<Vec<u8>, std::io::Error>,
            >());
            Response::new(body)
        })
        .await;
        let client =
            IndexerClient::with_timeout(&server.client.base_url, Duration::from_millis(50));
        let result = tokio::time::timeout(Duration::from_secs(1), client.root_and_path(0))
            .await
            .expect("an indexer that never finishes its body must time out");
        assert!(matches!(result, Err(AuthError::Indexer(_))));
        server.assert_only_snapshots(1);
    }

    #[tokio::test]
    async fn oversized_snapshot_is_rejected_with_or_without_content_length() {
        for content_length in [true, false] {
            let server = Server::new(move || {
                let mut response = if content_length {
                    Response::new(Body::from_stream(futures_util::stream::pending::<
                        Result<Vec<u8>, std::io::Error>,
                    >()))
                } else {
                    let chunks = (0..=32).map(|_| Ok::<_, std::io::Error>(vec![b' '; 1024 * 1024]));
                    Response::new(Body::from_stream(futures_util::stream::iter(chunks)))
                };
                if content_length {
                    response.headers_mut().insert(
                        header::CONTENT_LENGTH,
                        (RESPONSE_LIMIT + 1).to_string().parse().unwrap(),
                    );
                }
                response
            })
            .await;
            let error = server.client.root_and_path(0).await.unwrap_err();
            assert!(error.to_string().contains("too large"), "{error}");
            server.assert_only_snapshots(1);
        }
    }

    #[test]
    fn snapshot_reconstruction_stops_after_its_deadline() {
        let (payload, _) = snapshot(vec![Felt252::ONE]);
        let payload: TreeSnapshotResponse = serde_json::from_value(payload).unwrap();
        assert!(matches!(
            payload.verify(Instant::now()),
            Err(AuthError::Indexer(_))
        ));
    }
}
