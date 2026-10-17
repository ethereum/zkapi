//! The operator's indexer. Every call is bounded (design §6.4 E0): the
//! indexer is operator-run, and request preparation reads it while holding
//! the wallet's locks, which every exit route takes too. A call that
//! connects and never answers, or drips its body, fails after
//! `CALL_TIMEOUT` instead of holding those locks. Exits never read it: they
//! name the note by its recorded values, with no Merkle path.

use std::time::Duration;

use serde::Deserialize;
use zkapi_types::Felt252;

use crate::error::AuthError;

/// E0's `CALL_TIMEOUT`, connect and full body included (shortened in tests,
/// like the exit routes' own bound).
#[cfg(not(test))]
pub(crate) const CALL_TIMEOUT: Duration =
    Duration::from_secs(zkapi_client::exit_policy::CALL_TIMEOUT_SECONDS);
#[cfg(test)]
pub(crate) const CALL_TIMEOUT: Duration = Duration::from_millis(1_500);

#[derive(Debug, Clone)]
pub struct IndexerClient {
    base_url: String,
    http: reqwest::Client,
}

#[derive(Debug, Deserialize)]
struct TreeRootResponse {
    root: Felt252,
    #[serde(default)]
    activation_cursor: u32,
}

#[derive(Debug, Deserialize)]
struct NextNoteIdResponse {
    next_note_id: u32,
}

/// A note's slot in the indexer's tree, from one view: the slot's tree leaf
/// (zero until the note is activated), its siblings and the root they hash
/// to, and the activation cursor of that view.
#[derive(Debug, Clone, Deserialize)]
pub struct NotePath {
    pub leaf: Felt252,
    pub siblings: Vec<Felt252>,
    pub root: Felt252,
    #[serde(default)]
    pub activated: bool,
    #[serde(default)]
    pub activation_cursor: u32,
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
        }
    }

    /// The root and the activation cursor of one view.
    pub async fn root_view(&self) -> Result<(Felt252, u32), AuthError> {
        let payload: TreeRootResponse = self.get(format!("{}/v1/tree/root", self.base_url)).await?;
        Ok((payload.root, payload.activation_cursor))
    }

    pub async fn next_note_id(&self) -> Result<u32, AuthError> {
        let payload: NextNoteIdResponse = self
            .get(format!("{}/v1/tree/next-note-id", self.base_url))
            .await?;
        Ok(payload.next_note_id)
    }

    /// `note_id`'s path, with the root it hashes to, in one call (E0): the
    /// pair a request proves against comes from one indexer view, which
    /// activations and retirements move.
    pub async fn note_path(&self, note_id: u32) -> Result<NotePath, AuthError> {
        let path: NotePath = self
            .get(format!("{}/v1/tree/notes/{note_id}/path", self.base_url))
            .await?;
        if path.siblings.len() != zkapi_types::MERKLE_DEPTH {
            return Err(AuthError::Indexer(format!(
                "the indexer's path of note {note_id} has {} siblings",
                path.siblings.len()
            )));
        }
        Ok(path)
    }

    async fn get<T: serde::de::DeserializeOwned>(&self, url: String) -> Result<T, AuthError> {
        let response = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|err| AuthError::Indexer(err.to_string()))?;
        let response = response
            .error_for_status()
            .map_err(|err| AuthError::Indexer(err.to_string()))?;
        response
            .json()
            .await
            .map_err(|err| AuthError::Indexer(err.to_string()))
    }
}
