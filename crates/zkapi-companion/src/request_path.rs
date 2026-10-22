//! Request paths (vault revision 4). A request proves its note's membership
//! at a root the server admits: one the vault reports through the computed
//! `currentRoot()`. Exits need no path at all; only requests read this.
//!
//! The indexer's path is the fast source, and untrusted: it is used only when
//! its root is the vault's `currentRoot()` at the block the indexer names
//! (EIP-1898, by hash), read through the deployment's RPC, and that block is
//! recent (at most [`INDEXER_MAX_LAG_BLOCKS`] behind `latest`, or its root is
//! still the root at `latest`). Otherwise the companion rebuilds the tree
//! from the vault itself (`zkapi_client::tree::rebuild_request_tree`):
//! `noteLeaves` pages, `nextNoteId()` and `currentRoot()` pinned to one block
//! hash, with the vault's logs as the fallback. A root an indexer made up is
//! never proved against, so an indexer cannot tag a request with a root of
//! its own.
//!
//! The first path also runs the deployment check (`LEAF_BOUND_EXIT_VERSION()`
//! is 1, `minDeposit()` the pinned value) when startup could not reach the RPC.

use std::sync::Arc;

use zkapi_client::tree::{self, PinnedBlock, TreeError};
use zkapi_types::{Felt252, MERKLE_DEPTH};

use crate::chain::{self, Rpc, VaultCheck};
use crate::config::AuthConfig;
use crate::error::AuthError;
use crate::indexer::{IndexerClient, IndexerPath};

/// How far behind `latest` the indexer's view may be when the vault's root
/// has moved since: about 48 s of 12 s blocks, inside the server's default
/// 60 s request-root grace.
pub(crate) const INDEXER_MAX_LAG_BLOCKS: u64 = 4;

/// Where request paths come from, and the once-per-process deployment check.
#[derive(Debug, Clone)]
pub(crate) struct RequestPaths {
    indexer: IndexerClient,
    rpc_url: Option<String>,
    chain_id: u64,
    contract: Felt252,
    deploy_block: u64,
    min_deposit_units: Option<u128>,
    checked: Arc<tokio::sync::OnceCell<()>>,
}

/// Which source a path came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PathSource {
    Indexer,
    Rebuild,
}

impl RequestPaths {
    pub(crate) fn new(config: &AuthConfig, indexer: IndexerClient) -> Self {
        Self {
            indexer,
            rpc_url: config.demo_rpc_url.clone(),
            chain_id: config.chain_id,
            contract: config.contract_address,
            deploy_block: config.deploy_block,
            min_deposit_units: config.min_deposit_units,
            checked: Arc::new(tokio::sync::OnceCell::new()),
        }
    }

    fn rpc(&self) -> Result<Rpc, AuthError> {
        let url = self.rpc_url.as_deref().ok_or_else(|| {
            AuthError::Wallet(
                "no request path: the deployment names no RPC to read the vault's request root"
                    .into(),
            )
        })?;
        Ok(Rpc::new(url)?.on_chain(self.chain_id))
    }

    /// The deployment check, once per process: refused for a vault that is
    /// not revision 4, retried while the RPC cannot be asked.
    pub(crate) async fn ensure_vault(&self, rpc: &Rpc) -> Result<(), AuthError> {
        let vault = chain::vault_address(&self.contract)?;
        self.checked
            .get_or_try_init(|| async {
                match chain::check_leaf_bound_vault(rpc, &vault, self.min_deposit_units).await {
                    VaultCheck::LeafBound => Ok(()),
                    VaultCheck::Refused(reason) => Err(AuthError::InvalidInput(format!(
                        "deployment check failed: {reason}"
                    ))),
                    VaultCheck::Unreachable(error) => Err(AuthError::Wallet(format!(
                        "no request path: the vault could not be checked: {error}"
                    ))),
                }
            })
            .await
            .map(|_| ())
    }

    /// Record a deployment check made elsewhere (at startup).
    pub(crate) fn mark_checked(&self) {
        let _ = self.checked.set(());
    }

    /// The root and siblings `note_id` (whose leaf is `leaf`) proves a
    /// request against: a root the vault reported.
    pub(crate) async fn path(
        &self,
        note_id: u32,
        leaf: &Felt252,
    ) -> Result<(Felt252, Vec<Felt252>), AuthError> {
        self.path_with_source(note_id, leaf)
            .await
            .map(|(root, siblings, _)| (root, siblings))
    }

    pub(crate) async fn path_with_source(
        &self,
        note_id: u32,
        leaf: &Felt252,
    ) -> Result<(Felt252, Vec<Felt252>, PathSource), AuthError> {
        let rpc = self.rpc()?;
        self.ensure_vault(&rpc).await?;
        let vault = chain::vault_address(&self.contract)?;
        let latest = tree::pin_block(&rpc, "latest").await.map_err(tree_error)?;
        match self.indexer.path_view(note_id).await {
            Ok(view) => match confirm(&rpc, &vault, &latest, note_id, leaf, &view).await {
                Ok(()) => return Ok((view.root, view.siblings, PathSource::Indexer)),
                Err(reason) => tracing::warn!(
                    note_id,
                    %reason,
                    "the indexer's request path is not confirmed by the vault; rebuilding the tree from the vault"
                ),
            },
            Err(error) => tracing::debug!(
                note_id,
                %error,
                "the indexer has no request path; rebuilding the tree from the vault"
            ),
        }
        let rebuilt = tree::rebuild_request_tree(&rpc, &vault, self.deploy_block, "latest")
            .await
            .map_err(tree_error)?;
        let (root, siblings) = rebuilt.path(note_id, leaf).map_err(tree_error)?;
        Ok((root, siblings, PathSource::Rebuild))
    }
}

/// Whether the indexer's `view` is a path of `leaf` at a root the vault held
/// at a recent block; the reason it is not otherwise.
async fn confirm(
    rpc: &Rpc,
    vault: &[u8; 20],
    latest: &PinnedBlock,
    note_id: u32,
    leaf: &Felt252,
    view: &IndexerPath,
) -> Result<(), String> {
    if view.leaf.is_some_and(|served| served != *leaf) {
        return Err("the indexer serves another leaf for the note".into());
    }
    let siblings: [Felt252; MERKLE_DEPTH] = view
        .siblings
        .clone()
        .try_into()
        .map_err(|_| "the indexer's path is not 32 siblings".to_string())?;
    if zkapi_core::v2::merkle_root(note_id, leaf, &siblings) != view.root {
        return Err("the indexer's path does not lead from the note's leaf to its root".into());
    }
    let at_latest = || async {
        tree::current_root_at(rpc, vault, latest)
            .await
            .map_err(|error| error.to_string())
    };
    match view.block {
        Some((number, hash)) => {
            let block = PinnedBlock { number, hash };
            let vault_root = tree::current_root_at(rpc, vault, &block)
                .await
                .map_err(|error| error.to_string())?;
            if vault_root != view.root {
                return Err(format!(
                    "the vault's currentRoot() at the indexer's block {number} is not the indexer's root"
                ));
            }
            if number.saturating_add(INDEXER_MAX_LAG_BLOCKS) < latest.number
                && at_latest().await? != view.root
            {
                return Err(format!(
                    "the indexer's view (block {number}) trails the latest block {} and the vault's root has moved since",
                    latest.number
                ));
            }
        }
        // An indexer that names no block: its root must be the latest one.
        None => {
            if at_latest().await? != view.root {
                return Err("the indexer's root is not the vault's currentRoot()".into());
            }
        }
    }
    Ok(())
}

/// Every failure to find a request path is a `wallet_error` that starts
/// with "no request path".
fn tree_error(error: TreeError) -> AuthError {
    match error {
        TreeError::LeafMismatch(note_id) => AuthError::Wallet(format!(
            "no request path: the vault's tree does not hold note {note_id}'s leaf: the note's secret, amount or expiry is not the one deposited"
        )),
        other => AuthError::Wallet(format!("no request path: {other}")),
    }
}
