//! Durable event-to-submission loop of the concession-exit challenger (§5.4).
//!
//! For each pending escape `(n, N, N⁺, B, c, deadline)`, read every poll from
//! `pendingWithdrawals(n)` and `pendingConcessions(n)` at one block:
//!
//! 1. **Defeat.** Verified evidence at `N⁺` in the server's `request_evidence`,
//!    whatever its lease status: `challengeEscapeWithdrawal(n, inputs, proof)`
//!    with the oldest such row. No indexer path and no live root are needed.
//! 2. **Raise.** Otherwise, once `Ω(N)` is final (a settled charge), or at
//!    `deadline - raise_lead_seconds` at the latest: if `min(Ω, bound, B)`
//!    exceeds `c` by at least `raise_min_units`, `raiseEscapeConcession(n,
//!    inputs, proof, Ω)` with the row at `N` with the largest solvency bound.
//! 3. Otherwise nothing: the honest outcome. After a raise, evidence at `N⁺`
//!    is still watched until the deadline.
//!
//! Rows at `N⁺` that do not verify defeat nothing: they never hold back the
//! raise, but keep the obligation critical (`evidence_invalid`) and count as
//! a possible missed defeat if the escape is paid out.
//!
//! One signer and one nonce lane. A same-nonce replacement may change only
//! fees, with one exception: a defeat may replace an unmined raise; a raise
//! never replaces a defeat. The call and its digest are persisted before
//! every send, so the transition survives a restart. A raise that lands
//! first leaves the defeat to the next nonce.
//!
//! A missed defeat (verified successor evidence before the deadline, and the
//! escape finalized) or missed raise (more owed than conceded at
//! finalization) is recorded; after a missed defeat, `retire_on_miss` retires
//! the closed note's leaf (`retireClosedLeaf`, with the indexer's path at the
//! live root).
//!
//! The configured RPC must expose an operator-controlled transaction signer.
//! Keys are never loaded by this service; the sender must be dedicated to it.
//! Transactions are EIP-1559, with fees the daemon proposes and escalates,
//! within its caps and a per-transaction fee ceiling, by same-nonce
//! replacement as deadlines approach. Every obligation's state, deadline and
//! blocking reason is published on the operator status endpoint (see
//! `challenge_status`).

use crate::{
    challenge_status::{
        self, unix_now, AlarmPolicy, BlockedReason, ChainStatus, ChallengeStatus,
        DetachedNonceStatus, EvidenceKind, IndexerState, IndexerStatus, MissedRecord,
        ObligationState, ObligationStatus, PollStatus, RemainingThresholds, SenderStatus, Severity,
        StatusHandle,
    },
    deployment::{probe_deployment, ContractReader, DeploymentManifest, ProbeError},
    error::ServerError,
    nullifier_store::{DeploymentBinding, NullifierStore, StatementIdentity},
    watcher::{
        CallKind, ChallengeWatcher, EvidenceBinding, EvidenceProof, NothingOwed, Owed, OwedBasis,
        SettlementProgress, VaultCall,
    },
};
use anyhow::{anyhow, bail, ensure, Context};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::{Arc, RwLock},
    time::Duration,
};
use zkapi_proof::compact::RequestVerifier;
use zkapi_types::{Felt252, MERKLE_DEPTH};

const ESCAPE_EVENT: &str =
    "EscapeWithdrawalInitiated(uint32,uint256,uint128,address,uint64,uint256)";
const CONCESSION_RECORDED_EVENT: &str = "EscapeConcessionRecorded(uint32,uint256,uint128,uint128)";
const CONCESSION_RAISED_EVENT: &str = "EscapeConcessionRaised(uint32,uint256,uint128,uint128)";
const CHALLENGED_EVENT: &str = "EscapeWithdrawalChallenged(uint32,uint256,uint256)";
const FINALIZED_EVENT: &str = "EscapeWithdrawalFinalized(uint32,uint256,uint128,address)";
/// `notes(noteId).status` of a note whose escape was finalized.
const NOTE_STATUS_CLOSED: u64 = 3;
/// Blocks per `eth_getLogs` request, as the event scan.
const LOG_RANGE_BLOCKS: u64 = 1_000;
/// Ranges the outcome search of disappeared escapes reads per poll.
const MAX_OUTCOME_RANGES_PER_POLL: usize = 8;
/// A latest-block read of a pending escape bounds its end from below at this
/// many blocks under the confirmed head, for an RPC whose backends lag.
const SEEN_MARGIN_BLOCKS: u64 = 64;
/// How far the chain's clock may have run ahead of an earlier release's
/// when it stamped a miss's `recorded_at` (see `legacy_miss_bound`).
const LEGACY_MISS_CLOCK_MARGIN_SECONDS: u64 = 900;
const GWEI: u128 = 1_000_000_000;
/// Older candidate hashes beyond this many are dropped from a nonce's record.
const MAX_SUPERSEDED_HASHES: usize = 32;
/// The signer may make several sequential upstream calls for one send.
const SEND_TIMEOUT: Duration = Duration::from_secs(95);
const INDEXER_TIMEOUT: Duration = Duration::from_secs(10);
/// Gas limit of a defeat unless its estimate (plus 20%) is higher (§5.4).
pub const DEFAULT_DEFEAT_GAS_LIMIT: u64 = 600_000;
/// Gas limit of a raise unless its estimate (plus 20%) is higher (§5.4).
pub const DEFAULT_RAISE_GAS_LIMIT: u64 = 450_000;
/// The raise is decided this long before the escape's deadline at the
/// latest (mainnet and Sepolia production; the drill uses 1,800).
pub const DEFAULT_RAISE_LEAD_SECONDS: u64 = 21_600;
/// Gas assumed for balance alarms before any estimate: one defeat.
const DEFAULT_CHALLENGE_GAS: u128 = DEFAULT_DEFEAT_GAS_LIMIT as u128;
/// Critical obligations and an indexer divergence are re-logged this often.
const RELOG_SECONDS: u64 = 300;
/// Indexer-listed escapes missing from the checkpoint checked per poll.
const MAX_ESCAPE_CHECKS_PER_POLL: usize = 64;
/// A listed note the vault holds no escape for is still read on every
/// listing until reads this far apart have found none: the indexer's head
/// view can be ahead of this daemon's RPC, so a fresh escape can read as
/// absent at first.
const DEAD_ESCAPE_CONFIRM_SECONDS: u64 = 60;
/// After that, it is read again only once this many listings have passed,
/// so such entries cannot spend the per-poll budget of the others.
const DEAD_ESCAPE_RECHECK_POLLS: u64 = 16;
const MAX_ERROR_CHARS: usize = 512;

/// EIP-1559 fee proposals. The signer enforces its own caps, which must be at
/// least these. A same-nonce replacement raises the tip by the minimum valid
/// step and the fee cap by `bump_percent`; two replacements stay reserved for
/// the critical threshold. Every bid keeps gas limit x maxFeePerGas within
/// the transaction fee ceiling.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeePolicy {
    pub max_fee_per_gas: u128,
    pub max_priority_fee_per_gas: u128,
    pub priority_fee_per_gas: u128,
    /// Highest gas limit x maxFeePerGas of one challenge transaction (wei).
    pub tx_fee_cap_wei: u128,
    pub bump_after_blocks: u64,
    pub bump_percent: u64,
}

impl FeePolicy {
    pub const DEFAULT_PRIORITY_FEE_PER_GAS: u128 = 2 * GWEI;
    /// 1 ether, the default `--rpc.txfeecap` of geth and reth: their RPC
    /// refuses a transaction whose gas limit x maxFeePerGas exceeds it.
    pub const DEFAULT_TX_FEE_CAP_WEI: u128 = 1_000_000_000_000_000_000;
    pub const DEFAULT_BUMP_AFTER_BLOCKS: u64 = 3;
    pub const DEFAULT_BUMP_PERCENT: u64 = 25;

    pub fn new(max_fee_per_gas: u128, max_priority_fee_per_gas: u128) -> Self {
        Self {
            max_fee_per_gas,
            max_priority_fee_per_gas,
            priority_fee_per_gas: Self::DEFAULT_PRIORITY_FEE_PER_GAS,
            tx_fee_cap_wei: Self::DEFAULT_TX_FEE_CAP_WEI,
            bump_after_blocks: Self::DEFAULT_BUMP_AFTER_BLOCKS,
            bump_percent: Self::DEFAULT_BUMP_PERCENT,
        }
    }

    /// A transaction fee ceiling as the signer reads it: a positive decimal
    /// wei amount without sign, leading zeros or spaces; empty means the
    /// default.
    pub fn parse_tx_fee_cap(value: &str) -> Result<u128, String> {
        if value.is_empty() {
            return Ok(Self::DEFAULT_TX_FEE_CAP_WEI);
        }
        if value.starts_with('0') || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err("must be a positive decimal integer in wei".into());
        }
        value
            .parse()
            .map_err(|_| "exceeds the largest supported amount".into())
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        ensure!(
            self.priority_fee_per_gas > 0,
            "priority fee per gas must be positive"
        );
        ensure!(
            self.max_priority_fee_per_gas <= self.max_fee_per_gas,
            "max priority fee per gas must not exceed max fee per gas"
        );
        // Nodes accept a same-nonce replacement only when both fees rise by
        // at least 10%, so the tip needs room above the first bid: twice the
        // first tip allows about five replacements before the critical
        // threshold and the two reserved for it.
        ensure!(
            self.max_priority_fee_per_gas >= self.priority_fee_per_gas.saturating_mul(2),
            "max priority fee per gas must be at least twice the priority fee per gas, leaving tip headroom for same-nonce replacement"
        );
        ensure!(
            self.max_fee_per_gas <= u128::MAX / 1_000,
            "max fee per gas is implausibly large"
        );
        ensure!(
            self.tx_fee_cap_wei > 0,
            "transaction fee cap must be positive"
        );
        ensure!(
            self.bump_after_blocks >= 1,
            "fee bump interval must be at least one block"
        );
        ensure!(
            (10..=100).contains(&self.bump_percent),
            "fee bump percent must be between 10 and 100"
        );
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct ChallengeServiceConfig {
    pub rpc_url: String,
    pub indexer_url: String,
    pub sender: String,
    pub contract_address: Felt252,
    pub chain_id: u64,
    pub from_block: u64,
    pub confirmations: u64,
    pub checkpoint: PathBuf,
    pub proof_setup_dir: PathBuf,
    pub fee: FeePolicy,
    pub alarms: AlarmPolicy,
    /// The raise is decided at `deadline - raise_lead_seconds` at the latest.
    pub raise_lead_seconds: u64,
    /// The smallest raise worth a transaction, in gwei units.
    pub raise_min_units: u128,
    /// Retire a closed note's leaf after a missed defeat.
    pub retire_on_miss: bool,
    pub defeat_gas_limit: u64,
    pub raise_gas_limit: u64,
}

/// What the startup timing checks need beyond the vault (§5.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChallengeTiming {
    /// The server's `ttl + grace + settlement deadline`: the deployment
    /// manifest's `settlement_window_seconds`.
    pub settlement_window_seconds: u64,
    /// The server's settlement poll interval.
    pub settlement_poll_seconds: u64,
}

/// An `Option<u128>` field of a struct that is `#[serde(flatten)]`ed (the
/// nonce attempts of a pending obligation or a detached nonce). Serde buffers
/// a flattened struct's fields in its own `Content`, which has no 128-bit
/// integers, so a plain `u128` read through it fails ("u128 is not
/// supported"): a checkpoint holding a raise attempt would never load again,
/// and the restarted challenger would stop. The amount is written as a
/// number while it fits in 64 bits (as checkpoints always held it), else as a
/// decimal string, and read through `deserialize_any`, which `Content`
/// supports.
mod flat_amount {
    use std::fmt;

    use serde::de::{self, Deserializer, Visitor};
    use serde::Serializer;

    pub fn serialize<S: Serializer>(
        value: &Option<u128>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            None => serializer.serialize_none(),
            Some(amount) => match u64::try_from(*amount) {
                Ok(small) => serializer.serialize_some(&small),
                Err(_) => serializer.serialize_some(&amount.to_string()),
            },
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<u128>, D::Error> {
        deserializer.deserialize_option(Amount)
    }

    struct Amount;

    impl<'de> Visitor<'de> for Amount {
        type Value = Option<u128>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("an amount: a non-negative integer, its decimal string, or null")
        }

        fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_some<D: Deserializer<'de>>(
            self,
            deserializer: D,
        ) -> Result<Self::Value, D::Error> {
            deserializer.deserialize_any(self)
        }

        fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
            Ok(Some(value.into()))
        }

        fn visit_u128<E: de::Error>(self, value: u128) -> Result<Self::Value, E> {
            Ok(Some(value))
        }

        fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
            u128::try_from(value)
                .map(Some)
                .map_err(|_| E::custom("a negative amount"))
        }

        fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
            value.parse::<u128>().map(Some).map_err(E::custom)
        }
    }
}

/// Attempts on one reserved nonce. Every field is written before a send, so a
/// crash or ambiguous result never loses what may have been broadcast.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct NonceAttempts {
    /// Earlier candidate hashes on the nonce, oldest first. Any may still mine.
    #[serde(default)]
    superseded_hashes: Vec<String>,
    /// Fees (0x-hex wei) of the latest attempt. A send on a nonce that an
    /// earlier attempt may hold must outbid them, so they are the highest of
    /// any attempt that may still be in a pool; a re-send of a nonce that no
    /// attempt holds may lower them to the current caps and ceiling.
    #[serde(default)]
    max_fee_per_gas: Option<String>,
    #[serde(default)]
    max_priority_fee_per_gas: Option<String>,
    /// Gas limit of the latest attempt.
    #[serde(default)]
    gas_limit: Option<u64>,
    #[serde(default)]
    submitted_block: Option<u64>,
    #[serde(default)]
    attempts: u32,
    /// The nonce was reserved by an older daemon that kept no attempt record,
    /// so it may hold an attempt this record does not describe.
    #[serde(default)]
    unrecorded_attempt: bool,
    /// Digest of (noteId, request inputs, proof) first sent on the nonce;
    /// replacements may change only siblings, gas and fees.
    #[serde(default)]
    evidence_digest: Option<String>,
    /// The vault root the latest attempt's siblings hash to.
    #[serde(default)]
    submitted_root: Option<Felt252>,
    /// An attempt may hold the nonce without a known hash, so a re-send must
    /// be a valid replacement of the persisted fees.
    #[serde(default)]
    unknown_attempt: bool,
    /// The vault call the attempts on this nonce make. None in records of an
    /// earlier release, whose attempts were challenges (defeats).
    #[serde(default)]
    action: Option<CallKind>,
    /// The `request_evidence` row a defeat or raise was built from.
    #[serde(default)]
    evidence_row: Option<i64>,
    /// The amount of a raise.
    #[serde(default, with = "flat_amount")]
    raise_amount: Option<u128>,
    /// A defeat replaced an unmined raise on this nonce: the one change of
    /// call a same-nonce replacement may make.
    #[serde(default)]
    replaced_raise: bool,
}

impl NonceAttempts {
    /// The call on the nonce; an earlier release only sent defeats.
    fn kind(&self) -> CallKind {
        self.action.unwrap_or(CallKind::Defeat)
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct PendingChallenge {
    nullifier: Felt252,
    transaction_hash: Option<String>,
    /// Persist before sending so an ambiguous RPC failure retries the same nonce.
    nonce: Option<u64>,
    #[serde(default)]
    deadline_reported: bool,
    #[serde(default)]
    first_seen_at: Option<u64>,
    #[serde(default)]
    challenge_deadline: Option<u64>,
    /// A block no later than the escape's end: its initiation, or a block
    /// at which it was read pending (less a margin for a latest-block read).
    /// Once the escape is gone after its deadline, the log search for how it
    /// ended starts here.
    #[serde(default)]
    seen_block: Option<u64>,
    /// The next block that search reads; persisted so it resumes.
    #[serde(default)]
    outcome_search_from: Option<u64>,
    /// The withdrawal was gone at a head before its challenge deadline, when
    /// finalization is impossible: a challenge (or a reorganized initiation)
    /// ended it, so it is shown resolved rather than as a possible payout.
    /// Also set when an obligation behind a blocked queue is read at
    /// confirmation depth to have ended so. Cleared when the withdrawal is
    /// seen pending again. Retirement past the deadline still reads how the
    /// escape ended.
    #[serde(default)]
    ended_before_deadline: bool,
    /// `N⁺`, `B` and `c` of the escape: from `pendingConcessions` at the last
    /// read, or from its events before any read.
    #[serde(default)]
    next_nullifier: Option<Felt252>,
    #[serde(default)]
    state_balance: Option<u128>,
    #[serde(default)]
    conceded: Option<u128>,
    /// What was missed when the deadline passed: a defeat or a raise.
    #[serde(default)]
    missed_kind: Option<CallKind>,
    /// After a missed defeat the escape was paid out: the obligation now
    /// retires the closed note's leaf.
    #[serde(default)]
    retire_leaf: bool,
    #[serde(flatten)]
    attempt: NonceAttempts,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Checkpoint {
    sender: String,
    chain_id: u64,
    contract_address: Felt252,
    from_block: u64,
    next_block: u64,
    last_block_hash: Option<String>,
    pending: BTreeMap<u32, PendingChallenge>,
    /// A completed/replaced withdrawal must not discard an in-flight nonce.
    #[serde(default)]
    detached_nonces: BTreeMap<u64, DetachedNonce>,
    #[serde(default)]
    missed_total: u64,
    /// Missed defeats: `escapes_finalized_with_successor_evidence_total`.
    #[serde(default)]
    missed_defeats_total: u64,
    #[serde(default)]
    missed_raises_total: u64,
    /// Leaves retired after missed defeats.
    #[serde(default)]
    retired_leaves_total: u64,
    #[serde(default)]
    last_missed: Option<MissedRecord>,
    /// Nullifiers of the escapes counted in `missed_total`: an escape tracked
    /// again (a replay, a restart) is never counted twice.
    #[serde(default)]
    missed_nullifiers: Vec<Felt252>,
    /// Set by the first poll of a checkpoint from an earlier release that
    /// counts misses whose nullifiers it lacks (`missed_total` above
    /// `missed_nullifiers`): the latest deadline that release can have
    /// counted a miss for. It counted one only once a head was at the
    /// deadline, and `last_missed` is its latest, so the bound is that
    /// miss's `recorded_at` plus LEGACY_MISS_CLOCK_MARGIN_SECONDS, or its
    /// own deadline if later, and at most this poll's head timestamp.
    ///
    /// A payout found of an escape that was not pending at the upgrade
    /// (`pending_at_upgrade`), with its deadline by this bound and its
    /// event below `scan_cursor_at_upgrade`, is taken for one of those
    /// misses while any remain, and not counted again: a replay tracks such
    /// a retired escape again. Any other payout past its deadline is
    /// counted, such as one of an escape initiated and paid out while the
    /// earlier release was down or its scan failed, which its first forward
    /// scan finds. A checkpoint saved mid-replay holds a cursor below what
    /// that release had scanned before; a payout it counted of an escape
    /// between the two blocks is counted again.
    #[serde(default)]
    legacy_miss_bound: Option<u64>,
    #[serde(default)]
    pending_at_upgrade: Vec<Felt252>,
    /// The earlier release's `next_block` at that poll, below which it had
    /// read the escape events. None when its checkpoint held no scanned
    /// block (its cursor reset for a replay): then only `legacy_miss_bound`
    /// limits the attribution.
    #[serde(default)]
    scan_cursor_at_upgrade: Option<u64>,
    /// Timestamp of the last block the event scan covered.
    #[serde(default)]
    scanned_through_timestamp: Option<u64>,
}

impl Checkpoint {
    /// Misses counted by an earlier release whose nullifiers are unknown.
    fn unattributed_misses(&self) -> u64 {
        self.missed_total
            .saturating_sub(self.missed_nullifiers.len() as u64)
    }

    /// `legacy_miss_bound` for a first poll whose head is at `head_timestamp`.
    /// No release writes misses without `last_missed`; for such a checkpoint
    /// the bound is the end of its event scan, if earlier.
    fn legacy_miss_deadline_bound(&self, head_timestamp: u64) -> u64 {
        match &self.last_missed {
            Some(last) => last
                .recorded_at
                .saturating_add(LEGACY_MISS_CLOCK_MARGIN_SECONDS)
                .max(last.challenge_deadline),
            None => self.scanned_through_timestamp.unwrap_or(head_timestamp),
        }
        .min(head_timestamp)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct DetachedNonce {
    note_id: u32,
    nullifier: Felt252,
    transaction_hash: Option<String>,
    #[serde(flatten)]
    attempt: NonceAttempts,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NonceState {
    Free,
    /// Reserved, and no known or hidden attempt occupies it: it was dropped,
    /// refused before broadcast, or never sent.
    Reserved,
    /// Reserved and possibly held by an attempt without a known hash, so a
    /// re-send must be a valid replacement of the persisted fees.
    Held,
    Pending,
    Mined,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct HeadInfo {
    number: u64,
    timestamp: u64,
    base_fee: Option<u128>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Fees {
    pub max_fee: u128,
    pub tip: u128,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FeePlan {
    /// No earlier attempt can occupy the nonce.
    First,
    /// Re-send after every earlier attempt left the pools.
    Resend(Fees),
    /// Must be a valid replacement of every earlier attempt.
    Bump(Fees),
}

#[derive(Clone, Debug)]
struct Evaluation {
    state: ObligationState,
    evidence: Option<EvidenceKind>,
    blocked: Option<BlockedReason>,
    detail: Option<String>,
    settlement: Option<SettlementProgress>,
    /// Ω, once known.
    owed: Option<u128>,
    raise_due_at: Option<u64>,
    evaluated_at: u64,
}

impl Evaluation {
    fn new(state: ObligationState, evidence: Option<EvidenceKind>) -> Self {
        Self {
            state,
            evidence,
            blocked: None,
            detail: None,
            settlement: None,
            owed: None,
            raise_due_at: None,
            evaluated_at: 0,
        }
    }

    fn blocked(mut self, reason: BlockedReason, detail: impl Into<String>) -> Self {
        self.blocked = Some(reason);
        self.detail = Some(bounded(&detail.into()));
        self
    }

    fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(bounded(&detail.into()));
        self
    }
}

/// A note's escape as the vault holds it at one block: `pendingWithdrawals`
/// and `pendingConcessions` read at the same block (§5.4).
#[derive(Clone, Debug, PartialEq, Eq)]
struct EscapeState {
    exists: bool,
    /// `N`, the escaped nullifier.
    nullifier: Felt252,
    /// The current payout, `B - c`.
    final_balance: u128,
    deadline: u64,
    /// `N⁺`: only a request proof at it defeats the escape.
    next_nullifier: Felt252,
    /// `B`.
    state_balance: u128,
    /// `c`.
    conceded: u128,
}

/// What made the loss of an escape a missed deadline.
#[derive(Clone, Debug)]
struct MissEvidence {
    /// What was due: a defeat or a raise.
    kind: CallKind,
    evidence: EvidenceKind,
    settlement: Option<SettlementProgress>,
    reason: String,
}

/// What a pending escape calls for (§5.4 decision order).
#[derive(Clone, Debug)]
struct Decision {
    /// The evidence kind the status shows.
    evidence: EvidenceKind,
    settlement: Option<SettlementProgress>,
    /// Ω, once known: final once settled, else the bound from the raise lead.
    owed: Option<u128>,
    raise_due_at: u64,
    due: Due,
    /// Rows at `N⁺` exist and none of them verifies. They defeat nothing, so
    /// `due` is decided from Ω as if they were absent, but they are alarmed
    /// on (evidence_invalid) and, at the deadline, counted as a possible
    /// missed defeat.
    successor_invalid: Option<String>,
}

#[derive(Clone, Debug)]
enum Due {
    /// Verified evidence at `N⁺`; `before_deadline` when a verified row was
    /// written before the deadline (a missed defeat otherwise).
    Defeat {
        evidence: EvidenceProof,
        before_deadline: bool,
    },
    /// Raise to `amount = Ω` with the row of the largest bound at `N`.
    Raise {
        evidence: EvidenceProof,
        amount: u128,
    },
    /// Ω is not final before the raise lead.
    AwaitingSettlement,
    /// Nothing is due; the detail says why.
    Nothing { covered: bool, detail: String },
    /// Evidence rows that do not verify: the defeat or raise `kind` may be
    /// due but cannot be built.
    Invalid { kind: CallKind, detail: String },
}

/// How an escape that left `pendingWithdrawals` ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EscapeOutcome {
    /// Challenged, or never confirmed (a reorganized initiation).
    NotPaidOut,
    /// Finalized. `inferred`: the note is closed but neither a challenged
    /// nullifier nor a log of the escape's end was found.
    PaidOut { inferred: bool },
}

/// A note the indexer lists as pending while the vault holds no escape for
/// it: the list lags the vault, or its log source missed the escape's end
/// and keeps the entry until a resync. Never kept for a tracked note, whose
/// vault record every poll reads.
struct DeadEscape {
    /// The listed nullifier; another one listed for the note is read at once.
    nullifier: Felt252,
    /// When the vault was first read without the escape.
    first_seen: u64,
    /// When the vault was last read without it.
    last_seen: u64,
    /// The listing in which the vault was last read for it.
    checked_at: u64,
    /// The head of a poll after the first read without the escape, so at or
    /// above that read's block.
    read_by: Option<u64>,
    /// A list served at a block between two reads without the escape named
    /// the note: the indexer has processed a block in which the vault held
    /// none, so its list does not merely lag the vault.
    bracketed: bool,
}

impl DeadEscape {
    /// Reads at least `seconds` apart have found no escape.
    fn absent_for(&self, seconds: u64) -> bool {
        self.last_seen.saturating_sub(self.first_seen) >= seconds
    }

    /// A read in this poll, at or above its `head`, brackets a list served
    /// at block `listed` with the first read: `listed` lies from `read_by`
    /// up to `head`. A list served without its block cannot be placed, and
    /// only time decides.
    fn brackets(&self, listed: Option<u64>, head: u64) -> bool {
        listed.is_none_or(|block| self.read_by.is_some_and(|read| read <= block) && block <= head)
    }

    /// Reported as a disagreement: reads `warning` seconds apart have found
    /// no escape, and a list served between two of them named the note.
    fn reported(&self, warning: u64) -> bool {
        self.bracketed && self.absent_for(warning)
    }

    /// Skipped at this listing: confirmed, and between its re-reads, unless
    /// its report, due `warning` seconds after the first read, waits for a
    /// read and this listing (`brackets`) or an earlier one can complete it.
    fn resting(&self, listing: u64, now: u64, warning: u64, brackets: bool) -> bool {
        self.absent_for(DEAD_ESCAPE_CONFIRM_SECONDS)
            && listing - self.checked_at < DEAD_ESCAPE_RECHECK_POLLS
            && (self.reported(warning)
                || now.saturating_sub(self.first_seen) < warning
                || !(self.bracketed || brackets))
    }
}

/// A JSON-RPC error object. Display stays `"{method}: {error_json}"`.
#[derive(Debug)]
pub(crate) struct RpcError {
    method: String,
    error: Value,
}

impl RpcError {
    fn code(&self) -> Option<i64> {
        self.error.get("code").and_then(Value::as_i64)
    }

    fn reason(&self) -> Option<&str> {
        self.error.get("data")?.get("reason")?.as_str()
    }

    fn transaction_hash(&self) -> Option<String> {
        let hash = self.error.get("data")?.get("transaction_hash")?.as_str()?;
        let digits = hash.strip_prefix("0x")?;
        (digits.len() == 64 && digits.chars().all(|c| c.is_ascii_hexdigit()))
            .then(|| hash.to_ascii_lowercase())
    }
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.method, self.error)
    }
}

impl std::error::Error for RpcError {}

/// An HTTP-level RPC failure. It never includes the URL, which may embed a key.
#[derive(Debug)]
struct TransportError {
    method: String,
    message: String,
    /// No connection was made, so the request never reached the signer.
    unsent: bool,
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.method, self.message)
    }
}

impl std::error::Error for TransportError {}

/// Startup check of the server database's deployment binding.
#[derive(Debug)]
pub enum DeploymentCheckError {
    /// The database or vault definitively belongs to another deployment.
    Mismatch(String),
    /// The check could not complete; retry.
    Unavailable(anyhow::Error),
}

impl std::fmt::Display for DeploymentCheckError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mismatch(message) => write!(f, "{message}"),
            Self::Unavailable(error) => write!(f, "deployment binding check unavailable: {error}"),
        }
    }
}

impl std::error::Error for DeploymentCheckError {}

/// Outcome classes of a failed `eth_sendTransaction`.
enum SendFailure {
    /// -32602/-32601/-32003: a definitive refusal; nothing was broadcast.
    Refused(Option<String>),
    /// A connection never made, or a signer-reported failure before
    /// broadcast (transient); nothing was broadcast.
    NotBroadcast(BlockedReason),
    /// Possibly broadcast, with the candidate hash when the signer reports it.
    Ambiguous(Option<String>),
}

enum IndexerFailure {
    Status(u16),
    Transport(String),
    Decode(String),
}

impl std::fmt::Display for IndexerFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Status(code) => write!(f, "HTTP {code}"),
            Self::Transport(error) | Self::Decode(error) => write!(f, "{error}"),
        }
    }
}

pub struct ChallengeService {
    config: ChallengeServiceConfig,
    client: reqwest::Client,
    watcher: ChallengeWatcher,
    verifier: RequestVerifier,
    /// The statement of the loaded verifying keys.
    identity: StatementIdentity,
    checkpoint: Checkpoint,
    status: StatusHandle,
    started_at: u64,
    // Vault immutables, read once per process.
    challenge_period: Option<u64>,
    vault_state_key: Option<(Felt252, Felt252)>,
    vault_warning: Option<String>,
    startup_warning: Option<String>,
    config_warnings: Vec<String>,
    head: Option<HeadInfo>,
    /// Latest head number and the wall time it was first observed.
    head_seen: Option<(u64, u64)>,
    vault_root: Option<Felt252>,
    /// Latest-block nonce count from the most recent nonce reconciliation.
    latest_nonce_count: Option<u64>,
    poll: PollStatus,
    indexer: IndexerStatus,
    indexer_logged_at: Option<u64>,
    /// Pending-escapes listings processed since the daemon started.
    escape_listings: u64,
    /// The listed note the next listing's vault reads start at.
    escape_cursor: u32,
    /// Listed notes the vault held no escape for when last read.
    dead_escapes: BTreeMap<u32, DeadEscape>,
    sender: SenderStatus,
    sender_balance: Option<u128>,
    /// The signer's transaction fee cap, from `zkapi_signerStatus` or a
    /// `tx_fee_above_cap` refusal.
    signer_tx_fee_cap: Option<u128>,
    /// The lowest transaction fee (gas limit x maxFeePerGas) that the signer's
    /// node refused as above its RPC fee cap (`upstream_tx_fee_cap`). Kept
    /// until restart; the node's cap is never reported.
    node_refused_tx_fee: Option<u128>,
    last_observed_at: Option<u64>,
    last_gas: Option<u128>,
    evaluations: BTreeMap<u32, Evaluation>,
    previous_evaluations: BTreeMap<u32, Evaluation>,
    /// Per note: when it became blocked, and for how many evaluations.
    blocked_since: BTreeMap<u32, (u64, u32)>,
    /// Fees read from a pending transaction whose fees were not persisted.
    observed_fees: BTreeMap<u32, Fees>,
    nonce_failures: BTreeMap<u32, String>,
    detached_status: Vec<DetachedNonceStatus>,
    logged: BTreeMap<u32, (ObligationState, Severity, Option<BlockedReason>, u64)>,
    /// `eth_getLogs` ranges the outcome search may still read this poll.
    outcome_ranges: usize,
}

impl ChallengeService {
    pub fn new(config: ChallengeServiceConfig, store: Arc<NullifierStore>) -> anyhow::Result<Self> {
        ensure!(
            config.contract_address.as_bytes()[..12]
                .iter()
                .all(|byte| *byte == 0),
            "vault address exceeds 20 bytes"
        );
        let sender = config
            .sender
            .strip_prefix("0x")
            .context("sender must be a 0x-prefixed address")?;
        ensure!(
            hex::decode(sender)?.len() == 20,
            "sender must be a 20-byte address"
        );
        config.fee.validate()?;
        config.alarms.validate().map_err(anyhow::Error::msg)?;
        ensure!(
            config.defeat_gas_limit > 0 && config.raise_gas_limit > 0,
            "defeat and raise gas limits must be positive"
        );
        let checkpoint: Checkpoint = if config.checkpoint.exists() {
            serde_json::from_slice(&std::fs::read(&config.checkpoint)?)?
        } else {
            Checkpoint {
                sender: config.sender.to_ascii_lowercase(),
                chain_id: config.chain_id,
                contract_address: config.contract_address,
                from_block: config.from_block,
                next_block: config.from_block,
                last_block_hash: None,
                pending: BTreeMap::new(),
                detached_nonces: BTreeMap::new(),
                missed_total: 0,
                missed_defeats_total: 0,
                missed_raises_total: 0,
                retired_leaves_total: 0,
                last_missed: None,
                missed_nullifiers: Vec::new(),
                legacy_miss_bound: None,
                pending_at_upgrade: Vec::new(),
                scan_cursor_at_upgrade: None,
                scanned_through_timestamp: None,
            }
        };
        ensure!(
            checkpoint.sender == config.sender.to_ascii_lowercase()
                && checkpoint.chain_id == config.chain_id
                && checkpoint.contract_address == config.contract_address
                && checkpoint.from_block == config.from_block,
            "challenge checkpoint belongs to another deployment"
        );
        let mut checkpoint = checkpoint;
        // Checkpoints from earlier releases record misses only on the
        // obligation and in `last_missed`.
        let reported: Vec<Felt252> = checkpoint
            .last_missed
            .iter()
            .map(|missed| missed.nullifier)
            .chain(
                checkpoint
                    .pending
                    .values()
                    .filter(|pending| pending.deadline_reported)
                    .map(|pending| pending.nullifier),
            )
            .collect();
        for nullifier in reported {
            if !checkpoint.missed_nullifiers.contains(&nullifier) {
                checkpoint.missed_nullifiers.push(nullifier);
            }
        }
        let mut config_warnings = Vec::new();
        if config.chain_id == 1 && config.fee.max_fee_per_gas < 100 * GWEI {
            config_warnings.push("fee cap below typical Mainnet base-fee peaks".to_string());
        }
        let started_at = unix_now();
        let sender = SenderStatus {
            address: config.sender.to_ascii_lowercase(),
            // No challenge can lock more than the transaction fee ceiling.
            min_balance_wei: config
                .alarms
                .min_sender_balance_wei
                .unwrap_or(
                    DEFAULT_CHALLENGE_GAS
                        .saturating_mul(config.fee.max_fee_per_gas)
                        .min(config.fee.tx_fee_cap_wei),
                )
                .to_string(),
            max_fee_per_gas_wei: config.fee.max_fee_per_gas.to_string(),
            max_priority_fee_per_gas_wei: config.fee.max_priority_fee_per_gas.to_string(),
            priority_fee_per_gas_wei: config.fee.priority_fee_per_gas.to_string(),
            tx_fee_cap_wei: config.fee.tx_fee_cap_wei.to_string(),
            ..Default::default()
        };
        let status = Arc::new(RwLock::new(ChallengeStatus::initial(
            ChainStatus::default(),
            sender.clone(),
            started_at,
        )));
        let proof_setup_dir = config.proof_setup_dir.display().to_string();
        let mut service = Self {
            verifier: RequestVerifier::load(&config.proof_setup_dir)?,
            identity: StatementIdentity::load(&proof_setup_dir)?,
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()?,
            watcher: ChallengeWatcher::new(store),
            checkpoint,
            status,
            started_at,
            challenge_period: None,
            vault_state_key: None,
            vault_warning: None,
            startup_warning: None,
            config_warnings,
            head: None,
            head_seen: None,
            vault_root: None,
            latest_nonce_count: None,
            poll: PollStatus::default(),
            indexer: IndexerStatus::default(),
            indexer_logged_at: None,
            escape_listings: 0,
            escape_cursor: 0,
            dead_escapes: BTreeMap::new(),
            sender,
            sender_balance: None,
            signer_tx_fee_cap: None,
            node_refused_tx_fee: None,
            last_observed_at: None,
            last_gas: None,
            evaluations: BTreeMap::new(),
            previous_evaluations: BTreeMap::new(),
            blocked_since: BTreeMap::new(),
            observed_fees: BTreeMap::new(),
            nonce_failures: BTreeMap::new(),
            detached_status: Vec::new(),
            logged: BTreeMap::new(),
            outcome_ranges: MAX_OUTCOME_RANGES_PER_POLL,
            config,
        };
        service.publish();
        Ok(service)
    }

    /// Shared handle for the status listener.
    pub fn status_handle(&self) -> StatusHandle {
        self.status.clone()
    }

    /// The status as the listener would serve it now.
    pub fn status(&self) -> ChallengeStatus {
        let snapshot = match self.status.read() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        challenge_status::evaluate(&snapshot, &self.config.alarms, unix_now())
    }

    /// Refuse a server database that is not bound to this deployment: the
    /// binding row must name this chain and vault, and its state signing key
    /// must equal the vault's immutable key read over the RPC. A daemon on the
    /// wrong database would report every fraudulent escape as no evidence.
    pub async fn verify_deployment_binding(
        &mut self,
    ) -> Result<DeploymentBinding, DeploymentCheckError> {
        let result = self.check_deployment_binding().await;
        self.startup_warning = match &result {
            Ok(_) => None,
            Err(error) => Some(format!("deployment binding not verified: {error}")),
        };
        self.publish();
        result
    }

    async fn check_deployment_binding(
        &mut self,
    ) -> Result<DeploymentBinding, DeploymentCheckError> {
        let binding = self
            .watcher
            .deployment_binding()
            .map_err(|error| DeploymentCheckError::Unavailable(anyhow!(error)))?
            .ok_or_else(|| {
                DeploymentCheckError::Mismatch(
                    "server database has no deployment binding; upgrade and start the API server first"
                        .into(),
                )
            })?;
        if binding.chain_id != self.config.chain_id
            || binding.contract_address != self.vault_address()
        {
            return Err(DeploymentCheckError::Mismatch(format!(
                "server database is bound to chain {} vault {}, not chain {} vault {}",
                binding.chain_id,
                binding.contract_address,
                self.config.chain_id,
                self.vault_address()
            )));
        }
        // The evidence was verified, and the vault verifies challenges, with
        // the keys of one statement and setup: this daemon's.
        if let Some(mismatch) = self.identity.mismatch(&binding) {
            return Err(DeploymentCheckError::Mismatch(format!(
                "server database serves another statement than this daemon's verifying keys: {mismatch}"
            )));
        }
        let chain = self
            .rpc("eth_chainId", json!([]))
            .await
            .and_then(|value| quantity(&value))
            .map_err(DeploymentCheckError::Unavailable)?;
        if chain != self.config.chain_id {
            return Err(DeploymentCheckError::Mismatch(
                "RPC chain ID does not match challenge deployment".into(),
            ));
        }
        let key = self
            .read_state_key()
            .await
            .map_err(DeploymentCheckError::Unavailable)?;
        if key != (binding.state_signing_key.x, binding.state_signing_key.y) {
            return Err(DeploymentCheckError::Mismatch(
                "server database state signing key differs from the vault's stateSigningKeyX/Y"
                    .into(),
            ));
        }
        self.vault_state_key = Some(key);
        Ok(binding)
    }

    /// The startup checks (§5.4, §5.5): the database binding (as
    /// `verify_deployment_binding`) must be the deployment manifest's; the
    /// vault and adapter must pass the startup probes (revision 3, the
    /// adapter's circuit and verifying-key hashes equal to the loaded keys,
    /// and the three runtime codehashes the manifest pins); and the vault's
    /// challenge period must be the manifest's and pass the G5 and raise
    /// timing checks with `timing` and `raise_lead_seconds`.
    pub async fn verify_deployment(
        &mut self,
        manifest: &DeploymentManifest,
        timing: ChallengeTiming,
    ) -> Result<DeploymentBinding, DeploymentCheckError> {
        let result = self.check_deployment(manifest, timing).await;
        self.startup_warning = match &result {
            Ok(_) => None,
            Err(error) => Some(format!("deployment not verified: {error}")),
        };
        self.publish();
        result
    }

    async fn check_deployment(
        &mut self,
        manifest: &DeploymentManifest,
        timing: ChallengeTiming,
    ) -> Result<DeploymentBinding, DeploymentCheckError> {
        let vault = self.vault_address();
        if manifest.chain_id != self.config.chain_id || manifest.contract_address != vault {
            return Err(DeploymentCheckError::Mismatch(format!(
                "the deployment manifest is for vault {} on chain {}, not vault {vault} on chain {}",
                manifest.contract_address, manifest.chain_id, self.config.chain_id
            )));
        }
        let binding = self.check_deployment_binding().await?;
        if let Some(mismatch) = manifest.binding_mismatch(&binding) {
            return Err(DeploymentCheckError::Mismatch(mismatch));
        }
        let reader = RpcReader {
            client: self.client.clone(),
            url: self.config.rpc_url.clone(),
        };
        probe_deployment(&reader, manifest, &self.identity)
            .await
            .map_err(|error| match error {
                ProbeError::Mismatch(message) => DeploymentCheckError::Mismatch(message),
                ProbeError::Unavailable(message) => {
                    DeploymentCheckError::Unavailable(anyhow!(message))
                }
            })?;
        let period = self
            .call(selector("challengePeriod()"))
            .await
            .and_then(|words| {
                ensure!(words.len() == 1, "malformed challengePeriod response");
                felt_u64(&words[0])
            })
            .map_err(DeploymentCheckError::Unavailable)?;
        if period != manifest.challenge_period || period != binding.challenge_period_seconds {
            return Err(DeploymentCheckError::Mismatch(format!(
                "vault challengePeriod() is {period} s, but the deployment manifest pins {} s and the database binding records {} s",
                manifest.challenge_period, binding.challenge_period_seconds
            )));
        }
        crate::config::validate_challenger_timing(
            timing.settlement_window_seconds,
            timing.settlement_poll_seconds,
            self.config.raise_lead_seconds,
            period,
        )
        .map_err(|error| DeploymentCheckError::Mismatch(format!("{error:#}")))?;
        self.challenge_period = Some(period);
        Ok(binding)
    }

    /// Scan a bounded event range, persist it, then reconcile and submit work.
    /// Errors leave the durable queue intact for the next poll or restart.
    pub async fn poll_once(&mut self) -> anyhow::Result<()> {
        self.poll.last_started_at = Some(unix_now());
        if let Ok(mut status) = self.status.write() {
            status.poll.last_started_at = self.poll.last_started_at;
        }
        let mut evaluated = BTreeSet::new();
        let mut scanned_head = None;
        let result = self.poll_inner(&mut evaluated, &mut scanned_head).await;
        if let Some(head) = scanned_head {
            // Every obligation the loop did not reach is still observed, so
            // its deadline and blocking reason stay visible.
            let blocker = self.queue_blocker();
            let unevaluated: Vec<u32> = self
                .checkpoint
                .pending
                .keys()
                .filter(|note| !evaluated.contains(note))
                .copied()
                .collect();
            for note in unevaluated {
                let blocked = match self.nonce_failures.remove(&note) {
                    Some(error) => Some((BlockedReason::RpcError, error)),
                    None => match blocker {
                        Some((nonce, owner)) => Some((
                            BlockedReason::NonceBlocked,
                            format!("queued behind unresolved nonce {nonce} (note {owner})"),
                        )),
                        None => result.as_ref().err().map(|error| {
                            (
                                BlockedReason::RpcError,
                                format!("poll aborted before this obligation: {error}"),
                            )
                        }),
                    },
                };
                if let Err(error) = self.observe_only(note, &head, blocked).await {
                    self.evaluate_failure(note, BlockedReason::RpcError, &error);
                }
            }
        }
        self.nonce_failures.clear();
        self.finish_poll(&result);
        result
    }

    async fn poll_inner(
        &mut self,
        evaluated: &mut BTreeSet<u32>,
        scanned_head: &mut Option<HeadInfo>,
    ) -> anyhow::Result<()> {
        let chain = self.rpc("eth_chainId", json!([])).await?;
        ensure!(
            quantity(&chain)? == self.config.chain_id,
            "RPC chain ID does not match challenge deployment"
        );
        let head = self.fetch_head().await?;
        if self.checkpoint.legacy_miss_bound.is_none() && self.checkpoint.unattributed_misses() > 0
        {
            self.checkpoint.legacy_miss_bound =
                Some(self.checkpoint.legacy_miss_deadline_bound(head.timestamp));
            self.checkpoint.pending_at_upgrade = self
                .checkpoint
                .pending
                .values()
                .map(|pending| pending.nullifier)
                .collect();
            self.checkpoint.scan_cursor_at_upgrade = self
                .checkpoint
                .last_block_hash
                .is_some()
                .then_some(self.checkpoint.next_block);
            self.persist()?;
        }
        self.outcome_ranges = MAX_OUTCOME_RANGES_PER_POLL;
        self.scan_events(head.number).await?;
        self.poll.last_scan_success_at = Some(unix_now());
        self.previous_evaluations = std::mem::take(&mut self.evaluations);
        *scanned_head = Some(head.clone());
        self.load_vault_constants().await;
        self.sync_pending_escapes(head.number).await?;
        if self.observation_due() {
            self.observe_sender().await;
            self.observe_indexer(&head).await;
        }
        self.reconcile_detached_nonces().await?;
        // Each note gets a fresh current-root path. A previous successful
        // challenge can change that root before the next submission.
        let mut notes: Vec<_> = self.checkpoint.pending.keys().copied().collect();
        // Durable ambiguous sends from *previous* polls must run before newly
        // eligible notes, irrespective of note ID or event arrival order.
        notes.sort_by_key(|note| {
            let pending = &self.checkpoint.pending[note];
            (
                pending.nonce.is_none() || pending.transaction_hash.is_some(),
                pending.nonce,
                *note,
            )
        });
        let mut first_error = None;
        for note in notes {
            // Nonce ownership is independent of the withdrawal's deadline,
            // evidence and current state. In particular, an ambiguous send
            // which has mined must not prevent other notes from progressing.
            let nonce_state = match self.reconcile_nonce(note).await {
                Ok(state) => state,
                Err(error) => {
                    self.nonce_failures
                        .insert(note, format!("nonce status unavailable: {error}"));
                    first_error.get_or_insert(error);
                    break; // No safe new allocation when nonce status is unknown.
                }
            };
            evaluated.insert(note);
            let owned_nonce = self.checkpoint.pending[&note].nonce;
            if let Err(error) = self.reconcile(note, nonce_state, &head).await {
                tracing::error!(note_id = note, error = %error, "escape challenge requires retry");
                if !self.evaluations.contains_key(&note) {
                    self.evaluate_failure(note, BlockedReason::RpcError, &error);
                }
                if first_error.is_none() {
                    first_error = Some(error);
                }
                // Invalid evidence or a stale path on one note must not starve
                // other notes. An ambiguous send is different: resolve its
                // reserved nonce before asking the signer for another one.
            }
            if nonce_state != NonceState::Mined
                && (self.checkpoint.pending.get(&note).is_some_and(|pending| {
                    pending.nonce.is_some() && pending.transaction_hash.is_none()
                }) || owned_nonce
                    .is_some_and(|nonce| self.checkpoint.detached_nonces.contains_key(&nonce)))
            {
                break;
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    async fn fetch_head(&mut self) -> anyhow::Result<HeadInfo> {
        let block = self
            .rpc("eth_getBlockByNumber", json!(["latest", false]))
            .await?;
        let number = match block.get("number").filter(|value| !value.is_null()) {
            Some(number) => quantity(number)?,
            None => quantity(&self.rpc("eth_blockNumber", json!([])).await?)?,
        };
        let head = HeadInfo {
            number,
            timestamp: quantity(&block["timestamp"]).context("latest block lacks a timestamp")?,
            base_fee: block
                .get("baseFeePerGas")
                .filter(|value| !value.is_null())
                .map(quantity_u128)
                .transpose()?,
        };
        if self.head_seen.is_none_or(|(seen, _)| seen != number) {
            self.head_seen = Some((number, unix_now()));
        }
        self.head = Some(head.clone());
        Ok(head)
    }

    async fn scan_events(&mut self, latest: u64) -> anyhow::Result<()> {
        if let Some(expected) = self.checkpoint.last_block_hash.clone() {
            // Only a block with another hash, read twice, is a reorganization;
            // a null answer fails the poll instead.
            let cursor = self.checkpoint.next_block - 1;
            if self.cursor_block_hash(cursor).await? != expected {
                if self.cursor_block_hash(cursor).await? == expected {
                    tracing::warn!(
                        block = cursor,
                        "an RPC answer for the challenge cursor block came from another fork; the next read matched the cursor"
                    );
                } else {
                    tracing::warn!(
                        block = cursor,
                        "challenge cursor was reorganized; replaying deployment events"
                    );
                    self.checkpoint.next_block = self.config.from_block;
                    self.checkpoint.last_block_hash = None;
                    self.persist()?;
                }
            }
        }
        let Some(safe_head) = latest.checked_sub(self.config.confirmations) else {
            return Ok(());
        };
        if self.checkpoint.next_block > safe_head {
            return Ok(());
        }
        let to = safe_head.min(self.checkpoint.next_block.saturating_add(999));
        let before = self
            .rpc("eth_getBlockByNumber", json!([format!("0x{to:x}"), false]))
            .await?;
        let before_hash = before["hash"].as_str().context("scan block lacks hash")?;
        let topic =
            |signature: &str| format!("0x{}", hex::encode(Keccak256::digest(signature.as_bytes())));
        let logs = self.rpc("eth_getLogs", json!([{
            "address": self.vault_address(), "fromBlock": format!("0x{:x}", self.checkpoint.next_block),
            "toBlock": format!("0x{to:x}"), "topics": [[
                topic(ESCAPE_EVENT), topic(CONCESSION_RECORDED_EVENT),
                topic(CONCESSION_RAISED_EVENT), topic(CHALLENGED_EVENT),
            ]]
        }])).await?;
        let after = self
            .rpc("eth_getBlockByNumber", json!([format!("0x{to:x}"), false]))
            .await?;
        let after_hash = after["hash"].as_str().context("scan block lacks hash")?;
        ensure!(
            before_hash == after_hash,
            "chain reorganized while reading escape events; retrying range"
        );
        let mut logs = logs
            .as_array()
            .context("RPC logs must be an array")?
            .iter()
            .filter(|log| log.get("removed").and_then(Value::as_bool) != Some(true))
            .map(|log| {
                let position = |field: &str| log.get(field).and_then(|value| quantity(value).ok());
                (position("blockNumber"), position("logIndex"), log)
            })
            .collect::<Vec<_>>();
        // The concession record follows its initiation in the same
        // transaction: apply the logs in chain order.
        logs.sort_by_key(|(block, index, _)| (*block, *index));
        for (block, _, log) in logs {
            match decode_scan_event(log)? {
                ScanEvent::Initiated {
                    note,
                    nullifier,
                    deadline,
                } => {
                    self.track_escape(note, nullifier, Some(deadline), block);
                }
                ScanEvent::Recorded {
                    note,
                    next_nullifier,
                    state_balance,
                    conceded,
                } => {
                    if let Some(entry) = self
                        .checkpoint
                        .pending
                        .get_mut(&note)
                        .filter(|entry| entry.next_nullifier.is_none())
                    {
                        entry.next_nullifier = Some(next_nullifier);
                        entry.state_balance = Some(state_balance);
                        entry.conceded = Some(conceded);
                    }
                }
                ScanEvent::Raised {
                    note,
                    nullifier,
                    conceded,
                } => {
                    if let Some(entry) = self
                        .checkpoint
                        .pending
                        .get_mut(&note)
                        .filter(|entry| entry.nullifier == nullifier)
                    {
                        entry.conceded = Some(entry.conceded.unwrap_or(0).max(conceded));
                    }
                }
                ScanEvent::Challenged { note, nullifier } => {
                    if self
                        .checkpoint
                        .pending
                        .get(&note)
                        .is_some_and(|entry| entry.nullifier == nullifier)
                    {
                        tracing::info!(note_id = note, nullifier = %nullifier, "escape defeated; any pending raise for it is dropped");
                    }
                }
            }
        }
        self.checkpoint.last_block_hash = Some(after_hash.to_owned());
        self.checkpoint.next_block = to.saturating_add(1);
        self.checkpoint.scanned_through_timestamp = after
            .get("timestamp")
            .and_then(|value| quantity(value).ok());
        self.persist()
    }

    /// The hash of the scan cursor block. A null or hash-less answer, as
    /// from a backend that has not reached the block, is an error to retry.
    async fn cursor_block_hash(&self, number: u64) -> anyhow::Result<String> {
        let block = self
            .rpc(
                "eth_getBlockByNumber",
                json!([format!("0x{number:x}"), false]),
            )
            .await?;
        block
            .get("hash")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .with_context(|| {
                format!("RPC returned no hash for the scan cursor block {number}; retrying")
            })
    }

    /// Track an escape from an event (`seen` is its block) or the indexer's
    /// pending list. The caller persists the checkpoint.
    fn track_escape(
        &mut self,
        note: u32,
        nullifier: Felt252,
        deadline: Option<u64>,
        seen: Option<u64>,
    ) -> bool {
        if let Some(existing) = self.checkpoint.pending.get_mut(&note) {
            if existing.nullifier == nullifier {
                let mut changed = false;
                if existing.challenge_deadline.is_none() && deadline.is_some() {
                    existing.challenge_deadline = deadline;
                    changed = true;
                }
                if seen.is_some() && existing.seen_block < seen {
                    existing.seen_block = seen;
                    changed = true;
                }
                return changed;
            }
        }
        self.detach_nonce(note);
        self.forget_observations(note);
        let mut pending = PendingChallenge {
            nullifier,
            challenge_deadline: deadline,
            first_seen_at: Some(unix_now()),
            seen_block: seen,
            ..Default::default()
        };
        // Replaying historical events may temporarily replace this note and
        // then restore its current nullifier. Recover its exact reservation
        // instead of stranding it.
        let restored_nonce = self
            .checkpoint
            .detached_nonces
            .iter()
            .find(|(_, entry)| entry.note_id == note && entry.nullifier == nullifier)
            .map(|(nonce, _)| *nonce);
        if let Some(nonce) = restored_nonce {
            let entry = self.checkpoint.detached_nonces.remove(&nonce).unwrap();
            pending.nonce = Some(nonce);
            pending.transaction_hash = entry.transaction_hash;
            pending.attempt = entry.attempt;
        }
        self.checkpoint.pending.insert(note, pending);
        true
    }

    /// Completeness against a lagging `eth_getLogs` replica: for every note the
    /// indexer lists that the checkpoint does not track as listed, track the
    /// escape the vault's `pendingWithdrawals` holds. Only the note ID is
    /// taken from the list: the vault can change after the indexer's block,
    /// and a challenge and re-escape pair leaves the root unchanged, so an
    /// indexer that checks only its root can list a stale nullifier and
    /// deadline. Older indexers without the endpoint are tolerated with a
    /// status warning.
    ///
    /// Each poll reads at most MAX_ESCAPE_CHECKS_PER_POLL listed notes, from
    /// the note where the previous poll's reads stopped, wrapping around, so
    /// every listed note due for a read is read within
    /// ceil(n / MAX_ESCAPE_CHECKS_PER_POLL) polls. A listed, untracked note
    /// the vault holds no escape for stays due on every listing until reads
    /// DEAD_ESCAPE_CONFIRM_SECONDS apart have found none; it is then read
    /// again only every DEAD_ESCAPE_RECHECK_POLLS listings. It is reported as
    /// a disagreement, which calls for a resync, once reads
    /// --blocked-warning-seconds apart have found none and a list served at
    /// a block between two of them named it. A list served below the first
    /// such read may only lag the vault, and one beyond this poll's `head`
    /// may hold an escape this RPC does not show yet; neither is reported.
    /// The entry is due for its report's read as soon as the period has
    /// passed and a listing can complete it.
    async fn sync_pending_escapes(&mut self, head: u64) -> anyhow::Result<()> {
        let now = unix_now();
        let listed = match self
            .indexer_get::<PendingEscapesResponse>("/v1/escapes/pending")
            .await
        {
            Ok(listed) => listed,
            Err(IndexerFailure::Status(404)) => {
                self.indexer.pending_escapes = "unsupported".into();
                self.indexer.pending_escapes_unavailable_since = None;
                self.indexer.pending_escapes_disagreement = None;
                self.indexer.pending_escapes_disagreement_since = None;
                return Ok(());
            }
            Err(error) => {
                if self.indexer.pending_escapes != "unavailable" {
                    tracing::warn!(error = %error, "indexer pending-escapes list unavailable");
                }
                self.indexer.pending_escapes = "unavailable".into();
                self.indexer
                    .pending_escapes_unavailable_since
                    .get_or_insert(now);
                return Ok(());
            }
        };
        self.indexer.pending_escapes = "ok".into();
        self.indexer.pending_escapes_unavailable_since = None;
        self.escape_listings += 1;
        let listing = self.escape_listings;
        let warning = self.config.alarms.blocked_warning_seconds;
        let mut changed = false;
        let mut checked = 0;
        let mut disagreements = Vec::new();
        let differs = |escape: &PendingEscape, nullifier: Felt252, deadline: u64| {
            (nullifier != escape.withdrawal_nullifier
                || escape
                    .challenge_deadline
                    .is_some_and(|listed| listed != deadline))
            .then(|| {
                format!(
                    "note {} listed with nullifier {} and deadline {}, the vault holds {} until {deadline}",
                    escape.note_id,
                    escape.withdrawal_nullifier,
                    escape
                        .challenge_deadline
                        .map_or("unknown".into(), |listed| listed.to_string()),
                    nullifier
                )
            })
        };
        let listed_block = listed.block_number;
        let mut unread = Vec::new();
        for escape in listed.escapes {
            // A note tracked as listed is compared with the vault on every
            // reconcile, which also keeps its deadline.
            if let Some(pending) = self
                .checkpoint
                .pending
                .get(&escape.note_id)
                .filter(|pending| pending.nullifier == escape.withdrawal_nullifier)
            {
                if let Some(deadline) = pending.challenge_deadline {
                    disagreements.extend(differs(&escape, pending.nullifier, deadline));
                }
                continue;
            }
            unread.push(escape);
        }
        // A dead entry lasts while its note is listed under the same
        // nullifier and untracked: reconcile reads a tracked note every poll.
        let listed_as: BTreeMap<u32, Felt252> = unread
            .iter()
            .map(|escape| (escape.note_id, escape.withdrawal_nullifier))
            .collect();
        let tracked = &self.checkpoint.pending;
        self.dead_escapes.retain(|note, dead| {
            listed_as.get(note) == Some(&dead.nullifier) && !tracked.contains_key(note)
        });
        for dead in self.dead_escapes.values_mut() {
            // This poll's head was fetched after every earlier listing's reads.
            dead.read_by.get_or_insert(head);
        }
        unread.sort_by_key(|escape| escape.note_id);
        let start = unread.partition_point(|escape| escape.note_id < self.escape_cursor);
        unread.rotate_left(start);
        for escape in unread {
            if self.dead_escapes.get(&escape.note_id).is_some_and(|dead| {
                dead.resting(listing, now, warning, dead.brackets(listed_block, head))
            }) {
                continue;
            }
            if checked == MAX_ESCAPE_CHECKS_PER_POLL {
                self.escape_cursor = escape.note_id;
                break;
            }
            checked += 1;
            let state = match self.escape_state(escape.note_id, head).await {
                Ok(state) => state,
                Err(error) => {
                    tracing::warn!(note_id = escape.note_id, error = %error, "could not confirm an indexer-listed escape");
                    continue;
                }
            };
            if !state.exists {
                if self.checkpoint.pending.contains_key(&escape.note_id) {
                    continue; // Tracked under another nullifier; reconcile retires it.
                }
                // The list may lag the vault, or never learn the escape ended;
                // or this RPC may not yet show a fresh escape.
                let dead = self
                    .dead_escapes
                    .entry(escape.note_id)
                    .or_insert(DeadEscape {
                        nullifier: escape.withdrawal_nullifier,
                        first_seen: now,
                        last_seen: now,
                        checked_at: listing,
                        read_by: None,
                        bracketed: false,
                    });
                dead.last_seen = now;
                dead.checked_at = listing;
                dead.bracketed |= dead.brackets(listed_block, head);
                continue;
            }
            self.dead_escapes.remove(&escape.note_id);
            disagreements.extend(differs(&escape, state.nullifier, state.deadline));
            // The vault is authoritative, whatever the list says.
            if self
                .checkpoint
                .pending
                .get(&escape.note_id)
                .is_some_and(|pending| pending.nullifier == state.nullifier)
            {
                continue;
            }
            let initiated = self
                .challenge_period
                .map(|period| state.deadline.saturating_sub(period));
            if initiated
                .zip(self.checkpoint.scanned_through_timestamp)
                .is_some_and(|(initiated, scanned)| initiated <= scanned)
            {
                tracing::warn!(
                    note_id = escape.note_id,
                    nullifier = %state.nullifier,
                    "escape missing from the event scan added from the indexer pending-escapes list; the RPC eth_getLogs may be lagging"
                );
            } else {
                tracing::info!(note_id = escape.note_id, nullifier = %state.nullifier, "escape ahead of the confirmed event scan added from the indexer pending-escapes list");
            }
            self.indexer.escapes_added_from_indexer += 1;
            changed |=
                self.track_escape(escape.note_id, state.nullifier, Some(state.deadline), None);
            self.set_concession(escape.note_id, &state);
        }
        let mut since = self
            .indexer
            .pending_escapes_disagreement_since
            .unwrap_or(now);
        let persisted: Vec<_> = self
            .dead_escapes
            .iter()
            .filter(|(_, dead)| dead.reported(warning))
            .collect();
        if let Some(first_seen) = persisted.iter().map(|(_, dead)| dead.first_seen).min() {
            // Reads at both ends of the warning period found no escape, and a
            // list served at a block between two of them named the note: the
            // indexer's list has disagreed with the vault since the first.
            since = since.min(first_seen);
            disagreements.push(format!(
                "{} listed note(s) with no pending escape in the vault: {}",
                persisted.len(),
                persisted
                    .iter()
                    .map(|(note, dead)| format!(
                        "note {note} listed with nullifier {}",
                        dead.nullifier
                    ))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        let disagreement = (!disagreements.is_empty()).then(|| bounded(&disagreements.join("; ")));
        if disagreement.is_some() && self.indexer.pending_escapes_disagreement.is_none() {
            tracing::warn!(
                detail = ?disagreement,
                "indexer pending-escapes list disagrees with the vault; tracking the vault's escapes"
            );
        }
        self.indexer.pending_escapes_disagreement_since = disagreement.as_ref().map(|_| since);
        self.indexer.pending_escapes_disagreement = disagreement;
        if changed {
            self.persist()?;
        }
        Ok(())
    }

    /// The vault holds a different escape for a tracked note: the owner
    /// escaped again after a challenge, or an event replay tracked an older
    /// escape. Track the vault's; the old reservation stays detached until
    /// its nonce is consumed or released.
    fn follow_vault_escape(
        &mut self,
        note: u32,
        tracked: Felt252,
        state: &EscapeState,
    ) -> anyhow::Result<()> {
        tracing::warn!(
            note_id = note,
            tracked = %tracked,
            vault = %state.nullifier,
            "the vault holds a different escape than the one tracked for this note; tracking the vault's"
        );
        self.track_escape(note, state.nullifier, Some(state.deadline), None);
        self.set_concession(note, state);
        self.persist()
    }

    /// Record the vault's concession of the tracked escape (the caller
    /// persists).
    fn set_concession(&mut self, note: u32, state: &EscapeState) {
        if let Some(entry) = self
            .checkpoint
            .pending
            .get_mut(&note)
            .filter(|entry| state.exists && entry.nullifier == state.nullifier)
        {
            entry.next_nullifier = Some(state.next_nullifier);
            entry.state_balance = Some(state.state_balance);
            entry.conceded = Some(state.conceded);
        }
    }

    fn observation_due(&mut self) -> bool {
        let now = unix_now();
        let due = self
            .last_observed_at
            .is_none_or(|at| now.saturating_sub(at) >= self.config.alarms.observe_interval_seconds);
        if due {
            self.last_observed_at = Some(now);
        }
        due
    }

    /// Tolerant: failures are recorded on the status and never abort a poll.
    /// The daemon never refuses to send because of the balance it observed.
    async fn observe_sender(&mut self) {
        let now = unix_now();
        match self
            .rpc("eth_getBalance", json!([self.config.sender, "latest"]))
            .await
            .and_then(|value| quantity_u128(&value))
        {
            Ok(balance) => {
                self.sender_balance = Some(balance);
                self.sender.balance_observed_at = Some(now);
                self.sender.balance_detail = None;
            }
            Err(error) if rpc_code(&error) == Some(-32601) => {
                self.sender_balance = None;
                self.sender.balance_detail =
                    Some("the signer RPC does not allow eth_getBalance".into());
            }
            Err(error) => self.sender.balance_detail = Some(bounded(&error.to_string())),
        }
        for tag in ["latest", "pending"] {
            let count = self
                .rpc("eth_getTransactionCount", json!([self.config.sender, tag]))
                .await
                .and_then(|value| quantity(&value))
                .ok();
            if tag == "latest" {
                self.sender.nonce_latest = count.or(self.sender.nonce_latest);
            } else {
                self.sender.nonce_pending = count.or(self.sender.nonce_pending);
            }
        }
        // The bundled signer reports its transaction fee cap; bids stay within
        // the lower of it and this daemon's. Without a report, a cap learned
        // from a refusal stays in force.
        match self
            .rpc("zkapi_signerStatus", json!([]))
            .await
            .and_then(|status| {
                status
                    .get("tx_fee_cap_wei")
                    .filter(|value| !value.is_null())
                    .map(quantity_u128)
                    .transpose()
            }) {
            Ok(Some(cap)) if cap > 0 => {
                self.signer_tx_fee_cap = Some(cap);
                self.sender.signer_status_detail = None;
            }
            Ok(Some(_)) => {
                self.sender.signer_status_detail =
                    Some("the signer reports a zero tx_fee_cap_wei; ignored".into());
            }
            Ok(None) => {
                self.sender.signer_status_detail =
                    Some("the signer does not report tx_fee_cap_wei".into());
            }
            Err(error) if rpc_code(&error) == Some(-32601) => {
                self.sender.signer_status_detail =
                    Some("the signer RPC does not provide zkapi_signerStatus".into());
            }
            Err(error) => self.sender.signer_status_detail = Some(bounded(&error.to_string())),
        }
    }

    /// Compare the indexer's served root with the vault. An exact verdict uses
    /// the vault root at the indexer's own block (EIP-1898 `blockHash`): equal
    /// means lagging, different means diverged, and an unknown hash is
    /// inconclusive. Expected lag is never counted as divergence.
    async fn observe_indexer(&mut self, head: &HeadInfo) {
        let response = match self.indexer_get::<TreeRootResponse>("/v1/tree/root").await {
            Ok(response) => response,
            Err(error) => {
                let phase = self.indexer_health_phase().await;
                match phase.as_deref() {
                    Some("diverged") => self.set_indexer_state(
                        IndexerState::Diverged,
                        Some("indexer /health reports diverged".into()),
                    ),
                    phase => self.set_indexer_state(
                        IndexerState::Unavailable,
                        Some(format!(
                            "indexer root unavailable ({error}); /health status {}",
                            phase.unwrap_or("unreachable")
                        )),
                    ),
                }
                return;
            }
        };
        self.indexer.root = Some(response.root);
        self.indexer.block_number = response.block_number;
        self.indexer.block_hash = response.block_hash.clone();
        let live = match self.live_root().await {
            Ok(root) => root,
            Err(error) => {
                self.indexer.detail = Some(bounded(&format!(
                    "vault currentRoot() unavailable: {error}"
                )));
                return;
            }
        };
        if response.root == live {
            self.indexer.lag_blocks = Some(0);
            self.set_indexer_state(IndexerState::Consistent, None);
            return;
        }
        let state = self
            .classify_root_mismatch(
                response.root,
                response.block_hash.as_deref(),
                response.block_number,
                head,
            )
            .await;
        let detail = match state {
            IndexerState::Diverged => "indexer root differs from the vault root",
            _ => "indexer root is behind the vault root",
        };
        self.set_indexer_state(state, Some(detail.into()));
    }

    async fn classify_root_mismatch(
        &mut self,
        indexer_root: Felt252,
        block_hash: Option<&str>,
        block_number: Option<u64>,
        head: &HeadInfo,
    ) -> IndexerState {
        self.indexer.lag_blocks = block_number.map(|block| head.number.saturating_sub(block));
        match block_hash {
            Some(hash) => match self.root_at_block_hash(hash).await {
                Ok(root) if root == indexer_root => IndexerState::Lagging,
                Ok(_) => IndexerState::Diverged,
                // The RPC does not know the indexer's block: inconclusive.
                Err(_) => IndexerState::Lagging,
            },
            None => {
                // An indexer without block metadata: a persistent mismatch
                // over time and observations is treated as divergence.
                let now = unix_now();
                let since = *self.indexer.mismatch_since.get_or_insert(now);
                self.indexer.consecutive_mismatches =
                    self.indexer.consecutive_mismatches.saturating_add(1);
                if now.saturating_sub(since) >= self.config.alarms.indexer_divergence_seconds
                    && self.indexer.consecutive_mismatches
                        >= self.config.alarms.indexer_divergence_polls
                {
                    IndexerState::Diverged
                } else {
                    IndexerState::Lagging
                }
            }
        }
    }

    fn set_indexer_state(&mut self, state: IndexerState, detail: Option<String>) {
        let now = unix_now();
        let previous = self.indexer.state;
        match state {
            IndexerState::Consistent => {
                self.indexer.mismatch_since = None;
                self.indexer.consecutive_mismatches = 0;
                self.indexer.unavailable_since = None;
            }
            IndexerState::Unavailable => {
                self.indexer.unavailable_since.get_or_insert(now);
            }
            IndexerState::Lagging | IndexerState::Diverged | IndexerState::Unknown => {
                self.indexer.unavailable_since = None;
            }
        }
        self.indexer.state = state;
        self.indexer.detail = detail;
        self.indexer.observed_at = Some(now);
        if state == IndexerState::Diverged {
            if previous != IndexerState::Diverged
                || self
                    .indexer_logged_at
                    .is_none_or(|at| now.saturating_sub(at) >= RELOG_SECONDS)
            {
                tracing::error!(
                    indexer_root = ?self.indexer.root,
                    vault_root = ?self.vault_root,
                    "indexer mirror diverged from vault currentRoot; challenges cannot be built until the indexer is resynced"
                );
                self.indexer_logged_at = Some(now);
            }
        } else if previous == IndexerState::Diverged {
            tracing::info!(state = ?state, "indexer mirror no longer diverges from vault currentRoot");
            self.indexer_logged_at = None;
        }
    }

    async fn load_vault_constants(&mut self) {
        let mut errors = Vec::new();
        if self.challenge_period.is_none() {
            match self
                .call(selector("challengePeriod()"))
                .await
                .and_then(|words| {
                    ensure!(words.len() == 1, "malformed challengePeriod response");
                    felt_u64(&words[0])
                }) {
                Ok(period) => self.challenge_period = Some(period),
                Err(error) => errors.push(format!("challengePeriod(): {error}")),
            }
        }
        if self.vault_state_key.is_none() {
            match self.read_state_key().await {
                Ok(key) => self.vault_state_key = Some(key),
                Err(error) => errors.push(format!("stateSigningKeyX/Y(): {error}")),
            }
        }
        self.vault_warning = (!errors.is_empty()).then(|| {
            bounded(&format!(
                "vault constants unavailable; retrying: {}",
                errors.join("; ")
            ))
        });
    }

    async fn read_state_key(&self) -> anyhow::Result<(Felt252, Felt252)> {
        let mut key = [Felt252::ZERO; 2];
        for (slot, getter) in key
            .iter_mut()
            .zip(["stateSigningKeyX()", "stateSigningKeyY()"])
        {
            let words = self.call(selector(getter)).await?;
            ensure!(words.len() == 1, "malformed {getter} response");
            *slot = words[0];
        }
        Ok((key[0], key[1]))
    }

    async fn reconcile(
        &mut self,
        note: u32,
        nonce_state: NonceState,
        head: &HeadInfo,
    ) -> anyhow::Result<()> {
        let pending = self.checkpoint.pending[&note].clone();
        if pending.retire_leaf {
            return self.reconcile_retirement(note, nonce_state, head).await;
        }
        let state = self.escape_state(note, head.number).await?;
        if state.exists && state.nullifier != pending.nullifier {
            // Re-checked every poll, so a tip reorg back to the tracked escape
            // restores it with its reservation.
            return self.follow_vault_escape(note, pending.nullifier, &state);
        }
        if !state.exists {
            return self.retire_if_confirmed(note, &pending, head).await;
        }
        self.note_pending(note, &state)?;
        self.note_seen(
            note,
            head.number
                .saturating_sub(self.config.confirmations)
                .saturating_sub(SEEN_MARGIN_BLOCKS),
            LOG_RANGE_BLOCKS,
        )?;
        let decision = match self.decide(&state, head.timestamp) {
            Ok(decision) => decision,
            Err(error) => {
                self.record(note, decision_unreadable(&error));
                return Err(error);
            }
        };
        if head.timestamp >= state.deadline {
            // Keep the obligation until confirmed vault completion, including
            // the possibility of a reorg back before the deadline.
            return self
                .record_expiry(note, &decision, &state, Some(nonce_state))
                .await;
        }
        let successor_invalid = decision.successor_invalid.clone();
        let acted = self.act(note, nonce_state, head, &pending, decision).await;
        let Some(detail) = successor_invalid else {
            return acted;
        };
        // Whatever was sent, the rows that do not verify stay alarmed on.
        self.flag_invalid_evidence(note, &detail);
        acted.and(Err(anyhow!(detail)))
    }

    /// Mark the obligation's recorded status blocked on evidence that does
    /// not verify, unless a condition as critical already blocks it.
    fn flag_invalid_evidence(&mut self, note: u32, detail: &str) {
        let Some(evaluation) = self.evaluations.get_mut(&note) else {
            return;
        };
        if evaluation
            .blocked
            .is_some_and(BlockedReason::is_immediately_critical)
        {
            return;
        }
        let detail = match (evaluation.blocked, &evaluation.detail) {
            (Some(_), Some(previous)) => format!("{detail}; {previous}"),
            _ => detail.to_owned(),
        };
        if evaluation.blocked.is_none() {
            let entry = self.blocked_since.entry(note).or_insert((unix_now(), 0));
            entry.1 = entry.1.saturating_add(1);
        }
        evaluation.blocked = Some(BlockedReason::EvidenceInvalid);
        evaluation.detail = Some(bounded(&detail));
    }

    /// The deployment every evidence row must name.
    fn evidence_binding(&self) -> anyhow::Result<EvidenceBinding> {
        let state_key = self
            .vault_state_key
            .context("vault state signing key not yet read")?;
        Ok(EvidenceBinding {
            chain_id: self.config.chain_id,
            contract_address: self.config.contract_address,
            state_key,
        })
    }

    /// §5.4's decision order for a pending escape at chain time `now`: a
    /// defeat with any verified evidence at `N⁺`; otherwise a raise to `Ω`
    /// once `Ω` is final, or at `deadline - raise_lead_seconds` at the
    /// latest, when `min(Ω, bound, B)` exceeds the concession by at least
    /// `raise_min_units`; otherwise nothing. Rows at `N⁺` that do not verify
    /// defeat nothing: they are reported (`successor_invalid`) and the raise
    /// is decided as without them. An unreadable database is an error, never
    /// "nothing due".
    fn decide(&self, state: &EscapeState, now: u64) -> anyhow::Result<Decision> {
        let binding = self.evidence_binding()?;
        let unreadable = |error: ServerError| anyhow!("evidence database read failed: {error}");
        let raise_due_at = state
            .deadline
            .saturating_sub(self.config.raise_lead_seconds);
        let successor = self
            .watcher
            .verified_evidence(&state.next_nullifier, &self.verifier, &binding)
            .map_err(unreadable)?;
        if let Some(evidence) = successor.earliest() {
            return Ok(Decision {
                evidence: EvidenceKind::Successor,
                settlement: None,
                owed: None,
                raise_due_at,
                due: Due::Defeat {
                    evidence: evidence.clone(),
                    before_deadline: successor.existed_before(state.deadline),
                },
                successor_invalid: None,
            });
        }
        let successor_invalid = (!successor.rejected.is_empty()).then(|| {
            format!(
                "evidence at the successor nullifier does not verify: {}",
                successor.rejected.join("; ")
            )
        });
        let decision = |evidence, settlement, owed, due: Due| Decision {
            // Shown as corrupt unless a raise is sent from verified rows.
            evidence: if successor_invalid.is_some() && !matches!(due, Due::Raise { .. }) {
                EvidenceKind::Corrupt
            } else {
                evidence
            },
            settlement,
            owed,
            raise_due_at,
            due,
            successor_invalid: successor_invalid.clone(),
        };
        let Owed { basis, settlement } = self.watcher.owed(&state.nullifier).map_err(unreadable)?;
        let at_escaped = self
            .watcher
            .verified_evidence(&state.nullifier, &self.verifier, &binding)
            .map_err(unreadable)?;
        let raise_evidence = at_escaped.max_bound();
        let (kind, owed) = match basis {
            OwedBasis::Settled { charge } => (EvidenceKind::Settled, Some(charge)),
            OwedBasis::Unsettled => (
                EvidenceKind::Unsettled,
                (now >= raise_due_at)
                    .then(|| raise_evidence.map(|evidence| evidence.inputs.solvency_bound))
                    .flatten(),
            ),
            OwedBasis::Nothing(why) => (nothing_kind(why), Some(0)),
        };
        let Some(owed) = owed else {
            if raise_evidence.is_none() && !at_escaped.rejected.is_empty() {
                return Ok(decision(
                    EvidenceKind::Corrupt,
                    settlement,
                    None,
                    Due::Invalid {
                        kind: CallKind::Raise,
                        detail: format!(
                            "evidence at the escaped nullifier does not verify: {}",
                            at_escaped.rejected.join("; ")
                        ),
                    },
                ));
            }
            return Ok(decision(kind, settlement, None, Due::AwaitingSettlement));
        };
        // What the vault would concede: min(amount, proof bound, B).
        let target = raise_evidence.map_or(0, |evidence| {
            owed.min(evidence.inputs.solvency_bound)
                .min(state.state_balance)
        });
        let due = match raise_evidence {
            Some(evidence)
                if target > state.conceded
                    && target - state.conceded >= self.config.raise_min_units =>
            {
                Due::Raise {
                    evidence: evidence.clone(),
                    amount: owed,
                }
            }
            None if owed > state.conceded && !at_escaped.rejected.is_empty() => Due::Invalid {
                kind: CallKind::Raise,
                detail: format!(
                    "evidence at the escaped nullifier does not verify: {}",
                    at_escaped.rejected.join("; ")
                ),
            },
            _ if owed == 0 => Due::Nothing {
                covered: false,
                detail: match basis {
                    OwedBasis::Nothing(why) => why.reason().to_string(),
                    _ => "the request at the escaped nullifier was charged nothing".into(),
                },
            },
            _ if target > state.conceded => Due::Nothing {
                covered: false,
                detail: format!(
                    "a raise of {} units is below --raise-min-units {}",
                    target - state.conceded,
                    self.config.raise_min_units
                ),
            },
            _ => Due::Nothing {
                covered: true,
                detail: format!(
                    "the concession {} covers the {owed} units owed",
                    state.conceded
                ),
            },
        };
        Ok(decision(
            if matches!(due, Due::Invalid { .. }) {
                EvidenceKind::Corrupt
            } else {
                kind
            },
            settlement,
            Some(owed),
            due,
        ))
    }

    /// Send, replace or keep the call `decision` makes due, on the note's
    /// nonce lane. A defeat replaces an unmined raise at its nonce; a raise
    /// never replaces a defeat; any other replacement changes only fees.
    async fn act(
        &mut self,
        note: u32,
        nonce_state: NonceState,
        head: &HeadInfo,
        pending: &PendingChallenge,
        decision: Decision,
    ) -> anyhow::Result<()> {
        let attempt = pending.attempt.kind();
        if nonce_state == NonceState::Mined {
            if attempt == CallKind::Raise || self.replaced_raise_mined(note, pending).await {
                // The raise landed, or reverted harmlessly. Its nonce stays
                // tracked until confirmed; a defeat goes on the next nonce.
                self.detach_nonce(note);
                let entry = self.checkpoint.pending.get_mut(&note).unwrap();
                entry.nonce = None;
                entry.transaction_hash = None;
                entry.attempt = NonceAttempts::default();
                self.observed_fees.remove(&note);
                self.persist()?;
                tracing::info!(
                    note_id = note,
                    "a raise was mined; any defeat goes on the next nonce"
                );
                let refreshed = self.checkpoint.pending[&note].clone();
                return Box::pin(self.act(note, NonceState::Free, head, &refreshed, decision))
                    .await;
            }
            self.mined_unconfirmed(note, decision.evidence).await;
            return Ok(());
        }
        let evidence_kind = decision.evidence;
        let (call, row) = match &decision.due {
            Due::Defeat { evidence, .. } => (
                VaultCall::Defeat {
                    note_id: note,
                    inputs: evidence.inputs.clone(),
                    proof: evidence.proof.clone(),
                },
                evidence.row_id,
            ),
            Due::Raise { evidence, amount } => (
                VaultCall::Raise {
                    note_id: note,
                    inputs: evidence.inputs.clone(),
                    proof: evidence.proof.clone(),
                    amount: *amount,
                },
                evidence.row_id,
            ),
            _ => {
                return self
                    .hold_without_call(note, nonce_state, head, pending, decision)
                    .await
            }
        };
        let context = SendContext {
            evidence: evidence_kind,
            evidence_row: Some(row),
            root: None,
            owed: decision.owed,
            raise_due_at: Some(decision.raise_due_at),
        };
        match (nonce_state, call.kind(), attempt) {
            // The one transition: a defeat replaces the unmined raise.
            (NonceState::Pending | NonceState::Held, CallKind::Defeat, CallKind::Raise) => {
                let nonce = pending.nonce.context("pending raise lacks a nonce")?;
                let old = self.persisted_fees(note).or_else(|| {
                    (nonce_state == NonceState::Pending)
                        .then(|| self.observed_fees.get(&note).copied())
                        .flatten()
                });
                let plan = old.map_or(FeePlan::First, FeePlan::Bump);
                tracing::warn!(note_id = note, nonce, "successor evidence appeared while a raise is pending; the defeat replaces it on the same nonce");
                self.submit(note, call, Some(nonce), head, plan, context)
                    .await
            }
            // A raise never replaces a defeat: keep the pending defeat.
            (NonceState::Pending | NonceState::Held, CallKind::Raise, CallKind::Defeat) => {
                self.record(
                    note,
                    Evaluation::new(ObligationState::Submitted, Some(evidence_kind)).detail(
                        "a defeat is pending on this note's nonce; a raise never replaces it",
                    ),
                );
                Ok(())
            }
            (NonceState::Pending | NonceState::Held, CallKind::Raise, CallKind::Raise) => {
                // Replacements keep the call: re-send the raise first sent.
                match self.pending_raise_call(note, pending, &decision)? {
                    Some(call) => {
                        self.maybe_replace(
                            note,
                            head,
                            nonce_state == NonceState::Pending,
                            call,
                            context,
                        )
                        .await
                    }
                    None => {
                        self.record(
                            note,
                            Evaluation::new(ObligationState::Submitted, Some(evidence_kind))
                                .detail("the pending raise was built from evidence no longer at hand; it is kept as sent"),
                        );
                        Ok(())
                    }
                }
            }
            (NonceState::Pending, _, _) => {
                self.maybe_replace(note, head, true, call, context).await
            }
            (NonceState::Held, _, _) => self.maybe_replace(note, head, false, call, context).await,
            (NonceState::Free, _, _) => {
                self.submit(note, call, None, head, FeePlan::First, context)
                    .await
            }
            (NonceState::Reserved, _, _) => {
                let plan = self
                    .persisted_fees(note)
                    .map_or(FeePlan::First, FeePlan::Resend);
                self.submit(note, call, pending.nonce, head, plan, context)
                    .await
            }
            (NonceState::Mined, _, _) => unreachable!("handled above"),
        }
    }

    /// The raise first sent on the note's nonce, rebuilt from its evidence
    /// row and amount (None when that row no longer verifies).
    fn pending_raise_call(
        &self,
        note: u32,
        pending: &PendingChallenge,
        decision: &Decision,
    ) -> anyhow::Result<Option<VaultCall>> {
        let (Some(row), Some(amount)) =
            (pending.attempt.evidence_row, pending.attempt.raise_amount)
        else {
            return Ok(None);
        };
        if let Due::Raise {
            evidence,
            amount: due,
        } = &decision.due
        {
            if evidence.row_id == row && *due == amount {
                return Ok(Some(VaultCall::Raise {
                    note_id: note,
                    inputs: evidence.inputs.clone(),
                    proof: evidence.proof.clone(),
                    amount,
                }));
            }
        }
        let binding = self.evidence_binding()?;
        let set = self
            .watcher
            .verified_evidence(&pending.nullifier, &self.verifier, &binding)
            .map_err(|error| anyhow!("evidence database read failed: {error}"))?;
        Ok(set
            .verified
            .into_iter()
            .find(|evidence| evidence.row_id == row)
            .map(|evidence| VaultCall::Raise {
                note_id: note,
                inputs: evidence.inputs,
                proof: evidence.proof,
                amount,
            }))
    }

    /// Whether the nonce of a defeat that replaced a raise was consumed by
    /// the raise: the defeat has no receipt although its nonce is mined.
    async fn replaced_raise_mined(&self, note: u32, pending: &PendingChallenge) -> bool {
        if !pending.attempt.replaced_raise || pending.attempt.kind() != CallKind::Defeat {
            return false;
        }
        let Some(hash) = pending.transaction_hash.as_ref() else {
            return false;
        };
        matches!(
            self.rpc("eth_getTransactionReceipt", json!([hash])).await,
            Ok(receipt) if receipt.is_null()
        ) && self
            .checkpoint
            .pending
            .get(&note)
            .is_some_and(|entry| entry.nonce.is_some())
    }

    /// Nothing is to be sent (awaiting settlement, nothing due, or invalid
    /// evidence). A raise already on the note's nonce is left to mine (a
    /// moot raise reverts harmlessly); one no attempt holds is released.
    async fn hold_without_call(
        &mut self,
        note: u32,
        nonce_state: NonceState,
        _head: &HeadInfo,
        pending: &PendingChallenge,
        decision: Decision,
    ) -> anyhow::Result<()> {
        let mut evaluation = evaluation_of(&decision);
        if let Some(nonce) = pending.nonce {
            match nonce_state {
                NonceState::Reserved if pending.attempt.kind() == CallKind::Raise => {
                    // No attempt holds the nonce: the raise is no longer due.
                    let entry = self.checkpoint.pending.get_mut(&note).unwrap();
                    entry.nonce = None;
                    entry.transaction_hash = None;
                    entry.attempt = NonceAttempts::default();
                    self.observed_fees.remove(&note);
                    self.persist()?;
                    tracing::warn!(note_id = note, nonce, "released the nonce of a raise that is no longer due and that no attempt holds");
                }
                NonceState::Pending | NonceState::Held => {
                    evaluation = Evaluation {
                        state: ObligationState::Submitted,
                        ..evaluation
                    }
                    .detail(format!(
                        "a {} no longer due is pending on nonce {nonce}; if it mines it reverts harmlessly",
                        pending.attempt.kind().as_str()
                    ));
                }
                _ => {}
            }
        }
        let error = match &decision.due {
            Due::Invalid { detail, .. } => Some(anyhow!("{detail}")),
            _ => None,
        };
        self.record(note, evaluation);
        error.map_or(Ok(()), Err)
    }

    /// Do not discard an obligation due to an unconfirmed defeat or
    /// finalization that a tip reorg could remove without changing the
    /// event-scan checkpoint block. An escape gone at confirmation depth
    /// while a defeat or raise was due may have been paid out rather than
    /// defeated: whatever polls saw before (the escaper can finalize in the
    /// first block at the deadline, or while the daemon is down), that is
    /// recorded as a missed deadline before the obligation retires, and
    /// after a missed defeat with `retire_on_miss` the obligation turns to
    /// retiring the closed note's leaf. While the evidence database cannot
    /// say whether evidence existed, the obligation is kept and the error
    /// returned, so a later poll decides.
    async fn retire_if_confirmed(
        &mut self,
        note: u32,
        pending: &PendingChallenge,
        head: &HeadInfo,
    ) -> anyhow::Result<()> {
        let ended_early = self.ended_before_deadline(note, head).await?;
        let (evidence, unreadable) = match self.payout_evidence(pending) {
            Ok(evidence) => (evidence, None),
            Err(error) => (None, Some(error)),
        };
        // Shown without evidence once it ended before its deadline. While
        // confirmations are awaited otherwise, an unreadable database fails
        // the poll as it does for a pending escape.
        let unconfirmed = match &unreadable {
            Some(error) if !ended_early => evidence_unreadable(error),
            _ => disappeared(evidence.as_ref(), ended_early, self.miss_reported(pending)),
        };
        let Some(confirmed) = self.gone_at_confirmed(note, pending).await? else {
            self.record(note, unconfirmed);
            return unreadable.filter(|_| !ended_early).map_or(Ok(()), Err);
        };
        let evidence = if !self.payout_undecided(pending, head, confirmed) {
            None
        } else if let Some(error) = unreadable {
            // Whether a payout was a missed deadline is decided once the
            // database reads, never taken for one.
            self.record(note, evidence_unreadable(&error));
            return Err(error);
        } else {
            evidence
        };
        let mut paid_out = false;
        if let Some(evidence) = evidence {
            match self
                .record_payout(note, pending, confirmed, &evidence)
                .await?
            {
                None => {
                    self.record(note, unconfirmed);
                    return Ok(());
                }
                Some(EscapeOutcome::NotPaidOut) => {}
                Some(EscapeOutcome::PaidOut { .. }) => paid_out = true,
            }
        }
        // A nonce no attempt was broadcast on is released rather than kept.
        self.release_if_never_broadcast(note).await;
        self.detach_nonce(note);
        let missed_defeat = self.checkpoint.pending[&note].missed_kind == Some(CallKind::Defeat);
        if missed_defeat
            && self.config.retire_on_miss
            && self.note_closed_at(note, confirmed).await?
        {
            let entry = self.checkpoint.pending.get_mut(&note).unwrap();
            entry.retire_leaf = true;
            entry.nonce = None;
            entry.transaction_hash = None;
            entry.attempt = NonceAttempts::default();
            self.forget_observations(note);
            self.persist()?;
            tracing::error!(note_id = note, nullifier = %pending.nullifier, "escape paid out after a missed defeat; retiring the closed note's leaf (--retire-on-miss)");
            self.record(
                note,
                Evaluation::new(ObligationState::RetiringLeaf, Some(EvidenceKind::Leaf))
                    .detail("retiring the closed note's leaf after a missed defeat"),
            );
            return Ok(());
        }
        self.checkpoint.pending.remove(&note);
        self.forget_observations(note);
        self.persist()?;
        if paid_out {
            tracing::warn!(note_id = note, nullifier = %pending.nullifier, "escape obligation retired: the escape was paid out after its challenge deadline");
        } else {
            tracing::info!(note_id = note, nullifier = %pending.nullifier, "escape obligation resolved at confirmation depth");
        }
        Ok(())
    }

    /// Whether `notes(note).status` is Closed at the `confirmed` block.
    async fn note_closed_at(&self, note: u32, confirmed: u64) -> anyhow::Result<bool> {
        let mut query = selector("notes(uint32)");
        query.extend_from_slice(Felt252::from_u64(note as u64).as_bytes());
        let state = self
            .call_at(query, json!(format!("0x{confirmed:x}")))
            .await?;
        ensure!(state.len() == 4, "malformed note response");
        Ok(felt_u64(&state[3])? == NOTE_STATUS_CLOSED)
    }

    /// The confirmed block (the latest less the confirmations) when the
    /// tracked escape, gone at the latest block, is gone there too; None
    /// while it is pending there or no block is that deep.
    async fn gone_at_confirmed(
        &mut self,
        note: u32,
        pending: &PendingChallenge,
    ) -> anyhow::Result<Option<u64>> {
        let latest = quantity(&self.rpc("eth_blockNumber", json!([])).await?)?;
        let Some(confirmed) = latest.checked_sub(self.config.confirmations) else {
            return Ok(None);
        };
        let state = self.escape_state(note, confirmed).await?;
        if state.exists && state.nullifier == pending.nullifier {
            self.note_seen(note, confirmed, 1)?;
            return Ok(None);
        }
        Ok(Some(confirmed))
    }

    /// Whether how an escape gone at `confirmed` ended still decides a
    /// missed deadline: a block up to the head is at its deadline, which
    /// finalization needs, and its miss is not counted yet.
    fn payout_undecided(
        &self,
        pending: &PendingChallenge,
        head: &HeadInfo,
        confirmed: u64,
    ) -> bool {
        let before_deadline = confirmed <= head.number
            && pending
                .challenge_deadline
                .is_some_and(|deadline| head.timestamp < deadline);
        !before_deadline && !self.miss_reported(pending)
    }

    /// Read how an escape with `evidence`, gone at the `confirmed` block past
    /// its deadline, ended, and record a payout as a missed deadline, or take
    /// it for a miss an earlier release counted without its nullifier (see
    /// `legacy_miss_bound`). None while the log search has more to read.
    async fn record_payout(
        &mut self,
        note: u32,
        pending: &PendingChallenge,
        confirmed: u64,
        evidence: &MissEvidence,
    ) -> anyhow::Result<Option<EscapeOutcome>> {
        let outcome = self.escape_outcome(note, pending, confirmed).await?;
        match outcome {
            None | Some(EscapeOutcome::NotPaidOut) => {}
            Some(EscapeOutcome::PaidOut { .. }) if self.counted_before_upgrade(pending) => {
                self.checkpoint.missed_nullifiers.push(pending.nullifier);
                self.persist()?;
                tracing::warn!(note_id = note, nullifier = %pending.nullifier, "the escape was paid out after its challenge deadline; taken for a miss the earlier release counted in missed_total without its nullifier, so not counted again");
            }
            Some(EscapeOutcome::PaidOut { inferred }) => {
                let mut evidence = evidence.clone();
                if inferred {
                    evidence.reason = format!(
                        "{}; the note is closed and no defeat of the escape is logged",
                        evidence.reason
                    );
                }
                self.record_missed(
                    note,
                    pending.challenge_deadline.unwrap_or_default(),
                    &evidence,
                )?;
            }
        }
        Ok(outcome)
    }

    /// What made losing an escape whose withdrawal is gone a missed deadline
    /// (as `record_expiry` decides it): verified evidence at `N⁺` written
    /// before the deadline (a missed defeat), or more owed at `N` than the
    /// last concession read (a missed raise). An unreadable evidence database
    /// is an error: unlike at the deadline, nothing is lost by waiting, as
    /// the escape has already ended.
    fn payout_evidence(&self, pending: &PendingChallenge) -> anyhow::Result<Option<MissEvidence>> {
        let (Some(deadline), Some(state_balance)) =
            (pending.challenge_deadline, pending.state_balance)
        else {
            return Ok(None);
        };
        let state = EscapeState {
            exists: true,
            nullifier: pending.nullifier,
            final_balance: state_balance.saturating_sub(pending.conceded.unwrap_or(0)),
            deadline,
            next_nullifier: pending.next_nullifier.unwrap_or(Felt252::ZERO),
            state_balance,
            conceded: pending.conceded.unwrap_or(0),
        };
        // After the deadline Ω is final or the request's bound.
        let decision = self.decide(&state, deadline)?;
        Ok(miss_of(&decision))
    }

    /// Whether the withdrawal, gone at the latest block, ended before its
    /// challenge deadline: it is also gone at the poll's head, whose
    /// timestamp is before the deadline. Recorded on the obligation once
    /// seen, so a later head past the deadline does not take it for a
    /// possible payout.
    async fn ended_before_deadline(&mut self, note: u32, head: &HeadInfo) -> anyhow::Result<bool> {
        let pending = &self.checkpoint.pending[&note];
        if pending.ended_before_deadline {
            return Ok(true);
        }
        if !pending
            .challenge_deadline
            .is_some_and(|deadline| head.timestamp < deadline)
        {
            return Ok(false);
        }
        let nullifier = pending.nullifier;
        let state = self.escape_state(note, head.number).await?;
        if state.exists && state.nullifier == nullifier {
            // Gone only in a block after the head, which may be at the deadline.
            return Ok(false);
        }
        self.checkpoint
            .pending
            .get_mut(&note)
            .unwrap()
            .ended_before_deadline = true;
        self.persist()?;
        Ok(true)
    }

    /// A payout taken for a miss an earlier release counted without its
    /// nullifier, while such misses remain: one of an escape that release
    /// can have tracked and counted (see `legacy_miss_bound`).
    fn counted_before_upgrade(&self, pending: &PendingChallenge) -> bool {
        let checkpoint = &self.checkpoint;
        checkpoint.unattributed_misses() > 0
            && !checkpoint.pending_at_upgrade.contains(&pending.nullifier)
            && checkpoint
                .legacy_miss_bound
                .zip(pending.challenge_deadline)
                .is_some_and(|(bound, deadline)| deadline <= bound)
            && checkpoint
                .scan_cursor_at_upgrade
                .is_none_or(|cursor| pending.seen_block.is_some_and(|seen| seen < cursor))
    }

    /// A miss of this escape is already counted.
    fn miss_reported(&self, pending: &PendingChallenge) -> bool {
        pending.deadline_reported
            || self
                .checkpoint
                .missed_nullifiers
                .contains(&pending.nullifier)
    }

    /// How an escape gone at the `confirmed` block ended; `None` while the
    /// log search has more to read. A finalization closes the note for good,
    /// while a challenge leaves it active until its owner closes it. A
    /// hardened vault records challenged nullifiers. On a legacy vault, or
    /// when that read fails, the escape's Challenged or Finalized log tells.
    async fn escape_outcome(
        &mut self,
        note: u32,
        pending: &PendingChallenge,
        confirmed: u64,
    ) -> anyhow::Result<Option<EscapeOutcome>> {
        let block = json!(format!("0x{confirmed:x}"));
        let mut query = selector("notes(uint32)");
        query.extend_from_slice(Felt252::from_u64(note as u64).as_bytes());
        let state = self.call_at(query, block.clone()).await?;
        ensure!(state.len() == 4, "malformed note response");
        if felt_u64(&state[3])? != NOTE_STATUS_CLOSED {
            return Ok(Some(EscapeOutcome::NotPaidOut));
        }
        let mut query = selector("challengedNullifiers(uint256)");
        query.extend_from_slice(pending.nullifier.as_bytes());
        match self.call_at(query, block).await {
            Ok(words) if words.len() == 1 => {
                return Ok(Some(if words[0] == Felt252::ZERO {
                    EscapeOutcome::PaidOut { inferred: false }
                } else {
                    EscapeOutcome::NotPaidOut
                }));
            }
            Ok(_) => {}
            Err(error) => {
                tracing::debug!(note_id = note, error = %error, "challengedNullifiers unavailable (a legacy vault); searching the escape's logs");
            }
        }
        self.search_outcome_logs(note, pending, confirmed).await
    }

    /// Search the vault's logs for the Challenged or Finalized event of the
    /// escape, from a block no later than its end up to `confirmed`, in
    /// ranges bounded per poll; the position persists between polls.
    async fn search_outcome_logs(
        &mut self,
        note: u32,
        pending: &PendingChallenge,
        confirmed: u64,
    ) -> anyhow::Result<Option<EscapeOutcome>> {
        let topic =
            |signature: &str| format!("0x{}", hex::encode(Keccak256::digest(signature.as_bytes())));
        let finalized = topic(FINALIZED_EVENT);
        let topics = json!([
            [topic(CHALLENGED_EVENT), finalized],
            format!("0x{note:064x}")
        ]);
        let mut from = pending
            .outcome_search_from
            .or(pending.seen_block)
            .unwrap_or(self.config.from_block);
        if from > confirmed {
            // An RPC whose block number lags a block the escape was read
            // pending at: nothing to search yet.
            return Ok(None);
        }
        while from <= confirmed {
            if self.outcome_ranges == 0 {
                let entry = self.checkpoint.pending.get_mut(&note).unwrap();
                if entry.outcome_search_from != Some(from) {
                    entry.outcome_search_from = Some(from);
                    self.persist()?;
                }
                return Ok(None);
            }
            self.outcome_ranges -= 1;
            let to = confirmed.min(from.saturating_add(LOG_RANGE_BLOCKS - 1));
            let logs = self
                .rpc(
                    "eth_getLogs",
                    json!([{ "address": self.vault_address(), "fromBlock": format!("0x{from:x}"),
                        "toBlock": format!("0x{to:x}"), "topics": topics }]),
                )
                .await?;
            for log in logs.as_array().context("RPC logs must be an array")? {
                if log.get("removed").and_then(Value::as_bool) == Some(true) {
                    continue;
                }
                if words(&log["data"])?.first() != Some(&pending.nullifier) {
                    continue;
                }
                let paid = log["topics"][0]
                    .as_str()
                    .is_some_and(|topic| topic.eq_ignore_ascii_case(&finalized));
                return Ok(Some(if paid {
                    EscapeOutcome::PaidOut { inferred: false }
                } else {
                    EscapeOutcome::NotPaidOut
                }));
            }
            from = to.saturating_add(1);
        }
        // The note is closed, and its challenge would have been logged.
        Ok(Some(EscapeOutcome::PaidOut { inferred: true }))
    }

    /// Record that the escape had not ended by `block`, once that moves the
    /// recorded block by at least `step` (latest-block reads use a log range,
    /// so polls do not rewrite the checkpoint).
    fn note_seen(&mut self, note: u32, block: u64, step: u64) -> anyhow::Result<()> {
        let entry = self.checkpoint.pending.get_mut(&note).unwrap();
        if entry
            .seen_block
            .is_none_or(|seen| block >= seen.saturating_add(step))
        {
            entry.seen_block = Some(block);
            self.persist()?;
        }
        Ok(())
    }

    /// How an escape with a miss, gone past its deadline behind a blocked
    /// queue, ended, once that is known at confirmation depth: a payout is
    /// recorded as a missed deadline when found, not once the queue moves.
    /// An escape a defeat ended (or whose initiation was reorganized out) is
    /// marked as ended before its deadline, so it is shown resolved and not
    /// read again. Returns whether it ended without a payout.
    async fn observe_payout(
        &mut self,
        note: u32,
        pending: &PendingChallenge,
        head: &HeadInfo,
        evidence: &MissEvidence,
    ) -> anyhow::Result<bool> {
        if self.miss_reported(pending) {
            return Ok(false);
        }
        let Some(confirmed) = self.gone_at_confirmed(note, pending).await? else {
            return Ok(false);
        };
        if !self.payout_undecided(pending, head, confirmed) {
            return Ok(false);
        }
        let outcome = self
            .record_payout(note, pending, confirmed, evidence)
            .await?;
        if outcome != Some(EscapeOutcome::NotPaidOut) {
            return Ok(false);
        }
        self.checkpoint
            .pending
            .get_mut(&note)
            .unwrap()
            .ended_before_deadline = true;
        self.persist()?;
        Ok(true)
    }

    /// In-memory observations belong to one obligation, not to its note.
    fn forget_observations(&mut self, note: u32) {
        self.evaluations.remove(&note);
        self.previous_evaluations.remove(&note);
        self.blocked_since.remove(&note);
        self.observed_fees.remove(&note);
        self.logged.remove(&note);
    }

    /// Evaluation for an obligation the poll loop did not reach, which
    /// neither sends nor retires it. It still records missed deadlines, so
    /// a note that expires entirely behind a blocked nonce is counted, as is
    /// a payout found at confirmation depth (the escaper can finalize in the
    /// first block at the deadline): the obligation and its nonce stay for
    /// the loop to retire.
    async fn observe_only(
        &mut self,
        note: u32,
        head: &HeadInfo,
        blocked: Option<(BlockedReason, String)>,
    ) -> anyhow::Result<()> {
        let pending = self.checkpoint.pending[&note].clone();
        if pending.retire_leaf {
            let mut evaluation =
                Evaluation::new(ObligationState::RetiringLeaf, Some(EvidenceKind::Leaf))
                    .detail("retiring the closed note's leaf after a missed defeat");
            if let Some((reason, detail)) = blocked {
                evaluation = evaluation.blocked(reason, detail);
            }
            self.record(note, evaluation);
            return Ok(());
        }
        let state = self.escape_state(note, head.number).await?;
        if state.exists && state.nullifier != pending.nullifier {
            return self.follow_vault_escape(note, pending.nullifier, &state);
        }
        if !state.exists {
            let mut ended_early = self.ended_before_deadline(note, head).await?;
            let evidence = self.payout_evidence(&pending);
            if let (false, Ok(Some(evidence))) = (ended_early, &evidence) {
                ended_early = self.observe_payout(note, &pending, head, evidence).await?;
            }
            let missed = self.miss_reported(&self.checkpoint.pending[&note]);
            let mut evaluation = match evidence {
                Err(error) if !ended_early => evidence_unreadable(&error),
                evidence => disappeared(evidence.ok().flatten().as_ref(), ended_early, missed),
            };
            if let (None, Some((reason, detail))) = (evaluation.blocked, blocked) {
                // Its retirement waits for the queue.
                evaluation = evaluation.blocked(reason, detail);
            }
            self.record(note, evaluation);
            return Ok(());
        }
        self.note_pending(note, &state)?;
        let decision = match self.decide(&state, head.timestamp) {
            Ok(decision) => decision,
            Err(error) => {
                self.record(note, decision_unreadable(&error));
                return Ok(());
            }
        };
        if head.timestamp >= state.deadline {
            return self.record_expiry(note, &decision, &state, None).await;
        }
        let mut evaluation = evaluation_of(&decision);
        if matches!(decision.due, Due::Defeat { .. } | Due::Raise { .. }) {
            evaluation.state = if pending.transaction_hash.is_some() {
                ObligationState::Submitted
            } else {
                ObligationState::Ready
            };
            if let Some((reason, detail)) = blocked {
                evaluation = evaluation.blocked(reason, detail);
            }
        }
        self.record(note, evaluation);
        Ok(())
    }

    /// The deadline passed: a missed defeat or raise when one was due,
    /// otherwise an expiry with nothing due. An unmined reserved nonce of an
    /// expired obligation still blocks new allocations, unless no attempt on
    /// it was broadcast.
    async fn record_expiry(
        &mut self,
        note: u32,
        decision: &Decision,
        state: &EscapeState,
        nonce_state: Option<NonceState>,
    ) -> anyhow::Result<()> {
        let mut evaluation = match miss_of(decision) {
            Some(miss) => {
                self.record_missed(note, state.deadline, &miss)?;
                Evaluation::new(ObligationState::Missed, Some(miss.evidence)).detail(miss.reason)
            }
            None => Evaluation::new(ObligationState::ExpiredNothingDue, Some(decision.evidence))
                .detail("deadline passed with nothing due"),
        };
        evaluation.settlement = decision.settlement.clone();
        evaluation.owed = decision.owed;
        evaluation.raise_due_at = Some(decision.raise_due_at);
        if matches!(nonce_state, Some(NonceState::Reserved | NonceState::Held)) {
            if self.release_if_never_broadcast(note).await {
                self.persist()?;
            } else {
                let nonce = self.checkpoint.pending[&note].nonce.unwrap_or_default();
                self.record(
                    note,
                    evaluation.blocked(
                        BlockedReason::NonceBlocked,
                        format!("expired obligation retains unmined reserved nonce {nonce}, which an attempt may hold; resolve it at the signer"),
                    ),
                );
                bail!("expired challenge retains an unmined reserved nonce; signer intervention required before allocating another nonce");
            }
        }
        self.record(note, evaluation);
        Ok(())
    }

    fn record_missed(
        &mut self,
        note: u32,
        deadline: u64,
        miss: &MissEvidence,
    ) -> anyhow::Result<()> {
        let entry = self.checkpoint.pending.get_mut(&note).unwrap();
        if entry.deadline_reported {
            return Ok(());
        }
        entry.deadline_reported = true;
        entry.missed_kind = Some(miss.kind);
        let nullifier = entry.nullifier;
        if self.checkpoint.missed_nullifiers.contains(&nullifier) {
            // Counted before the escape was tracked again.
            return self.persist();
        }
        self.checkpoint.missed_nullifiers.push(nullifier);
        self.checkpoint.missed_total = self.checkpoint.missed_total.saturating_add(1);
        match miss.kind {
            CallKind::Raise => {
                self.checkpoint.missed_raises_total =
                    self.checkpoint.missed_raises_total.saturating_add(1)
            }
            _ => {
                self.checkpoint.missed_defeats_total =
                    self.checkpoint.missed_defeats_total.saturating_add(1)
            }
        }
        self.checkpoint.last_missed = Some(MissedRecord {
            note_id: note,
            nullifier,
            challenge_deadline: deadline,
            reason: miss.reason.clone(),
            recorded_at: unix_now(),
            kind: Some(miss.kind),
        });
        tracing::error!(note_id = note, nullifier = %nullifier, missed = miss.kind.as_str(), reason = %miss.reason, "MISSED escape deadline");
        self.persist()
    }

    /// The tracked escape is pending at the poll's head with `state`.
    fn note_pending(&mut self, note: u32, state: &EscapeState) -> anyhow::Result<()> {
        let entry = self.checkpoint.pending.get_mut(&note).unwrap();
        let concession = (
            Some(state.next_nullifier),
            Some(state.state_balance),
            Some(state.conceded),
        );
        if entry.challenge_deadline != Some(state.deadline)
            || entry.ended_before_deadline
            || (entry.next_nullifier, entry.state_balance, entry.conceded) != concession
        {
            entry.challenge_deadline = Some(state.deadline);
            // A reorganization undid the end seen before the deadline.
            entry.ended_before_deadline = false;
            (entry.next_nullifier, entry.state_balance, entry.conceded) = concession;
            self.persist()?;
        }
        Ok(())
    }

    /// The nonce was consumed while the escape is still pending, so the mined
    /// defeat (or leaf retirement) reverted. It keeps its deadline-derived
    /// severity until resubmission.
    async fn mined_unconfirmed(&mut self, note: u32, evidence: EvidenceKind) {
        let pending = self.checkpoint.pending[&note].clone();
        let action = pending.attempt.kind().as_str();
        let mut detail = format!(
            "nonce consumed while the escape is still pending; resubmitting the {action} after confirmations"
        );
        for hash in pending
            .transaction_hash
            .iter()
            .chain(pending.attempt.superseded_hashes.last())
        {
            if let Ok(receipt) = self.rpc("eth_getTransactionReceipt", json!([hash])).await {
                if receipt.get("status").and_then(Value::as_str) == Some("0x0") {
                    detail = format!("{action} {hash} reverted; resubmitting after confirmations");
                    break;
                }
            }
        }
        self.record(
            note,
            Evaluation::new(ObligationState::MinedUnconfirmed, Some(evidence)).detail(detail),
        );
    }

    /// After a missed defeat was paid out: retire the closed note's leaf
    /// with the indexer's path at the live root, then retire the obligation
    /// once the leaf is zero there.
    async fn reconcile_retirement(
        &mut self,
        note: u32,
        nonce_state: NonceState,
        head: &HeadInfo,
    ) -> anyhow::Result<()> {
        let base = |state: ObligationState| Evaluation::new(state, Some(EvidenceKind::Leaf));
        macro_rules! blocked {
            ($reason:expr, $error:expr) => {{
                let error: anyhow::Error = $error;
                self.record(
                    note,
                    base(ObligationState::RetiringLeaf).blocked($reason, error.to_string()),
                );
                return Err(error);
            }};
        }
        let response = match self
            .indexer_get::<PathResponse>(&format!("/v1/tree/notes/{note}/path"))
            .await
        {
            Ok(response) => response,
            Err(IndexerFailure::Decode(error)) => blocked!(
                BlockedReason::IndexerInvalidResponse,
                anyhow!("indexer returned a malformed path: {error}")
            ),
            Err(error) => blocked!(
                BlockedReason::IndexerUnavailable,
                anyhow!("indexer path request failed: {error}")
            ),
        };
        if response.note_id != note {
            blocked!(
                BlockedReason::IndexerInvalidResponse,
                anyhow!("indexer returned the path of another note")
            );
        }
        let Ok(siblings) = <[Felt252; MERKLE_DEPTH]>::try_from(response.siblings) else {
            blocked!(
                BlockedReason::IndexerInvalidResponse,
                anyhow!("indexer path must have 32 siblings")
            );
        };
        let root = match self.live_root().await {
            Ok(root) => root,
            Err(error) => blocked!(BlockedReason::RpcError, error),
        };
        if zkapi_core::v2::merkle_root(note, &response.leaf, &siblings) != root {
            let state = self
                .classify_root_mismatch(
                    response.root.unwrap_or(Felt252::ZERO),
                    response.block_hash.as_deref(),
                    response.block_number,
                    head,
                )
                .await;
            let reason = if state == IndexerState::Diverged {
                BlockedReason::IndexerDiverged
            } else {
                BlockedReason::IndexerPathBehind
            };
            blocked!(
                reason,
                anyhow!("indexer path of note {note} does not hash to the vault's current root")
            );
        }
        if response.leaf.is_zero() {
            // The leaf is retired at the live root.
            self.release_if_never_broadcast(note).await;
            self.detach_nonce(note);
            self.checkpoint.pending.remove(&note);
            self.checkpoint.retired_leaves_total =
                self.checkpoint.retired_leaves_total.saturating_add(1);
            self.forget_observations(note);
            self.persist()?;
            tracing::warn!(
                note_id = note,
                "closed note's leaf retired after a missed defeat"
            );
            return Ok(());
        }
        let call = VaultCall::Retire {
            note_id: note,
            siblings: Box::new(siblings),
        };
        let context = SendContext {
            evidence: EvidenceKind::Leaf,
            evidence_row: None,
            root: Some(root),
            owed: None,
            raise_due_at: None,
        };
        match nonce_state {
            NonceState::Mined => {
                self.mined_unconfirmed(note, EvidenceKind::Leaf).await;
                Ok(())
            }
            NonceState::Pending => self.maybe_replace(note, head, true, call, context).await,
            NonceState::Held => self.maybe_replace(note, head, false, call, context).await,
            NonceState::Free => {
                self.submit(note, call, None, head, FeePlan::First, context)
                    .await
            }
            NonceState::Reserved => {
                let nonce = self.checkpoint.pending[&note].nonce;
                let plan = self
                    .persisted_fees(note)
                    .map_or(FeePlan::First, FeePlan::Resend);
                self.submit(note, call, nonce, head, plan, context).await
            }
        }
    }

    /// Replace the queue-head attempt on its nonce when it has waited
    /// `bump_after_blocks`, the base fee rose above its fee cap, the queue is
    /// critical, or the vault root moved so it would revert. The attempt is
    /// either a known pending transaction (`visible`) or one without a known
    /// hash that may hold the nonce, which is outbid at the same pace.
    async fn maybe_replace(
        &mut self,
        note: u32,
        head: &HeadInfo,
        visible: bool,
        call: VaultCall,
        context: SendContext,
    ) -> anyhow::Result<()> {
        let pending = self.checkpoint.pending[&note].clone();
        let nonce = pending.nonce.context("pending challenge lacks a nonce")?;
        let (submitted, waiting) = if visible {
            (
                context.evaluation(ObligationState::Submitted),
                format!("{} pending on nonce {nonce}", call.kind().as_str()),
            )
        } else {
            (
                context.evaluation(ObligationState::Ready),
                format!("nonce {nonce} may be held by an attempt without a known hash"),
            )
        };
        let hold = |evaluation: Evaluation, detail: String| {
            if visible {
                evaluation.detail(detail)
            } else {
                evaluation.blocked(BlockedReason::SendAmbiguous, detail)
            }
        };
        if self.latest_nonce_count != Some(nonce) {
            self.record(
                note,
                hold(submitted, format!("{waiting}, behind an earlier challenge")),
            );
            return Ok(());
        }
        let old = self.persisted_fees(note).or_else(|| {
            visible
                .then(|| self.observed_fees.get(&note).copied())
                .flatten()
        });
        let Some(old) = old else {
            if !visible {
                // A reservation from an older daemon: its fees are unknown.
                return self
                    .submit(note, call, Some(nonce), head, FeePlan::First, context)
                    .await;
            }
            self.record(
                note,
                submitted.detail(format!("{waiting} with unknown fees; not replaceable")),
            );
            return Ok(());
        };
        let critical = self.queue_severity(note, head) == Severity::Critical;
        // The ceiling at the gas limit of the latest attempt; the send itself
        // plans with the exact gas limit.
        let tx_fee_limit = pending
            .attempt
            .gas_limit
            .map(u128::from)
            .or(self.last_gas)
            .map(|gas| self.tx_fee_limit(gas));
        let policy = &self.config.fee;
        let waited = pending
            .attempt
            .submitted_block
            .is_none_or(|block| head.number.saturating_sub(block) >= policy.bump_after_blocks);
        let base_above = head.base_fee.is_some_and(|base| base > old.max_fee);
        let max_fee_cap = policy
            .max_fee_per_gas
            .min(tx_fee_limit.unwrap_or(u128::MAX));
        let below_critical = critical
            && (old.max_fee < headroom(max_fee_cap)
                || old.tip < headroom(policy.max_priority_fee_per_gas));
        let stale_root = match pending.attempt.submitted_root {
            Some(root) => self.live_root().await.is_ok_and(|live| live != root),
            None => false,
        };
        if !(waited || base_above || below_critical || stale_root) {
            self.record(note, hold(submitted, waiting));
            return Ok(());
        }
        // Skip the path and simulation work while no valid bump exists. A
        // pending attempt that cannot be outbid within the caps and the
        // transaction fee ceiling is kept, and observed until it mines.
        match plan_fees(
            &self.config.fee,
            FeePlan::Bump(old),
            head.base_fee,
            critical,
            tx_fee_limit,
            None,
        ) {
            Ok(Some(_)) => {}
            Ok(None) => {
                let detail = format!(
                    "{waiting}; the remaining fee headroom is reserved for the critical threshold"
                );
                // Reported as blocked, so a challenge that stays pending after
                // its budget is spent escalates with time like an exhausted cap.
                let evaluation = if visible {
                    submitted.blocked(BlockedReason::FeeReserveHeld, detail)
                } else {
                    hold(submitted, detail)
                };
                self.record(note, evaluation);
                return Ok(());
            }
            Err(reason) => {
                self.record(
                    note,
                    submitted.blocked(
                        reason,
                        format!(
                            "{waiting} at max fee {} and tip {} wei; no valid replacement within the caps{}",
                            old.max_fee,
                            old.tip,
                            if reason == BlockedReason::TxFeeCapReached {
                                format!(" and the transaction fee ceiling of {} wei", self.tx_fee_cap())
                            } else {
                                String::new()
                            }
                        ),
                    ),
                );
                return Ok(());
            }
        }
        self.submit(note, call, Some(nonce), head, FeePlan::Bump(old), context)
            .await
    }

    /// Build, simulate and send `call` on a new or reused nonce. The nonce,
    /// call, fees and digest are persisted before the send. Every attempt on
    /// a nonce makes the same call (the same digest), with one exception: a
    /// defeat replaces a raise. A raise or a retirement never replaces a
    /// defeat; a raise no attempt holds the nonce of may be replaced by any
    /// call.
    async fn submit(
        &mut self,
        note: u32,
        call: VaultCall,
        reuse: Option<u64>,
        head: &HeadInfo,
        plan: FeePlan,
        context: SendContext,
    ) -> anyhow::Result<()> {
        let pending = self.checkpoint.pending[&note].clone();
        let base_state = if matches!(plan, FeePlan::Bump(_)) && pending.transaction_hash.is_some() {
            ObligationState::Submitted
        } else {
            ObligationState::Ready
        };
        macro_rules! blocked {
            ($reason:expr, $error:expr) => {{
                let error: anyhow::Error = $error;
                self.record(
                    note,
                    context
                        .evaluation(base_state)
                        .blocked($reason, error.to_string()),
                );
                return Err(error);
            }};
        }
        let digest = call.digest();
        let recorded = pending
            .attempt
            .evidence_digest
            .as_ref()
            .filter(|_| reuse.is_some());
        // An attempt may hold the nonce (a bump) or none does (a re-send).
        let held = matches!(plan, FeePlan::Bump(_));
        let transition = match recorded {
            None => false,
            Some(recorded) if *recorded == digest => false,
            Some(_) if pending.attempt.kind() == CallKind::Raise && call.kind() == CallKind::Defeat => {
                true
            }
            Some(_) if pending.attempt.kind() == CallKind::Raise && !held => true,
            Some(_) => blocked!(
                BlockedReason::EvidenceInvalid,
                anyhow!(
                    "a replacement would change the {} on its nonce to {} (only a defeat may replace a raise)",
                    pending.attempt.kind().as_str(),
                    call.kind().as_str()
                )
            ),
        };
        let calldata = match call.calldata() {
            Ok(calldata) => calldata,
            Err(error) => blocked!(BlockedReason::EvidenceInvalid, anyhow!(error)),
        };
        let data = format!("0x{}", hex::encode(calldata));
        let mut transaction =
            json!({ "from": self.config.sender, "to": self.vault_address(), "data": data });
        // Simulate against the live contract to check keys, proof, deadline
        // and concession together.
        if let Err(error) = self.rpc("eth_call", json!([transaction, "latest"])).await {
            return self.simulation_failed(note, base_state, error, &context);
        }
        let estimated_gas = match self
            .rpc("eth_estimateGas", json!([transaction]))
            .await
            .and_then(|value| quantity(&value))
        {
            Ok(gas) => gas,
            Err(error) => return self.simulation_failed(note, base_state, error, &context),
        };
        let estimated = estimated_gas
            .checked_add(estimated_gas / 5)
            .context("challenge gas estimate overflow")?;
        // §5.4 default gas limits; a higher estimate wins, as a limit below
        // it would run out of gas.
        let gas = match call.kind() {
            CallKind::Defeat => estimated.max(self.config.defeat_gas_limit),
            CallKind::Raise => estimated.max(self.config.raise_gas_limit),
            CallKind::Retire => estimated,
        };
        self.last_gas = Some(gas as u128);
        let nonce = match reuse {
            Some(nonce) => nonce,
            None => {
                let chain_nonce = self.transaction_count("pending").await?;
                if self
                    .checkpoint
                    .pending
                    .values()
                    .any(|entry| entry.nonce == Some(chain_nonce))
                    || self.checkpoint.detached_nonces.contains_key(&chain_nonce)
                {
                    blocked!(
                        BlockedReason::NonceConflict,
                        anyhow!("RPC pending nonce conflicts with a durable challenge reservation")
                    );
                }
                chain_nonce
            }
        };
        let critical = self.queue_severity(note, head) == Severity::Critical;
        let affordable = self
            .sender_balance
            .map(|balance| balance / (gas as u128).max(1));
        // The signer and its node refuse gas x maxFeePerGas above the ceiling.
        let tx_fee_limit = self.tx_fee_limit(gas as u128);
        let fees = match plan_fees(
            &self.config.fee,
            plan,
            head.base_fee,
            critical,
            Some(tx_fee_limit),
            affordable,
        ) {
            Ok(Some(fees)) => fees,
            Ok(None) => {
                // Only a replacement keeps the reserve, as in maybe_replace.
                let (reason, waiting) = if pending.transaction_hash.is_some() {
                    (
                        BlockedReason::FeeReserveHeld,
                        format!("pending on nonce {nonce}"),
                    )
                } else {
                    (
                        BlockedReason::SendAmbiguous,
                        format!("nonce {nonce} may be held by an attempt without a known hash"),
                    )
                };
                self.record(
                    note,
                    context.evaluation(base_state).blocked(
                        reason,
                        format!("{waiting}; the remaining fee headroom is reserved for the critical threshold"),
                    ),
                );
                return Ok(());
            }
            Err(reason) => {
                // Nothing is sent; retried next poll. A reused nonce that no
                // attempt was broadcast on is released.
                let detail = match reason {
                    BlockedReason::BaseFeeAboveFeeCap => format!(
                        "base fee {} wei exceeds the usable fee cap",
                        head.base_fee.unwrap_or_default()
                    ),
                    BlockedReason::TxFeeCapReached => format!(
                        "the transaction fee ceiling of {} wei allows a maxFeePerGas of at most {tx_fee_limit} wei at {gas} gas; base fee {} wei{}",
                        self.tx_fee_cap(),
                        head.base_fee.unwrap_or_default(),
                        if matches!(plan, FeePlan::Bump(_)) {
                            "; no valid replacement"
                        } else {
                            ""
                        }
                    ),
                    BlockedReason::InsufficientBalance => format!(
                        "sender balance {} wei cannot fund a valid bid at {gas} gas",
                        self.sender_balance.unwrap_or_default()
                    ),
                    BlockedReason::TipCapReached => {
                        "no valid replacement: the tip cap is reached".into()
                    }
                    _ => "no valid replacement: the fee cap is reached".into(),
                };
                if reuse.is_some() && self.release_if_never_broadcast(note).await {
                    self.persist()?;
                }
                self.record(note, context.evaluation(base_state).blocked(reason, detail));
                return Ok(());
            }
        };
        if let FeePlan::Resend(old) = plan {
            if fees.max_fee < old.max_fee || fees.tip < old.tip {
                tracing::warn!(
                    note_id = note,
                    nonce,
                    previous_max_fee_per_gas = old.max_fee,
                    previous_max_priority_fee_per_gas = old.tip,
                    max_fee_per_gas = fees.max_fee,
                    max_priority_fee_per_gas = fees.tip,
                    "re-sending a nonce no attempt holds below its earlier bid, within the current caps, transaction fee ceiling and balance"
                );
            }
        }
        // Write ahead: a crash or ambiguous result after this point never
        // loses the reservation, the fees that may be in a pool, or the call.
        // A bid outbids every attempt that may hold the nonce, so its fees
        // are the highest in any pool; a re-send of a nonce no attempt holds
        // keeps its earlier fees within the current caps and ceiling.
        let rollback = {
            let entry = self.checkpoint.pending.get_mut(&note).unwrap();
            let rollback = (
                entry.nonce,
                entry.transaction_hash.clone(),
                entry.attempt.clone(),
            );
            entry.nonce = Some(nonce);
            if let Some(hash) = entry.transaction_hash.take() {
                push_superseded(&mut entry.attempt, hash);
            }
            entry.attempt.max_fee_per_gas = Some(format!("0x{:x}", fees.max_fee));
            entry.attempt.max_priority_fee_per_gas = Some(format!("0x{:x}", fees.tip));
            entry.attempt.gas_limit = Some(gas);
            entry.attempt.attempts = entry.attempt.attempts.saturating_add(1);
            entry.attempt.submitted_block = Some(head.number);
            entry.attempt.evidence_digest = Some(digest);
            entry.attempt.submitted_root = context.root;
            entry.attempt.unknown_attempt = true;
            entry.attempt.replaced_raise |= transition && call.kind() == CallKind::Defeat;
            entry.attempt.action = Some(call.kind());
            entry.attempt.evidence_row = context.evidence_row;
            entry.attempt.raise_amount = match &call {
                VaultCall::Raise { amount, .. } => Some(*amount),
                _ => None,
            };
            rollback
        };
        self.persist()?;
        transaction["gas"] = json!(format!("0x{gas:x}"));
        transaction["nonce"] = json!(format!("0x{nonce:x}"));
        transaction["maxFeePerGas"] = json!(format!("0x{:x}", fees.max_fee));
        transaction["maxPriorityFeePerGas"] = json!(format!("0x{:x}", fees.tip));
        let sent = self
            .rpc_with_timeout(
                "eth_sendTransaction",
                json!([transaction]),
                Some(SEND_TIMEOUT),
            )
            .await
            .and_then(|hash| {
                hash.as_str()
                    .map(str::to_owned)
                    .context("transaction response lacks hash")
            });
        match sent {
            Ok(hash) => {
                let entry = self.checkpoint.pending.get_mut(&note).unwrap();
                entry.transaction_hash = Some(hash.clone());
                entry.attempt.unknown_attempt = false;
                self.persist()?;
                tracing::info!(
                    note_id = note,
                    nonce,
                    call = call.kind().as_str(),
                    transaction_hash = %hash,
                    max_fee_per_gas = fees.max_fee,
                    max_priority_fee_per_gas = fees.tip,
                    "submitted escape {}",
                    call.kind().as_str()
                );
                self.record(
                    note,
                    context
                        .evaluation(ObligationState::Submitted)
                        .detail(format!("{} pending on nonce {nonce}", call.kind().as_str())),
                );
                Ok(())
            }
            Err(error) => {
                self.send_failed(
                    note,
                    nonce,
                    (gas, fees.max_fee),
                    base_state,
                    rollback,
                    error,
                    &context,
                )
                .await
            }
        }
    }

    /// `sent` is the gas limit and maxFeePerGas of the failed send.
    #[allow(clippy::too_many_arguments)]
    async fn send_failed(
        &mut self,
        note: u32,
        nonce: u64,
        sent: (u64, u128),
        base_state: ObligationState,
        rollback: (Option<u64>, Option<String>, NonceAttempts),
        error: anyhow::Error,
        context: &SendContext,
    ) -> anyhow::Result<()> {
        let (gas, max_fee) = sent;
        let reason = match classify_send_error(&error) {
            SendFailure::Refused(reason) => {
                self.roll_back_unsent(note, nonce, rollback).await;
                if reason.as_deref() == Some("tx_fee_above_cap") {
                    // Later bids stay within the signer's cap.
                    if let Some(cap) = refused_tx_fee_cap(&error, gas) {
                        self.signer_tx_fee_cap = Some(cap);
                    }
                }
                if reason.as_deref() == Some("upstream_tx_fee_cap") {
                    self.learn_node_tx_fee_bound(note, refused_tx_fee(&error, gas, max_fee));
                }
                refusal_reason(reason.as_deref())
            }
            SendFailure::NotBroadcast(reason) => {
                self.roll_back_unsent(note, nonce, rollback).await;
                reason
            }
            SendFailure::Ambiguous(hash) => {
                // Keep the write-ahead record; a candidate hash lets the next
                // poll find the transaction, otherwise re-sends must bump.
                if let Some(hash) = hash {
                    let entry = self.checkpoint.pending.get_mut(&note).unwrap();
                    entry.transaction_hash = Some(hash);
                    entry.attempt.unknown_attempt = false;
                }
                BlockedReason::SendAmbiguous
            }
        };
        self.persist()?;
        self.record(
            note,
            context
                .evaluation(base_state)
                .blocked(reason, error.to_string()),
        );
        Err(error)
    }

    /// Nothing was broadcast: restore the nonce's earlier record, counting the
    /// attempt, and release the nonce when no attempt can occupy it, so that a
    /// failure lasting until the deadline cannot stall later notes. The caller
    /// persists.
    async fn roll_back_unsent(
        &mut self,
        note: u32,
        nonce: u64,
        rollback: (Option<u64>, Option<String>, NonceAttempts),
    ) {
        let (previous_nonce, previous_hash, previous_attempt) = rollback;
        let entry = self.checkpoint.pending.get_mut(&note).unwrap();
        // A reservation an older daemon made without a record may hold an
        // attempt the record does not describe.
        let unrecorded_attempt = previous_attempt.unrecorded_attempt
            || (previous_nonce.is_some() && previous_attempt.attempts == 0);
        entry.nonce = previous_nonce.or(Some(nonce));
        entry.transaction_hash = previous_hash;
        entry.attempt = NonceAttempts {
            attempts: entry.attempt.attempts,
            unrecorded_attempt,
            ..previous_attempt
        };
        self.release_if_never_broadcast(note).await;
    }

    /// Release the note's reserved nonce when no attempt recorded on it was
    /// broadcast and neither the latest nor the pending count has passed it.
    /// The caller persists.
    async fn release_if_never_broadcast(&mut self, note: u32) -> bool {
        let Some(nonce) = self
            .checkpoint
            .pending
            .get(&note)
            .filter(|pending| never_broadcast(pending.transaction_hash.as_ref(), &pending.attempt))
            .and_then(|pending| pending.nonce)
        else {
            return false;
        };
        if !self.nonce_unused(nonce).await {
            return false;
        }
        let entry = self.checkpoint.pending.get_mut(&note).unwrap();
        entry.nonce = None;
        entry.transaction_hash = None;
        entry.attempt = NonceAttempts::default();
        self.observed_fees.remove(&note);
        tracing::info!(
            note_id = note,
            nonce,
            "released a reserved nonce that no attempt was broadcast on"
        );
        true
    }

    /// Neither the latest nor the pending transaction count has passed `nonce`.
    async fn nonce_unused(&self, nonce: u64) -> bool {
        self.transaction_count("latest")
            .await
            .is_ok_and(|count| count <= nonce)
            && self
                .transaction_count("pending")
                .await
                .is_ok_and(|count| count <= nonce)
    }

    /// The transaction fee ceiling in force: the lowest of this daemon's, the
    /// signer's and the bound learned from the signer's node.
    fn tx_fee_cap(&self) -> u128 {
        self.config
            .fee
            .tx_fee_cap_wei
            .min(self.signer_tx_fee_cap.unwrap_or(u128::MAX))
            .min(self.node_tx_fee_bound().unwrap_or(u128::MAX))
    }

    /// The ceiling the node's refusals imply: 10/11 of the lowest transaction
    /// fee it refused, which exceeded its RPC fee cap. The node refuses before
    /// its pool and never reports that cap, so each refusal lowers the bids
    /// that follow by at least 9% until one is accepted; the bound stays above
    /// 10/11 of the node's cap.
    fn node_tx_fee_bound(&self) -> Option<u128> {
        self.node_refused_tx_fee
            .map(headroom)
            .filter(|bound| *bound > 0)
    }

    fn learn_node_tx_fee_bound(&mut self, note: u32, refused: u128) {
        let lowest = self
            .node_refused_tx_fee
            .map_or(refused, |lowest| lowest.min(refused));
        self.node_refused_tx_fee = Some(lowest);
        tracing::warn!(
            note_id = note,
            refused_tx_fee_wei = refused,
            node_tx_fee_cap_bound_wei = headroom(lowest),
            "the signer's node refused the transaction fee as above its RPC fee cap; later bids stay within 10/11 of the lowest refused fee until restart"
        );
    }

    /// The highest maxFeePerGas the ceiling allows at `gas`.
    fn tx_fee_limit(&self, gas: u128) -> u128 {
        self.tx_fee_cap() / gas.max(1)
    }

    fn simulation_failed(
        &mut self,
        note: u32,
        base_state: ObligationState,
        error: anyhow::Error,
        context: &SendContext,
    ) -> anyhow::Result<()> {
        let revert = vault_revert(&error);
        let reason = match revert {
            Some("NotPendingWithdrawal()" | "ReplayedNullifier()") => {
                // A race with the chain tip: only the confirmed-depth path
                // ever retires an obligation, so re-check next poll.
                self.record(
                    note,
                    context
                        .evaluation(ObligationState::ResolvedUnconfirmed)
                        .detail(format!(
                            "simulation reverted {}; re-checking the escape next poll",
                            revert.unwrap_or_default()
                        )),
                );
                return Ok(());
            }
            Some("NotARaise()") => {
                // The concession already covers the raise (another raise
                // landed): re-read next poll.
                self.record(
                    note,
                    context.evaluation(ObligationState::Raised).detail(
                        "simulation reverted NotARaise(): the concession already covers this raise",
                    ),
                );
                return Ok(());
            }
            Some("StaleRoot()") => BlockedReason::IndexerPathBehind,
            // The evidence does not match the vault's escape or verifier.
            Some("NotSuccessorEvidence()" | "NotStateEvidence()" | "InvalidProof()") => {
                BlockedReason::EvidenceInvalid
            }
            Some(_) => BlockedReason::SimulationReverted,
            None if error.downcast_ref::<RpcError>().is_some() => BlockedReason::SimulationReverted,
            None => BlockedReason::RpcError,
        };
        let detail = match revert {
            Some(name) => format!("simulation reverted {name}: {error}"),
            None => error.to_string(),
        };
        self.record(note, context.evaluation(base_state).blocked(reason, detail));
        Err(error)
    }

    /// Retain ownership even if the note's withdrawal is completed or replaced.
    /// The caller persists the queue change and this reservation atomically.
    fn detach_nonce(&mut self, note: u32) {
        if let Some(pending) = self.checkpoint.pending.get(&note) {
            if let Some(nonce) = pending.nonce {
                self.checkpoint.detached_nonces.insert(
                    nonce,
                    DetachedNonce {
                        note_id: note,
                        nullifier: pending.nullifier,
                        transaction_hash: pending.transaction_hash.clone(),
                        attempt: pending.attempt.clone(),
                    },
                );
            }
        }
    }

    async fn transaction_count(&self, tag: &str) -> anyhow::Result<u64> {
        quantity(
            &self
                .rpc("eth_getTransactionCount", json!([self.config.sender, tag]))
                .await?,
        )
    }

    async fn nonce_counts(&mut self) -> anyhow::Result<(u64, u64)> {
        let head = quantity(&self.rpc("eth_blockNumber", json!([])).await?)?;
        let latest = self.transaction_count("latest").await?;
        let confirmed = if let Some(block) = head.checked_sub(self.config.confirmations) {
            self.transaction_count(&format!("0x{block:x}")).await?
        } else {
            0
        };
        self.latest_nonce_count = Some(latest);
        // A reorg or newly mined block may race the two reads. Never retire a
        // reservation whose consumption the latest nonce read did not observe.
        Ok((latest, confirmed.min(latest)))
    }

    async fn reconcile_nonce(&mut self, note: u32) -> anyhow::Result<NonceState> {
        let pending = self.checkpoint.pending[&note].clone();
        let Some(nonce) = pending.nonce else {
            return Ok(NonceState::Free);
        };
        let (latest, confirmed) = self.nonce_counts().await?;
        if confirmed > nonce {
            let entry = self.checkpoint.pending.get_mut(&note).unwrap();
            entry.nonce = None;
            entry.transaction_hash = None;
            entry.attempt = NonceAttempts::default();
            self.observed_fees.remove(&note);
            self.persist()?;
            return Ok(NonceState::Free);
        }
        if latest > nonce {
            // Let other notes advance, but retain this ownership until enough
            // confirmations have passed to protect against a tip reorg.
            return Ok(NonceState::Mined);
        }
        // Probe only the current and the most recent superseded candidate.
        for hash in pending
            .transaction_hash
            .iter()
            .chain(pending.attempt.superseded_hashes.last())
        {
            let transaction = self.rpc("eth_getTransactionByHash", json!([hash])).await?;
            if !transaction.is_null() {
                match transaction_fees(&transaction) {
                    Some(fees) => {
                        self.observed_fees.insert(note, fees);
                    }
                    None => {
                        self.observed_fees.remove(&note);
                    }
                }
                return Ok(NonceState::Pending);
            }
        }
        if let Some(hash) = pending.transaction_hash {
            // Unknown to the RPC, but it may still mine: keep the candidate
            // until the nonce is consumed.
            let entry = self.checkpoint.pending.get_mut(&note).unwrap();
            entry.transaction_hash = None;
            push_superseded(&mut entry.attempt, hash);
            self.persist()?;
        }
        // The sender is dedicated, so a pending count past this unmined nonce
        // means an attempt without a known hash occupies it.
        if pending.attempt.unknown_attempt || self.transaction_count("pending").await? > nonce {
            return Ok(NonceState::Held);
        }
        Ok(NonceState::Reserved)
    }

    async fn reconcile_detached_nonces(&mut self) -> anyhow::Result<()> {
        if self.checkpoint.detached_nonces.is_empty() {
            self.detached_status.clear();
            return Ok(());
        }
        let (latest, confirmed) = self.nonce_counts().await?;
        self.checkpoint
            .detached_nonces
            .retain(|nonce, _| *nonce >= confirmed);
        // An unmined nonce that no attempt was broadcast on cannot be pending
        // anywhere: release it instead of blocking every later allocation.
        let unsent: Vec<u64> = self
            .checkpoint
            .detached_nonces
            .iter()
            .filter(|(nonce, entry)| {
                **nonce >= latest
                    && never_broadcast(entry.transaction_hash.as_ref(), &entry.attempt)
            })
            .map(|(nonce, _)| *nonce)
            .collect();
        for nonce in unsent {
            if self.nonce_unused(nonce).await {
                let entry = self.checkpoint.detached_nonces.remove(&nonce).unwrap();
                tracing::info!(
                    note_id = entry.note_id,
                    nonce,
                    "released a detached nonce that no attempt was broadcast on"
                );
            }
        }
        self.persist()?;
        self.detached_status = self
            .checkpoint
            .detached_nonces
            .iter()
            .map(|(nonce, entry)| {
                let wei = |value: &Option<String>| {
                    value
                        .as_deref()
                        .and_then(parse_hex_u128)
                        .map(|wei| wei.to_string())
                };
                DetachedNonceStatus {
                    nonce: *nonce,
                    note_id: entry.note_id,
                    nullifier: entry.nullifier,
                    transaction_hash: entry.transaction_hash.clone(),
                    superseded_hashes: entry.attempt.superseded_hashes.clone(),
                    max_fee_per_gas_wei: wei(&entry.attempt.max_fee_per_gas),
                    max_priority_fee_per_gas_wei: wei(&entry.attempt.max_priority_fee_per_gas),
                    gas_limit: entry.attempt.gas_limit,
                    mined: *nonce < latest,
                }
            })
            .collect();
        if let Some((nonce, entry)) = self
            .checkpoint
            .detached_nonces
            .iter()
            .find(|(nonce, _)| **nonce >= latest)
        {
            bail!(
                "unmined reserved nonce {nonce} for completed or replaced note {} requires signer intervention; refusing conflicting challenge submission",
                entry.note_id
            );
        }
        Ok(())
    }

    /// The first unresolved nonce that blocks new allocations, if any.
    fn queue_blocker(&self) -> Option<(u64, u32)> {
        self.detached_status
            .iter()
            .find(|entry| !entry.mined)
            .map(|entry| (entry.nonce, entry.note_id))
            .or_else(|| {
                self.checkpoint
                    .pending
                    .iter()
                    .filter(|(_, entry)| entry.transaction_hash.is_none())
                    .find_map(|(note, entry)| entry.nonce.map(|nonce| (nonce, *note)))
            })
    }

    /// Escalation urgency for a send: the most urgent deadline among this
    /// obligation and every obligation queued behind it (holding a later
    /// nonce, or waiting for one) that has a defeat or raise due or pending.
    fn queue_severity(&self, note: u32, head: &HeadInfo) -> Severity {
        let thresholds = self.thresholds();
        let own_nonce = self
            .checkpoint
            .pending
            .get(&note)
            .and_then(|entry| entry.nonce);
        self.checkpoint
            .pending
            .iter()
            .filter(|(other, entry)| {
                **other == note
                    || match (own_nonce, entry.nonce) {
                        (Some(own), Some(theirs)) => theirs > own,
                        (_, None) => true,
                        (None, Some(_)) => false,
                    }
            })
            .filter(|(other, entry)| {
                **other == note
                    || entry.nonce.is_some()
                    || self
                        .evaluations
                        .get(other)
                        .or_else(|| self.previous_evaluations.get(other))
                        .is_none_or(|evaluation| {
                            matches!(
                                evaluation.state,
                                ObligationState::Ready
                                    | ObligationState::Submitted
                                    | ObligationState::MinedUnconfirmed
                                    | ObligationState::Unevaluated
                            )
                        })
            })
            .filter(|(_, entry)| !entry.retire_leaf)
            .filter_map(|(_, entry)| entry.challenge_deadline)
            // An expired obligation can no longer be acted on.
            .filter(|deadline| *deadline > head.timestamp)
            .map(|deadline| {
                challenge_status::deadline_severity(Some(deadline - head.timestamp), thresholds)
            })
            .max()
            .unwrap_or(Severity::Ok)
    }

    fn persisted_fees(&self, note: u32) -> Option<Fees> {
        let attempt = &self.checkpoint.pending.get(&note)?.attempt;
        Some(Fees {
            max_fee: parse_hex_u128(attempt.max_fee_per_gas.as_deref()?)?,
            tip: parse_hex_u128(attempt.max_priority_fee_per_gas.as_deref()?)?,
        })
    }

    fn thresholds(&self) -> RemainingThresholds {
        self.config
            .alarms
            .remaining_thresholds(self.challenge_period)
    }

    fn record(&mut self, note: u32, mut evaluation: Evaluation) {
        let now = unix_now();
        match evaluation.blocked {
            Some(_) => {
                let entry = self.blocked_since.entry(note).or_insert((now, 0));
                entry.1 = entry.1.saturating_add(1);
            }
            None => {
                self.blocked_since.remove(&note);
            }
        }
        evaluation.evaluated_at = now;
        self.evaluations.insert(note, evaluation);
    }

    /// Keep the last known state of an obligation that could not be
    /// evaluated, marked with why.
    fn evaluate_failure(&mut self, note: u32, reason: BlockedReason, error: &anyhow::Error) {
        let previous = self
            .evaluations
            .get(&note)
            .or_else(|| self.previous_evaluations.get(&note))
            .cloned()
            .unwrap_or_else(|| Evaluation::new(ObligationState::Unevaluated, None));
        self.record(note, previous.blocked(reason, error.to_string()));
    }

    fn finish_poll(&mut self, result: &anyhow::Result<()>) {
        let now = unix_now();
        self.poll.last_completed_at = Some(now);
        match result {
            Ok(()) => {
                self.poll.consecutive_failures = 0;
                self.poll.last_error = None;
                self.poll.last_success_at = Some(now);
            }
            Err(error) => {
                self.poll.consecutive_failures = self.poll.consecutive_failures.saturating_add(1);
                self.poll.last_error = Some(bounded(&error.to_string()));
            }
        }
        self.publish();
    }

    fn publish(&mut self) {
        let now = unix_now();
        let snapshot = self.build_status(now);
        let current = challenge_status::evaluate(&snapshot, &self.config.alarms, now);
        self.log_transitions(&current, now);
        match self.status.write() {
            Ok(mut status) => *status = current,
            Err(poisoned) => *poisoned.into_inner() = current,
        }
    }

    fn build_status(&self, now: u64) -> ChallengeStatus {
        let head = self.head.as_ref();
        let fee = &self.config.fee;
        let gas = self.last_gas.unwrap_or(DEFAULT_CHALLENGE_GAS);
        let proposed = head.map(|head| {
            head.base_fee
                .map_or(fee.max_fee_per_gas, |base| {
                    fee.max_fee_per_gas.min(
                        base.saturating_mul(2)
                            .saturating_add(fee.priority_fee_per_gas),
                    )
                })
                .min(self.tx_fee_limit(gas))
        });
        let mut obligations = Vec::new();
        let mut outstanding = 0u64;
        for (note, pending) in &self.checkpoint.pending {
            let evaluation = self.evaluations.get(note);
            let state = evaluation.map_or(ObligationState::Unevaluated, |e| e.state);
            let settlement = evaluation.and_then(|e| e.settlement.clone());
            let wei = |value: &Option<String>| {
                value
                    .as_deref()
                    .and_then(parse_hex_u128)
                    .map(|wei| wei.to_string())
            };
            let obligation = ObligationStatus {
                note_id: *note,
                nullifier: pending.nullifier,
                next_nullifier: pending.next_nullifier,
                state_balance: pending.state_balance,
                conceded: pending.conceded,
                owed: evaluation.and_then(|e| e.owed),
                raise_due_at: evaluation.and_then(|e| e.raise_due_at),
                action: pending.nonce.map(|_| pending.attempt.kind()),
                state,
                severity: Severity::Ok,
                challenge_deadline: pending.challenge_deadline,
                seconds_remaining: None,
                evidence: evaluation.and_then(|e| e.evidence),
                blocked_reason: evaluation.and_then(|e| e.blocked),
                detail: evaluation.and_then(|e| e.detail.clone()),
                blocked_since: self.blocked_since.get(note).map(|(since, _)| *since),
                consecutive_failures: self.blocked_since.get(note).map_or(0, |(_, count)| *count),
                settlement,
                nonce: pending.nonce,
                transaction_hash: pending.transaction_hash.clone(),
                superseded_hashes: pending.attempt.superseded_hashes.clone(),
                max_fee_per_gas_wei: wei(&pending.attempt.max_fee_per_gas),
                max_priority_fee_per_gas_wei: wei(&pending.attempt.max_priority_fee_per_gas),
                attempts: pending.attempt.attempts,
                submitted_block: pending.attempt.submitted_block,
                first_seen_at: pending.first_seen_at,
                evaluated_at: evaluation.map(|e| e.evaluated_at),
            };
            let may_need_gas = matches!(
                state,
                ObligationState::Unevaluated
                    | ObligationState::Ready
                    | ObligationState::Submitted
                    | ObligationState::MinedUnconfirmed
                    | ObligationState::AwaitingSettlement
                    | ObligationState::RetiringLeaf
            );
            if may_need_gas {
                outstanding += 1;
            }
            obligations.push(obligation);
        }
        let mut sender = self.sender.clone();
        sender.balance_wei = self.sender_balance.map(|balance| balance.to_string());
        sender.outstanding_obligations = outstanding;
        sender.proposed_max_fee_per_gas_wei = proposed.map(|fee| fee.to_string());
        sender.required_balance_wei = proposed.filter(|_| outstanding > 0).map(|fee| {
            (outstanding as u128)
                .saturating_mul(gas)
                .saturating_mul(fee)
                .to_string()
        });
        sender.signer_tx_fee_cap_wei = self.signer_tx_fee_cap.map(|cap| cap.to_string());
        sender.node_tx_fee_cap_bound_wei = self.node_tx_fee_bound().map(|bound| bound.to_string());
        sender.effective_tx_fee_cap_wei = self.tx_fee_cap().to_string();
        sender.challenge_gas_limit = self.last_gas.and_then(|gas| u64::try_from(gas).ok());
        sender.tx_fee_cap_max_fee_per_gas_wei =
            self.last_gas.map(|gas| self.tx_fee_limit(gas).to_string());
        let mut config_warnings = self.config_warnings.clone();
        config_warnings.extend(self.startup_warning.clone());
        config_warnings.extend(self.vault_warning.clone());
        if let Some(signer) = self
            .signer_tx_fee_cap
            .filter(|cap| *cap != fee.tx_fee_cap_wei)
        {
            config_warnings.push(format!(
                "the signer's tx_fee_cap_wei {signer} differs from --tx-fee-cap-wei {}; bids stay within the lower",
                fee.tx_fee_cap_wei
            ));
        }
        if let Some((refused, bound)) = self.node_refused_tx_fee.zip(self.node_tx_fee_bound()) {
            config_warnings.push(format!(
                "the signer's node refused a transaction fee of {refused} wei (upstream_tx_fee_cap): its RPC fee cap is below the ceiling, so bids stay within {bound} wei until restart; set ZKAPI_CHALLENGE_TX_FEE_CAP_WEI in the env files of the signer and this daemon to the node's --rpc.txfeecap and recreate both containers (docker compose up -d; a restart keeps the old environment), or raise the node's cap and restart this daemon"
            ));
        }
        // A defeat needs about 0.6M gas: a fee cap above the ceiling per gas
        // is never reached.
        let challenge_gas = gas.max(DEFAULT_CHALLENGE_GAS);
        if fee.max_fee_per_gas.saturating_mul(challenge_gas) > self.tx_fee_cap() {
            config_warnings.push(format!(
                "--max-fee-per-gas-wei {} x {challenge_gas} gas exceeds the transaction fee ceiling of {} wei; bids stop at {} wei per gas (raise the ceiling with the upstream node's RPC fee cap, or lower the fee cap)",
                fee.max_fee_per_gas,
                self.tx_fee_cap(),
                self.tx_fee_limit(challenge_gas)
            ));
        }
        let mut indexer = self.indexer.clone();
        if indexer.root.is_none() && indexer.state == IndexerState::Unknown {
            indexer.detail = Some("not yet observed".into());
        }
        let mut status = ChallengeStatus::initial(
            ChainStatus {
                chain_id: self.config.chain_id,
                vault: self.vault_address(),
                latest_block: head.map(|head| head.number),
                latest_block_timestamp: head.map(|head| head.timestamp),
                head_observed_at: self.head_seen.map(|(_, at)| at),
                head_age_seconds: None,
                base_fee_per_gas_wei: head
                    .and_then(|head| head.base_fee)
                    .map(|fee| fee.to_string()),
                scan_next_block: self.checkpoint.next_block,
                scan_lag_blocks: head.map(|head| {
                    head.number
                        .checked_sub(self.config.confirmations)
                        .map_or(0, |safe| {
                            safe.saturating_add(1)
                                .saturating_sub(self.checkpoint.next_block)
                        })
                }),
                confirmations: self.config.confirmations,
                challenge_period_seconds: self.challenge_period,
                vault_root: self.vault_root,
            },
            sender,
            self.started_at,
        );
        status.generated_at = now;
        status.poll = self.poll.clone();
        status.indexer = indexer;
        status.obligations = obligations;
        status.detached_nonces = self.detached_status.clone();
        status.missed_total = self.checkpoint.missed_total;
        status.escapes_finalized_with_successor_evidence_total =
            self.checkpoint.missed_defeats_total;
        status.missed_raises_total = self.checkpoint.missed_raises_total;
        status.last_missed = self.checkpoint.last_missed.clone();
        status.config_warnings = config_warnings;
        status
    }

    /// Log each obligation's state transitions at a level matching its
    /// severity, and re-log critical ones periodically.
    fn log_transitions(&mut self, status: &ChallengeStatus, now: u64) {
        self.logged
            .retain(|note, _| self.checkpoint.pending.contains_key(note));
        for o in &status.obligations {
            let key = (o.state, o.severity, o.blocked_reason);
            let relog = o.severity == Severity::Critical
                && self
                    .logged
                    .get(&o.note_id)
                    .is_some_and(|(.., at)| now.saturating_sub(*at) >= RELOG_SECONDS);
            if self
                .logged
                .get(&o.note_id)
                .is_some_and(|(state, severity, blocked, _)| (*state, *severity, *blocked) == key)
                && !relog
            {
                continue;
            }
            self.logged
                .insert(o.note_id, (o.state, o.severity, o.blocked_reason, now));
            let state = challenge_status::wire_name(o.state);
            let blocked = o.blocked_reason.map(challenge_status::wire_name);
            match o.severity {
                Severity::Ok => {
                    tracing::info!(note_id = o.note_id, nullifier = %o.nullifier, state, severity = "ok", blocked_reason = ?blocked, seconds_remaining = ?o.seconds_remaining, "challenge obligation status changed")
                }
                Severity::Warning => {
                    tracing::warn!(note_id = o.note_id, nullifier = %o.nullifier, state, severity = "warning", blocked_reason = ?blocked, seconds_remaining = ?o.seconds_remaining, detail = ?o.detail, "challenge obligation status changed")
                }
                Severity::Critical => {
                    tracing::error!(note_id = o.note_id, nullifier = %o.nullifier, state, severity = "critical", blocked_reason = ?blocked, seconds_remaining = ?o.seconds_remaining, detail = ?o.detail, "challenge obligation status changed")
                }
            }
        }
    }

    fn vault_address(&self) -> String {
        format!(
            "0x{}",
            hex::encode(&self.config.contract_address.as_bytes()[12..])
        )
    }

    /// The note's escape at `block`: `pendingWithdrawals(note)` (6 words)
    /// and `pendingConcessions(note)` (3 words), both read at that block
    /// number, strictly decoded and checked against each other
    /// (`finalBalance + conceded == stateBalance`, and a successor nullifier
    /// exactly when an escape exists). A backend without the block fails the
    /// read, which the poll retries, rather than answering stale.
    async fn escape_state(&self, note: u32, block: u64) -> anyhow::Result<EscapeState> {
        let tag = json!(format!("0x{block:x}"));
        let argument = Felt252::from_u64(note as u64);
        let mut withdrawal = selector("pendingWithdrawals(uint32)");
        withdrawal.extend_from_slice(argument.as_bytes());
        let mut concession = selector("pendingConcessions(uint32)");
        concession.extend_from_slice(argument.as_bytes());
        let pending = self.call_at(withdrawal, tag.clone()).await?;
        ensure!(pending.len() == 6, "malformed pending withdrawal response");
        let concession = self.call_at(concession, tag).await?;
        ensure!(
            concession.len() == 3,
            "malformed pending concession response"
        );
        let exists = match felt_u64(&pending[0])? {
            0 => false,
            1 => true,
            _ => bail!("malformed pending withdrawal flag"),
        };
        ensure!(
            pending[4].as_bytes()[..12].iter().all(|byte| *byte == 0),
            "malformed pending withdrawal destination"
        );
        let state = EscapeState {
            exists,
            nullifier: pending[2],
            final_balance: felt_u128(&pending[3])?,
            deadline: felt_u64(&pending[5])?,
            next_nullifier: concession[0],
            state_balance: felt_u128(&concession[1])?,
            conceded: felt_u128(&concession[2])?,
        };
        if exists {
            ensure!(
                !state.next_nullifier.is_zero()
                    && state.final_balance.checked_add(state.conceded) == Some(state.state_balance),
                "vault concession of note {note} is inconsistent with its pending escape"
            );
        } else {
            ensure!(
                state.next_nullifier.is_zero() && state.state_balance == 0 && state.conceded == 0,
                "vault holds a concession for note {note} without a pending escape"
            );
        }
        Ok(state)
    }

    async fn live_root(&mut self) -> anyhow::Result<Felt252> {
        let root = self.call(selector("currentRoot()")).await?;
        ensure!(root.len() == 1, "malformed currentRoot response");
        self.vault_root = Some(root[0]);
        Ok(root[0])
    }

    /// The vault root at a block named by hash (EIP-1898).
    async fn root_at_block_hash(&self, block_hash: &str) -> anyhow::Result<Felt252> {
        let root = self
            .call_at(
                selector("currentRoot()"),
                json!({ "blockHash": block_hash }),
            )
            .await?;
        ensure!(root.len() == 1, "malformed currentRoot response");
        Ok(root[0])
    }

    async fn call(&self, data: Vec<u8>) -> anyhow::Result<Vec<Felt252>> {
        self.call_at(data, json!("latest")).await
    }

    async fn call_at(&self, data: Vec<u8>, block: Value) -> anyhow::Result<Vec<Felt252>> {
        words(&self.rpc("eth_call", json!([{ "to": self.vault_address(), "data": format!("0x{}", hex::encode(data)) }, block])).await?)
    }

    async fn rpc(&self, method: &str, params: Value) -> anyhow::Result<Value> {
        self.rpc_with_timeout(method, params, None).await
    }

    async fn rpc_with_timeout(
        &self,
        method: &str,
        params: Value,
        timeout: Option<Duration>,
    ) -> anyhow::Result<Value> {
        let mut request = self
            .client
            .post(&self.config.rpc_url)
            .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }));
        if let Some(timeout) = timeout {
            request = request.timeout(timeout);
        }
        let transport = |error: reqwest::Error| TransportError {
            method: method.into(),
            unsent: error.is_connect() || error.is_builder(),
            message: error.without_url().to_string(),
        };
        let response: Value = request
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(transport)?
            .json()
            .await
            .map_err(transport)?;
        if let Some(error) = response.get("error") {
            return Err(RpcError {
                method: method.into(),
                error: error.clone(),
            }
            .into());
        }
        response
            .get("result")
            .cloned()
            .with_context(|| format!("{method}: missing RPC result"))
    }

    /// The indexer's internal /health phase (`syncing`, `diverged`, ...),
    /// which it reports with a 503 whenever it is not serving.
    async fn indexer_health_phase(&self) -> Option<String> {
        let response = self
            .client
            .get(format!(
                "{}/health",
                self.config.indexer_url.trim_end_matches('/')
            ))
            .timeout(INDEXER_TIMEOUT)
            .send()
            .await
            .ok()?;
        response.json::<IndexerHealth>().await.ok()?.status
    }

    async fn indexer_get<T: DeserializeOwned>(&self, path: &str) -> Result<T, IndexerFailure> {
        let response = self
            .client
            .get(format!(
                "{}{path}",
                self.config.indexer_url.trim_end_matches('/')
            ))
            .timeout(INDEXER_TIMEOUT)
            .send()
            .await
            .map_err(|error| IndexerFailure::Transport(error.without_url().to_string()))?;
        if !response.status().is_success() {
            return Err(IndexerFailure::Status(response.status().as_u16()));
        }
        response
            .json()
            .await
            .map_err(|error| IndexerFailure::Decode(error.without_url().to_string()))
    }

    fn persist(&self) -> anyhow::Result<()> {
        let path = &self.config.checkpoint;
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent)?;
        }
        let temporary = path.with_extension("tmp");
        let mut file = std::fs::File::create(&temporary)?;
        std::io::Write::write_all(&mut file, &serde_json::to_vec_pretty(&self.checkpoint)?)?;
        file.sync_all()?;
        std::fs::rename(&temporary, path)?;
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(std::path::Path::new("."));
        std::fs::File::open(parent)?.sync_all()?;
        Ok(())
    }
}

/// What a send reports on the status besides its outcome.
#[derive(Clone, Debug)]
struct SendContext {
    evidence: EvidenceKind,
    /// The `request_evidence` row of a defeat or raise.
    evidence_row: Option<i64>,
    /// The root a retirement's siblings hash to.
    root: Option<Felt252>,
    owed: Option<u128>,
    raise_due_at: Option<u64>,
}

impl SendContext {
    fn evaluation(&self, state: ObligationState) -> Evaluation {
        let mut evaluation = Evaluation::new(state, Some(self.evidence));
        evaluation.owed = self.owed;
        evaluation.raise_due_at = self.raise_due_at;
        evaluation
    }
}

/// The status of a pending escape before any send.
fn evaluation_of(decision: &Decision) -> Evaluation {
    let mut evaluation = match &decision.due {
        Due::Defeat { .. } => Evaluation::new(ObligationState::Ready, Some(decision.evidence))
            .detail("verified evidence at the successor nullifier: a defeat is due"),
        Due::Raise { amount, .. } => {
            Evaluation::new(ObligationState::Ready, Some(decision.evidence))
                .detail(format!("a raise to {amount} units is due"))
        }
        Due::AwaitingSettlement => Evaluation::new(
            ObligationState::AwaitingSettlement,
            Some(decision.evidence),
        )
        .detail("the request at the escaped nullifier may have been delivered and has not settled; the raise is decided once it settles, or at the raise lead"),
        Due::Nothing { covered: true, detail } => {
            Evaluation::new(ObligationState::Raised, Some(decision.evidence)).detail(detail.clone())
        }
        Due::Nothing { covered: false, detail } => {
            Evaluation::new(ObligationState::NothingDue, Some(decision.evidence))
                .detail(detail.clone())
        }
        Due::Invalid { detail, .. } => Evaluation::new(ObligationState::Ready, Some(decision.evidence))
            .blocked(BlockedReason::EvidenceInvalid, detail.clone()),
    };
    if let Some(invalid) = &decision.successor_invalid {
        let detail = match (&decision.due, &evaluation.detail) {
            (Due::Invalid { .. }, Some(detail)) => format!("{invalid}; {detail}"),
            _ => invalid.clone(),
        };
        evaluation = evaluation.blocked(BlockedReason::EvidenceInvalid, detail);
    }
    evaluation.settlement = decision.settlement.clone();
    evaluation.owed = decision.owed;
    evaluation.raise_due_at = Some(decision.raise_due_at);
    evaluation
}

/// A pending escape whose evidence database cannot be read.
fn decision_unreadable(error: &anyhow::Error) -> Evaluation {
    Evaluation::new(ObligationState::Ready, Some(EvidenceKind::Unavailable))
        .blocked(BlockedReason::EvidenceDbError, error.to_string())
}

fn nothing_kind(why: NothingOwed) -> EvidenceKind {
    match why {
        NothingOwed::NoRequest | NothingOwed::NotALease => EvidenceKind::Unknown,
        NothingOwed::Clearance => EvidenceKind::Clearance,
        NothingOwed::NoLeaseRow => EvidenceKind::ReservedWithoutLease,
        NothingOwed::NeverDelivered => EvidenceKind::NeverDelivered,
    }
}

/// The miss a decision makes of an escape whose deadline passed: a defeat
/// due with evidence written before the deadline, a raise due, or evidence
/// that does not verify where one of them may have been due.
fn miss_of(decision: &Decision) -> Option<MissEvidence> {
    let miss = |kind, evidence, reason: String| MissEvidence {
        kind,
        evidence,
        settlement: decision.settlement.clone(),
        reason,
    };
    if let Some(detail) = &decision.successor_invalid {
        // Rows at N⁺ that may have been a defeat: a possible missed defeat,
        // whatever was due at N.
        return Some(miss(
            CallKind::Defeat,
            EvidenceKind::Corrupt,
            format!("evidence invalid at the deadline: {detail}"),
        ));
    }
    match &decision.due {
        Due::Defeat {
            before_deadline: true,
            ..
        } => Some(miss(
            CallKind::Defeat,
            EvidenceKind::Successor,
            "defeat not mined before the deadline: verified evidence at the successor nullifier existed".into(),
        )),
        Due::Raise { amount, .. } => Some(miss(
            CallKind::Raise,
            decision.evidence,
            format!("raise not mined before the deadline: {amount} units owed exceeded the concession"),
        )),
        Due::Invalid { kind, detail } => Some(miss(
            *kind,
            EvidenceKind::Corrupt,
            format!("evidence invalid at the deadline: {detail}"),
        )),
        Due::Defeat {
            before_deadline: false,
            ..
        }
        | Due::AwaitingSettlement
        | Due::Nothing { .. } => None,
    }
}

/// An obligation whose escape is gone at the latest block. With a miss it
/// may have been paid out, so it keeps its deadline severity until the
/// outcome is known at confirmation depth, unless it ended before the
/// deadline (`ended_early`), when it cannot have been. Once its miss is
/// counted (`missed`) it is shown missed until it retires.
fn disappeared(evidence: Option<&MissEvidence>, ended_early: bool, missed: bool) -> Evaluation {
    match evidence {
        _ if ended_early => Evaluation::new(ObligationState::ResolvedUnconfirmed, None).detail(
            "escape ended before its challenge deadline, so it was not paid out; retirement waits for confirmations",
        ),
        Some(evidence) if missed => {
            let mut evaluation = Evaluation::new(ObligationState::Missed, Some(evidence.evidence))
                .detail("missed deadline recorded; the escape is no longer pending, and the obligation retires at confirmation depth");
            evaluation.settlement = evidence.settlement.clone();
            evaluation
        }
        Some(evidence) => {
            let mut evaluation = Evaluation::new(
                ObligationState::ResolvedUnconfirmed,
                Some(evidence.evidence),
            )
            .detail(
                "escape no longer pending at the latest block; at confirmation depth it is retired, or recorded missed if it was paid out",
            );
            evaluation.settlement = evidence.settlement.clone();
            evaluation
        }
        None => Evaluation::new(ObligationState::ResolvedUnconfirmed, None).detail(
            "escape no longer pending at the latest block; retirement waits for confirmations",
        ),
    }
}

/// An obligation whose escape is gone while the evidence database cannot
/// say whether a defeat or raise was due, so whether a payout was a missed
/// deadline.
fn evidence_unreadable(error: &anyhow::Error) -> Evaluation {
    Evaluation::new(
        ObligationState::ResolvedUnconfirmed,
        Some(EvidenceKind::Unavailable),
    )
    .blocked(
        BlockedReason::EvidenceDbError,
        format!("{error}; whether a payout of the escape was a missed deadline is decided once it reads"),
    )
}

/// The challenger's RPC as a `ContractReader` for the startup probes.
struct RpcReader {
    client: reqwest::Client,
    url: String,
}

impl RpcReader {
    async fn rpc(&self, method: &str, params: Value) -> Result<Value, String> {
        let response: Value = self
            .client
            .post(&self.url)
            .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }))
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|error| format!("{method}: {}", error.without_url()))?
            .json()
            .await
            .map_err(|error| format!("{method}: {}", error.without_url()))?;
        if let Some(error) = response.get("error") {
            return Err(format!("{method}: {error}"));
        }
        response
            .get("result")
            .cloned()
            .ok_or_else(|| format!("{method}: missing RPC result"))
    }
}

impl ContractReader for RpcReader {
    async fn contract_word(&self, address: &str, selector: &str) -> Result<[u8; 32], String> {
        let result = self
            .rpc(
                "eth_call",
                json!([{ "to": address, "data": selector }, "latest"]),
            )
            .await?;
        let word = result
            .as_str()
            .and_then(|raw| raw.strip_prefix("0x"))
            .filter(|raw| raw.len() == 64)
            .ok_or("getter returned no 32-byte word (is the contract deployed at this address on this chain?)")?;
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(word, &mut bytes).map_err(|_| "malformed ABI word".to_string())?;
        Ok(bytes)
    }

    async fn code_hash(&self, address: &str) -> Result<[u8; 32], String> {
        let code = self.rpc("eth_getCode", json!([address, "latest"])).await?;
        let body = code
            .as_str()
            .and_then(|raw| raw.strip_prefix("0x"))
            .ok_or("invalid eth_getCode response")?;
        if body.is_empty() {
            return Err("no contract code at this address on this chain".into());
        }
        let bytes = hex::decode(body).map_err(|_| "invalid eth_getCode response".to_string())?;
        Ok(Keccak256::digest(&bytes).into())
    }
}

/// Plan the fees of one send at its exact gas limit. `tx_fee_limit` is the
/// highest maxFeePerGas the transaction fee ceiling allows at that gas limit
/// and bounds every bid like a lower fee cap. A bump raises the tip by the
/// minimum valid replacement step and the fee cap by `bump_percent`.
///
/// Two valid replacements stay in reserve for the critical threshold: other
/// bids stay within 10/11 of 10/11 of the caps, unless the base fee needs
/// more, or rose above a pending bid that cannot otherwise be outbid. A
/// critical send bids 10/11 of the caps, then the caps. `Ok(None)` keeps a
/// pending attempt when only that reserve is left.
fn plan_fees(
    policy: &FeePolicy,
    plan: FeePlan,
    base_fee: Option<u128>,
    critical: bool,
    tx_fee_limit: Option<u128>,
    affordable: Option<u128>,
) -> Result<Option<Fees>, BlockedReason> {
    let caps = Fees {
        max_fee: policy
            .max_fee_per_gas
            .min(tx_fee_limit.unwrap_or(u128::MAX)),
        tip: policy.max_priority_fee_per_gas,
    };
    if base_fee.is_some_and(|base| base > policy.max_fee_per_gas) {
        return Err(BlockedReason::BaseFeeAboveFeeCap);
    }
    if base_fee.is_some_and(|base| base > caps.max_fee) {
        return Err(BlockedReason::TxFeeCapReached);
    }
    let reserve = |steps: u32| {
        (0..steps).fold(caps, |fees, _| Fees {
            max_fee: headroom(fees.max_fee),
            tip: headroom(fees.tip),
        })
    };
    // Just under the caps, unless the base fee already exceeds that bid.
    let critical_target = match base_fee {
        Some(base) if base > headroom(caps.max_fee) => caps,
        _ => reserve(1),
    };
    // The limits of every other bid, raised only as far as the base fee needs.
    let limit = match base_fee {
        Some(base) if base > headroom(caps.max_fee) => caps,
        Some(base) if base > reserve(2).max_fee => reserve(1),
        _ => reserve(2),
    };
    let bid = |tip: u128| {
        base_fee.map_or(limit.max_fee, |base| {
            limit
                .max_fee
                .min(base.saturating_mul(2).saturating_add(tip))
        })
    };
    // A max fee the ceiling keeps from rising 10% (or below the raised tip)
    // is reported first: raising only the tip cap cannot help then.
    let cap_reason = |old: Fees| {
        let pinned = min_bump(old.max_fee).max(min_bump(old.tip)) > caps.max_fee;
        if pinned && caps.max_fee < policy.max_fee_per_gas {
            BlockedReason::TxFeeCapReached
        } else if min_bump(old.tip) > caps.tip {
            BlockedReason::TipCapReached
        } else {
            BlockedReason::FeeCapReached
        }
    };
    let bump = |old: Fees, limit: Fees| {
        let tip = min_bump(old.tip)
            .max(policy.priority_fee_per_gas)
            .min(limit.tip);
        let mut max_fee = old
            .max_fee
            .saturating_mul(100 + policy.bump_percent as u128)
            .div_ceil(100);
        if let Some(base) = base_fee {
            max_fee = max_fee.max(base.saturating_mul(2).saturating_add(tip));
        }
        let fees = Fees {
            max_fee: max_fee.min(limit.max_fee),
            tip,
        };
        is_valid_bump(old, fees).then_some(fees)
    };
    // A target's tip never exceeds its max fee, which the ceiling can lower
    // below the tip cap.
    let escalate = |old: Fees| {
        [critical_target, caps]
            .into_iter()
            .map(|fees| Fees {
                tip: fees.tip.min(fees.max_fee),
                ..fees
            })
            .find(|fees| is_valid_bump(old, *fees))
            .ok_or_else(|| cap_reason(old))
    };
    let mut fees = match plan {
        FeePlan::First if critical => critical_target,
        FeePlan::First => Fees {
            max_fee: bid(policy.priority_fee_per_gas),
            tip: policy.priority_fee_per_gas,
        },
        FeePlan::Resend(old) => {
            let tip = old.tip.min(caps.tip);
            let fees = Fees {
                max_fee: old.max_fee.min(caps.max_fee).max(bid(tip)),
                tip,
            };
            if critical {
                Fees {
                    max_fee: fees.max_fee.max(critical_target.max_fee),
                    tip: fees.tip.max(critical_target.tip),
                }
            } else {
                fees
            }
        }
        FeePlan::Bump(old) if critical => escalate(old)?,
        FeePlan::Bump(old) => match bump(old, limit) {
            Some(fees) => fees,
            // The pending bid can no longer be included: spend the reserve.
            None if base_fee.is_some_and(|base| base > old.max_fee) => escalate(old)?,
            None if bump(old, caps).is_none() => return Err(cap_reason(old)),
            None => return Ok(None),
        },
    };
    fees.tip = fees.tip.min(fees.max_fee);
    let mut clamped = false;
    if let Some(limit) = affordable.filter(|limit| fees.max_fee > *limit) {
        fees.max_fee = limit;
        fees.tip = fees.tip.min(limit);
        clamped = true;
    }
    let includable = fees.tip > 0 && base_fee.is_none_or(|base| fees.max_fee >= base);
    let valid = match plan {
        FeePlan::Bump(old) => is_valid_bump(old, fees),
        _ => true,
    };
    if clamped && !(includable && valid) {
        return Err(BlockedReason::InsufficientBalance);
    }
    if !includable {
        return Err(BlockedReason::BaseFeeAboveFeeCap);
    }
    Ok(Some(fees))
}

/// Every attempt recorded on a nonce was a definite non-broadcast: a signer
/// refusal, a failure the signer reports before broadcasting, or a connection
/// never made. Any other attempt leaves a candidate hash or an unknown attempt,
/// and a reservation an older daemon made leaves no record at all.
fn never_broadcast(transaction_hash: Option<&String>, attempt: &NonceAttempts) -> bool {
    transaction_hash.is_none()
        && attempt.superseded_hashes.is_empty()
        && !attempt.unknown_attempt
        && !attempt.unrecorded_attempt
        && attempt.attempts > 0
}

/// The blocked reason of a definitive signer refusal.
fn refusal_reason(reason: Option<&str>) -> BlockedReason {
    match reason {
        Some("base_fee_above_max_fee") => BlockedReason::BaseFeeAboveMaxFee,
        Some("insufficient_balance") => BlockedReason::InsufficientBalance,
        Some("tx_fee_above_cap") => BlockedReason::TxFeeAboveCap,
        Some("upstream_tx_fee_cap") => BlockedReason::UpstreamTxFeeCap,
        _ => BlockedReason::SignerRefused,
    }
}

/// The signer's transaction fee cap from a `tx_fee_above_cap` refusal: its
/// `tx_fee_cap_wei`, or else `max_fee_per_gas_allowed` x the gas limit.
fn refused_tx_fee_cap(error: &anyhow::Error, gas: u64) -> Option<u128> {
    let data = error.downcast_ref::<RpcError>()?.error.get("data")?;
    let field = |name: &str| data.get(name).and_then(|value| quantity_u128(value).ok());
    field("tx_fee_cap_wei")
        .or_else(|| {
            Some(
                field("max_fee_per_gas_allowed")?
                    .saturating_mul(field("gas_limit").unwrap_or(u128::from(gas))),
            )
        })
        .filter(|cap| *cap > 0)
}

/// Gas limit x maxFeePerGas of a refused send: the refusal's `gas_limit` and
/// `max_fee_per_gas` (the bundled signer reports both with
/// `upstream_tx_fee_cap`), else the send's own. A reported fee that leaves
/// no bound (zero) cannot be what the node refused; like a zero signer cap,
/// it is ignored for the send's own.
fn refused_tx_fee(error: &anyhow::Error, gas: u64, max_fee: u128) -> u128 {
    let data = error
        .downcast_ref::<RpcError>()
        .and_then(|rpc| rpc.error.get("data"));
    let field = |name: &str| {
        data.and_then(|data| data.get(name))
            .and_then(|value| quantity_u128(value).ok())
    };
    let reported = field("gas_limit")
        .unwrap_or(u128::from(gas))
        .saturating_mul(field("max_fee_per_gas").unwrap_or(max_fee));
    if headroom(reported) > 0 {
        reported
    } else {
        u128::from(gas).saturating_mul(max_fee)
    }
}

/// The smallest value nodes accept as a 10% replacement bump.
fn min_bump(value: u128) -> u128 {
    value.saturating_mul(110).div_ceil(100)
}

/// The largest value that still leaves one valid bump below `cap`.
fn headroom(cap: u128) -> u128 {
    cap.saturating_mul(10) / 11
}

/// Geth, reth, erigon and besu replace a pending transaction only when both
/// fees rise by at least 10%.
fn is_valid_bump(old: Fees, new: Fees) -> bool {
    new.max_fee >= min_bump(old.max_fee) && new.tip >= min_bump(old.tip) && new.tip <= new.max_fee
}

/// Fees of a pending transaction object; a legacy one bids its gas price as
/// both fees.
fn transaction_fees(transaction: &Value) -> Option<Fees> {
    let field = |name: &str| {
        transaction
            .get(name)
            .filter(|value| !value.is_null())
            .and_then(|value| quantity_u128(value).ok())
    };
    match (field("maxFeePerGas"), field("maxPriorityFeePerGas")) {
        (Some(max_fee), Some(tip)) => Some(Fees { max_fee, tip }),
        _ => field("gasPrice").map(|price| Fees {
            max_fee: price,
            tip: price,
        }),
    }
}

fn push_superseded(attempt: &mut NonceAttempts, hash: String) {
    if !attempt.superseded_hashes.contains(&hash) {
        attempt.superseded_hashes.push(hash);
    }
    let excess = attempt
        .superseded_hashes
        .len()
        .saturating_sub(MAX_SUPERSEDED_HASHES);
    attempt.superseded_hashes.drain(..excess);
}

fn classify_send_error(error: &anyhow::Error) -> SendFailure {
    if error
        .downcast_ref::<TransportError>()
        .is_some_and(|transport| transport.unsent)
    {
        return SendFailure::NotBroadcast(BlockedReason::RpcError);
    }
    // Timeouts, HTTP errors and broken responses may follow a broadcast.
    let Some(rpc) = error.downcast_ref::<RpcError>() else {
        return SendFailure::Ambiguous(None);
    };
    match (rpc.code(), rpc.reason()) {
        (Some(-32602 | -32601 | -32003), reason) => SendFailure::Refused(reason.map(str::to_owned)),
        (Some(-32000), Some("simulation_failed")) => {
            SendFailure::NotBroadcast(BlockedReason::SimulationReverted)
        }
        (
            Some(-32000),
            Some(
                "upstream_unavailable"
                | "upstream_rejected"
                | "upstream_chain_mismatch"
                | "base_fee_unavailable",
            ),
        ) => SendFailure::NotBroadcast(BlockedReason::RpcError),
        _ => SendFailure::Ambiguous(rpc.transaction_hash()),
    }
}

/// The vault custom error a defeat, raise or retirement simulation reverted
/// with, when the RPC passes the revert data through.
fn vault_revert(error: &anyhow::Error) -> Option<&'static str> {
    let rpc = error.downcast_ref::<RpcError>()?;
    let candidates = [
        rpc.error.get("data").and_then(Value::as_str),
        rpc.error
            .get("data")
            .and_then(|data| data.get("data"))
            .and_then(Value::as_str),
        rpc.error.get("message").and_then(Value::as_str),
    ];
    [
        "StaleRoot()",
        "ChallengeExpired()",
        "NotPendingWithdrawal()",
        "ReplayedNullifier()",
        "NotARaise()",
        "NotSuccessorEvidence()",
        "NotStateEvidence()",
        "InvalidProof()",
        "NoteNotClosed()",
    ]
    .into_iter()
    .find(|signature| {
        let selector = hex::encode(selector(signature));
        candidates
            .iter()
            .flatten()
            .any(|text| text.to_ascii_lowercase().contains(&selector))
    })
}

fn rpc_code(error: &anyhow::Error) -> Option<i64> {
    error.downcast_ref::<RpcError>()?.code()
}

fn bounded(text: &str) -> String {
    text.chars().take(MAX_ERROR_CHARS).collect()
}

#[derive(Deserialize)]
struct PathResponse {
    note_id: u32,
    leaf: Felt252,
    siblings: Vec<Felt252>,
    #[serde(default)]
    root: Option<Felt252>,
    #[serde(default)]
    block_number: Option<u64>,
    #[serde(default)]
    block_hash: Option<String>,
}

#[derive(Deserialize)]
struct TreeRootResponse {
    root: Felt252,
    #[serde(default)]
    block_number: Option<u64>,
    #[serde(default)]
    block_hash: Option<String>,
}

#[derive(Deserialize)]
struct IndexerHealth {
    #[serde(default)]
    status: Option<String>,
}

#[derive(Deserialize)]
struct PendingEscapesResponse {
    /// The block of the indexer's view the list was taken from.
    #[serde(default)]
    block_number: Option<u64>,
    escapes: Vec<PendingEscape>,
}

/// Only the note ID is authoritative; the vault supplies the rest.
#[derive(Deserialize)]
struct PendingEscape {
    note_id: u32,
    withdrawal_nullifier: Felt252,
    #[serde(default)]
    challenge_deadline: Option<u64>,
}

/// An escape event of the scan, strictly decoded.
#[derive(Debug, PartialEq, Eq)]
enum ScanEvent {
    Initiated {
        note: u32,
        nullifier: Felt252,
        deadline: u64,
    },
    Recorded {
        note: u32,
        next_nullifier: Felt252,
        state_balance: u128,
        conceded: u128,
    },
    Raised {
        note: u32,
        nullifier: Felt252,
        conceded: u128,
    },
    Challenged {
        note: u32,
        nullifier: Felt252,
    },
}

/// Decode an `EscapeWithdrawalInitiated` (5 words), `EscapeConcessionRecorded`
/// (3), `EscapeConcessionRaised` (3) or `EscapeWithdrawalChallenged` (2) log,
/// with exactly two topics and canonical uint widths; anything else is an
/// error that fails the scan of the range.
fn decode_scan_event(log: &Value) -> anyhow::Result<ScanEvent> {
    let topics = log["topics"]
        .as_array()
        .context("escape event lacks topics")?;
    ensure!(topics.len() == 2, "malformed escape event topics");
    let topic0 = topics[0].as_str().context("malformed escape event topic")?;
    let note = quantity(&topics[1])?;
    ensure!(note <= u32::MAX as u64, "escape note ID exceeds uint32");
    let note = note as u32;
    let words = words(&log["data"])?;
    let is = |signature: &str| {
        topic0.eq_ignore_ascii_case(&format!(
            "0x{}",
            hex::encode(Keccak256::digest(signature.as_bytes()))
        ))
    };
    let count = |expected: usize, name: &str| {
        ensure!(words.len() == expected, "malformed {name} event data");
        Ok(())
    };
    if is(ESCAPE_EVENT) {
        count(5, "EscapeWithdrawalInitiated")?;
        felt_u128(&words[1])?;
        ensure!(
            words[2].as_bytes()[..12].iter().all(|byte| *byte == 0),
            "malformed escape destination"
        );
        return Ok(ScanEvent::Initiated {
            note,
            nullifier: words[0],
            deadline: felt_u64(&words[3])?,
        });
    }
    if is(CONCESSION_RECORDED_EVENT) {
        count(3, "EscapeConcessionRecorded")?;
        return Ok(ScanEvent::Recorded {
            note,
            next_nullifier: words[0],
            state_balance: felt_u128(&words[1])?,
            conceded: felt_u128(&words[2])?,
        });
    }
    if is(CONCESSION_RAISED_EVENT) {
        count(3, "EscapeConcessionRaised")?;
        felt_u128(&words[2])?;
        return Ok(ScanEvent::Raised {
            note,
            nullifier: words[0],
            conceded: felt_u128(&words[1])?,
        });
    }
    if is(CHALLENGED_EVENT) {
        count(2, "EscapeWithdrawalChallenged")?;
        return Ok(ScanEvent::Challenged {
            note,
            nullifier: words[0],
        });
    }
    bail!("unexpected event topic {topic0} in the escape scan")
}

fn selector(signature: &str) -> Vec<u8> {
    Keccak256::digest(signature.as_bytes())[..4].to_vec()
}
fn quantity(value: &Value) -> anyhow::Result<u64> {
    let value = quantity_u128(value)?;
    u64::try_from(value).context("quantity exceeds uint64")
}
fn quantity_u128(value: &Value) -> anyhow::Result<u128> {
    let value = value
        .as_str()
        .context("expected hex quantity")?
        .strip_prefix("0x")
        .context("hex quantity lacks prefix")?;
    parse_digits_u128(value).context("quantity exceeds uint128")
}
fn parse_hex_u128(value: &str) -> Option<u128> {
    parse_digits_u128(value.strip_prefix("0x")?)
}
fn parse_digits_u128(digits: &str) -> Option<u128> {
    if digits.chars().all(|c| c == '0') {
        return Some(0);
    }
    u128::from_str_radix(digits.trim_start_matches('0'), 16).ok()
}
fn felt_u128(value: &Felt252) -> anyhow::Result<u128> {
    value.to_u128().context("value exceeds uint128")
}
fn felt_u64(value: &Felt252) -> anyhow::Result<u64> {
    ensure!(
        value.as_bytes()[..24].iter().all(|byte| *byte == 0),
        "value exceeds uint64"
    );
    Ok(u64::from_be_bytes(
        value.as_bytes()[24..].try_into().unwrap(),
    ))
}
fn words(value: &Value) -> anyhow::Result<Vec<Felt252>> {
    let raw = value
        .as_str()
        .context("expected ABI bytes")?
        .strip_prefix("0x")
        .context("ABI bytes lack prefix")?;
    let bytes = hex::decode(raw)?;
    ensure!(bytes.len().is_multiple_of(32), "malformed ABI words");
    Ok(bytes
        .as_chunks::<32>()
        .0
        .iter()
        .map(|chunk| Felt252(*chunk))
        .collect())
}

#[cfg(test)]
mod tests {
    /// A checkpoint whose pending obligation or detached nonce records a
    /// raise loads again: the amount sits in the flattened attempt record
    /// (found by the Anvil acceptance, whose challenger restarted with a
    /// detached raise nonce and refused its checkpoint).
    #[test]
    fn a_checkpoint_with_a_raise_attempt_loads_again() {
        use super::{CallKind, DetachedNonce, Felt252, NonceAttempts, PendingChallenge};
        for amount in [
            400u128,
            u128::from(u64::MAX),
            u128::from(u64::MAX) + 1,
            u128::MAX,
        ] {
            let attempt = NonceAttempts {
                action: Some(CallKind::Raise),
                raise_amount: Some(amount),
                attempts: 1,
                ..Default::default()
            };
            let detached = DetachedNonce {
                note_id: 19,
                nullifier: Felt252::from_u64(7),
                transaction_hash: Some(format!("0x{}", "8e".repeat(32))),
                attempt: attempt.clone(),
            };
            let back: DetachedNonce =
                serde_json::from_str(&serde_json::to_string(&detached).unwrap()).unwrap();
            assert_eq!(back.attempt, attempt, "{amount}");
            let pending = PendingChallenge {
                nullifier: Felt252::from_u64(7),
                state_balance: Some(1_000_000),
                attempt: attempt.clone(),
                ..Default::default()
            };
            let back: PendingChallenge =
                serde_json::from_str(&serde_json::to_string(&pending).unwrap()).unwrap();
            assert_eq!(back.attempt, attempt, "{amount}");
        }
        // A record an earlier build wrote (a numeric amount, or none) loads.
        let earlier = format!(
            r#"{{"note_id":19,"nullifier":"0x{}","transaction_hash":null,"attempts":1,"action":"raise","raise_amount":400}}"#,
            "0".repeat(63) + "7"
        );
        let back: DetachedNonce = serde_json::from_str(&earlier).unwrap();
        assert_eq!(back.attempt.raise_amount, Some(400));
        let without = earlier.replace(r#","raise_amount":400"#, "");
        let back: DetachedNonce = serde_json::from_str(&without).unwrap();
        assert_eq!(back.attempt.raise_amount, None);
        let null = earlier.replace(r#""raise_amount":400"#, r#""raise_amount":null"#);
        let back: DetachedNonce = serde_json::from_str(&null).unwrap();
        assert_eq!(back.attempt.raise_amount, None);
    }

    use super::*;
    use crate::watcher::tests::{
        finalized_transcript, finalized_v2_request, two_finalized_v2_requests,
    };
    use crate::watcher::{DEFEAT_SELECTOR, RAISE_SELECTOR, RETIRE_SELECTOR};
    use axum::{
        extract::{Path, State},
        http::StatusCode,
        response::{IntoResponse, Response},
        routing::{get, post},
        Json, Router,
    };
    use std::{collections::VecDeque, sync::Mutex};
    use zkapi_types::wire::{ApiRequestV2, CurvePointWire};

    const ONE_ETHER: u128 = 1_000_000_000_000_000_000;
    /// The default escape's nullifier `N`: no request was made at it.
    const ESCAPED: Felt252 = Felt252([0x0e; 32]);
    /// The nullifier of a re-escape of note 0 from another state.
    const RE_ESCAPED: Felt252 = Felt252([0x0c; 32]);

    struct MockChain {
        /// `N`, the escaped nullifier of the default escape.
        nullifier: Felt252,
        /// `N⁺` of the default escape: by default the fixture request's
        /// nullifier, whose evidence defeats the escape.
        next_nullifier: Felt252,
        /// `c` of the default escape; `B` is its final balance 100 plus `c`.
        conceded: u128,
        /// Concessions `(N⁺, c)` of escapes in `withdrawals`; by default the
        /// default escape's.
        concessions: BTreeMap<u32, (Felt252, u128)>,
        /// Receipts by transaction hash (null for any other hash).
        receipts: BTreeMap<String, Value>,
        /// Simulation error of raises only.
        raise_simulation_error: Option<Value>,
        /// The indexer's path of a note's slot: (leaf, siblings).
        leaf_paths: BTreeMap<u32, (Felt252, [Felt252; MERKLE_DEPTH])>,
        /// Words of no-argument getters (the startup probes), by calldata.
        probe_words: BTreeMap<String, Felt252>,
        /// Runtime code by lowercase address.
        code: BTreeMap<String, String>,
        /// ("withdrawal" | "concession", block parameter) of escape reads.
        escape_reads: Vec<(&'static str, Value)>,
        /// pendingConcessions of the default escape answers these words.
        concession_words: Option<Vec<Felt252>>,
        /// The scan's concession record lacks its last word.
        malformed_concession_event: bool,
        active: bool,
        confirmed_active: bool,
        mined_nonce: u64,
        pending_nonce: Option<u64>,
        confirmed_nonce: Option<u64>,
        transaction_known: bool,
        withdrawals: BTreeMap<u32, (bool, Felt252, u64)>,
        event_note: u32,
        fail_note_one: bool,
        reorg_during_scan: bool,
        block_hash: String,
        sends: Vec<Value>,
        fail_first_send: bool,
        root: Felt252,
        siblings: [Felt252; MERKLE_DEPTH],
        head_number: u64,
        head_timestamp: u64,
        /// Deadline of note 0 (and of notes without an explicit withdrawal).
        deadline: u64,
        base_fee: Option<u128>,
        state_key: (Felt252, Felt252),
        balance: Option<u128>,
        fail_all: bool,
        send_errors: VecDeque<Value>,
        refuse_notes: BTreeSet<u32>,
        drop_logs: bool,
        /// None: an indexer that predates /v1/escapes/pending.
        escapes: Option<Vec<Value>>,
        /// The block the pending-escapes list is served at; None: the head.
        escapes_block: Option<u64>,
        indexer_root: Option<Value>,
        indexer_health: &'static str,
        roots_by_hash: BTreeMap<String, Felt252>,
        path_unavailable: u32,
        path_meta: Option<Value>,
        simulation_error: Option<Value>,
        legacy_gas_price: Option<u128>,
        /// eth_estimateGas answer; the default 10M gas gives a 12M gas limit.
        estimate: u64,
        /// Sends whose gas x maxFeePerGas exceeds the cap are refused with
        /// the reason: `tx_fee_above_cap` (the bundled signer),
        /// `upstream_tx_fee_cap` (its node), or `broadcast_ambiguous` (an
        /// earlier signer relaying its node's rejection, with a hash no node
        /// knows).
        tx_fee_cap: Option<(u128, &'static str)>,
        fee_capped_sends: usize,
        fee_capped_hashes: BTreeSet<String>,
        /// The zkapi_signerStatus result; None: an RPC without the method.
        signer_status: Option<Value>,
        /// pendingWithdrawals reads per note.
        withdrawal_reads: BTreeMap<u32, usize>,
        /// notes(noteId).status; by default PendingWithdrawal while the
        /// escape is active at the latest block, else Active.
        note_status: BTreeMap<u32, u64>,
        /// challengedNullifiers of a hardened vault.
        challenged: std::collections::HashSet<Felt252>,
        /// A vault without challengedNullifiers (calls are rejected).
        legacy_vault: bool,
        /// EscapeWithdrawalChallenged / Finalized logs: (block, note,
        /// nullifier, finalized).
        end_logs: Vec<(u64, u32, Felt252, bool)>,
        /// Numbered blocks the RPC answers with null.
        null_blocks: BTreeSet<u64>,
        /// Numbered block reads answered with another fork's hash.
        forked_block_reads: u32,
        /// A load-balanced RPC's backend behind the head answers latest-block
        /// pendingWithdrawals reads of the default escape with this activity.
        latest_active: Option<bool>,
        /// pendingWithdrawals reads of the default escape at the head block
        /// fail: the backend serving them lacks it.
        head_block_unknown: bool,
    }

    impl MockChain {
        fn new(nullifier: Felt252, next_nullifier: Felt252, state_key: (Felt252, Felt252)) -> Self {
            let siblings = zkapi_core::v2::zero_hashes()[..MERKLE_DEPTH]
                .try_into()
                .unwrap();
            let now = unix_now();
            Self {
                nullifier,
                next_nullifier,
                conceded: 0,
                concessions: BTreeMap::new(),
                receipts: BTreeMap::new(),
                raise_simulation_error: None,
                leaf_paths: BTreeMap::new(),
                probe_words: BTreeMap::new(),
                code: BTreeMap::new(),
                escape_reads: Vec::new(),
                concession_words: None,
                malformed_concession_event: false,
                active: true,
                confirmed_active: true,
                mined_nonce: 3,
                pending_nonce: None,
                confirmed_nonce: None,
                transaction_known: true,
                withdrawals: BTreeMap::new(),
                event_note: 0,
                fail_note_one: false,
                reorg_during_scan: false,
                block_hash: "0xforkA".into(),
                sends: vec![],
                fail_first_send: false,
                root: zkapi_core::v2::merkle_root(0, &Felt252::ZERO, &siblings),
                siblings,
                head_number: 5,
                head_timestamp: now,
                deadline: now + 100,
                base_fee: Some(GWEI),
                state_key,
                balance: Some(1_000 * GWEI * GWEI),
                fail_all: false,
                send_errors: VecDeque::new(),
                refuse_notes: BTreeSet::new(),
                drop_logs: false,
                escapes: Some(vec![]),
                escapes_block: None,
                indexer_root: None,
                indexer_health: "ok",
                roots_by_hash: BTreeMap::new(),
                path_unavailable: 0,
                path_meta: None,
                simulation_error: None,
                legacy_gas_price: None,
                estimate: 10_000_000,
                tx_fee_cap: None,
                fee_capped_sends: 0,
                fee_capped_hashes: BTreeSet::new(),
                signer_status: None,
                withdrawal_reads: BTreeMap::new(),
                note_status: BTreeMap::new(),
                challenged: Default::default(),
                legacy_vault: false,
                end_logs: Vec::new(),
                null_blocks: BTreeSet::new(),
                forked_block_reads: 0,
                latest_active: None,
                head_block_unknown: false,
            }
        }

        /// The escaper finalized note 0's escape at `block`: gone at every
        /// depth, the note closed, its Finalized log emitted.
        fn pay_out(&mut self, block: u64) {
            self.active = false;
            self.confirmed_active = false;
            self.note_status.insert(0, NOTE_CLOSED);
            self.end_logs.push((block, 0, self.nullifier, true));
        }
    }

    const NOTE_ACTIVE: u64 = 1;
    const NOTE_CLOSED: u64 = 3;

    fn encoded(values: &[Felt252]) -> Value {
        json!(format!(
            "0x{}",
            hex::encode(
                values
                    .iter()
                    .flat_map(|v| v.as_bytes().iter().copied())
                    .collect::<Vec<_>>()
            )
        ))
    }

    fn hex_quantity(value: u128) -> Value {
        json!(format!("0x{value:x}"))
    }

    fn rpc_error(code: i64, message: &str) -> Response {
        Json(json!({ "jsonrpc": "2.0", "id": 1, "error": { "code": code, "message": message } }))
            .into_response()
    }

    fn call_data(signature: &str) -> String {
        format!("0x{}", hex::encode(selector(signature)))
    }

    async fn rpc(
        State(state): State<Arc<Mutex<MockChain>>>,
        Json(request): Json<Value>,
    ) -> Response {
        let mut state = state.lock().unwrap();
        if state.fail_all {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
        let method = request["method"].as_str().unwrap();
        let result = match method {
            "eth_chainId" => json!("0x1"),
            "eth_blockNumber" => hex_quantity(state.head_number as u128),
            "eth_getBlockByNumber" => {
                let tag = request["params"][0].as_str().unwrap();
                if tag != "latest" {
                    let number = quantity(&request["params"][0]).unwrap();
                    if state.null_blocks.contains(&number) {
                        return Json(json!({ "jsonrpc": "2.0", "id": 1, "result": null }))
                            .into_response();
                    }
                    if state.forked_block_reads > 0 {
                        state.forked_block_reads -= 1;
                        return Json(json!({ "jsonrpc": "2.0", "id": 1, "result": {
                            "hash": "0xstale", "number": hex_quantity(number as u128),
                            "timestamp": hex_quantity(state.head_timestamp as u128) } }))
                        .into_response();
                    }
                }
                let mut block = json!({
                    "hash": state.block_hash,
                    "number": hex_quantity(state.head_number as u128),
                    "timestamp": hex_quantity(state.head_timestamp as u128),
                });
                if let Some(fee) = state.base_fee {
                    block["baseFeePerGas"] = hex_quantity(fee);
                }
                block
            }
            "eth_getLogs" => {
                let filter = &request["params"][0];
                let from = quantity(&filter["fromBlock"]).unwrap();
                if filter["topics"].as_array().unwrap().len() == 2 {
                    let to = quantity(&filter["toBlock"]).unwrap();
                    let note = filter["topics"][1]
                        .as_str()
                        .map(|topic| quantity(&json!(topic)).unwrap());
                    let topic = |signature: &str| {
                        format!("0x{}", hex::encode(Keccak256::digest(signature.as_bytes())))
                    };
                    let logs: Vec<Value> = state
                        .end_logs
                        .iter()
                        .filter(|(block, log_note, ..)| {
                            (from..=to).contains(block) && note.is_none_or(|note| note == u64::from(*log_note))
                        })
                        .map(|(block, log_note, nullifier, finalized)| {
                            let (signature, data) = if *finalized {
                                ("EscapeWithdrawalFinalized(uint32,uint256,uint128,address)", encoded(&[*nullifier, Felt252::from_u64(100), Felt252::from_u64(5)]))
                            } else {
                                ("EscapeWithdrawalChallenged(uint32,uint256,uint256)", encoded(&[*nullifier, state.root]))
                            };
                            json!({ "topics": [topic(signature), format!("0x{log_note:064x}")], "data": data, "blockNumber": hex_quantity(*block as u128) })
                        })
                        .collect();
                    return Json(json!({ "jsonrpc": "2.0", "id": 1, "result": logs }))
                        .into_response();
                }
                if state.reorg_during_scan {
                    state.block_hash = "0xforkB".into();
                    state.reorg_during_scan = false;
                }
                if state.drop_logs {
                    json!([])
                } else {
                    let topic = |signature: &str| {
                        format!("0x{}", hex::encode(Keccak256::digest(signature.as_bytes())))
                    };
                    // The initiation and its concession record, in one
                    // transaction; served in reverse to check the ordering.
                    let mut recorded = vec![
                        state.next_nullifier,
                        Felt252::from_u128(100 + state.conceded),
                        Felt252::from_u128(state.conceded),
                    ];
                    if state.malformed_concession_event {
                        recorded.pop();
                    }
                    json!([{
                        "topics": [topic(CONCESSION_RECORDED_EVENT), format!("0x{:064x}", state.event_note)],
                        "data": encoded(&recorded),
                        "blockNumber": hex_quantity(from as u128), "logIndex": "0x1"
                    }, {
                        "topics": [topic(ESCAPE_EVENT), format!("0x{:064x}", state.event_note)],
                        "data": encoded(&[state.nullifier, Felt252::from_u64(100), Felt252::from_u64(5), Felt252::from_u64(state.deadline), state.root]),
                        "blockNumber": hex_quantity(from as u128), "logIndex": "0x0"
                    }])
                }
            }
            "eth_call" => {
                let data = request["params"][0]["data"].as_str().unwrap();
                let block = &request["params"][1];
                if state.fail_note_one
                    && data
                        == format!(
                            "{}{}",
                            call_data("pendingWithdrawals(uint32)"),
                            hex::encode(Felt252::ONE.as_bytes())
                        )
                {
                    return rpc_error(-32000, "temporary note-state failure");
                }
                let concession_read = data.starts_with(&call_data("pendingConcessions(uint32)"));
                if let Some(word) = state.probe_words.get(data) {
                    encoded(&[*word])
                } else if data.starts_with(&call_data("pendingWithdrawals(uint32)"))
                    || concession_read
                {
                    let note = u32::from_str_radix(&data[data.len() - 8..], 16).unwrap();
                    let kind = if concession_read {
                        "concession"
                    } else {
                        "withdrawal"
                    };
                    state.escape_reads.push((kind, block.clone()));
                    if let Some(words) = state
                        .concession_words
                        .clone()
                        .filter(|_| concession_read && note == 0)
                    {
                        return Json(
                            json!({ "jsonrpc": "2.0", "id": 1, "result": encoded(&words) }),
                        )
                        .into_response();
                    }
                    if !concession_read {
                        *state.withdrawal_reads.entry(note).or_default() += 1;
                    }
                    let concession = |active: bool| {
                        let (next, conceded) = state
                            .concessions
                            .get(&note)
                            .copied()
                            .unwrap_or((state.next_nullifier, state.conceded));
                        if active {
                            encoded(&[
                                next,
                                Felt252::from_u128(100 + conceded),
                                Felt252::from_u128(conceded),
                            ])
                        } else {
                            encoded(&[Felt252::ZERO; 3])
                        }
                    };
                    if let Some((active, nullifier, deadline)) = state.withdrawals.get(&note) {
                        if concession_read {
                            concession(*active)
                        } else {
                            encoded(&[
                                Felt252::from_u64(*active as u64),
                                Felt252::from_u64(8),
                                *nullifier,
                                Felt252::from_u64(100),
                                Felt252::from_u64(5),
                                Felt252::from_u64(*deadline),
                            ])
                        }
                    } else {
                        // A read at the head block sees the latest state.
                        let latest = *block == "latest";
                        let at_head = latest
                            || block
                                .as_str()
                                .and_then(|block| u64::from_str_radix(&block[2..], 16).ok())
                                .is_some_and(|block| block >= state.head_number);
                        if at_head && !latest && state.head_block_unknown {
                            return rpc_error(-32000, "header not found");
                        }
                        let active = if latest {
                            state.latest_active.unwrap_or(state.active)
                        } else if at_head {
                            state.active
                        } else {
                            state.confirmed_active
                        };
                        if concession_read {
                            return Json(
                                json!({ "jsonrpc": "2.0", "id": 1, "result": concession(active) }),
                            )
                            .into_response();
                        }
                        encoded(&[
                            Felt252::from_u64(active as u64),
                            Felt252::from_u64(8),
                            state.nullifier,
                            Felt252::from_u64(100),
                            Felt252::from_u64(5),
                            Felt252::from_u64(state.deadline),
                        ])
                    }
                } else if data.starts_with(&call_data("notes(uint32)")) {
                    let note = u32::from_str_radix(&data[data.len() - 8..], 16).unwrap();
                    let pending = if *block == "latest" {
                        state.active
                    } else {
                        state.confirmed_active
                    };
                    let status = state.note_status.get(&note).copied().unwrap_or(if pending {
                        2
                    } else {
                        NOTE_ACTIVE
                    });
                    encoded(&[
                        Felt252::from_u64(0xc0),
                        Felt252::from_u64(100),
                        Felt252::from_u64(state.deadline + 86_400),
                        Felt252::from_u64(status),
                    ])
                } else if data.starts_with(&call_data("challengedNullifiers(uint256)")) {
                    if state.legacy_vault {
                        // The bundled signer relays any upstream error so.
                        return Json(json!({ "jsonrpc": "2.0", "id": 1, "error": {
                            "code": -32000, "message": "Upstream RPC rejected the request",
                            "data": { "reason": "upstream_rejected" } } }))
                        .into_response();
                    }
                    let nullifier = Felt252(hex::decode(&data[10..]).unwrap().try_into().unwrap());
                    encoded(&[Felt252::from_u64(
                        state.challenged.contains(&nullifier) as u64
                    )])
                } else if data == call_data("currentRoot()") {
                    match block.get("blockHash").and_then(Value::as_str) {
                        Some(hash) => match state.roots_by_hash.get(hash) {
                            Some(root) => encoded(&[*root]),
                            None => return rpc_error(-32000, "header for hash not found"),
                        },
                        None => encoded(&[state.root]),
                    }
                } else if data == call_data("challengePeriod()") {
                    encoded(&[Felt252::from_u64(86_400)])
                } else if data == call_data("stateSigningKeyX()") {
                    encoded(&[state.state_key.0])
                } else if data == call_data("stateSigningKeyY()") {
                    encoded(&[state.state_key.1])
                } else if [DEFEAT_SELECTOR, RAISE_SELECTOR, RETIRE_SELECTOR]
                    .iter()
                    .any(|selector| data.starts_with(&format!("0x{}", hex::encode(selector))))
                {
                    let raise = data.starts_with(&format!("0x{}", hex::encode(RAISE_SELECTOR)));
                    if let Some(error) = state
                        .raise_simulation_error
                        .as_ref()
                        .filter(|_| raise)
                        .or(state.simulation_error.as_ref())
                    {
                        return Json(json!({ "jsonrpc": "2.0", "id": 1, "error": error }))
                            .into_response();
                    }
                    json!("0x")
                } else {
                    json!("0x")
                }
            }
            "eth_estimateGas" => hex_quantity(state.estimate as u128),
            "eth_getCode" => json!(state
                .code
                .get(&request["params"][0].as_str().unwrap().to_ascii_lowercase())
                .cloned()
                .unwrap_or_else(|| "0x".into())),
            "eth_getTransactionCount" => hex_quantity(if request["params"][1] == "pending" {
                state.pending_nonce.unwrap_or(state.mined_nonce)
            } else if request["params"][1] == "latest" {
                state.mined_nonce
            } else {
                state.confirmed_nonce.unwrap_or(state.mined_nonce)
            } as u128),
            "eth_getBalance" => match state.balance {
                Some(balance) => hex_quantity(balance),
                None => return rpc_error(-32601, "RPC method is not allowed"),
            },
            "eth_sendTransaction" => {
                let transaction = request["params"][0].clone();
                state.sends.push(transaction.clone());
                if let Some(error) = state.send_errors.pop_front() {
                    return Json(json!({ "jsonrpc": "2.0", "id": 1, "error": error }))
                        .into_response();
                }
                if state.fail_first_send {
                    state.fail_first_send = false;
                    return rpc_error(-32000, "temporary signer failure");
                }
                let note = u32::from_str_radix(&transaction["data"].as_str().unwrap()[10..74], 16)
                    .unwrap();
                if state.refuse_notes.contains(&note) {
                    return Json(json!({ "jsonrpc": "2.0", "id": 1, "error": {
                        "code": -32602, "message": "Requested fees are outside the configured bounds",
                        "data": { "reason": "fee_out_of_bounds" } } }))
                    .into_response();
                }
                if let Some((cap, reason)) = state.tx_fee_cap {
                    let gas = quantity_u128(&transaction["gas"]).unwrap();
                    let max_fee = quantity_u128(&transaction["maxFeePerGas"]).unwrap();
                    if gas * max_fee > cap {
                        state.fee_capped_sends += 1;
                        let (code, data) = match reason {
                            "tx_fee_above_cap" => (
                                -32003,
                                json!({ "reason": reason, "gas_limit": hex_quantity(gas),
                                    "max_fee_per_gas": hex_quantity(max_fee),
                                    "tx_fee_cap_wei": hex_quantity(cap),
                                    "max_fee_per_gas_allowed": hex_quantity(cap / gas) }),
                            ),
                            "upstream_tx_fee_cap" => (
                                -32003,
                                json!({ "reason": reason, "gas_limit": hex_quantity(gas),
                                    "max_fee_per_gas": hex_quantity(max_fee) }),
                            ),
                            _ => {
                                let hash = format!(
                                    "0x{:064x}",
                                    0xdead_0000_0000u64 + state.sends.len() as u64
                                );
                                state.fee_capped_hashes.insert(hash.clone());
                                (
                                    -32000,
                                    json!({ "reason": reason, "transaction_hash": hash }),
                                )
                            }
                        };
                        return Json(json!({ "jsonrpc": "2.0", "id": 1, "error": {
                            "code": code, "message": "Transaction fee exceeds the cap", "data": data } }))
                        .into_response();
                    }
                }
                let nonce = quantity(&transaction["nonce"]).unwrap();
                state.pending_nonce = Some(
                    state
                        .pending_nonce
                        .unwrap_or(state.mined_nonce)
                        .max(nonce + 1),
                );
                json!(format!("0x{:064x}", state.sends.len()))
            }
            "eth_getTransactionByHash" => {
                if !state.transaction_known
                    || state
                        .fee_capped_hashes
                        .contains(request["params"][0].as_str().unwrap())
                {
                    Value::Null
                } else {
                    let hash = request["params"][0].as_str().unwrap();
                    let mut transaction = json!({ "hash": hash, "blockNumber": Value::Null });
                    let sent = parse_hex_u128(hash)
                        .and_then(|index| state.sends.get((index as usize).checked_sub(1)?));
                    if let Some(sent) = sent {
                        transaction["maxFeePerGas"] = sent["maxFeePerGas"].clone();
                        transaction["maxPriorityFeePerGas"] = sent["maxPriorityFeePerGas"].clone();
                    } else if let Some(price) = state.legacy_gas_price {
                        transaction["type"] = json!("0x0");
                        transaction["gasPrice"] = hex_quantity(price);
                    }
                    transaction
                }
            }
            "eth_getTransactionReceipt" => state
                .receipts
                .get(request["params"][0].as_str().unwrap())
                .cloned()
                .unwrap_or(Value::Null),
            "zkapi_signerStatus" => match &state.signer_status {
                Some(status) => status.clone(),
                None => return rpc_error(-32601, "RPC method is not allowed"),
            },
            _ => panic!("unexpected RPC method {method}"),
        };
        Json(json!({ "jsonrpc": "2.0", "id": 1, "result": result })).into_response()
    }

    fn unavailable() -> Response {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"status": "unavailable", "error_code": "indexer_unavailable",
                "error_message": "indexer is not ready", "retriable": true, "retry_after_seconds": 5})),
        )
            .into_response()
    }

    async fn path(State(state): State<Arc<Mutex<MockChain>>>, Path(note): Path<u32>) -> Response {
        let mut state = state.lock().unwrap();
        if state.path_unavailable > 0 {
            state.path_unavailable -= 1;
            return unavailable();
        }
        let mut body =
            json!({"note_id": note, "leaf": Felt252::ZERO, "siblings": state.siblings.to_vec()});
        if let Some(meta) = state.path_meta.as_ref().and_then(Value::as_object) {
            for (key, value) in meta {
                body[key] = value.clone();
            }
        }
        Json(body).into_response()
    }

    /// `/v1/tree/notes/{note}/path`: a configured leaf path of the note.
    async fn leaf_path(
        State(state): State<Arc<Mutex<MockChain>>>,
        Path(note): Path<u32>,
    ) -> Response {
        let mut state = state.lock().unwrap();
        if state.path_unavailable > 0 {
            state.path_unavailable -= 1;
            return unavailable();
        }
        match state.leaf_paths.get(&note) {
            Some((leaf, siblings)) => Json(json!({
                "note_id": note, "leaf": leaf, "siblings": siblings.to_vec(),
                "root": zkapi_core::v2::merkle_root(note, leaf, siblings),
            }))
            .into_response(),
            None => unavailable(),
        }
    }

    async fn tree_root(State(state): State<Arc<Mutex<MockChain>>>) -> Response {
        let state = state.lock().unwrap();
        if state.indexer_health != "ok" {
            return unavailable();
        }
        Json(
            state
                .indexer_root
                .clone()
                .unwrap_or(json!({ "root": state.root })),
        )
        .into_response()
    }

    async fn indexer_health(State(state): State<Arc<Mutex<MockChain>>>) -> Response {
        let state = state.lock().unwrap();
        let code = if state.indexer_health == "ok" {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        };
        (code, Json(json!({ "status": state.indexer_health }))).into_response()
    }

    async fn pending_escapes(State(state): State<Arc<Mutex<MockChain>>>) -> Response {
        let state = state.lock().unwrap();
        match &state.escapes {
            None => StatusCode::NOT_FOUND.into_response(),
            Some(escapes) => Json(json!({
                "block_number": state.escapes_block.unwrap_or(state.head_number),
                "block_hash": state.block_hash, "root": state.root, "escapes": escapes,
            }))
            .into_response(),
        }
    }

    struct Fixture {
        store: Arc<NullifierStore>,
        config: ChallengeServiceConfig,
        chain: Arc<Mutex<MockChain>>,
        server: tokio::task::JoinHandle<()>,
        _directory: tempfile::TempDir,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            self.server.abort();
        }
    }

    impl Fixture {
        /// The default escape, defeated by the fixture request's evidence,
        /// written long before any deadline a test sets.
        async fn new() -> Self {
            let (_, request) = finalized_v2_request().await;
            let store = Arc::new(NullifierStore::in_memory().unwrap());
            crate::watcher::tests::append_raw_evidence(
                &store,
                &request.public_inputs.request_nullifier,
                &serde_json::to_string(&request.public_inputs).unwrap(),
                &request.public_inputs.solvency_bound.to_string(),
                &base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    &request.proof.proof,
                )
                .unwrap(),
                1,
            );
            Self::with_store(store, &request).await
        }

        async fn with_store(store: Arc<NullifierStore>, request: &ApiRequestV2) -> Self {
            let public = &request.public_inputs;
            // The default escape is from the state before the request: its
            // successor nullifier is the request's, whose evidence defeats it.
            let chain = Arc::new(Mutex::new(MockChain::new(
                ESCAPED,
                public.request_nullifier,
                (public.state_signing_key_x, public.state_signing_key_y),
            )));
            let app = Router::new()
                .route("/", post(rpc))
                .route("/v1/tree/notes/{note}/zero-path", get(path))
                .route("/v1/tree/notes/{note}/path", get(leaf_path))
                .route("/v1/tree/root", get(tree_root))
                .route("/v1/escapes/pending", get(pending_escapes))
                .route("/health", get(indexer_health))
                .with_state(chain.clone());
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            let directory = tempfile::tempdir().unwrap();
            let config = ChallengeServiceConfig {
                rpc_url: url.clone(),
                indexer_url: url,
                sender: "0x0000000000000000000000000000000000000001".into(),
                contract_address: public.contract_address,
                chain_id: 1,
                from_block: 0,
                confirmations: 2,
                checkpoint: directory.path().join("checkpoint.json"),
                proof_setup_dir: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("../../protocol/setup/v2-concession-dev"),
                // A transaction fee ceiling the mock's 12M gas limit never
                // reaches at these caps; the ceiling tests use real figures.
                fee: FeePolicy {
                    tx_fee_cap_wei: 10 * ONE_ETHER,
                    ..FeePolicy::new(100 * GWEI, 10 * GWEI)
                },
                // The mock deadline is 100 s away: severity ok unless a test
                // moves the chain clock.
                alarms: AlarmPolicy {
                    warning_remaining_seconds: Some(50),
                    critical_remaining_seconds: Some(10),
                    observe_interval_seconds: 0,
                    ..Default::default()
                },
                // The raise of the 100 s escape is decided 60 s before it.
                raise_lead_seconds: 60,
                raise_min_units: 0,
                // The retire-on-miss tests opt in; the miss-accounting tests
                // see the obligation retire after a payout.
                retire_on_miss: false,
                defeat_gas_limit: DEFAULT_DEFEAT_GAS_LIMIT,
                raise_gas_limit: DEFAULT_RAISE_GAS_LIMIT,
            };
            Self {
                store,
                config,
                chain,
                server,
                _directory: directory,
            }
        }

        fn service(&self) -> ChallengeService {
            ChallengeService::new(self.config.clone(), self.store.clone()).unwrap()
        }

        fn service_with(
            &self,
            change: impl FnOnce(&mut ChallengeServiceConfig),
        ) -> ChallengeService {
            let mut config = self.config.clone();
            change(&mut config);
            ChallengeService::new(config, self.store.clone()).unwrap()
        }

        fn sends(&self) -> Vec<Value> {
            self.chain.lock().unwrap().sends.clone()
        }

        /// pendingWithdrawals reads of `note` so far.
        fn withdrawal_reads(&self, note: u32) -> usize {
            let chain = self.chain.lock().unwrap();
            chain.withdrawal_reads.get(&note).copied().unwrap_or(0)
        }

        fn reserve(&self, service: &mut ChallengeService, note: u32, expired: bool) {
            let mut chain = self.chain.lock().unwrap();
            let nullifier = chain.nullifier;
            let deadline = if expired {
                chain.head_timestamp
            } else {
                chain.deadline
            };
            chain.withdrawals.insert(note, (true, nullifier, deadline));
            service.checkpoint.pending.insert(
                note,
                PendingChallenge {
                    nullifier,
                    nonce: Some(3),
                    ..Default::default()
                },
            );
            service.persist().unwrap();
        }

        /// Track a further live escape of the fixture's nullifier on `note`.
        fn track(&self, service: &mut ChallengeService, note: u32, deadline: u64) {
            let mut chain = self.chain.lock().unwrap();
            let nullifier = chain.nullifier;
            chain.withdrawals.insert(note, (true, nullifier, deadline));
            service.checkpoint.pending.insert(
                note,
                PendingChallenge {
                    nullifier,
                    challenge_deadline: Some(deadline),
                    ..Default::default()
                },
            );
            service.persist().unwrap();
        }
    }

    /// The defeat calldata of `request`'s evidence for `note`.
    fn defeat_of(request: &ApiRequestV2, note: u32) -> Vec<u8> {
        VaultCall::Defeat {
            note_id: note,
            inputs: request.public_inputs.clone(),
            proof: base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                &request.proof.proof,
            )
            .unwrap(),
        }
        .calldata()
        .unwrap()
    }

    fn obligation(status: &ChallengeStatus, note: u32) -> ObligationStatus {
        status
            .obligations
            .iter()
            .find(|o| o.note_id == note)
            .cloned()
            .unwrap_or_else(|| panic!("no obligation for note {note}: {status:?}"))
    }

    fn fee(transaction: &Value, field: &str) -> u128 {
        parse_hex_u128(transaction[field].as_str().unwrap()).unwrap()
    }

    /// (noteId word, 12-word request tuple, proof) of defeat calldata.
    fn decode_call(transaction: &Value) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let data = hex::decode(&transaction["data"].as_str().unwrap()[2..]).unwrap();
        assert_eq!(data[..4], DEFEAT_SELECTOR);
        assert_eq!(data.len(), crate::watcher::DEFEAT_CALLDATA_LEN);
        let word = |index: usize| 4 + index * 32;
        (
            data[word(0)..word(1)].to_vec(),
            data[word(1)..word(13)].to_vec(),
            data[word(15)..].to_vec(),
        )
    }

    /// The call a send makes and its note.
    fn sent_call(transaction: &Value) -> (CallKind, u32) {
        let data = hex::decode(&transaction["data"].as_str().unwrap()[2..]).unwrap();
        let note = u32::from_be_bytes(data[32..36].try_into().unwrap());
        let kind = match data[..4].try_into().unwrap() {
            DEFEAT_SELECTOR => CallKind::Defeat,
            RAISE_SELECTOR => CallKind::Raise,
            RETIRE_SELECTOR => CallKind::Retire,
            other => panic!("unexpected selector {other:?}"),
        };
        (kind, note)
    }

    /// The amount of raise calldata.
    fn raise_amount(transaction: &Value) -> u128 {
        let data = hex::decode(&transaction["data"].as_str().unwrap()[2..]).unwrap();
        assert_eq!(data[..4], RAISE_SELECTOR);
        assert_eq!(data.len(), crate::watcher::RAISE_CALLDATA_LEN);
        u128::from_be_bytes(data[4 + 14 * 32 + 16..4 + 15 * 32].try_into().unwrap())
    }

    fn alternate_tree() -> ([Felt252; MERKLE_DEPTH], Felt252) {
        let mut siblings: [Felt252; MERKLE_DEPTH] = zkapi_core::v2::zero_hashes()[..MERKLE_DEPTH]
            .try_into()
            .unwrap();
        siblings[0] = Felt252::from_u64(5);
        let root = zkapi_core::v2::merkle_root(0, &Felt252::ZERO, &siblings);
        (siblings, root)
    }

    #[tokio::test]
    async fn expired_ambiguous_mined_nonce_allows_queue_progress_across_restart() {
        let fixture = Fixture::new().await;
        let mut service = fixture.service();
        fixture.reserve(&mut service, 1, true);
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.mined_nonce = 4;
            chain.confirmed_nonce = Some(3);
        }
        drop(service);
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        assert_eq!(fixture.sends().len(), 1);
        assert_eq!(fixture.sends()[0]["nonce"], "0x4");
        assert_eq!(
            service.checkpoint.pending[&1].nonce,
            Some(3),
            "retain tip-reorg protection"
        );
        assert!(service.checkpoint.pending[&1].deadline_reported);
        let status = service.status();
        assert_eq!(obligation(&status, 1).state, ObligationState::Missed);
        assert_eq!(status.missed_total, 1);
        assert_eq!(status.last_missed.as_ref().unwrap().note_id, 1);
        drop(service);
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        assert_eq!(
            fixture.sends().len(),
            1,
            "restart cannot duplicate submission"
        );
        assert_eq!(service.status().missed_total, 1, "a miss is counted once");
        fixture.chain.lock().unwrap().confirmed_nonce = Some(4);
        service.poll_once().await.unwrap();
        assert_eq!(service.checkpoint.pending[&1].nonce, None);
        assert_eq!(fixture.sends().len(), 1);
    }

    #[tokio::test]
    async fn expired_ambiguous_unmined_nonce_blocks_conflicts_even_when_pending_count_advances() {
        let fixture = Fixture::new().await;
        let mut service = fixture.service();
        fixture.reserve(&mut service, 1, true);
        fixture.chain.lock().unwrap().pending_nonce = Some(4);
        drop(service);
        let mut service = fixture.service();
        assert!(service
            .poll_once()
            .await
            .unwrap_err()
            .to_string()
            .contains("unmined reserved nonce"));
        assert!(fixture.sends().is_empty());
        assert_eq!(service.checkpoint.pending[&1].nonce, Some(3));
        assert_eq!(service.checkpoint.pending[&0].nonce, None);
        // Both obligations stay visible: the expired one blocks the queue.
        let status = service.status();
        let blocking = obligation(&status, 1);
        assert_eq!(blocking.state, ObligationState::Missed);
        assert_eq!(blocking.blocked_reason, Some(BlockedReason::NonceBlocked));
        let queued = obligation(&status, 0);
        assert_eq!(queued.state, ObligationState::Ready);
        assert_eq!(queued.blocked_reason, Some(BlockedReason::NonceBlocked));
        assert!(queued
            .detail
            .unwrap()
            .contains("queued behind unresolved nonce 3 (note 1)"));
        assert_eq!(status.status, Severity::Critical);
    }

    #[tokio::test]
    async fn completed_withdrawal_retains_ambiguous_nonce_through_restart_and_tip_reorg() {
        let fixture = Fixture::new().await;
        let mut service = fixture.service();
        fixture.reserve(&mut service, 1, false);
        fixture
            .chain
            .lock()
            .unwrap()
            .withdrawals
            .get_mut(&1)
            .unwrap()
            .0 = false;
        service.poll_once().await.unwrap();
        assert!(!service.checkpoint.pending.contains_key(&1));
        assert!(service.checkpoint.detached_nonces.contains_key(&3));
        assert!(fixture.sends().is_empty());
        drop(service);
        let mut service = fixture.service();
        assert!(service
            .poll_once()
            .await
            .unwrap_err()
            .to_string()
            .contains("requires signer intervention"));
        // An unmined detached nonce is critical on the status endpoint.
        let status = service.status();
        assert_eq!(status.detached_nonces.len(), 1);
        assert_eq!(status.detached_nonces[0].nonce, 3);
        assert!(!status.detached_nonces[0].mined);
        assert_eq!(status.status, Severity::Critical);
        assert_eq!(
            obligation(&status, 0).blocked_reason,
            Some(BlockedReason::NonceBlocked)
        );
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.mined_nonce = 4;
            chain.confirmed_nonce = Some(3);
        }
        service.poll_once().await.unwrap();
        assert_eq!(fixture.sends().len(), 1);
        assert!(service.checkpoint.detached_nonces.contains_key(&3));
        assert!(service.status().detached_nonces[0].mined);
        // A tip reorg undoes consumption, so the durable reservation blocks
        // fresh nonce allocation again rather than silently forgetting it.
        fixture.chain.lock().unwrap().mined_nonce = 3;
        drop(service);
        let mut service = fixture.service();
        assert!(service
            .poll_once()
            .await
            .unwrap_err()
            .to_string()
            .contains("requires signer intervention"));
        assert_eq!(fixture.sends().len(), 1);
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.mined_nonce = 5;
            chain.confirmed_nonce = Some(5);
            chain.active = false;
            chain.confirmed_active = false;
        }
        service.poll_once().await.unwrap();
        assert!(service.checkpoint.detached_nonces.is_empty());
        assert!(service.checkpoint.pending.is_empty());
        assert!(service.status().detached_nonces.is_empty());
    }

    #[tokio::test]
    async fn replacement_withdrawal_event_does_not_discard_old_reserved_nonce() {
        let fixture = Fixture::new().await;
        let mut service = fixture.service();
        let old_nullifier = Felt252::from_u64(999);
        service.checkpoint.pending.insert(
            0,
            PendingChallenge {
                nullifier: old_nullifier,
                nonce: Some(3),
                ..Default::default()
            },
        );
        service.persist().unwrap();
        assert!(service
            .poll_once()
            .await
            .unwrap_err()
            .to_string()
            .contains("requires signer intervention"));
        assert_eq!(
            service.checkpoint.detached_nonces[&3].nullifier,
            old_nullifier
        );
        assert_eq!(
            service.checkpoint.pending[&0].nullifier,
            fixture.chain.lock().unwrap().nullifier
        );
        assert!(fixture.sends().is_empty());
        drop(service);
        fixture.chain.lock().unwrap().mined_nonce = 4;
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        assert!(service.checkpoint.detached_nonces.is_empty());
        assert_eq!(fixture.sends().len(), 1);
        assert_eq!(fixture.sends()[0]["nonce"], "0x4");
    }

    #[tokio::test]
    async fn event_replay_restores_reservation_when_its_original_nullifier_returns() {
        let fixture = Fixture::new().await;
        let mut service = fixture.service();
        let original_nullifier = fixture.chain.lock().unwrap().nullifier;
        fixture.reserve(&mut service, 0, false);
        // An intervening fork presents a different withdrawal for this note,
        // in its events and in the vault's state.
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.nullifier = Felt252::from_u64(999);
            chain.withdrawals.get_mut(&0).unwrap().1 = Felt252::from_u64(999);
        }
        assert!(service
            .poll_once()
            .await
            .unwrap_err()
            .to_string()
            .contains("requires signer intervention"));
        assert!(service.checkpoint.detached_nonces.contains_key(&3));
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.nullifier = original_nullifier;
            chain.withdrawals.get_mut(&0).unwrap().1 = original_nullifier;
            chain.block_hash = "0xforkB".into();
        }
        drop(service);
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        assert!(service.checkpoint.detached_nonces.is_empty());
        assert_eq!(service.checkpoint.pending[&0].nonce, Some(3));
        assert_eq!(fixture.sends().len(), 1);
        assert_eq!(fixture.sends()[0]["nonce"], "0x3");
    }

    #[tokio::test]
    async fn lagging_rpc_pending_count_cannot_reuse_another_notes_known_nonce() {
        let fixture = Fixture::new().await;
        let mut service = fixture.service();
        fixture.reserve(&mut service, 1, true);
        service
            .checkpoint
            .pending
            .get_mut(&1)
            .unwrap()
            .transaction_hash = Some("0xsubmitted".into());
        service.persist().unwrap();
        assert!(service
            .poll_once()
            .await
            .unwrap_err()
            .to_string()
            .contains("conflicts with a durable challenge reservation"));
        assert!(fixture.sends().is_empty());
        assert_eq!(service.checkpoint.pending[&1].nonce, Some(3));
        assert_eq!(service.checkpoint.pending[&0].nonce, None);
        assert_eq!(
            obligation(&service.status(), 0).blocked_reason,
            Some(BlockedReason::NonceConflict)
        );
    }

    #[tokio::test]
    async fn event_to_submission_retries_after_restart_and_preserves_v2_calldata() {
        let fixture = Fixture::new().await;
        let (_, request) = finalized_v2_request().await;
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.reorg_during_scan = true;
            chain.fail_first_send = true;
        }
        let expected = defeat_of(&request, 0);
        let mut service = fixture.service();
        assert!(service
            .poll_once()
            .await
            .unwrap_err()
            .to_string()
            .contains("chain reorganized while reading escape events"));
        assert_eq!(service.checkpoint.next_block, 0);
        assert!(service.checkpoint.pending.is_empty());
        assert!(fixture.sends().is_empty());
        assert!(service
            .poll_once()
            .await
            .unwrap_err()
            .to_string()
            .contains("temporary signer failure"));
        assert_eq!(service.checkpoint.next_block, 4);
        assert_eq!(service.checkpoint.pending[&0].nonce, Some(3));
        assert!(
            service.checkpoint.pending[&0].attempt.unknown_attempt,
            "an unclassified send error may have broadcast"
        );
        assert_eq!(
            obligation(&service.status(), 0).blocked_reason,
            Some(BlockedReason::SendAmbiguous)
        );
        drop(service);
        let mut restarted = fixture.service();
        // The unknown attempt may hold the nonce, so the retry must outbid it,
        // at the same pace as any replacement rather than on every poll.
        restarted.poll_once().await.unwrap();
        assert_eq!(fixture.sends().len(), 1);
        let held = obligation(&restarted.status(), 0);
        assert_eq!(held.blocked_reason, Some(BlockedReason::SendAmbiguous));
        assert!(held.detail.unwrap().contains("without a known hash"));
        fixture.chain.lock().unwrap().head_number += 3;
        restarted.poll_once().await.unwrap();
        {
            let sends = fixture.sends();
            assert_eq!(sends.len(), 2);
            // Exactly the EIP-1559 fields; never value, chainId, type or gasPrice.
            for send in &sends {
                let mut keys: Vec<_> = send.as_object().unwrap().keys().cloned().collect();
                keys.sort();
                assert_eq!(
                    keys,
                    [
                        "data",
                        "from",
                        "gas",
                        "maxFeePerGas",
                        "maxPriorityFeePerGas",
                        "nonce",
                        "to"
                    ]
                );
            }
            // The first bid is twice the 1 gwei base fee plus the 2 gwei tip.
            assert_eq!(sends[0]["maxFeePerGas"], "0xee6b2800");
            assert_eq!(sends[0]["maxPriorityFeePerGas"], "0x77359400");
            for field in ["from", "to", "data", "gas", "nonce"] {
                assert_eq!(
                    sends[0][field], sends[1][field],
                    "retry uses the same transaction nonce and payload"
                );
            }
            // The unknown attempt may hold the nonce: the retry is a valid
            // replacement of it, never a lower or equal bid.
            for field in ["maxFeePerGas", "maxPriorityFeePerGas"] {
                assert!(fee(&sends[1], field) >= min_bump(fee(&sends[0], field)));
            }
            assert_eq!(sends[1]["data"], format!("0x{}", hex::encode(expected)));
        }
        restarted.poll_once().await.unwrap();
        assert_eq!(
            fixture.sends().len(),
            2,
            "pending receipt must not cause another send"
        );
        assert_eq!(
            obligation(&restarted.status(), 0).state,
            ObligationState::Submitted
        );
        // A reverted challenge refreshes the live path and is resubmitted.
        // A reverted transaction consumes its nonce while leaving the
        // withdrawal active; receipt availability is not needed to recover.
        fixture.chain.lock().unwrap().mined_nonce += 1;
        restarted.poll_once().await.unwrap();
        assert_eq!(fixture.sends().len(), 3);
        assert_eq!(fixture.sends()[2]["nonce"], "0x4");
        // A latest-block success alone must not drop the obligation: it can
        // disappear in a tip reorg while the scan checkpoint stays canonical.
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.active = false;
            chain.mined_nonce = 5;
            chain.confirmed_nonce = Some(4);
        }
        restarted.poll_once().await.unwrap();
        assert!(!restarted.checkpoint.pending.is_empty());
        assert_eq!(
            obligation(&restarted.status(), 0).state,
            ObligationState::ResolvedUnconfirmed
        );
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.confirmed_active = false;
            chain.confirmed_nonce = None;
        }
        restarted.poll_once().await.unwrap();
        assert!(restarted.checkpoint.pending.is_empty());
        assert!(restarted.status().obligations.is_empty());

        // A restored ambiguous nonce for a higher note ID must be handled
        // before an earlier note becomes eligible, even if its state RPC fails.
        // Otherwise the new note can steal/replace the reserved transaction.
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.active = true;
            chain.confirmed_active = true;
            chain.fail_note_one = true;
            chain.mined_nonce = 3;
            chain.pending_nonce = None;
            chain.sends.clear();
        }
        restarted.checkpoint.pending.insert(
            0,
            PendingChallenge {
                nullifier: ESCAPED,
                ..Default::default()
            },
        );
        restarted.checkpoint.pending.insert(
            1,
            PendingChallenge {
                nullifier: Felt252::from_u64(999),
                nonce: Some(3),
                ..Default::default()
            },
        );
        restarted.persist().unwrap();
        assert!(restarted
            .poll_once()
            .await
            .unwrap_err()
            .to_string()
            .contains("temporary note-state failure"));
        assert!(fixture.sends().is_empty());
        assert!(restarted.checkpoint.pending[&0].nonce.is_none());
        let status = restarted.status();
        assert_eq!(
            obligation(&status, 1).blocked_reason,
            Some(BlockedReason::RpcError)
        );
        assert_eq!(
            obligation(&status, 0).blocked_reason,
            Some(BlockedReason::NonceBlocked)
        );
    }

    /// A nullifier with no request evidence.
    const NO_EVIDENCE: Felt252 = Felt252([0x0d; 32]);

    /// A fixture whose escape is at `request`'s own nullifier `N`: the
    /// request decides Ω, and the escape's successor `N⁺` has no evidence.
    async fn escape_at_request(store: Arc<NullifierStore>, request: &ApiRequestV2) -> Fixture {
        let fixture = Fixture::with_store(store, request).await;
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.nullifier = request.public_inputs.request_nullifier;
            chain.next_nullifier = NO_EVIDENCE;
        }
        fixture
    }

    /// A reserved request whose key was issued and may have been delivered,
    /// not settled.
    fn issued_lease(store: &NullifierStore, request: &ApiRequestV2) {
        store.reserve_openrouter_lease(request).unwrap();
        let now = unix_now();
        store
            .create_openrouter_lease(request, "oa_org", now, now + 20, now + 30, 1.0)
            .unwrap();
        store
            .activate_openrouter_lease(&request.client_request_id, "issued-key-hash")
            .unwrap();
    }

    fn settle(store: &NullifierStore, request: &ApiRequestV2, charge: u128) {
        store.execute_for_test(
            "UPDATE nullifiers SET settled_charge = ?1, settled_basis = 'measured',
                settled_at = 1 WHERE nullifier = ?2",
            rusqlite::params![
                charge as i64,
                request.public_inputs.request_nullifier.to_hex()
            ],
        );
    }

    #[tokio::test]
    async fn an_unsettled_request_waits_for_its_charge_then_is_raised_to_it() {
        let (_, request) = finalized_v2_request().await;
        let store = Arc::new(NullifierStore::in_memory().unwrap());
        issued_lease(&store, &request);
        let fixture = escape_at_request(store.clone(), &request).await;
        let deadline = fixture.chain.lock().unwrap().deadline;
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        assert!(
            fixture.sends().is_empty(),
            "Ω is not final before settlement or the raise lead"
        );
        let awaiting = obligation(&service.status(), 0);
        assert_eq!(awaiting.state, ObligationState::AwaitingSettlement);
        assert_eq!(awaiting.evidence, Some(EvidenceKind::Unsettled));
        assert_eq!(awaiting.owed, None);
        assert_eq!(awaiting.raise_due_at, Some(deadline - 60));
        assert_eq!(awaiting.next_nullifier, Some(NO_EVIDENCE));
        assert_eq!(
            (awaiting.state_balance, awaiting.conceded),
            (Some(100), Some(0))
        );
        assert!(awaiting.settlement.unwrap().possibly_delivered);
        assert_eq!(awaiting.severity, Severity::Ok);

        // Settled: Ω is final at once, long before the raise lead.
        settle(&store, &request, 1);
        service.poll_once().await.unwrap();
        let sends = fixture.sends();
        assert_eq!(sends.len(), 1);
        assert_eq!(sent_call(&sends[0]), (CallKind::Raise, 0));
        assert_eq!(raise_amount(&sends[0]), 1);
        let expected = VaultCall::Raise {
            note_id: 0,
            inputs: request.public_inputs.clone(),
            proof: base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                &request.proof.proof,
            )
            .unwrap(),
            amount: 1,
        };
        assert_eq!(
            sends[0]["data"],
            format!("0x{}", hex::encode(expected.calldata().unwrap()))
        );
        assert_eq!(
            service.checkpoint.pending[&0].attempt.evidence_digest,
            Some(expected.digest())
        );
        let raised = obligation(&service.status(), 0);
        assert_eq!(raised.state, ObligationState::Submitted);
        assert_eq!(raised.action, Some(CallKind::Raise));
        assert_eq!(raised.owed, Some(1));

        // The vault takes the raise: the concession covers what is owed.
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.conceded = 1;
            chain.mined_nonce = 4;
        }
        service.poll_once().await.unwrap();
        assert_eq!(fixture.sends().len(), 1);
        let covered = obligation(&service.status(), 0);
        assert_eq!(covered.state, ObligationState::Raised);
        assert_eq!(covered.conceded, Some(1));
        assert_eq!(covered.severity, Severity::Ok);
    }

    #[tokio::test]
    async fn an_unsettled_request_is_raised_to_its_bound_at_the_raise_lead() {
        let (_, request) = finalized_v2_request().await;
        let store = Arc::new(NullifierStore::in_memory().unwrap());
        issued_lease(&store, &request);
        let fixture = escape_at_request(store, &request).await;
        let deadline = fixture.chain.lock().unwrap().deadline;
        let mut service = fixture.service();
        // One second before the lead: still waiting.
        fixture.chain.lock().unwrap().head_timestamp = deadline - 61;
        service.poll_once().await.unwrap();
        assert!(fixture.sends().is_empty());
        // At deadline - raise_lead_seconds Ω is the request's bound.
        fixture.chain.lock().unwrap().head_timestamp = deadline - 60;
        service.poll_once().await.unwrap();
        let sends = fixture.sends();
        assert_eq!(sends.len(), 1);
        assert_eq!(sent_call(&sends[0]), (CallKind::Raise, 0));
        assert_eq!(
            raise_amount(&sends[0]),
            request.public_inputs.solvency_bound
        );
        assert_eq!(obligation(&service.status(), 0).owed, Some(1));
    }

    #[tokio::test]
    async fn the_raise_uses_the_largest_bound_and_honours_the_minimum() {
        let (_, request) = finalized_v2_request().await;
        // A second proof at the same state with a larger bound, filed by a
        // --rebind; Ω (unsettled, at the lead) is that bound.
        let larger = crate::watcher::tests::request_at_genesis(42, "same-state-larger", 2);
        assert_eq!(
            larger.public_inputs.request_nullifier,
            request.public_inputs.request_nullifier
        );
        let store = Arc::new(NullifierStore::in_memory().unwrap());
        issued_lease(&store, &request);
        crate::watcher::tests::append_raw_evidence(
            &store,
            &larger.public_inputs.request_nullifier,
            &serde_json::to_string(&larger.public_inputs).unwrap(),
            "2",
            &base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                &larger.proof.proof,
            )
            .unwrap(),
            unix_now(),
        );
        for (min_units, conceded, expected) in [
            (0, 0, Some(2)),
            // The vault would concede 2: a raise of 2 is below a minimum of 3.
            (3, 0, None),
            // Already conceding 2: nothing to raise.
            (0, 2, None),
        ] {
            let fixture = escape_at_request(store.clone(), &request).await;
            let deadline = {
                let mut chain = fixture.chain.lock().unwrap();
                chain.conceded = conceded;
                chain.head_timestamp = chain.deadline - 60;
                chain.deadline
            };
            let mut service = fixture.service_with(|config| config.raise_min_units = min_units);
            service.poll_once().await.unwrap();
            let sends = fixture.sends();
            let status = obligation(&service.status(), 0);
            assert_eq!(status.raise_due_at, Some(deadline - 60));
            match expected {
                Some(amount) => {
                    assert_eq!(sends.len(), 1);
                    assert_eq!(raise_amount(&sends[0]), amount);
                    let data = hex::decode(&sends[0]["data"].as_str().unwrap()[2..]).unwrap();
                    // The tuple's solvencyBound word is the larger proof's.
                    assert_eq!(
                        &data[4 + 8 * 32..4 + 9 * 32],
                        Felt252::from_u128(2).as_bytes()
                    );
                }
                None => {
                    assert!(sends.is_empty(), "{min_units} {conceded}");
                    let state = if conceded > 0 {
                        ObligationState::Raised
                    } else {
                        ObligationState::NothingDue
                    };
                    assert_eq!(status.state, state, "{:?}", status.detail);
                }
            }
        }
    }

    #[tokio::test]
    async fn nothing_is_owed_for_a_key_never_delivered_and_its_expiry_is_no_miss() {
        let (_, request) = finalized_v2_request().await;
        // A reservation without a lease row, a key never issued, and one
        // issued but never returned: each owes nothing.
        for (case, kind) in [
            ("no lease row", EvidenceKind::ReservedWithoutLease),
            ("never issued", EvidenceKind::NeverDelivered),
            ("never delivered", EvidenceKind::NeverDelivered),
        ] {
            let store = Arc::new(NullifierStore::in_memory().unwrap());
            store.reserve_openrouter_lease(&request).unwrap();
            if case != "no lease row" {
                store
                    .create_openrouter_lease(&request, "oa_org", 1, 2, 3, 1.0)
                    .unwrap();
            }
            if case == "never delivered" {
                store
                    .activate_openrouter_lease(&request.client_request_id, "key-hash")
                    .unwrap();
                store.execute_for_test("UPDATE openrouter_leases SET delivered = 0", []);
            }
            let fixture = escape_at_request(store, &request).await;
            let mut service = fixture.service();
            {
                let mut chain = fixture.chain.lock().unwrap();
                chain.head_timestamp = chain.deadline - 60;
            }
            service.poll_once().await.unwrap();
            let nothing = obligation(&service.status(), 0);
            assert_eq!(nothing.state, ObligationState::NothingDue, "{case}");
            assert_eq!(nothing.evidence, Some(kind), "{case}");
            assert_eq!(nothing.owed, Some(0), "{case}");
            assert_eq!(nothing.severity, Severity::Ok, "{case}");
            {
                let mut chain = fixture.chain.lock().unwrap();
                chain.head_timestamp = chain.deadline;
            }
            service.poll_once().await.unwrap();
            let status = service.status();
            let expired = obligation(&status, 0);
            assert_eq!(expired.state, ObligationState::ExpiredNothingDue, "{case}");
            assert_eq!(expired.severity, Severity::Ok);
            assert_eq!(status.missed_total, 0);
            assert!(!service.checkpoint.pending[&0].deadline_reported);
            assert!(fixture.sends().is_empty());
        }
    }

    #[tokio::test]
    async fn a_raise_still_due_at_the_deadline_is_a_missed_raise() {
        let (_, request) = finalized_v2_request().await;
        let store = Arc::new(NullifierStore::in_memory().unwrap());
        issued_lease(&store, &request);
        settle(&store, &request, 1);
        let fixture = escape_at_request(store, &request).await;
        // Every raise simulation reverts, so none is sent.
        fixture.chain.lock().unwrap().raise_simulation_error =
            Some(json!({ "code": -32000, "message": "execution reverted" }));
        let mut service = fixture.service();
        assert!(service.poll_once().await.is_err());
        assert!(fixture.sends().is_empty());
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.head_timestamp = chain.deadline;
            chain.head_number += 1;
        }
        service.poll_once().await.unwrap();
        assert_eq!(
            service.checkpoint.pending[&0].missed_kind,
            Some(CallKind::Raise)
        );
        let status = service.status();
        assert_eq!(status.missed_total, 1);
        assert_eq!(status.missed_raises_total, 1);
        assert_eq!(status.escapes_finalized_with_successor_evidence_total, 0);
        let last = status.last_missed.as_ref().unwrap();
        assert_eq!(last.kind, Some(CallKind::Raise));
        let missed = obligation(&status, 0);
        assert_eq!(missed.state, ObligationState::Missed);
        assert_eq!(missed.severity, Severity::Critical);
        // Paid out at confirmation depth: a missed raise retires the
        // obligation (only a missed defeat retires the leaf).
        fixture.chain.lock().unwrap().pay_out(5);
        service.poll_once().await.unwrap();
        assert!(service.checkpoint.pending.is_empty());
        let status = service.status();
        assert_eq!(status.missed_total, 1);
        assert!(status.alarms[0].contains("raise not mined before the deadline"));
    }

    #[tokio::test]
    async fn signer_refusal_is_reported_on_status_with_remaining_deadline() {
        let fixture = Fixture::new().await;
        fixture.chain.lock().unwrap().refuse_notes.insert(0);
        let mut service = fixture.service();
        let error = service.poll_once().await.unwrap_err().to_string();
        assert!(
            error.contains("Requested fees are outside the configured bounds"),
            "{error}"
        );
        assert_eq!(fixture.sends().len(), 1);
        // Nothing was broadcast, so the refused nonce is released.
        assert_eq!(service.checkpoint.pending[&0].nonce, None);
        let status = service.status();
        let refused = obligation(&status, 0);
        assert_eq!(refused.state, ObligationState::Ready);
        assert_eq!(refused.blocked_reason, Some(BlockedReason::SignerRefused));
        assert!(refused
            .detail
            .unwrap()
            .contains("Requested fees are outside the configured bounds"));
        let remaining = refused.seconds_remaining.unwrap();
        assert!((99..=100).contains(&remaining), "{remaining}");
        assert_eq!(refused.severity, Severity::Critical);
        assert_eq!(status.status, Severity::Critical);
        let response = tower::ServiceExt::oneshot(
            challenge_status::router(service.status_handle(), fixture.config.alarms.clone()),
            axum::http::Request::builder()
                .uri("/health")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn definitive_refusal_until_deadline_does_not_stall_later_notes() {
        let fixture = Fixture::new().await;
        let mut service = fixture.service();
        let later = fixture.chain.lock().unwrap().deadline + 1_000;
        fixture.track(&mut service, 1, later);
        fixture.chain.lock().unwrap().refuse_notes.insert(0);
        assert!(service.poll_once().await.is_err());
        let sends = fixture.sends();
        assert_eq!(sends.len(), 2);
        assert_eq!(decode_call(&sends[0]).0, Felt252::from_u64(0).as_bytes());
        assert_eq!(decode_call(&sends[1]).0, Felt252::from_u64(1).as_bytes());
        // The refused nonce was released and reused by the next note.
        assert_eq!(sends[0]["nonce"], "0x3");
        assert_eq!(sends[1]["nonce"], "0x3");
        assert_eq!(service.checkpoint.pending[&0].nonce, None);
        assert_eq!(service.checkpoint.pending[&1].nonce, Some(3));
        // The refusal persists; note 1 is unaffected.
        assert!(service.poll_once().await.is_err());
        assert_eq!(fixture.sends().len(), 3);
        assert_eq!(fixture.sends()[2]["nonce"], "0x4");
        assert_eq!(service.checkpoint.pending[&0].nonce, None);
        // At note 0's deadline nothing stalls the queue either.
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.head_timestamp = chain.deadline;
        }
        service.poll_once().await.unwrap();
        assert_eq!(fixture.sends().len(), 3);
        let status = service.status();
        assert_eq!(obligation(&status, 0).state, ObligationState::Missed);
        assert_eq!(obligation(&status, 1).state, ObligationState::Submitted);
    }

    #[tokio::test]
    async fn pending_challenge_is_replaced_on_same_nonce_with_bumped_fees_and_same_call() {
        let fixture = Fixture::new().await;
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        service.poll_once().await.unwrap();
        assert_eq!(fixture.sends().len(), 1, "no bump before bump_after_blocks");
        let first_hash = service.checkpoint.pending[&0]
            .transaction_hash
            .clone()
            .unwrap();
        fixture.chain.lock().unwrap().head_number += 3;
        service.poll_once().await.unwrap();
        let sends = fixture.sends();
        assert_eq!(sends.len(), 2);
        for field in ["from", "to", "nonce", "data", "gas"] {
            assert_eq!(sends[0][field], sends[1][field], "{field}");
        }
        for (field, cap) in [
            ("maxFeePerGas", 100 * GWEI),
            ("maxPriorityFeePerGas", 10 * GWEI),
        ] {
            assert!(
                fee(&sends[1], field) >= min_bump(fee(&sends[0], field)),
                "{field}"
            );
            assert!(fee(&sends[1], field) <= cap, "{field}");
        }
        // The tip rises by the minimum valid step, the fee cap by 25%.
        assert_eq!(fee(&sends[1], "maxPriorityFeePerGas"), 2_200_000_000);
        assert_eq!(fee(&sends[1], "maxFeePerGas"), 5 * GWEI);
        let pending = &service.checkpoint.pending[&0];
        assert_eq!(pending.attempt.superseded_hashes, vec![first_hash.clone()]);
        assert_eq!(pending.attempt.attempts, 2);
        assert_ne!(pending.transaction_hash.as_ref(), Some(&first_hash));
        let status = obligation(&service.status(), 0);
        assert_eq!(status.superseded_hashes, vec![first_hash]);
        assert_eq!(status.max_fee_per_gas_wei.as_deref(), Some("5000000000"));

        // An ambiguous replacement followed by a restart never bids lower.
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain
                .send_errors
                .push_back(json!({ "code": -32000, "message": "upstream timeout" }));
            chain.head_number += 3;
        }
        assert!(service.poll_once().await.is_err());
        let ambiguous = fixture.sends()[2].clone();
        assert!(fee(&ambiguous, "maxFeePerGas") >= min_bump(5 * GWEI));
        drop(service);
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.transaction_known = false;
            chain.head_number += 3;
        }
        let mut restarted = fixture.service();
        restarted.poll_once().await.unwrap();
        let sends = fixture.sends();
        assert_eq!(sends.len(), 4);
        assert_eq!(sends[3]["nonce"], ambiguous["nonce"]);
        for field in ["maxFeePerGas", "maxPriorityFeePerGas"] {
            assert!(
                fee(&sends[3], field) >= min_bump(fee(&ambiguous, field)),
                "{field}"
            );
        }
    }

    #[tokio::test]
    async fn ambiguous_send_held_by_an_unknown_attempt_rebids_both_fees() {
        // The signer returns a candidate hash for an ambiguous broadcast.
        let fixture = Fixture::new().await;
        let candidate = format!("0x{:064x}", 0xabcdu64);
        fixture.chain.lock().unwrap().send_errors.push_back(json!({
            "code": -32000, "message": "Transaction broadcast outcome is unknown",
            "data": { "reason": "broadcast_ambiguous", "transaction_hash": candidate }
        }));
        let mut service = fixture.service();
        assert!(service.poll_once().await.is_err());
        let pending = &service.checkpoint.pending[&0];
        assert_eq!(
            pending.transaction_hash.as_deref(),
            Some(candidate.as_str())
        );
        assert!(!pending.attempt.unknown_attempt);
        // The RPC does not know the hash, but the pending count shows the
        // nonce is occupied, and the base fee then exceeds the first bid.
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.transaction_known = false;
            chain.pending_nonce = Some(4);
            chain.base_fee = Some(10 * GWEI);
        }
        service.poll_once().await.unwrap();
        let sends = fixture.sends();
        assert_eq!(sends.len(), 2);
        assert_eq!(sends[0]["nonce"], sends[1]["nonce"]);
        for field in ["maxFeePerGas", "maxPriorityFeePerGas"] {
            assert!(
                fee(&sends[1], field) >= min_bump(fee(&sends[0], field)),
                "{field}"
            );
        }
        assert!(fee(&sends[1], "maxFeePerGas") >= 20 * GWEI);
        assert_eq!(
            service.checkpoint.pending[&0].attempt.superseded_hashes,
            vec![candidate]
        );

        // An unclassifiable failure (no hash) also makes the next send bump.
        let fixture = Fixture::new().await;
        fixture
            .chain
            .lock()
            .unwrap()
            .send_errors
            .push_back(json!({ "code": -32603, "message": "Signer request failed" }));
        let mut service = fixture.service();
        assert!(service.poll_once().await.is_err());
        assert!(service.checkpoint.pending[&0].attempt.unknown_attempt);
        service.poll_once().await.unwrap();
        assert_eq!(fixture.sends().len(), 1, "no re-bid on every poll");
        fixture.chain.lock().unwrap().head_number += 3;
        service.poll_once().await.unwrap();
        let sends = fixture.sends();
        assert_eq!(sends.len(), 2);
        for field in ["maxFeePerGas", "maxPriorityFeePerGas"] {
            assert!(
                fee(&sends[1], field) >= min_bump(fee(&sends[0], field)),
                "{field}"
            );
        }

        // A signer-reported failure before broadcast needs no bump, and its
        // nonce is released.
        let fixture = Fixture::new().await;
        fixture.chain.lock().unwrap().send_errors.push_back(json!({
            "code": -32000, "message": "Upstream RPC request failed",
            "data": { "reason": "upstream_unavailable" }
        }));
        let mut service = fixture.service();
        assert!(service.poll_once().await.is_err());
        assert!(!service.checkpoint.pending[&0].attempt.unknown_attempt);
        assert_eq!(service.checkpoint.pending[&0].nonce, None);
        assert_eq!(
            obligation(&service.status(), 0).blocked_reason,
            Some(BlockedReason::RpcError)
        );
        service.poll_once().await.unwrap();
        let sends = fixture.sends();
        assert_eq!(sends.len(), 2);
        assert_eq!(sends[0], sends[1]);
    }

    #[tokio::test]
    async fn base_fee_above_cap_reports_blocked_and_submits_after_it_falls() {
        let fixture = Fixture::new().await;
        fixture.chain.lock().unwrap().base_fee = Some(150 * GWEI);
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        service.poll_once().await.unwrap();
        assert!(fixture.sends().is_empty());
        assert_eq!(service.checkpoint.pending[&0].nonce, None);
        let blocked = obligation(&service.status(), 0);
        assert_eq!(blocked.state, ObligationState::Ready);
        assert_eq!(
            blocked.blocked_reason,
            Some(BlockedReason::BaseFeeAboveFeeCap)
        );
        fixture.chain.lock().unwrap().base_fee = Some(30 * GWEI);
        service.poll_once().await.unwrap();
        let sends = fixture.sends();
        assert_eq!(sends.len(), 1);
        assert_eq!(fee(&sends[0], "maxFeePerGas"), 62 * GWEI);
        assert_eq!(fee(&sends[0], "maxPriorityFeePerGas"), 2 * GWEI);
        // A base fee above the pending bid triggers a replacement, within the
        // non-critical limit that keeps two replacements for the critical
        // threshold.
        fixture.chain.lock().unwrap().base_fee = Some(70 * GWEI);
        service.poll_once().await.unwrap();
        let sends = fixture.sends();
        assert_eq!(sends.len(), 2);
        assert_eq!(
            fee(&sends[1], "maxFeePerGas"),
            headroom(headroom(100 * GWEI))
        );
        assert_eq!(fee(&sends[1], "maxPriorityFeePerGas"), 2_200_000_000);
        // Above the cap nothing more can be done but report it.
        fixture.chain.lock().unwrap().base_fee = Some(120 * GWEI);
        service.poll_once().await.unwrap();
        assert_eq!(fixture.sends().len(), 2);
        let blocked = obligation(&service.status(), 0);
        assert_eq!(blocked.state, ObligationState::Submitted);
        assert_eq!(
            blocked.blocked_reason,
            Some(BlockedReason::BaseFeeAboveFeeCap)
        );
    }

    #[tokio::test]
    async fn critical_deadline_escalates_pending_challenge_to_fee_caps() {
        let fixture = Fixture::new().await;
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.head_timestamp = chain.deadline - 5;
        }
        service.poll_once().await.unwrap();
        let sends = fixture.sends();
        assert_eq!(sends.len(), 2);
        // Just under the caps, keeping one valid bump of headroom.
        assert_eq!(fee(&sends[1], "maxFeePerGas"), headroom(100 * GWEI));
        assert_eq!(fee(&sends[1], "maxPriorityFeePerGas"), headroom(10 * GWEI));
        assert_eq!(sends[1]["nonce"], sends[0]["nonce"]);
        fixture.chain.lock().unwrap().head_number += 3;
        service.poll_once().await.unwrap();
        let sends = fixture.sends();
        assert_eq!(sends.len(), 3);
        assert_eq!(fee(&sends[2], "maxFeePerGas"), 100 * GWEI);
        assert_eq!(fee(&sends[2], "maxPriorityFeePerGas"), 10 * GWEI);
        fixture.chain.lock().unwrap().head_number += 3;
        service.poll_once().await.unwrap();
        assert_eq!(fixture.sends().len(), 3, "no valid bump above the caps");
        let capped = obligation(&service.status(), 0);
        assert_eq!(capped.blocked_reason, Some(BlockedReason::TipCapReached));
        assert_eq!(capped.severity, Severity::Critical);
    }

    #[tokio::test]
    async fn critical_queued_obligation_escalates_the_head_replacement() {
        let fixture = Fixture::new().await;
        fixture.chain.lock().unwrap().deadline += 1_000;
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        assert_eq!(fee(&fixture.sends()[0], "maxFeePerGas"), 4 * GWEI);
        // A second escape near its deadline queues behind the head nonce.
        let near = fixture.chain.lock().unwrap().head_timestamp + 5;
        fixture.track(&mut service, 1, near);
        service.poll_once().await.unwrap();
        let sends = fixture.sends();
        assert_eq!(sends.len(), 3);
        let by_nonce = |nonce: &str| {
            sends
                .iter()
                .filter(|send| send["nonce"] == nonce)
                .cloned()
                .collect::<Vec<_>>()
        };
        let head = by_nonce("0x3");
        assert_eq!(head.len(), 2, "the non-critical head is replaced");
        assert_eq!(fee(&head[1], "maxFeePerGas"), headroom(100 * GWEI));
        let queued = by_nonce("0x4");
        assert_eq!(queued.len(), 1);
        assert_eq!(fee(&queued[0], "maxFeePerGas"), headroom(100 * GWEI));
    }

    #[tokio::test]
    async fn replacement_waits_while_an_earlier_nonce_is_pending() {
        let fixture = Fixture::new().await;
        let mut service = fixture.service();
        let deadline = fixture.chain.lock().unwrap().deadline;
        fixture.track(&mut service, 1, deadline);
        service.poll_once().await.unwrap();
        let sends = fixture.sends();
        assert_eq!(sends.len(), 2);
        assert_eq!(sends[0]["nonce"], "0x3");
        assert_eq!(sends[1]["nonce"], "0x4");
        fixture.chain.lock().unwrap().head_number += 3;
        service.poll_once().await.unwrap();
        let sends = fixture.sends();
        assert_eq!(sends.len(), 3, "only the queue head is replaced");
        assert_eq!(sends[2]["nonce"], "0x3");
        assert!(obligation(&service.status(), 1)
            .detail
            .unwrap()
            .contains("behind an earlier challenge"));
        // Once nonce 3 is consumed, nonce 4 is the head and is replaced.
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.mined_nonce = 4;
            chain.confirmed_nonce = Some(3);
            chain.head_number += 3;
        }
        service.poll_once().await.unwrap();
        let sends = fixture.sends();
        assert_eq!(sends.len(), 4);
        assert_eq!(sends[3]["nonce"], "0x4");
        // The consumed nonce left the withdrawal pending: a revert keeps its
        // deadline-derived severity.
        assert_eq!(
            obligation(&service.status(), 0).state,
            ObligationState::MinedUnconfirmed
        );
    }

    #[tokio::test]
    async fn not_pending_withdrawal_revert_is_resolved_unconfirmed_and_retried() {
        let fixture = Fixture::new().await;
        let revert = |signature: &str| {
            json!({ "code": 3, "message": "execution reverted",
                "data": format!("0x{}", hex::encode(selector(signature))) })
        };
        fixture.chain.lock().unwrap().simulation_error = Some(revert("NotPendingWithdrawal()"));
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        assert!(fixture.sends().is_empty());
        assert!(
            service.checkpoint.pending.contains_key(&0),
            "only confirmed depth retires"
        );
        assert_eq!(
            obligation(&service.status(), 0).state,
            ObligationState::ResolvedUnconfirmed
        );
        // Evidence the vault does not take for this escape is invalid.
        fixture.chain.lock().unwrap().simulation_error = Some(revert("NotSuccessorEvidence()"));
        assert!(service.poll_once().await.is_err());
        let invalid = obligation(&service.status(), 0);
        assert_eq!(invalid.blocked_reason, Some(BlockedReason::EvidenceInvalid));
        assert_eq!(invalid.severity, Severity::Critical);
        fixture.chain.lock().unwrap().simulation_error = Some(revert("ChallengeExpired()"));
        assert!(service.poll_once().await.is_err());
        let expired = obligation(&service.status(), 0);
        assert_eq!(
            expired.blocked_reason,
            Some(BlockedReason::SimulationReverted)
        );
        assert!(expired.detail.unwrap().contains("ChallengeExpired()"));
        fixture.chain.lock().unwrap().simulation_error = None;
        service.poll_once().await.unwrap();
        assert_eq!(fixture.sends().len(), 1);
    }

    #[tokio::test]
    async fn insufficient_balance_clamps_fee_and_reports_aggregate_alarm() {
        let fixture = Fixture::new().await;
        // The mock estimate is 10M gas, so the gas limit is 12M.
        fixture.chain.lock().unwrap().balance = Some(12_000_000 * 3 * GWEI);
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        let sends = fixture.sends();
        assert_eq!(fee(&sends[0], "maxFeePerGas"), 3 * GWEI);
        assert_eq!(fee(&sends[0], "maxPriorityFeePerGas"), 2 * GWEI);
        let status = service.status();
        assert_eq!(
            status.sender.balance_wei.as_deref(),
            Some("36000000000000000")
        );
        assert_eq!(status.sender.outstanding_obligations, 1);
        assert_eq!(
            status.sender.required_balance_wei.as_deref(),
            Some("48000000000000000")
        );
        assert!(status
            .alarms
            .iter()
            .any(|alarm| alarm.contains("cannot fund every outstanding challenge")));
        assert!(status.status >= Severity::Warning);
        // A replacement the balance cannot fund is not sent.
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.balance = Some(12_000_000 * GWEI / 2);
            chain.head_number += 3;
        }
        service.poll_once().await.unwrap();
        assert_eq!(fixture.sends().len(), 1);
        assert_eq!(
            obligation(&service.status(), 0).blocked_reason,
            Some(BlockedReason::InsufficientBalance)
        );
        // A signer that disallows eth_getBalance leaves the balance unknown.
        fixture.chain.lock().unwrap().balance = None;
        service.poll_once().await.unwrap();
        let sender = service.status().sender;
        assert_eq!(sender.balance_wei, None);
        assert!(sender
            .balance_detail
            .unwrap()
            .contains("does not allow eth_getBalance"));
    }

    #[tokio::test]
    async fn an_indexer_divergence_alarms_but_never_blocks_a_defeat() {
        // Heuristic mode: an indexer without block metadata.
        let fixture = Fixture::new().await;
        let (_, other_root) = alternate_tree();
        fixture.chain.lock().unwrap().indexer_root = Some(json!({ "root": other_root }));
        let mut service = fixture.service_with(|config| {
            config.alarms.indexer_divergence_seconds = 0;
            config.alarms.indexer_divergence_polls = 3;
        });
        service.poll_once().await.unwrap();
        assert_eq!(service.status().indexer.state, IndexerState::Lagging);
        // A defeat needs no indexer path and no live root (§5.4).
        assert_eq!(fixture.sends().len(), 1);
        assert_eq!(sent_call(&fixture.sends()[0]), (CallKind::Defeat, 0));
        service.poll_once().await.unwrap();
        assert_eq!(service.status().indexer.state, IndexerState::Lagging);
        service.poll_once().await.unwrap();
        let status = service.status();
        assert_eq!(status.indexer.state, IndexerState::Diverged);
        assert_eq!(obligation(&status, 0).blocked_reason, None);
        assert_eq!(status.status, Severity::Critical);
        assert!(status
            .alarms
            .iter()
            .any(|alarm| alarm.contains("indexer mirror diverged")));

        // Exact mode: the vault root at the indexer's own block differs.
        let fixture = Fixture::new().await;
        {
            let mut chain = fixture.chain.lock().unwrap();
            let live = chain.root;
            chain.indexer_root =
                Some(json!({ "root": other_root, "block_number": 5, "block_hash": "0xindexer" }));
            chain.roots_by_hash.insert("0xindexer".into(), live);
        }
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        let status = service.status();
        assert_eq!(status.indexer.state, IndexerState::Diverged);
        assert_eq!(fixture.sends().len(), 1);

        // A consistent but lagging root is not an alarm.
        let fixture = Fixture::new().await;
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.indexer_root =
                Some(json!({ "root": other_root, "block_number": 4, "block_hash": "0xold" }));
            chain.roots_by_hash.insert("0xold".into(), other_root);
        }
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        let status = service.status();
        assert_eq!(status.indexer.state, IndexerState::Lagging);
        assert_eq!(status.indexer.lag_blocks, Some(1));
        assert_eq!(status.status, Severity::Ok, "{:?}", status.alarms);
        assert_eq!(fixture.sends().len(), 1);
    }

    #[tokio::test]
    async fn a_null_cursor_block_is_retried_not_replayed() {
        let fixture = Fixture::new().await;
        fixture.chain.lock().unwrap().head_number = 5_000;
        let mut service = fixture.service_with(|config| config.from_block = 1_000);
        for _ in 0..4 {
            service.poll_once().await.unwrap();
        }
        assert_eq!(service.checkpoint.next_block, 4_999);
        // A lagging backend answers null for the cursor block: the poll fails
        // and is retried, and the scan does not replay from the deployment.
        fixture.chain.lock().unwrap().null_blocks.insert(4_998);
        let error = service.poll_once().await.unwrap_err().to_string();
        assert!(error.contains("scan cursor block 4998"), "{error}");
        assert_eq!(service.checkpoint.next_block, 4_999);
        let status = service.status();
        assert_eq!(status.chain.scan_lag_blocks, Some(0));
        assert!(
            !status
                .alarms
                .iter()
                .any(|alarm| alarm.contains("event scan")),
            "{:?}",
            status.alarms
        );
        fixture.chain.lock().unwrap().null_blocks.clear();
        service.poll_once().await.unwrap();
        // One answer from another fork, contradicted on a second read, is
        // not a reorganization either.
        fixture.chain.lock().unwrap().forked_block_reads = 1;
        service.poll_once().await.unwrap();
        assert_eq!(service.checkpoint.next_block, 4_999);
        // A different hash on both reads is: the scan replays.
        fixture.chain.lock().unwrap().block_hash = "0xforkB".into();
        service.poll_once().await.unwrap();
        assert_eq!(service.checkpoint.next_block, 2_000);
    }

    #[tokio::test]
    async fn an_unavailable_indexer_never_delays_a_defeat() {
        let fixture = Fixture::new().await;
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.path_unavailable = u32::MAX;
            chain.indexer_health = "rebuilding";
            chain.escapes = None;
        }
        let mut service = fixture.service_with(|config| config.alarms.blocked_warning_seconds = 0);
        service.poll_once().await.unwrap();
        assert_eq!(fixture.sends().len(), 1);
        let submitted = obligation(&service.status(), 0);
        assert_eq!(submitted.state, ObligationState::Submitted);
        assert_eq!(submitted.blocked_reason, None);
        // The unavailable indexer is visible on the status.
        let status = service.status();
        assert_eq!(status.indexer.state, IndexerState::Unavailable);
        assert!(status.indexer.detail.unwrap().contains("rebuilding"));
        assert!(status
            .alarms
            .iter()
            .any(|alarm| alarm.contains("indexer unavailable")));
    }

    #[tokio::test]
    async fn escape_missing_from_lagging_get_logs_is_added_from_indexer_pending_list() {
        let fixture = Fixture::new().await;
        let deadline = {
            let mut chain = fixture.chain.lock().unwrap();
            chain.drop_logs = true;
            let listed = json!([
                { "note_id": 0, "withdrawal_nullifier": chain.nullifier, "challenge_deadline": chain.deadline },
                // Listed with a stale nullifier and deadline: the vault's
                // escape of note 7 is tracked instead.
                { "note_id": 7, "withdrawal_nullifier": Felt252::from_u64(77), "challenge_deadline": chain.deadline },
            ]);
            chain.escapes = Some(listed.as_array().unwrap().clone());
            let deadline = chain.deadline;
            chain
                .withdrawals
                .insert(7, (true, Felt252::from_u64(78), deadline + 5));
            chain.concessions.insert(7, (NO_EVIDENCE, 0));
            deadline
        };
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        assert_eq!(
            service.checkpoint.next_block, 4,
            "the lagging scan moved on"
        );
        assert_eq!(
            service
                .checkpoint
                .pending
                .keys()
                .copied()
                .collect::<Vec<_>>(),
            [0, 7]
        );
        assert_eq!(
            service.checkpoint.pending[&7].nullifier,
            Felt252::from_u64(78)
        );
        // Note 7's escape has no server request: nothing to send.
        assert_eq!(fixture.sends().len(), 1);
        let status = service.status();
        assert_eq!(status.indexer.pending_escapes, "ok");
        assert_eq!(status.indexer.escapes_added_from_indexer, 2);
        assert_eq!(obligation(&status, 0).challenge_deadline, Some(deadline));
        assert_eq!(
            obligation(&status, 7).challenge_deadline,
            Some(deadline + 5)
        );
        assert_eq!(obligation(&status, 7).state, ObligationState::NothingDue);
        assert!(status
            .indexer
            .pending_escapes_disagreement
            .unwrap()
            .starts_with("note 7 listed with nullifier"));

        // An indexer that predates the endpoint is tolerated with a warning.
        fixture.chain.lock().unwrap().escapes = None;
        service.poll_once().await.unwrap();
        let status = service.status();
        assert_eq!(status.indexer.pending_escapes, "unsupported");
        assert_eq!(status.status, Severity::Warning);
    }

    #[tokio::test]
    async fn re_escape_with_a_different_nullifier_after_confirmed_challenge_is_challenged_again() {
        let (store, first, second) = two_finalized_v2_requests().await;
        let fixture = Fixture::with_store(store, &first).await;
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        let sends = fixture.sends();
        assert_eq!(sends.len(), 1);
        let nullifier_word = |send: &Value| decode_call(send).1[8 * 32..9 * 32].to_vec();
        assert_eq!(
            nullifier_word(&sends[0]),
            first.public_inputs.request_nullifier.as_bytes()
        );
        // The challenge mines and the withdrawal is resolved at confirmation depth.
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.mined_nonce = 4;
            chain.active = false;
            chain.confirmed_active = false;
        }
        service.poll_once().await.unwrap();
        assert!(service.checkpoint.pending.is_empty());
        // The owner escapes again from another state, whose successor the
        // second request spent: a new obligation.
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.nullifier = RE_ESCAPED;
            chain.next_nullifier = second.public_inputs.request_nullifier;
            chain.active = true;
            chain.confirmed_active = true;
            chain.head_number += 1;
        }
        service.poll_once().await.unwrap();
        let sends = fixture.sends();
        assert_eq!(sends.len(), 2);
        assert_eq!(sends[1]["nonce"], "0x4");
        assert_eq!(
            nullifier_word(&sends[1]),
            second.public_inputs.request_nullifier.as_bytes()
        );
        assert_eq!(service.checkpoint.pending[&0].nullifier, RE_ESCAPED);
        assert_eq!(
            service.checkpoint.pending[&0].next_nullifier,
            Some(second.public_inputs.request_nullifier)
        );
    }

    #[tokio::test]
    async fn evidence_database_error_is_critical_not_silent() {
        let (_, request) = finalized_v2_request().await;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("server.db");
        let server = NullifierStore::new(&path).unwrap();
        server.reserve_openrouter_lease(&request).unwrap();
        server
            .finalize(
                &request.public_inputs.request_nullifier,
                &finalized_transcript(&request, 1),
            )
            .unwrap();
        let reader = Arc::new(NullifierStore::open_read_only(&path).unwrap());
        let fixture = Fixture::with_store(reader, &request).await;
        rusqlite::Connection::open(&path)
            .unwrap()
            .execute_batch("DROP TRIGGER request_evidence_no_delete; DROP TABLE request_evidence;")
            .unwrap();
        let mut service = fixture.service();
        let error = service.poll_once().await.unwrap_err().to_string();
        assert!(error.contains("evidence database read failed"), "{error}");
        assert!(fixture.sends().is_empty());
        let status = service.status();
        let unreadable = obligation(&status, 0);
        assert_eq!(
            unreadable.blocked_reason,
            Some(BlockedReason::EvidenceDbError)
        );
        assert_eq!(unreadable.evidence, Some(EvidenceKind::Unavailable));
        assert_eq!(unreadable.severity, Severity::Critical);
        assert_eq!(status.status, Severity::Critical);
    }

    #[tokio::test]
    async fn evidence_of_another_state_key_is_invalid_and_critical() {
        let fixture = Fixture::new().await;
        fixture.chain.lock().unwrap().state_key.0 = Felt252::from_u64(5);
        let mut service = fixture.service();
        let error = service.poll_once().await.unwrap_err().to_string();
        assert!(
            error.contains("names a state key other than the vault's"),
            "{error}"
        );
        assert!(fixture.sends().is_empty());
        let invalid = obligation(&service.status(), 0);
        assert_eq!(invalid.blocked_reason, Some(BlockedReason::EvidenceInvalid));
        assert_eq!(invalid.severity, Severity::Critical);
    }

    #[tokio::test]
    async fn legacy_checkpoint_without_fee_fields_loads_and_replaces_only_with_a_valid_bump() {
        let fixture = Fixture::new().await;
        let nullifier = fixture.chain.lock().unwrap().nullifier;
        // A checkpoint written by the previous daemon, with a pending type-0
        // transaction whose fees it never recorded.
        std::fs::write(
            &fixture.config.checkpoint,
            serde_json::to_vec(&json!({
                "sender": "0x0000000000000000000000000000000000000001",
                "chain_id": 1, "contract_address": fixture.config.contract_address,
                "from_block": 0, "next_block": 4, "last_block_hash": "0xforkA",
                "pending": { "0": { "nullifier": nullifier, "transaction_hash": "0xlegacy",
                    "nonce": 3, "deadline_reported": false } },
                "detached_nonces": {}
            }))
            .unwrap(),
        )
        .unwrap();
        // 1.1 x 9.5 gwei exceeds the 10 gwei tip cap: no valid replacement.
        fixture.chain.lock().unwrap().legacy_gas_price = Some(9_500_000_000);
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        assert!(fixture.sends().is_empty());
        let capped = obligation(&service.status(), 0);
        assert_eq!(capped.state, ObligationState::Submitted);
        assert_eq!(capped.blocked_reason, Some(BlockedReason::TipCapReached));
        // A gas price both caps exceed by 10% is replaced on its nonce.
        fixture.chain.lock().unwrap().legacy_gas_price = Some(5 * GWEI);
        service.poll_once().await.unwrap();
        let sends = fixture.sends();
        assert_eq!(sends.len(), 1);
        assert_eq!(sends[0]["nonce"], "0x3");
        for field in ["maxFeePerGas", "maxPriorityFeePerGas"] {
            assert!(fee(&sends[0], field) >= min_bump(5 * GWEI), "{field}");
        }
        assert_eq!(
            service.checkpoint.pending[&0].attempt.superseded_hashes,
            vec!["0xlegacy".to_string()]
        );
    }

    #[tokio::test]
    async fn fee_policy_validation_rejects_invalid_caps() {
        let valid = FeePolicy::new(100 * GWEI, 10 * GWEI);
        assert!(valid.validate().is_ok());
        for (policy, message) in [
            (
                FeePolicy {
                    max_priority_fee_per_gas: 200 * GWEI,
                    ..valid.clone()
                },
                "must not exceed max fee",
            ),
            (
                FeePolicy {
                    priority_fee_per_gas: 0,
                    ..valid.clone()
                },
                "must be positive",
            ),
            (
                FeePolicy {
                    max_priority_fee_per_gas: 3 * GWEI,
                    ..valid.clone()
                },
                "at least twice",
            ),
            (
                FeePolicy {
                    bump_after_blocks: 0,
                    ..valid.clone()
                },
                "at least one block",
            ),
            (
                FeePolicy {
                    bump_percent: 9,
                    ..valid.clone()
                },
                "between 10 and 100",
            ),
            (
                FeePolicy {
                    bump_percent: 101,
                    ..valid.clone()
                },
                "between 10 and 100",
            ),
        ] {
            let error = policy.validate().unwrap_err().to_string();
            assert!(error.contains(message), "{error}");
        }
        let fixture = Fixture::new().await;
        let mut config = fixture.config.clone();
        config.fee.max_priority_fee_per_gas = 3 * GWEI;
        assert!(ChallengeService::new(config, fixture.store.clone()).is_err());
        let mut config = fixture.config.clone();
        config.alarms.critical_remaining_seconds = Some(60);
        assert!(ChallengeService::new(config, fixture.store.clone()).is_err());
        // A low Mainnet cap is a configuration warning, not an error.
        let mut config = fixture.config.clone();
        config.fee = FeePolicy::new(50 * GWEI, 10 * GWEI);
        let service = ChallengeService::new(config, fixture.store.clone()).unwrap();
        assert!(service
            .status()
            .config_warnings
            .iter()
            .any(|warning| warning.contains("Mainnet")));
    }

    #[test]
    fn fee_plans_bid_bump_and_escalate_within_caps() {
        let policy = FeePolicy::new(100 * GWEI, 10 * GWEI);
        let plan = |plan, base, critical, affordable| {
            plan_fees(&policy, plan, base, critical, None, affordable)
        };
        let fees = |max_fee, tip| Fees { max_fee, tip };
        let caps = fees(100 * GWEI, 10 * GWEI);
        let reserve = |fees: Fees| Fees {
            max_fee: headroom(fees.max_fee),
            tip: headroom(fees.tip),
        };
        // A first bid is twice the base fee plus the tip, within 10/11 of
        // 10/11 of the cap, or as much more as the base fee needs.
        assert_eq!(
            plan(FeePlan::First, Some(GWEI), false, None),
            Ok(Some(fees(4 * GWEI, 2 * GWEI)))
        );
        assert_eq!(
            plan(FeePlan::First, Some(60 * GWEI), false, None),
            Ok(Some(fees(reserve(reserve(caps)).max_fee, 2 * GWEI)))
        );
        assert_eq!(
            plan(FeePlan::First, Some(85 * GWEI), false, None),
            Ok(Some(fees(reserve(caps).max_fee, 2 * GWEI)))
        );
        assert_eq!(
            plan(FeePlan::First, Some(95 * GWEI), false, None),
            Ok(Some(fees(100 * GWEI, 2 * GWEI)))
        );
        assert_eq!(
            plan(FeePlan::First, None, false, None),
            Ok(Some(fees(reserve(reserve(caps)).max_fee, 2 * GWEI)))
        );
        assert_eq!(
            plan(FeePlan::First, Some(101 * GWEI), false, None),
            Err(BlockedReason::BaseFeeAboveFeeCap)
        );
        // Critical: just under both caps, then the caps, then nothing.
        let critical = plan(FeePlan::First, Some(GWEI), true, None)
            .unwrap()
            .unwrap();
        assert_eq!(critical, fees(90_909_090_909, 9_090_909_090));
        assert_eq!(
            plan(FeePlan::Bump(critical), Some(GWEI), true, None),
            Ok(Some(caps))
        );
        assert_eq!(
            plan(FeePlan::Bump(caps), Some(GWEI), true, None),
            Err(BlockedReason::TipCapReached)
        );
        // A base fee above the critical bid goes straight to the caps.
        assert_eq!(
            plan(FeePlan::First, Some(95 * GWEI), true, None),
            Ok(Some(caps))
        );
        // A normal bump raises the tip minimally and the fee cap by 25%.
        assert_eq!(
            plan(
                FeePlan::Bump(fees(4 * GWEI, 2 * GWEI)),
                Some(GWEI),
                false,
                None
            ),
            Ok(Some(fees(5 * GWEI, 2_200_000_000)))
        );
        let mut current = fees(4 * GWEI, 2 * GWEI);
        let mut bumps = 0;
        while let Ok(Some(next)) = plan(FeePlan::Bump(current), Some(GWEI), false, None) {
            assert!(is_valid_bump(current, next));
            assert!(next.max_fee <= caps.max_fee && next.tip <= caps.tip);
            current = next;
            bumps += 1;
        }
        assert!(bumps >= 7, "only {bumps} replacements before a cap");
        // Then the last two replacements wait for the critical threshold.
        assert!(current.tip <= reserve(reserve(caps)).tip);
        assert_eq!(
            plan(FeePlan::Bump(current), Some(GWEI), false, None),
            Ok(None)
        );
        let first = plan(FeePlan::Bump(current), Some(GWEI), true, None)
            .unwrap()
            .unwrap();
        assert_eq!(first, reserve(caps));
        assert_eq!(
            plan(FeePlan::Bump(first), Some(GWEI), true, None),
            Ok(Some(caps))
        );
        // A pending bid below the base fee spends the reserve for inclusion.
        assert_eq!(
            plan(
                FeePlan::Bump(fees(50 * GWEI, 8 * GWEI)),
                Some(55 * GWEI),
                false,
                None
            ),
            Ok(Some(reserve(caps)))
        );
        // Re-sending a dropped bid needs no bump but follows the base fee.
        assert_eq!(
            plan(
                FeePlan::Resend(fees(4 * GWEI, 2 * GWEI)),
                Some(10 * GWEI),
                false,
                None
            ),
            Ok(Some(fees(22 * GWEI, 2 * GWEI)))
        );
        // The balance clamp keeps a valid bid or reports the shortfall.
        assert_eq!(
            plan(FeePlan::First, Some(GWEI), false, Some(3 * GWEI)),
            Ok(Some(fees(3 * GWEI, 2 * GWEI)))
        );
        assert_eq!(
            plan(FeePlan::First, Some(GWEI), false, Some(GWEI / 2)),
            Err(BlockedReason::InsufficientBalance)
        );
        assert_eq!(
            plan(
                FeePlan::Bump(fees(4 * GWEI, 2 * GWEI)),
                Some(GWEI),
                false,
                Some(4_200_000_000)
            ),
            Err(BlockedReason::InsufficientBalance)
        );

        // The transaction fee ceiling bounds every bid like a lower fee cap:
        // 1 ether over a real challenge's 7,534,341 gas is about 132.7 gwei.
        let policy = FeePolicy::new(300 * GWEI, 10 * GWEI);
        let limit = ONE_ETHER / 7_534_341;
        let plan =
            |plan, base, critical| plan_fees(&policy, plan, base, critical, Some(limit), None);
        let ceiling = fees(limit, 10 * GWEI);
        assert_eq!(
            plan(FeePlan::First, Some(70 * GWEI), false),
            Ok(Some(fees(reserve(reserve(ceiling)).max_fee, 2 * GWEI)))
        );
        let critical = plan(FeePlan::First, Some(10 * GWEI), true)
            .unwrap()
            .unwrap();
        assert_eq!(critical, reserve(ceiling));
        assert_eq!(
            plan(FeePlan::Bump(critical), Some(10 * GWEI), true),
            Ok(Some(ceiling))
        );
        assert_eq!(
            plan(FeePlan::Bump(fees(limit, 5 * GWEI)), Some(10 * GWEI), true),
            Err(BlockedReason::TxFeeCapReached)
        );
        // With both fees at their limits the ceiling is named: a higher tip
        // cap alone cannot make a replacement valid. A tip at its cap below
        // the ceiling is the tip cap's.
        assert_eq!(
            plan(FeePlan::Bump(ceiling), Some(10 * GWEI), true),
            Err(BlockedReason::TxFeeCapReached)
        );
        assert_eq!(
            plan(
                FeePlan::Bump(fees(limit / 2, 10 * GWEI)),
                Some(10 * GWEI),
                true
            ),
            Err(BlockedReason::TipCapReached)
        );
        assert_eq!(
            plan(
                FeePlan::Resend(fees(142 * GWEI, 2 * GWEI)),
                Some(10 * GWEI),
                false
            ),
            Ok(Some(fees(limit, 2 * GWEI)))
        );
        assert_eq!(
            plan(FeePlan::First, Some(140 * GWEI), false),
            Err(BlockedReason::TxFeeCapReached)
        );
        assert_eq!(
            plan(FeePlan::First, Some(301 * GWEI), true),
            Err(BlockedReason::BaseFeeAboveFeeCap)
        );
        // A legacy transaction bids its gas price as both fees.
        assert_eq!(
            transaction_fees(&json!({ "gasPrice": "0x2540be400" })),
            Some(fees(10 * GWEI, 10 * GWEI))
        );
        assert_eq!(
            transaction_fees(
                &json!({ "maxFeePerGas": "0x3", "maxPriorityFeePerGas": "0x2", "gasPrice": "0x1" })
            ),
            Some(fees(3, 2))
        );
    }

    #[tokio::test]
    async fn send_errors_are_classified_by_broadcast_risk() {
        let rpc = |error: Value| {
            anyhow::Error::from(RpcError {
                method: "eth_sendTransaction".into(),
                error,
            })
        };
        let classify = |error: Value| classify_send_error(&rpc(error));
        assert!(matches!(
            classify(json!({ "code": -32602, "message": "m", "data": { "reason": "fee_out_of_bounds" } })),
            SendFailure::Refused(Some(reason)) if reason == "fee_out_of_bounds"
        ));
        assert!(matches!(
            classify(
                json!({ "code": -32003, "message": "m", "data": { "reason": "insufficient_balance" } })
            ),
            SendFailure::Refused(Some(_))
        ));
        assert!(matches!(
            classify(json!({ "code": -32601, "message": "m" })),
            SendFailure::Refused(None)
        ));
        // The signer's and its node's transaction fee caps refuse before any
        // pool, each under its own reason.
        for (reason, blocked) in [
            ("tx_fee_above_cap", BlockedReason::TxFeeAboveCap),
            ("upstream_tx_fee_cap", BlockedReason::UpstreamTxFeeCap),
            ("base_fee_above_max_fee", BlockedReason::BaseFeeAboveMaxFee),
            ("insufficient_balance", BlockedReason::InsufficientBalance),
            ("fee_out_of_bounds", BlockedReason::SignerRefused),
        ] {
            assert!(matches!(
                classify(json!({ "code": -32003, "message": "m", "data": { "reason": reason } })),
                SendFailure::Refused(Some(refused)) if refused == reason
            ));
            assert_eq!(refusal_reason(Some(reason)), blocked);
        }
        let capped = |data: Value| rpc(json!({ "code": -32003, "message": "m", "data": data }));
        assert_eq!(
            refused_tx_fee_cap(
                &capped(
                    json!({ "reason": "tx_fee_above_cap", "gas_limit": "0x72f6c5",
                    "tx_fee_cap_wei": "0xde0b6b3a7640000", "max_fee_per_gas_allowed": "0x1ee6c4df42" })
                ),
                1
            ),
            Some(ONE_ETHER)
        );
        assert_eq!(
            refused_tx_fee_cap(
                &capped(json!({ "reason": "tx_fee_above_cap", "max_fee_per_gas_allowed": "0x64" })),
                7
            ),
            Some(700)
        );
        assert_eq!(
            refused_tx_fee_cap(&capped(json!({ "reason": "tx_fee_above_cap" })), 7),
            None
        );
        // The refused fee of upstream_tx_fee_cap: as reported, else the
        // send's own, also for a report that leaves no bound.
        let refused = |data: Value| refused_tx_fee(&capped(data), 7, 100);
        assert_eq!(
            refused(
                json!({ "reason": "upstream_tx_fee_cap", "gas_limit": "0x5", "max_fee_per_gas": "0x40" })
            ),
            320
        );
        assert_eq!(refused(json!({ "reason": "upstream_tx_fee_cap" })), 700);
        for zero in [
            json!({ "reason": "upstream_tx_fee_cap", "gas_limit": "0x0", "max_fee_per_gas": "0x0" }),
            json!({ "reason": "upstream_tx_fee_cap", "max_fee_per_gas": "0x0" }),
            json!({ "reason": "upstream_tx_fee_cap", "gas_limit": "0x1", "max_fee_per_gas": "0x1" }),
        ] {
            assert_eq!(refused(zero.clone()), 700, "{zero}");
        }
        assert!(matches!(
            classify(
                json!({ "code": -32000, "message": "m", "data": { "reason": "simulation_failed" } })
            ),
            SendFailure::NotBroadcast(BlockedReason::SimulationReverted)
        ));
        assert!(matches!(
            classify(
                json!({ "code": -32000, "message": "m", "data": { "reason": "upstream_unavailable" } })
            ),
            SendFailure::NotBroadcast(BlockedReason::RpcError)
        ));
        let hash = format!("0x{}", "ab".repeat(32));
        assert!(matches!(
            classify(json!({ "code": -32000, "message": "m",
                "data": { "reason": "broadcast_ambiguous", "transaction_hash": hash } })),
            SendFailure::Ambiguous(Some(candidate)) if candidate == hash
        ));
        // Anything unrecognised may have broadcast; a malformed hash is ignored.
        assert!(matches!(
            classify(
                json!({ "code": -32000, "message": "m", "data": { "transaction_hash": "0x12" } })
            ),
            SendFailure::Ambiguous(None)
        ));
        assert!(matches!(
            classify(json!({ "code": -32603, "message": "Signer request failed" })),
            SendFailure::Ambiguous(None)
        ));
        // A refused connection never reached the signer; other transport
        // failures (timeouts, HTTP errors) may follow a broadcast.
        let fixture = Fixture::new().await;
        let unreachable =
            fixture.service_with(|config| config.rpc_url = "http://127.0.0.1:9/v3/key".into());
        let error = unreachable
            .rpc("eth_sendTransaction", json!([]))
            .await
            .unwrap_err();
        assert!(!error.to_string().contains("/v3/key"), "{error}");
        assert!(matches!(
            classify_send_error(&error),
            SendFailure::NotBroadcast(BlockedReason::RpcError)
        ));
        fixture.chain.lock().unwrap().fail_all = true;
        let error = fixture
            .service()
            .rpc("eth_sendTransaction", json!([]))
            .await
            .unwrap_err();
        assert!(matches!(
            classify_send_error(&error),
            SendFailure::Ambiguous(None)
        ));
        // Vault custom errors are found in revert data or the message.
        assert_eq!(hex::encode(selector("StaleRoot()")), "607447de");
        let revert = |error: Value| vault_revert(&rpc(error));
        assert_eq!(
            revert(json!({ "code": 3, "message": "execution reverted", "data": "0x607447de" })),
            Some("StaleRoot()")
        );
        assert_eq!(
            revert(
                json!({ "code": -32000, "message": "execution reverted: custom error 0x607447de" })
            ),
            Some("StaleRoot()")
        );
        assert_eq!(
            revert(json!({ "code": -32000, "message": "m", "data": {
                "data": format!("0x{}", hex::encode(selector("NotPendingWithdrawal()"))) } })),
            Some("NotPendingWithdrawal()")
        );
        assert_eq!(
            revert(
                json!({ "code": -32000, "message": "Upstream RPC rejected the request",
                "data": { "reason": "upstream_rejected" } })
            ),
            None
        );
        // Withdrawal-only errors are never named for a challenge.
        for signature in ["UnknownRoot()", "ChallengedNullifier()"] {
            let data = format!("0x{}", hex::encode(selector(signature)));
            assert_eq!(
                revert(json!({ "code": 3, "message": "execution reverted", "data": data })),
                None
            );
        }
    }

    #[tokio::test]
    async fn missed_deadline_behind_a_blocked_nonce_is_recorded() {
        let fixture = Fixture::new().await;
        let mut service = fixture.service();
        // Note 1 holds an unresolved reserved nonce and its state is unreadable,
        // so the loop stops before note 0, whose deadline passes meanwhile.
        fixture.reserve(&mut service, 1, false);
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.fail_note_one = true;
            chain.head_timestamp = chain.deadline;
        }
        assert!(service
            .poll_once()
            .await
            .unwrap_err()
            .to_string()
            .contains("temporary note-state failure"));
        assert!(fixture.sends().is_empty());
        assert!(service.checkpoint.pending[&0].deadline_reported);
        let status = service.status();
        assert_eq!(obligation(&status, 0).state, ObligationState::Missed);
        assert_eq!(status.missed_total, 1);
        assert_eq!(
            obligation(&status, 1).blocked_reason,
            Some(BlockedReason::RpcError)
        );
        drop(service);
        assert_eq!(fixture.service().checkpoint.missed_total, 1, "persisted");
    }

    /// The recorded miss of note 0: counted once, with a critical alarm.
    fn assert_missed_once(status: &ChallengeStatus, nullifier: Felt252, deadline: u64) {
        assert_eq!(status.missed_total, 1, "{status:?}");
        let missed = status.last_missed.as_ref().unwrap();
        assert_eq!(
            (missed.note_id, missed.nullifier, missed.challenge_deadline),
            (0, nullifier, deadline)
        );
        assert_eq!(status.status, Severity::Critical, "{:?}", status.alarms);
        assert!(
            status
                .alarms
                .iter()
                .any(|alarm| alarm.starts_with("critical: missed challenge deadline of note 0")),
            "{:?}",
            status.alarms
        );
    }

    #[tokio::test]
    async fn escape_paid_out_in_the_first_deadline_block_is_recorded_missed() {
        for legacy in [false, true] {
            let fixture = Fixture::new().await;
            // Every defeat simulation reverts, so the defeat stays blocked
            // into the critical threshold.
            let (nullifier, deadline) = {
                let mut chain = fixture.chain.lock().unwrap();
                chain.simulation_error =
                    Some(json!({ "code": -32000, "message": "execution reverted" }));
                chain.legacy_vault = legacy;
                chain.head_timestamp = chain.deadline - 5;
                (chain.nullifier, chain.deadline)
            };
            let mut service = fixture.service();
            assert!(service.poll_once().await.is_err());
            let blocked = obligation(&service.status(), 0);
            assert_eq!(blocked.state, ObligationState::Ready);
            assert_eq!(blocked.severity, Severity::Critical);
            // The escaper finalizes in the first block at the deadline: gone
            // at the latest block, still pending at confirmation depth.
            {
                let mut chain = fixture.chain.lock().unwrap();
                chain.head_number += 1;
                chain.head_timestamp = deadline;
                let block = chain.head_number;
                chain.pay_out(block);
                chain.confirmed_active = true;
            }
            service.poll_once().await.unwrap();
            let status = service.status();
            let paid = obligation(&status, 0);
            assert_eq!(paid.state, ObligationState::ResolvedUnconfirmed);
            assert_eq!(paid.severity, Severity::Critical, "legacy {legacy}");
            assert_eq!(status.status, Severity::Critical);
            assert_eq!(status.missed_total, 0);
            // At confirmation depth the payout is recorded as a miss, once.
            {
                let mut chain = fixture.chain.lock().unwrap();
                chain.head_number += 2;
                chain.confirmed_active = false;
            }
            service.poll_once().await.unwrap();
            assert!(service.checkpoint.pending.is_empty());
            assert_missed_once(&service.status(), nullifier, deadline);
            // Told by challengedNullifiers, or on a legacy vault by the log.
            assert_eq!(
                service.status().last_missed.unwrap().reason,
                "defeat not mined before the deadline: verified evidence at the successor nullifier existed"
            );
            service.poll_once().await.unwrap();
            assert_eq!(service.status().missed_total, 1);
            drop(service);
            let mut restarted = fixture.service();
            restarted.poll_once().await.unwrap();
            assert_missed_once(&restarted.status(), nullifier, deadline);
            assert!(fixture.sends().is_empty());
        }
    }

    #[tokio::test]
    async fn escape_paid_out_while_the_daemon_was_down_is_recorded_missed_once() {
        let fixture = Fixture::new().await;
        let (nullifier, deadline) = {
            let chain = fixture.chain.lock().unwrap();
            (chain.nullifier, chain.deadline)
        };
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        assert_eq!(fixture.sends().len(), 1);
        drop(service);
        // While the daemon is down its challenge reverts, consuming the
        // nonce, the deadline passes and the escaper is paid out.
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.mined_nonce = 4;
            chain.confirmed_nonce = Some(4);
            chain.head_number += 10;
            chain.head_timestamp = deadline + 60;
            let block = chain.head_number - 5;
            chain.pay_out(block);
        }
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        assert!(service.checkpoint.pending.is_empty());
        assert_missed_once(&service.status(), nullifier, deadline);
        drop(service);
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        assert_missed_once(&service.status(), nullifier, deadline);
        // A replay of the deployment's events tracks the escape again; it
        // is not counted again.
        fixture.chain.lock().unwrap().block_hash = "0xforkB".into();
        service.poll_once().await.unwrap();
        assert!(service.checkpoint.pending.is_empty());
        assert_missed_once(&service.status(), nullifier, deadline);
        assert_eq!(fixture.sends().len(), 1);
    }

    #[tokio::test]
    async fn escape_first_seen_after_its_payout_is_recorded_missed() {
        // A legacy vault whose logs lack the escape's end: the closed note
        // alone tells, as no challenge is logged.
        for (legacy, logged) in [(false, true), (true, true), (true, false)] {
            let fixture = Fixture::new().await;
            let (nullifier, deadline) = {
                let mut chain = fixture.chain.lock().unwrap();
                chain.legacy_vault = legacy;
                chain.head_timestamp = chain.deadline + 600;
                chain.pay_out(2);
                if !logged {
                    chain.end_logs.clear();
                }
                (chain.nullifier, chain.deadline)
            };
            let mut service = fixture.service();
            service.poll_once().await.unwrap();
            assert!(service.checkpoint.pending.is_empty());
            let status = service.status();
            assert_missed_once(&status, nullifier, deadline);
            assert_eq!(
                status
                    .last_missed
                    .unwrap()
                    .reason
                    .contains("no defeat of the escape is logged"),
                !logged
            );
            assert!(fixture.sends().is_empty());
        }
    }

    #[tokio::test]
    async fn a_missed_escape_tracked_again_is_never_counted_twice() {
        let fixture = Fixture::new().await;
        let (nullifier, deadline) = {
            let mut chain = fixture.chain.lock().unwrap();
            chain.simulation_error =
                Some(json!({ "code": -32000, "message": "execution reverted" }));
            chain.head_timestamp = chain.deadline;
            (chain.nullifier, chain.deadline)
        };
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        assert_missed_once(&service.status(), nullifier, deadline);
        // A replay of an earlier escape of the note replaces the obligation,
        // then tracks the vault's escape afresh, still past its deadline.
        service.checkpoint.pending.remove(&0);
        service.track_escape(0, nullifier, Some(deadline), None);
        service.persist().unwrap();
        service.poll_once().await.unwrap();
        assert_eq!(
            obligation(&service.status(), 0).state,
            ObligationState::Missed
        );
        assert_missed_once(&service.status(), nullifier, deadline);
        drop(service);
        // A checkpoint from the previous release records its misses only in
        // last_missed (or on the obligation, which is retired here).
        std::fs::write(
            &fixture.config.checkpoint,
            serde_json::to_vec(&json!({
                "sender": "0x0000000000000000000000000000000000000001",
                "chain_id": 1, "contract_address": fixture.config.contract_address,
                "from_block": 0, "next_block": 0, "last_block_hash": null,
                "pending": {}, "detached_nonces": {}, "missed_total": 1,
                "last_missed": { "note_id": 0, "nullifier": nullifier, "challenge_deadline": deadline,
                    "reason": "defeat not mined before the deadline: verified evidence at the successor nullifier existed", "recorded_at": unix_now() }
            }))
            .unwrap(),
        )
        .unwrap();
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        assert_eq!(
            obligation(&service.status(), 0).state,
            ObligationState::Missed
        );
        assert_missed_once(&service.status(), nullifier, deadline);
    }

    #[tokio::test]
    async fn an_unreadable_evidence_database_at_retirement_defers_the_payout_decision() {
        // An honest exit seen expired without evidence at its deadline, and
        // an evidenced escape first seen after its payout.
        for evidenced in [false, true] {
            let (_, request) = finalized_v2_request().await;
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("server.db");
            let server = NullifierStore::new(&path).unwrap();
            if evidenced {
                server.reserve_openrouter_lease(&request).unwrap();
                server
                    .finalize(
                        &request.public_inputs.request_nullifier,
                        &finalized_transcript(&request, 1),
                    )
                    .unwrap();
            }
            let reader = Arc::new(NullifierStore::open_read_only(&path).unwrap());
            let fixture = Fixture::with_store(reader, &request).await;
            let database = rusqlite::Connection::open(&path).unwrap();
            let (nullifier, deadline) = {
                let mut chain = fixture.chain.lock().unwrap();
                chain.head_timestamp = chain.deadline + 60;
                (chain.nullifier, chain.deadline)
            };
            let mut service = fixture.service();
            if !evidenced {
                service.poll_once().await.unwrap();
                assert_eq!(
                    obligation(&service.status(), 0).state,
                    ObligationState::ExpiredNothingDue
                );
            }
            {
                let mut chain = fixture.chain.lock().unwrap();
                chain.head_number += 3;
                let block = chain.head_number - 2;
                chain.pay_out(block);
            }
            // The evidence database cannot be read when the payout is found.
            database
                .execute_batch("ALTER TABLE request_evidence RENAME TO hidden;")
                .unwrap();
            for _ in 0..2 {
                let error = service.poll_once().await.unwrap_err().to_string();
                assert!(error.contains("evidence database read failed"), "{error}");
                assert!(
                    service.checkpoint.pending.contains_key(&0),
                    "kept until it reads"
                );
                let status = service.status();
                assert_eq!(status.missed_total, 0, "evidenced {evidenced}");
                assert!(status.last_missed.is_none());
                let unreadable = obligation(&status, 0);
                assert_eq!(unreadable.state, ObligationState::ResolvedUnconfirmed);
                assert_eq!(
                    unreadable.blocked_reason,
                    Some(BlockedReason::EvidenceDbError)
                );
            }
            database
                .execute_batch("ALTER TABLE hidden RENAME TO request_evidence;")
                .unwrap();
            service.poll_once().await.unwrap();
            assert!(service.checkpoint.pending.is_empty());
            let status = service.status();
            if evidenced {
                assert_missed_once(&status, nullifier, deadline);
                let last = status.last_missed.unwrap();
                assert_eq!(
                    last.reason,
                    "defeat not mined before the deadline: verified evidence at the successor nullifier existed"
                );
                assert_eq!(last.kind, Some(CallKind::Defeat));
                assert_eq!(status.escapes_finalized_with_successor_evidence_total, 1);
            } else {
                assert_eq!(status.missed_total, 0);
                assert!(status.last_missed.is_none());
                assert_eq!(status.status, Severity::Ok, "{:?}", status.alarms);
            }
        }
    }

    /// A checkpoint of the previous release with two misses counted, note
    /// 7's last (recorded at `recorded_at`), and no nullifier recorded for
    /// the other. `cursor` is its `next_block` and `last_block_hash`, none
    /// once reset for a replay.
    fn write_legacy_checkpoint(
        fixture: &Fixture,
        cursor: Option<(u64, &str)>,
        pending: Value,
        recorded_at: u64,
    ) {
        write_legacy_checkpoint_with_deadline(fixture, cursor, pending, recorded_at, 1);
    }

    /// `write_legacy_checkpoint` whose last miss had `last_deadline`.
    fn write_legacy_checkpoint_with_deadline(
        fixture: &Fixture,
        cursor: Option<(u64, &str)>,
        pending: Value,
        recorded_at: u64,
        last_deadline: u64,
    ) {
        let (next_block, hash) = cursor.map_or((0, None), |(next, hash)| (next, Some(hash)));
        std::fs::write(
            &fixture.config.checkpoint,
            serde_json::to_vec(&json!({
                "sender": "0x0000000000000000000000000000000000000001",
                "chain_id": 1, "contract_address": fixture.config.contract_address,
                "from_block": 0, "next_block": next_block, "last_block_hash": hash,
                "pending": pending, "detached_nonces": {}, "missed_total": 2,
                "last_missed": { "note_id": 7, "nullifier": Felt252::from_u64(77),
                    "challenge_deadline": last_deadline,
                    "reason": "defeat not mined before the deadline: verified evidence at the successor nullifier existed",
                    "recorded_at": recorded_at }
            }))
            .unwrap(),
        )
        .unwrap();
    }

    #[tokio::test]
    async fn a_replay_never_counts_again_a_miss_an_earlier_release_counted() {
        let day_ago = unix_now() - 86_400;
        let missed_note = |status: &ChallengeStatus| status.last_missed.as_ref().unwrap().note_id;
        // Note 0's escape is that other miss: its deadline two days ago, paid
        // out and retired before the upgrade, tracked again by a replay, from
        // a cursor reset for one or from a reorganized one above its event.
        for cursor in [None, Some((3, "0xreorged"))] {
            let fixture = Fixture::new().await;
            let nullifier = {
                let mut chain = fixture.chain.lock().unwrap();
                chain.deadline = unix_now() - 2 * 86_400;
                chain.head_timestamp = unix_now();
                chain.pay_out(2);
                chain.nullifier
            };
            write_legacy_checkpoint(&fixture, cursor, json!({}), day_ago);
            let mut service = fixture.service();
            service.poll_once().await.unwrap();
            assert_eq!(service.checkpoint.next_block, 4, "replayed");
            assert!(service.checkpoint.pending.is_empty());
            let status = service.status();
            assert_eq!(status.missed_total, 2, "cursor {cursor:?}");
            assert_eq!(missed_note(&status), 7);
            assert_ne!(status.status, Severity::Critical, "{:?}", status.alarms);
            assert_eq!(service.checkpoint.missed_nullifiers.len(), 2);
            assert!(service.checkpoint.missed_nullifiers.contains(&nullifier));
            // Another replay, after a restart, finds it counted.
            drop(service);
            fixture.chain.lock().unwrap().block_hash = "0xforkB".into();
            let mut service = fixture.service();
            service.poll_once().await.unwrap();
            service.poll_once().await.unwrap();
            assert!(service.checkpoint.pending.is_empty());
            assert_eq!(service.status().missed_total, 2);
        }

        // The earlier release can have counted an escape whose deadline came
        // up to LEGACY_MISS_CLOCK_MARGIN_SECONDS after its last miss was
        // recorded (a chain clock ahead of its own), or up to that miss's
        // own deadline if later: such a payout, tracked again by a replay
        // from a cursor reset for one, is not counted again.
        let now = unix_now();
        for (recorded_at, last_deadline, deadline) in [
            (now - 600, now - 700, now - 400),
            (now - 5_000, now - 1_000, now - 2_000),
        ] {
            let fixture = Fixture::new().await;
            let nullifier = {
                let mut chain = fixture.chain.lock().unwrap();
                chain.deadline = deadline;
                chain.head_timestamp = now;
                chain.pay_out(2);
                chain.nullifier
            };
            write_legacy_checkpoint_with_deadline(
                &fixture,
                None,
                json!({}),
                recorded_at,
                last_deadline,
            );
            let mut service = fixture.service();
            service.poll_once().await.unwrap();
            let case = format!("recorded {recorded_at} last {last_deadline} deadline {deadline}");
            assert!(service.checkpoint.pending.is_empty(), "{case}");
            let status = service.status();
            assert_eq!(status.missed_total, 2, "{case}");
            assert_eq!(missed_note(&status), 7, "{case}");
            assert!(
                service.checkpoint.missed_nullifiers.contains(&nullifier),
                "{case}"
            );
        }

        // An escape pending at the upgrade, whose deadline passed while the
        // daemon was down, is a miss of its own, also when its deadline is
        // within that bound: the earlier release's last miss was recorded
        // minutes before the upgrade.
        for (recorded_at, deadline) in [(day_ago, None), (now - 600, Some(now - 300))] {
            let fixture = Fixture::new().await;
            let (nullifier, deadline) = {
                let mut chain = fixture.chain.lock().unwrap();
                if let Some(deadline) = deadline {
                    chain.deadline = deadline;
                }
                chain.head_timestamp = chain.deadline + 600;
                chain.pay_out(2);
                (chain.nullifier, chain.deadline)
            };
            write_legacy_checkpoint(
                &fixture,
                None,
                json!({ "0": { "nullifier": nullifier, "challenge_deadline": deadline,
                    "deadline_reported": false } }),
                recorded_at,
            );
            let mut service = fixture.service();
            service.poll_once().await.unwrap();
            assert!(service.checkpoint.pending.is_empty());
            let status = service.status();
            assert_eq!(status.missed_total, 3, "recorded {recorded_at}");
            assert_eq!(missed_note(&status), 0);
            assert_eq!(status.status, Severity::Critical);
        }

        // So is an escape whose deadline passes after the upgrade, also when
        // the last miss was recorded within the margin before it: the bound
        // is at most the first head's timestamp.
        for recorded_at in [day_ago, now - 60] {
            let fixture = Fixture::new().await;
            fixture.chain.lock().unwrap().simulation_error =
                Some(json!({ "code": -32000, "message": "execution reverted" }));
            write_legacy_checkpoint(&fixture, None, json!({}), recorded_at);
            let mut service = fixture.service();
            assert!(service.poll_once().await.is_err());
            assert!(service.checkpoint.pending.contains_key(&0));
            {
                let mut chain = fixture.chain.lock().unwrap();
                chain.head_number += 3;
                chain.head_timestamp = chain.deadline + 60;
                let block = chain.head_number - 2;
                chain.pay_out(block);
            }
            service.poll_once().await.unwrap();
            assert!(service.checkpoint.pending.is_empty());
            let status = service.status();
            assert_eq!(status.missed_total, 3, "recorded {recorded_at}");
            assert_eq!(missed_note(&status), 0);
        }
    }

    #[tokio::test]
    async fn a_payout_the_earlier_release_cannot_have_counted_is_counted() {
        // Two misses of the previous release, one without its nullifier, and
        // an escape of note 0 paid out past its deadline that it never
        // counted, which the upgraded daemon finds gone:
        // - initiated and paid out while it was down, beyond the cursor it
        //   left intact (no replay): with its deadline after that release's
        //   last recorded miss, and before it, when only the cursor tells;
        // - one it had scanned, tracked again by a replay, from a reorganized
        //   cursor above its event or one reset for a replay, whose deadline
        //   came after its last recorded miss.
        let now = unix_now();
        let cases = [
            (Some((1, "0xforkA")), now + 100, now - 86_400),
            (Some((1, "0xforkA")), now - 2 * 86_400, now - 86_400),
            (Some((3, "0xreorged")), now - 2 * 86_400, now - 3 * 86_400),
            (None, now - 2 * 86_400, now - 3 * 86_400),
        ];
        for (cursor, deadline, recorded_at) in cases {
            let fixture = Fixture::new().await;
            let nullifier = {
                let mut chain = fixture.chain.lock().unwrap();
                chain.deadline = deadline;
                chain.head_timestamp = deadline.max(now) + 600;
                chain.pay_out(2);
                chain.nullifier
            };
            write_legacy_checkpoint(&fixture, cursor, json!({}), recorded_at);
            let mut service = fixture.service();
            service.poll_once().await.unwrap();
            let case = format!("cursor {cursor:?} deadline {deadline} recorded {recorded_at}");
            assert!(service.checkpoint.pending.is_empty(), "{case}");
            let status = service.status();
            assert_eq!(status.missed_total, 3, "{case}");
            let missed = status.last_missed.as_ref().unwrap();
            assert_eq!((missed.note_id, missed.nullifier), (0, nullifier), "{case}");
            assert_eq!(missed.challenge_deadline, deadline, "{case}");
            assert_eq!(status.status, Severity::Critical, "{case}");
            assert!(
                status
                    .alarms
                    .iter()
                    .any(|alarm| alarm.starts_with("critical: missed challenge deadline of note 0")),
                "{case}: {:?}",
                status.alarms
            );
            // The miss without a nullifier stays unattributed.
            assert_eq!(service.checkpoint.missed_nullifiers.len(), 2, "{case}");
            assert_eq!(service.checkpoint.unattributed_misses(), 1, "{case}");
        }
    }

    #[tokio::test]
    async fn an_escape_ended_before_its_deadline_is_never_shown_as_a_possible_payout() {
        let fixture = Fixture::new().await;
        let mut service = fixture.service();
        // Note 1 holds an expired obligation's unmined reserved nonce, so
        // the queue is blocked and note 0 is only observed.
        fixture.reserve(&mut service, 1, true);
        {
            let mut chain = fixture.chain.lock().unwrap();
            // Inside the critical threshold.
            chain.deadline = chain.head_timestamp + 5;
            // A third party challenged note 0's escape.
            chain.active = false;
            chain.confirmed_active = false;
            let nullifier = chain.nullifier;
            chain.challenged.insert(nullifier);
            chain.end_logs.push((3, 0, nullifier, false));
        }
        // Also once the head, and the wall clock, pass the deadline.
        for round in 0..3 {
            assert!(service.poll_once().await.is_err());
            let status = service.status();
            assert_eq!(
                obligation(&status, 1).blocked_reason,
                Some(BlockedReason::NonceBlocked)
            );
            let ended = obligation(&status, 0);
            assert_eq!(ended.state, ObligationState::ResolvedUnconfirmed);
            assert_eq!(ended.evidence, None);
            assert_eq!(ended.severity, Severity::Ok, "round {round}");
            assert!(
                !status.alarms.iter().any(|alarm| alarm.contains("note 0")),
                "{:?}",
                status.alarms
            );
            // Only note 1's expiry, with evidence, is a miss.
            assert_eq!(status.missed_total, 1);
            assert_eq!(status.last_missed.as_ref().unwrap().note_id, 1);
            let mut chain = fixture.chain.lock().unwrap();
            chain.head_number += 1;
            chain.head_timestamp += 10;
        }
        assert!(service.checkpoint.pending[&0].ended_before_deadline);
        // Seen pending again (a reorganization), it is an escape to challenge.
        fixture.chain.lock().unwrap().active = true;
        let _ = service.poll_once().await;
        assert!(!service.checkpoint.pending[&0].ended_before_deadline);

        // Retirement past the deadline still reads how the escape ended: a
        // reorganization took out the challenge seen before the deadline and
        // the escaper was paid out before the next poll.
        let fixture = Fixture::new().await;
        let (nullifier, deadline) = {
            let mut chain = fixture.chain.lock().unwrap();
            chain.head_timestamp = chain.deadline - 30;
            (chain.nullifier, chain.deadline)
        };
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        assert_eq!(fixture.sends().len(), 1);
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.head_number += 1;
            chain.active = false;
            chain.mined_nonce = 4;
        }
        service.poll_once().await.unwrap();
        assert!(service.checkpoint.pending[&0].ended_before_deadline);
        assert_eq!(obligation(&service.status(), 0).severity, Severity::Ok);
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.head_number += 3;
            chain.head_timestamp = deadline + 30;
            let block = chain.head_number - 2;
            chain.pay_out(block);
        }
        service.poll_once().await.unwrap();
        assert!(service.checkpoint.pending.is_empty());
        assert_missed_once(&service.status(), nullifier, deadline);
    }

    #[tokio::test]
    async fn outcome_log_search_is_bounded_per_poll_and_resumes_after_restart() {
        let fixture = Fixture::new().await;
        let (nullifier, deadline) = {
            let mut chain = fixture.chain.lock().unwrap();
            chain.legacy_vault = true;
            chain.head_number = 20_000;
            chain.head_timestamp = chain.deadline + 600;
            chain.pay_out(17_000);
            (chain.nullifier, chain.deadline)
        };
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        // Initiated in block 0 per the scan: eight log ranges per poll.
        assert_eq!(
            service.checkpoint.pending[&0].outcome_search_from,
            Some(8_000)
        );
        let status = service.status();
        let searching = obligation(&status, 0);
        assert_eq!(searching.state, ObligationState::ResolvedUnconfirmed);
        assert_eq!(searching.severity, Severity::Critical);
        assert_eq!(status.missed_total, 0);
        drop(service);
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        assert_eq!(
            service.checkpoint.pending[&0].outcome_search_from,
            Some(16_000)
        );
        service.poll_once().await.unwrap();
        assert!(service.checkpoint.pending.is_empty());
        let status = service.status();
        assert_missed_once(&status, nullifier, deadline);
        assert_eq!(
            status.last_missed.unwrap().reason,
            "defeat not mined before the deadline: verified evidence at the successor nullifier existed"
        );
        // An escape read pending above the confirmed block (an RPC whose block
        // number lags) is searched only once that block is confirmed.
        let fixture = Fixture::new().await;
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.legacy_vault = true;
            chain.head_timestamp = chain.deadline + 600;
            chain.head_number = 40;
            chain.pay_out(41);
        }
        service.checkpoint.pending.get_mut(&0).unwrap().seen_block = Some(40);
        service.poll_once().await.unwrap();
        let status = service.status();
        assert_eq!(
            obligation(&status, 0).state,
            ObligationState::ResolvedUnconfirmed
        );
        assert_eq!(status.missed_total, 0);
        fixture.chain.lock().unwrap().head_number = 43;
        service.poll_once().await.unwrap();
        assert!(service.checkpoint.pending.is_empty());
        assert_eq!(
            service.status().last_missed.unwrap().reason,
            "defeat not mined before the deadline: verified evidence at the successor nullifier existed"
        );
    }

    #[tokio::test]
    async fn a_challenged_or_unevidenced_escape_is_never_recorded_missed() {
        // Our challenge succeeds just before the deadline; the note is closed
        // later, before the obligation retires after the deadline. On a
        // hardened vault challengedNullifiers tells, on a legacy one the
        // Challenged log does (a third party's challenge alike).
        for legacy in [false, true] {
            let fixture = Fixture::new().await;
            let mut service = fixture.service();
            service.poll_once().await.unwrap();
            assert_eq!(fixture.sends().len(), 1);
            {
                let mut chain = fixture.chain.lock().unwrap();
                chain.legacy_vault = legacy;
                chain.head_number += 1;
                chain.head_timestamp = chain.deadline - 1;
                chain.active = false;
                chain.mined_nonce = 4;
                let (block, nullifier) = (chain.head_number, chain.nullifier);
                chain.challenged.insert(nullifier);
                chain.end_logs.push((block, 0, nullifier, false));
            }
            service.poll_once().await.unwrap();
            let status = service.status();
            let challenged = obligation(&status, 0);
            assert_eq!(challenged.state, ObligationState::ResolvedUnconfirmed);
            // Gone at a head before the deadline, it cannot have been paid out.
            assert_eq!(challenged.evidence, None);
            assert_eq!(challenged.severity, Severity::Ok);
            {
                let mut chain = fixture.chain.lock().unwrap();
                chain.head_number += 2;
                chain.head_timestamp = chain.deadline + 30;
                chain.confirmed_active = false;
                chain.confirmed_nonce = Some(4);
                chain.note_status.insert(0, NOTE_CLOSED);
            }
            service.poll_once().await.unwrap();
            assert!(service.checkpoint.pending.is_empty());
            let status = service.status();
            assert_eq!(status.missed_total, 0, "legacy {legacy}");
            assert_eq!(status.status, Severity::Ok, "{:?}", status.alarms);
        }
        // An escape without evidence (an honest exit) is paid out unreported.
        let (_, request) = finalized_v2_request().await;
        let store = Arc::new(NullifierStore::in_memory().unwrap());
        let fixture = Fixture::with_store(store, &request).await;
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.head_timestamp = chain.deadline + 600;
            chain.pay_out(2);
        }
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        assert!(service.checkpoint.pending.is_empty());
        let status = service.status();
        assert_eq!(status.missed_total, 0);
        assert_eq!(status.status, Severity::Ok, "{:?}", status.alarms);
    }

    /// Note 9 holds nonce 5, reserved without a known hash, for a live
    /// escape without evidence: every poll stops there, so note 0 is only
    /// observed.
    fn block_queue(fixture: &Fixture, service: &mut ChallengeService) {
        let blocker = Felt252::from_u64(12345);
        {
            let mut chain = fixture.chain.lock().unwrap();
            let deadline = chain.deadline + 10_000;
            chain.withdrawals.insert(9, (true, blocker, deadline));
            // Nothing is due for note 9: its reserved nonce stays unsent.
            chain.concessions.insert(9, (NO_EVIDENCE, 0));
        }
        service.checkpoint.pending.insert(
            9,
            PendingChallenge {
                nullifier: blocker,
                nonce: Some(5),
                ..Default::default()
            },
        );
        service.persist().unwrap();
    }

    #[tokio::test]
    async fn a_payout_behind_a_blocked_queue_is_recorded_missed_when_found() {
        for legacy in [false, true] {
            let fixture = Fixture::new().await;
            let mut service = fixture.service();
            block_queue(&fixture, &mut service);
            let (nullifier, deadline) = {
                let mut chain = fixture.chain.lock().unwrap();
                chain.legacy_vault = legacy;
                chain.head_timestamp = chain.deadline - 5;
                (chain.nullifier, chain.deadline)
            };
            service.poll_once().await.unwrap();
            let queued = obligation(&service.status(), 0);
            assert_eq!(queued.state, ObligationState::Ready);
            assert_eq!(queued.blocked_reason, Some(BlockedReason::NonceBlocked));
            // The escaper is paid out in the first block at the deadline, so
            // no poll sees the escape pending past it.
            {
                let mut chain = fixture.chain.lock().unwrap();
                chain.head_number += 1;
                chain.head_timestamp = deadline;
                let block = chain.head_number;
                chain.pay_out(block);
                chain.confirmed_active = true;
            }
            service.poll_once().await.unwrap();
            let status = service.status();
            assert_eq!(status.missed_total, 0, "legacy {legacy}: unconfirmed");
            assert_eq!(
                obligation(&status, 0).state,
                ObligationState::ResolvedUnconfirmed
            );
            // At confirmation depth the payout is recorded missed while the
            // queue still waits for note 9's nonce; the obligation stays for
            // the loop to retire.
            {
                let mut chain = fixture.chain.lock().unwrap();
                chain.head_number += 2;
                chain.confirmed_active = false;
            }
            for _ in 0..2 {
                service.poll_once().await.unwrap();
                assert!(service.checkpoint.pending.contains_key(&0));
                let status = service.status();
                assert_missed_once(&status, nullifier, deadline);
                assert_eq!(
                    status.last_missed.as_ref().unwrap().reason,
                    "defeat not mined before the deadline: verified evidence at the successor nullifier existed",
                    "legacy {legacy}"
                );
                let missed = obligation(&status, 0);
                assert_eq!(missed.state, ObligationState::Missed);
                assert_eq!(missed.blocked_reason, Some(BlockedReason::NonceBlocked));
                fixture.chain.lock().unwrap().head_number += 1;
            }
            drop(service);
            let mut service = fixture.service();
            service.poll_once().await.unwrap();
            assert_missed_once(&service.status(), nullifier, deadline);
            // Note 9's escape ends with its nonce unmined, which blocks the
            // queue until the signer consumes it; then note 0 retires.
            fixture
                .chain
                .lock()
                .unwrap()
                .withdrawals
                .insert(9, (false, Felt252::from_u64(12345), deadline + 10_000));
            for _ in 0..2 {
                let _ = service.poll_once().await;
                assert_missed_once(&service.status(), nullifier, deadline);
            }
            assert!(service.checkpoint.pending.contains_key(&0));
            {
                let mut chain = fixture.chain.lock().unwrap();
                chain.mined_nonce = 6;
                chain.confirmed_nonce = Some(6);
            }
            service.poll_once().await.unwrap();
            assert!(service.checkpoint.pending.is_empty());
            assert_missed_once(&service.status(), nullifier, deadline);
            assert!(fixture.sends().is_empty());
        }
    }

    #[tokio::test]
    async fn a_latest_read_behind_the_head_never_records_a_challenge_missed() {
        // Our challenge, or behind a blocked queue a third party's, mines in
        // the last block before the deadline. The next head, the first block
        // at the deadline, comes from a backend of a load-balanced RPC that
        // has it; one behind it answers the latest-block read with the
        // escape still pending.
        for (legacy, blocked) in [(false, false), (true, false), (false, true), (true, true)] {
            let case = format!("legacy {legacy} blocked {blocked}");
            let fixture = Fixture::new().await;
            let mut service = fixture.service();
            if blocked {
                block_queue(&fixture, &mut service);
            }
            let deadline = {
                let mut chain = fixture.chain.lock().unwrap();
                chain.legacy_vault = legacy;
                chain.head_timestamp = chain.deadline - 13;
                chain.deadline
            };
            service.poll_once().await.unwrap();
            assert_eq!(fixture.sends().len(), usize::from(!blocked), "{case}");
            {
                let mut chain = fixture.chain.lock().unwrap();
                chain.head_number += 2;
                chain.head_timestamp = deadline;
                if !blocked {
                    chain.mined_nonce = 4;
                }
                let (block, nullifier) = (chain.head_number - 1, chain.nullifier);
                chain.challenged.insert(nullifier);
                chain.end_logs.push((block, 0, nullifier, false));
                chain.active = false;
                chain.latest_active = Some(true);
            }
            // A read at the head that the backend cannot serve fails; it is
            // never taken for a pending escape.
            for head_known in [false, true] {
                fixture.chain.lock().unwrap().head_block_unknown = !head_known;
                let result = service.poll_once().await;
                assert_eq!(result.is_ok(), head_known || blocked, "{case}: {result:?}");
                let status = service.status();
                assert_eq!(status.missed_total, 0, "{case}");
                assert!(status.last_missed.is_none(), "{case}");
                assert_ne!(
                    obligation(&status, 0).state,
                    ObligationState::Missed,
                    "{case}"
                );
            }
            // The backend catches up, and the challenge reaches confirmation
            // depth.
            {
                let mut chain = fixture.chain.lock().unwrap();
                chain.latest_active = None;
                chain.confirmed_active = false;
                if !blocked {
                    chain.confirmed_nonce = Some(4);
                }
                chain.head_number += 3;
                chain.head_timestamp += 36;
            }
            for _ in 0..2 {
                service.poll_once().await.unwrap();
                fixture.chain.lock().unwrap().head_number += 1;
            }
            let status = service.status();
            assert_eq!(status.missed_total, 0, "{case}");
            assert!(status.last_missed.is_none(), "{case}");
            if blocked {
                // Known not paid out, it waits for the queue to retire it.
                let ended = obligation(&status, 0);
                assert_eq!(ended.state, ObligationState::ResolvedUnconfirmed);
                assert_eq!(ended.severity, Severity::Ok, "{case}");
                assert!(service.checkpoint.pending[&0].ended_before_deadline);
            } else {
                assert!(service.checkpoint.pending.is_empty(), "{case}");
                assert_eq!(status.status, Severity::Ok, "{case}: {:?}", status.alarms);
            }
        }
    }

    #[tokio::test]
    async fn deployment_binding_must_match_config_and_vault_state_key() {
        let (_, request) = finalized_v2_request().await;
        let store = Arc::new(NullifierStore::in_memory().unwrap());
        let fixture = Fixture::with_store(store.clone(), &request).await;
        let mut service = fixture.service();
        let mismatch = |result: Result<DeploymentBinding, DeploymentCheckError>| match result {
            Err(DeploymentCheckError::Mismatch(message)) => message,
            other => panic!("expected a mismatch, got {other:?}"),
        };
        assert!(
            mismatch(service.verify_deployment_binding().await).contains("no deployment binding")
        );
        assert!(service
            .status()
            .config_warnings
            .iter()
            .any(|warning| warning.contains("deployment binding not verified")));
        let public = &request.public_inputs;
        let binding = DeploymentBinding {
            chain_id: 1,
            contract_address: format!("0x{:040x}", 0xdead),
            state_signing_key: CurvePointWire {
                x: public.state_signing_key_x,
                y: public.state_signing_key_y,
            },
            clearance_signing_key: CurvePointWire {
                x: Felt252::from_u64(1),
                y: Felt252::from_u64(2),
            },
            challenge_period_seconds: 86_400,
            verified_at: 1,
            verified_block: None,
            circuit_id: Some(zkapi_proof::compact::CIRCUIT_ID.into()),
            setup_id: Some("dev".into()),
            request_vk_keccak256: Some(service.identity.request_vk_keccak256.clone()),
            withdrawal_vk_keccak256: Some(service.identity.withdrawal_vk_keccak256.clone()),
            source: crate::nullifier_store::BINDING_SOURCE_VAULT.into(),
        };
        // A database bound to another statement (here, one bound before
        // circuit identifiers were recorded) is refused.
        store
            .write_deployment_binding(&DeploymentBinding {
                circuit_id: None,
                ..binding.clone()
            })
            .unwrap();
        assert!(mismatch(service.verify_deployment_binding().await).contains("another statement"));
        store
            .write_deployment_binding(&DeploymentBinding {
                request_vk_keccak256: Some(format!("0x{}", "11".repeat(32))),
                ..binding.clone()
            })
            .unwrap();
        assert!(
            mismatch(service.verify_deployment_binding().await).contains("request_vk_keccak256")
        );
        store.write_deployment_binding(&binding).unwrap();
        assert_eq!(service.verify_deployment_binding().await.unwrap(), binding);
        assert!(service.status().config_warnings.is_empty());
        for (wrong, message) in [
            (
                DeploymentBinding {
                    chain_id: 11_155_111,
                    ..binding.clone()
                },
                "bound to chain 11155111",
            ),
            (
                DeploymentBinding {
                    contract_address: format!("0x{:040x}", 0xbeef),
                    ..binding.clone()
                },
                "beef",
            ),
        ] {
            store.write_deployment_binding(&wrong).unwrap();
            assert!(mismatch(service.verify_deployment_binding().await).contains(message));
        }
        store.write_deployment_binding(&binding).unwrap();
        fixture.chain.lock().unwrap().state_key.1 = Felt252::from_u64(9);
        assert!(mismatch(service.verify_deployment_binding().await)
            .contains("state signing key differs"));
        fixture.chain.lock().unwrap().fail_all = true;
        assert!(matches!(
            service.verify_deployment_binding().await,
            Err(DeploymentCheckError::Unavailable(_))
        ));
    }

    /// The gas limit of a measured real Groth16 challenge (estimate + 20%).
    const REAL_GAS_LIMIT: u128 = 7_534_341;

    /// Every send kept gas limit x maxFeePerGas within `cap`.
    fn within(sends: &[Value], cap: u128) -> bool {
        sends
            .iter()
            .all(|send| fee(send, "gas") * fee(send, "maxFeePerGas") <= cap)
    }

    /// Mainnet caps of 300 and 10 gwei with the default 1 ether ceiling.
    fn mainnet_fees(config: &mut ChallengeServiceConfig) {
        config.fee = FeePolicy::new(300 * GWEI, 10 * GWEI);
    }

    #[tokio::test]
    async fn rpc_fee_cap_bids_stay_within_the_ceiling_and_later_notes_are_challenged() {
        // A node with the default 1 ether RPC fee cap refuses a costlier bid
        // before its pool; an earlier signer reported that as possibly
        // broadcast, which locked the nonce at the refused fee.
        for refusal in ["broadcast_ambiguous", "tx_fee_above_cap"] {
            let fixture = Fixture::new().await;
            {
                let mut chain = fixture.chain.lock().unwrap();
                chain.tx_fee_cap = Some((ONE_ETHER, refusal));
                chain.estimate = 6_278_618;
                // A Mainnet spike, below the daemon's cap.
                chain.base_fee = Some(70 * GWEI);
                chain.deadline += 10_000;
            }
            let mut service = fixture.service_with(mainnet_fees);
            service.poll_once().await.unwrap();
            fixture.chain.lock().unwrap().drop_logs = true;
            assert!(fee(&fixture.sends()[0], "maxFeePerGas") >= 70 * GWEI);
            // The spike ends; the challenge stays pending meanwhile.
            fixture.chain.lock().unwrap().base_fee = Some(10 * GWEI);
            for _ in 0..20 {
                fixture.chain.lock().unwrap().head_number += 3;
                service.poll_once().await.unwrap();
            }
            // Kept: the spike bid's max fee is at the non-critical limit, so
            // the rest of the headroom is held for the critical threshold.
            let head = obligation(&service.status(), 0);
            assert_eq!(head.state, ObligationState::Submitted, "{refusal}");
            assert_eq!(
                head.blocked_reason,
                Some(BlockedReason::FeeReserveHeld),
                "{refusal}"
            );
            // A later escape is challenged on the next nonce at once.
            let later = fixture.chain.lock().unwrap().deadline + 5_000;
            fixture.track(&mut service, 1, later);
            fixture.chain.lock().unwrap().head_number += 3;
            service.poll_once().await.unwrap();
            let sends = fixture.sends();
            let queued: Vec<_> = sends
                .iter()
                .filter(|send| decode_call(send).0 == Felt252::from_u64(1).as_bytes())
                .collect();
            assert_eq!(queued.len(), 1, "{refusal}");
            assert_eq!(queued[0]["nonce"], "0x4");
            assert!(within(&sends, ONE_ETHER), "{refusal}");
            assert_eq!(fixture.chain.lock().unwrap().fee_capped_sends, 0);
            assert_eq!(service.status().status, Severity::Warning, "{refusal}");
        }
    }

    #[tokio::test]
    async fn a_critical_bid_at_its_ceiling_bound_target_waits_for_the_bump_interval() {
        let fixture = Fixture::new().await;
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.estimate = 6_278_618;
            chain.base_fee = Some(10 * GWEI);
            chain.head_timestamp = chain.deadline - 5;
        }
        let mut service = fixture.service_with(mainnet_fees);
        service.poll_once().await.unwrap();
        let limit = ONE_ETHER / REAL_GAS_LIMIT;
        assert_eq!(fee(&fixture.sends()[0], "maxFeePerGas"), headroom(limit));
        // Far below the 300 gwei fee cap, but at the critical target the
        // ceiling bounds: kept until bump_after_blocks have passed.
        for _ in 0..2 {
            fixture.chain.lock().unwrap().head_number += 1;
            service.poll_once().await.unwrap();
            assert_eq!(fixture.sends().len(), 1);
        }
        fixture.chain.lock().unwrap().head_number += 1;
        service.poll_once().await.unwrap();
        let sends = fixture.sends();
        assert_eq!(sends.len(), 2);
        assert_eq!(fee(&sends[1], "maxFeePerGas"), limit);
    }

    #[tokio::test]
    async fn critical_escalation_stays_within_the_rpc_fee_cap_at_low_base_fee() {
        for refusal in ["broadcast_ambiguous", "tx_fee_above_cap"] {
            let fixture = Fixture::new().await;
            {
                let mut chain = fixture.chain.lock().unwrap();
                chain.tx_fee_cap = Some((ONE_ETHER, refusal));
                chain.estimate = 6_278_618;
                chain.base_fee = Some(10 * GWEI);
                // First seen inside the critical threshold.
                chain.head_timestamp = chain.deadline - 5;
            }
            let mut service = fixture.service_with(mainnet_fees);
            for _ in 0..6 {
                service.poll_once().await.unwrap();
                fixture.chain.lock().unwrap().head_number += 3;
            }
            let sends = fixture.sends();
            assert_eq!(
                fixture.chain.lock().unwrap().fee_capped_sends,
                0,
                "{refusal}"
            );
            // 10/11 of the ceiling's fee per gas, then the ceiling itself.
            let limit = ONE_ETHER / REAL_GAS_LIMIT;
            assert_eq!(sends.len(), 2, "{refusal}");
            assert_eq!(fee(&sends[0], "maxFeePerGas"), headroom(limit));
            assert_eq!(fee(&sends[1], "maxFeePerGas"), limit);
            assert!(within(&sends, ONE_ETHER));
            // Then the pending bid is kept, and the ceiling is reported.
            let capped = obligation(&service.status(), 0);
            assert_eq!(capped.state, ObligationState::Submitted);
            assert_eq!(capped.blocked_reason, Some(BlockedReason::TxFeeCapReached));
            assert!(capped
                .detail
                .unwrap()
                .contains("and the transaction fee ceiling of 1000000000000000000 wei"));
        }
    }

    #[tokio::test]
    async fn signer_tx_fee_cap_bounds_bids_and_its_refusals_are_reported() {
        let half = ONE_ETHER / 2;
        let critical_at_low_base_fee = |chain: &mut MockChain| {
            chain.estimate = 6_278_618;
            chain.base_fee = Some(10 * GWEI);
            chain.head_timestamp = chain.deadline - 5;
        };
        // The signer reports a lower cap: bids stay within it, with a warning.
        let fixture = Fixture::new().await;
        {
            let mut chain = fixture.chain.lock().unwrap();
            critical_at_low_base_fee(&mut chain);
            chain.tx_fee_cap = Some((half, "tx_fee_above_cap"));
            chain.signer_status = Some(json!({ "tx_fee_cap_wei": hex_quantity(half) }));
        }
        let mut service = fixture.service_with(mainnet_fees);
        service.poll_once().await.unwrap();
        let sends = fixture.sends();
        assert_eq!(sends.len(), 1);
        assert_eq!(
            fee(&sends[0], "maxFeePerGas"),
            headroom(half / REAL_GAS_LIMIT)
        );
        let status = service.status();
        assert_eq!(status.sender.tx_fee_cap_wei, ONE_ETHER.to_string());
        assert_eq!(status.sender.signer_tx_fee_cap_wei, Some(half.to_string()));
        assert_eq!(status.sender.effective_tx_fee_cap_wei, half.to_string());
        assert!(status
            .config_warnings
            .iter()
            .any(|warning| warning.contains("differs from --tx-fee-cap-wei")));
        // A zero report is malformed and leaves the cap in force.
        fixture.chain.lock().unwrap().signer_status = Some(json!({ "tx_fee_cap_wei": "0x0" }));
        service.poll_once().await.unwrap();
        let status = service.status();
        assert_eq!(status.sender.effective_tx_fee_cap_wei, half.to_string());
        assert!(status
            .sender
            .signer_status_detail
            .unwrap()
            .contains("zero tx_fee_cap_wei"));

        // A signer that does not report it refuses the bid with its cap: a
        // definitive refusal that bounds the next bid.
        let fixture = Fixture::new().await;
        {
            let mut chain = fixture.chain.lock().unwrap();
            critical_at_low_base_fee(&mut chain);
            chain.tx_fee_cap = Some((half, "tx_fee_above_cap"));
        }
        let mut service = fixture.service_with(mainnet_fees);
        let error = service.poll_once().await.unwrap_err().to_string();
        assert!(error.contains("tx_fee_above_cap"), "{error}");
        assert_eq!(service.checkpoint.pending[&0].nonce, None);
        let refused = obligation(&service.status(), 0);
        assert_eq!(refused.blocked_reason, Some(BlockedReason::TxFeeAboveCap));
        service.poll_once().await.unwrap();
        let sends = fixture.sends();
        assert_eq!(sends.len(), 2);
        assert_eq!(sends[1]["nonce"], "0x3");
        assert!(within(&sends[1..], half));
        assert_eq!(fixture.chain.lock().unwrap().fee_capped_sends, 1);
        assert_eq!(
            service.status().sender.signer_tx_fee_cap_wei,
            Some(half.to_string())
        );

        // Its node's lower RPC fee cap is a definitive refusal too, and needs
        // the operator at once.
        let fixture = Fixture::new().await;
        {
            let mut chain = fixture.chain.lock().unwrap();
            critical_at_low_base_fee(&mut chain);
            chain.tx_fee_cap = Some((half, "upstream_tx_fee_cap"));
        }
        let mut service = fixture.service_with(mainnet_fees);
        assert!(service.poll_once().await.is_err());
        assert_eq!(service.checkpoint.pending[&0].nonce, None);
        let refused = obligation(&service.status(), 0);
        assert_eq!(
            refused.blocked_reason,
            Some(BlockedReason::UpstreamTxFeeCap)
        );
        assert_eq!(refused.severity, Severity::Critical);
    }

    #[tokio::test]
    async fn base_fee_above_the_tx_fee_ceiling_reports_tx_fee_cap_reached() {
        let fixture = Fixture::new().await;
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.tx_fee_cap = Some((ONE_ETHER, "tx_fee_above_cap"));
            chain.estimate = 6_278_618;
            // Above the 132.7 gwei the ceiling allows, below the 300 gwei cap.
            chain.base_fee = Some(140 * GWEI);
        }
        let mut service = fixture.service_with(mainnet_fees);
        service.poll_once().await.unwrap();
        service.poll_once().await.unwrap();
        assert!(fixture.sends().is_empty());
        assert_eq!(service.checkpoint.pending[&0].nonce, None);
        let limit = ONE_ETHER / REAL_GAS_LIMIT;
        let status = service.status();
        let blocked = obligation(&status, 0);
        assert_eq!(blocked.state, ObligationState::Ready);
        assert_eq!(blocked.blocked_reason, Some(BlockedReason::TxFeeCapReached));
        assert!(blocked
            .detail
            .unwrap()
            .contains(&format!("allows a maxFeePerGas of at most {limit} wei")));
        assert!(status.alarms.contains(&format!(
            "warning: transaction fee ceiling {ONE_ETHER} wei allows a maxFeePerGas of at most {limit} wei at {REAL_GAS_LIMIT} gas; base fee {} wei",
            140 * GWEI
        )));
        // A 300 gwei cap is never reached under a 1 ether ceiling.
        assert!(status
            .config_warnings
            .iter()
            .any(|warning| warning.contains("exceeds the transaction fee ceiling")));
        // Once the base fee falls, the challenge is sent within the ceiling.
        fixture.chain.lock().unwrap().base_fee = Some(100 * GWEI);
        service.poll_once().await.unwrap();
        let sends = fixture.sends();
        assert_eq!(sends.len(), 1);
        assert!(within(&sends, ONE_ETHER));
        assert_eq!(fixture.chain.lock().unwrap().fee_capped_sends, 0);
    }

    #[tokio::test]
    async fn bids_above_the_ceiling_are_observed_or_re_planned_never_resent() {
        // A pending challenge bid above the ceiling, for example under an
        // earlier daemon: no replacement fits, so it is kept and observed.
        let fixture = Fixture::new().await;
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.estimate = 6_278_618;
            chain.base_fee = Some(10 * GWEI);
            chain.head_timestamp = chain.deadline - 5;
        }
        let mut service = fixture.service_with(|config| {
            config.fee = FeePolicy {
                tx_fee_cap_wei: 10 * ONE_ETHER,
                ..FeePolicy::new(300 * GWEI, 10 * GWEI)
            }
        });
        service.poll_once().await.unwrap();
        let first = fixture.sends()[0].clone();
        assert!(fee(&first, "gas") * fee(&first, "maxFeePerGas") > ONE_ETHER);
        drop(service);
        fixture.chain.lock().unwrap().tx_fee_cap = Some((ONE_ETHER, "tx_fee_above_cap"));
        let mut service = fixture.service_with(mainnet_fees);
        for _ in 0..3 {
            fixture.chain.lock().unwrap().head_number += 3;
            service.poll_once().await.unwrap();
        }
        assert_eq!(fixture.sends().len(), 1, "no refused bid is re-sent");
        let kept = obligation(&service.status(), 0);
        assert_eq!(kept.state, ObligationState::Submitted);
        assert_eq!(kept.blocked_reason, Some(BlockedReason::TxFeeCapReached));
        assert!(kept.detail.unwrap().contains("transaction fee ceiling"));

        // A nonce an earlier daemon locked at a refused 142 gwei bid, whose
        // candidate hash no node knows: nothing holds it, so it is re-planned
        // within the ceiling.
        let fixture = Fixture::new().await;
        let refused_hash = format!("0x{:064x}", 0xdead_0000_0000u64);
        let nullifier = {
            let mut chain = fixture.chain.lock().unwrap();
            chain.tx_fee_cap = Some((ONE_ETHER, "broadcast_ambiguous"));
            chain.fee_capped_hashes.insert(refused_hash.clone());
            chain.estimate = 6_278_618;
            chain.base_fee = Some(10 * GWEI);
            chain.deadline += 10_000;
            chain.nullifier
        };
        let mut service = fixture.service_with(mainnet_fees);
        service.checkpoint.pending.insert(
            0,
            PendingChallenge {
                nullifier,
                nonce: Some(3),
                attempt: NonceAttempts {
                    superseded_hashes: vec![refused_hash],
                    max_fee_per_gas: Some(format!("0x{:x}", 142 * GWEI)),
                    max_priority_fee_per_gas: Some(format!("0x{:x}", 2 * GWEI)),
                    attempts: 21,
                    ..Default::default()
                },
                ..Default::default()
            },
        );
        service.persist().unwrap();
        service.poll_once().await.unwrap();
        let sends = fixture.sends();
        assert_eq!(sends.len(), 1);
        assert_eq!(sends[0]["nonce"], "0x3");
        assert!(within(&sends, ONE_ETHER));
        assert_eq!(fixture.chain.lock().unwrap().fee_capped_sends, 0);
        // The record now holds that bid, so replacements are planned from it.
        assert_eq!(
            service.persisted_fees(0),
            Some(Fees {
                max_fee: ONE_ETHER / REAL_GAS_LIMIT,
                tip: 2 * GWEI
            })
        );
        assert_eq!(
            obligation(&service.status(), 0).state,
            ObligationState::Submitted
        );
    }

    #[tokio::test]
    async fn not_broadcast_nonce_is_released_and_later_notes_are_challenged() {
        let fixture = Fixture::new().await;
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.base_fee = Some(30 * GWEI);
            chain.send_errors.push_back(json!({
                "code": -32000, "message": "Challenge simulation failed",
                "data": { "reason": "simulation_failed" } }));
        }
        let mut service = fixture.service();
        assert!(service.poll_once().await.is_err());
        fixture.chain.lock().unwrap().drop_logs = true;
        // The signer reports the failure before broadcasting: the fresh
        // nonce is released at once.
        assert_eq!(service.checkpoint.pending[&0].nonce, None);
        // The base fee then stays above the 100 gwei cap until the deadline.
        fixture.chain.lock().unwrap().base_fee = Some(150 * GWEI);
        service.poll_once().await.unwrap();
        let later = fixture.chain.lock().unwrap().deadline + 5_000;
        fixture.track(&mut service, 1, later);
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.head_timestamp = chain.deadline;
        }
        service.poll_once().await.unwrap();
        assert_eq!(
            obligation(&service.status(), 0).state,
            ObligationState::Missed
        );
        // The escaper finalizes, and fees normalise.
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.active = false;
            chain.confirmed_active = false;
            chain.base_fee = Some(10 * GWEI);
            chain.head_number += 3;
        }
        service.poll_once().await.unwrap();
        service.poll_once().await.unwrap();
        let sends = fixture.sends();
        assert_eq!(sends.len(), 2);
        assert_eq!(decode_call(&sends[1]).0, Felt252::from_u64(1).as_bytes());
        assert_eq!(sends[1]["nonce"], "0x3");
        assert!(!service.checkpoint.pending.contains_key(&0));
        let status = service.status();
        assert!(status.detached_nonces.is_empty());
        assert_eq!(obligation(&status, 1).state, ObligationState::Submitted);
        assert_eq!(status.missed_total, 1);
    }

    #[tokio::test]
    async fn never_broadcast_reservations_left_by_an_earlier_daemon_are_released() {
        // The record an earlier daemon kept after attempts that all failed
        // before broadcast.
        let unsent = || NonceAttempts {
            attempts: 1,
            ..Default::default()
        };
        // An expired obligation releases its nonce instead of blocking.
        let fixture = Fixture::new().await;
        let mut service = fixture.service();
        let (nullifier, deadline) = {
            let chain = fixture.chain.lock().unwrap();
            (chain.nullifier, chain.deadline)
        };
        service.checkpoint.pending.insert(
            0,
            PendingChallenge {
                nullifier,
                nonce: Some(3),
                challenge_deadline: Some(deadline),
                attempt: unsent(),
                ..Default::default()
            },
        );
        fixture.track(&mut service, 1, deadline + 1_000);
        fixture.chain.lock().unwrap().head_timestamp = deadline;
        service.poll_once().await.unwrap();
        let sends = fixture.sends();
        assert_eq!(sends.len(), 1);
        assert_eq!(decode_call(&sends[0]).0, Felt252::from_u64(1).as_bytes());
        assert_eq!(sends[0]["nonce"], "0x3");
        assert_eq!(
            obligation(&service.status(), 0).state,
            ObligationState::Missed
        );

        // So does a detached one.
        let fixture = Fixture::new().await;
        let mut service = fixture.service();
        service.checkpoint.detached_nonces.insert(
            3,
            DetachedNonce {
                note_id: 5,
                nullifier: Felt252::from_u64(5),
                transaction_hash: None,
                attempt: unsent(),
            },
        );
        service.persist().unwrap();
        service.poll_once().await.unwrap();
        assert!(service.checkpoint.detached_nonces.is_empty());
        assert!(service.status().detached_nonces.is_empty());
        assert_eq!(fixture.sends().len(), 1);
        assert_eq!(fixture.sends()[0]["nonce"], "0x3");

        // And one whose withdrawal is resolved, instead of detaching it.
        let fixture = Fixture::new().await;
        let mut service = fixture.service();
        let nullifier = fixture.chain.lock().unwrap().nullifier;
        service.checkpoint.pending.insert(
            0,
            PendingChallenge {
                nullifier,
                nonce: Some(3),
                attempt: unsent(),
                ..Default::default()
            },
        );
        service.persist().unwrap();
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.active = false;
            chain.confirmed_active = false;
        }
        service.poll_once().await.unwrap();
        assert!(service.checkpoint.pending.is_empty());
        assert!(service.checkpoint.detached_nonces.is_empty());
        let later = fixture.chain.lock().unwrap().deadline + 1_000;
        fixture.track(&mut service, 1, later);
        service.poll_once().await.unwrap();
        assert_eq!(fixture.sends().len(), 1);
        assert_eq!(fixture.sends()[0]["nonce"], "0x3");

        // A reservation an earlier daemon made without any attempt record is
        // never released, even after a refusal of this daemon's attempt.
        let fixture = Fixture::new().await;
        let mut service = fixture.service();
        fixture.reserve(&mut service, 1, false);
        fixture.chain.lock().unwrap().refuse_notes.insert(1);
        assert!(service.poll_once().await.is_err());
        let held = &service.checkpoint.pending[&1];
        assert_eq!(held.nonce, Some(3));
        assert!(held.attempt.unrecorded_attempt);
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.head_timestamp = chain.deadline;
        }
        assert!(service
            .poll_once()
            .await
            .unwrap_err()
            .to_string()
            .contains("signer intervention required"));
        assert_eq!(service.checkpoint.pending[&1].nonce, Some(3));
    }

    #[tokio::test]
    async fn critical_replacements_remain_after_non_critical_bumps_spend_their_budget() {
        let fixture = Fixture::new().await;
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.estimate = 6_278_618;
            chain.base_fee = Some(10 * GWEI);
            chain.deadline += 10_000;
        }
        // The documented minimum tip cap: twice the 2 gwei first tip.
        let mut service =
            fixture.service_with(|config| config.fee = FeePolicy::new(130 * GWEI, 4 * GWEI));
        service.poll_once().await.unwrap();
        fixture.chain.lock().unwrap().drop_logs = true;
        for _ in 0..12 {
            // Not mined for three blocks each time.
            fixture.chain.lock().unwrap().head_number += 3;
            service.poll_once().await.unwrap();
        }
        let last = fixture.sends().last().unwrap().clone();
        assert!(fixture.sends().len() > 5);
        assert!(fee(&last, "maxPriorityFeePerGas") <= headroom(headroom(4 * GWEI)));
        let waiting = obligation(&service.status(), 0);
        assert_eq!(waiting.blocked_reason, Some(BlockedReason::FeeReserveHeld));
        assert!(waiting
            .detail
            .unwrap()
            .contains("reserved for the critical threshold"));
        // The base fee rises above the pending bid, below the cap, as the
        // obligation turns critical.
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.base_fee = Some(110 * GWEI);
            chain.head_timestamp = chain.deadline - 5;
            chain.head_number += 3;
        }
        let before = fixture.sends().len();
        service.poll_once().await.unwrap();
        let sends = fixture.sends();
        assert_eq!(sends.len(), before + 1, "a critical replacement is sent");
        let critical = &sends[before];
        assert_eq!(critical["nonce"], last["nonce"]);
        assert!(fee(critical, "maxFeePerGas") >= 110 * GWEI);
        for field in ["maxFeePerGas", "maxPriorityFeePerGas"] {
            assert!(
                fee(critical, field) >= min_bump(fee(&last, field)),
                "{field}"
            );
        }
        // And one more, at the caps.
        fixture.chain.lock().unwrap().head_number += 3;
        service.poll_once().await.unwrap();
        let sends = fixture.sends();
        assert_eq!(sends.len(), before + 2);
        assert_eq!(fee(&sends[before + 1], "maxFeePerGas"), 130 * GWEI);
        assert_eq!(fee(&sends[before + 1], "maxPriorityFeePerGas"), 4 * GWEI);
    }

    #[tokio::test]
    async fn back_run_re_escape_is_challenged_when_the_listing_is_stale() {
        let (store, first, second) = two_finalized_v2_requests().await;
        let fixture = Fixture::with_store(store, &first).await;
        let b = second.public_inputs.request_nullifier;
        let mut service = fixture.service_with(|config| config.alarms.blocked_warning_seconds = 0);
        service.poll_once().await.unwrap();
        assert_eq!(fixture.sends().len(), 1, "escape A challenged");
        {
            let mut chain = fixture.chain.lock().unwrap();
            // The challenge of A mined, and in the same block the owner
            // escaped again with B, another finalized request.
            chain.mined_nonce = 4;
            chain.nullifier = RE_ESCAPED;
            chain.next_nullifier = b;
            chain.head_number += 3;
            // The scan misses B, and the indexer, whose log source dropped
            // the root-neutral pair, still lists A.
            chain.drop_logs = true;
            chain.escapes = Some(vec![json!({
                "note_id": 0, "withdrawal_nullifier": ESCAPED, "challenge_deadline": chain.deadline
            })]);
        }
        for _ in 0..3 {
            service.poll_once().await.unwrap();
        }
        let sends = fixture.sends();
        assert_eq!(sends.len(), 2, "B is challenged");
        assert_eq!(sends[1]["nonce"], "0x4");
        assert_eq!(decode_call(&sends[1]).1[8 * 32..9 * 32], b.as_bytes()[..]);
        assert_eq!(service.checkpoint.pending[&0].nullifier, RE_ESCAPED);
        let status = service.status();
        assert!(status
            .indexer
            .pending_escapes_disagreement
            .as_ref()
            .unwrap()
            .starts_with("note 0 listed with nullifier"));
        assert!(status
            .alarms
            .iter()
            .any(|alarm| alarm.contains("pending-escapes list disagrees with the vault")));
        assert_eq!(status.missed_total, 0);
    }

    #[tokio::test]
    async fn indexer_listed_note_with_a_stale_nullifier_tracks_the_vaults_escape() {
        let fixture = Fixture::new().await;
        let live = {
            let mut chain = fixture.chain.lock().unwrap();
            // The event scan misses the live escape.
            chain.drop_logs = true;
            // The indexer lists note 0 with an earlier, challenged escape.
            chain.escapes = Some(vec![json!({
                "note_id": 0, "withdrawal_nullifier": Felt252::from_u64(0x384),
                "challenge_deadline": chain.deadline
            })]);
            chain.nullifier
        };
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        assert_eq!(service.checkpoint.pending[&0].nullifier, live);
        assert_eq!(fixture.sends().len(), 1);
        let status = service.status();
        assert_eq!(status.indexer.escapes_added_from_indexer, 1);
        assert!(status.indexer.pending_escapes_disagreement.is_some());
        // Past its deadline it would be counted, never silently dropped.
        assert_eq!(obligation(&status, 0).state, ObligationState::Submitted);
    }

    #[tokio::test]
    async fn signer_base_fee_refusal_of_a_stale_bid_has_its_own_reason() {
        let fixture = Fixture::new().await;
        fixture.chain.lock().unwrap().send_errors.push_back(json!({
            "code": -32003, "message": "Base fee exceeds the transaction max fee per gas",
            "data": { "reason": "base_fee_above_max_fee",
                "base_fee_per_gas": "0x12a05f200", "max_fee_per_gas": "0xee6b2800" }
        }));
        let mut service = fixture.service();
        assert!(service.poll_once().await.is_err());
        assert_eq!(service.checkpoint.pending[&0].nonce, None);
        assert_eq!(
            obligation(&service.status(), 0).blocked_reason,
            Some(BlockedReason::BaseFeeAboveMaxFee)
        );
        // The next poll bids again from the current base fee.
        service.poll_once().await.unwrap();
        assert_eq!(fixture.sends().len(), 2);
        assert_eq!(obligation(&service.status(), 0).blocked_reason, None);
    }

    #[test]
    fn tx_fee_cap_is_a_strict_positive_decimal() {
        let parse = FeePolicy::parse_tx_fee_cap;
        assert_eq!(parse(""), Ok(FeePolicy::DEFAULT_TX_FEE_CAP_WEI));
        assert_eq!(parse("1"), Ok(1));
        assert_eq!(parse("1000000000000000000"), Ok(ONE_ETHER));
        for invalid in [
            "0",
            "01",
            "+1",
            "-1",
            " 1",
            "1 ",
            "1e18",
            "0x10",
            "1.5",
            "340282366920938463463374607431768211456",
        ] {
            assert!(parse(invalid).is_err(), "{invalid}");
        }
        let policy = FeePolicy {
            tx_fee_cap_wei: 0,
            ..FeePolicy::new(100 * GWEI, 10 * GWEI)
        };
        assert!(policy
            .validate()
            .unwrap_err()
            .to_string()
            .contains("transaction fee cap must be positive"));
    }

    /// (gas limit x maxFeePerGas, accepted) of every send, in order.
    fn sent_tx_fees(fixture: &Fixture, cap: u128) -> Vec<(u128, bool)> {
        fixture
            .sends()
            .iter()
            .map(|send| {
                let tx_fee = fee(send, "gas") * fee(send, "maxFeePerGas");
                (tx_fee, tx_fee <= cap)
            })
            .collect()
    }

    #[tokio::test]
    async fn node_fee_cap_below_the_ceiling_is_learned_from_its_refusals() {
        // The node behind the signer caps transaction fees at 0.5 ether,
        // below the 1 ether ceiling both services were given.
        let node_cap = ONE_ETHER / 2;
        for signer_reports_its_cap in [false, true] {
            // First seen inside the critical threshold at a low base fee,
            // where a 22 gwei bid (0.17 ether) would be included.
            let fixture = Fixture::new().await;
            {
                let mut chain = fixture.chain.lock().unwrap();
                chain.tx_fee_cap = Some((node_cap, "upstream_tx_fee_cap"));
                chain.estimate = 6_278_618;
                chain.base_fee = Some(10 * GWEI);
                chain.head_timestamp = chain.deadline - 9;
                if signer_reports_its_cap {
                    chain.signer_status =
                        Some(json!({ "tx_fee_cap_wei": hex_quantity(ONE_ETHER) }));
                }
            }
            let mut service = fixture.service_with(mainnet_fees);
            // A refusal is critical at once, and nothing holds the nonce.
            assert!(service.poll_once().await.is_err());
            let refused = obligation(&service.status(), 0);
            assert_eq!(
                refused.blocked_reason,
                Some(BlockedReason::UpstreamTxFeeCap)
            );
            assert_eq!(refused.severity, Severity::Critical);
            assert_eq!(service.checkpoint.pending[&0].nonce, None);
            for _ in 0..5 {
                let _ = service.poll_once().await;
                fixture.chain.lock().unwrap().head_number += 1;
            }
            // Each refusal lowers the next bid until the node accepts one.
            let sent = sent_tx_fees(&fixture, node_cap);
            let refusals: Vec<u128> = sent
                .iter()
                .take_while(|(_, accepted)| !accepted)
                .map(|(tx_fee, _)| *tx_fee)
                .collect();
            assert!(
                refusals.windows(2).all(|pair| pair[1] <= headroom(pair[0])),
                "{sent:?}"
            );
            assert!(refusals.len() <= 4, "{sent:?}");
            let (accepted, _) = sent[refusals.len()];
            assert!(accepted <= node_cap && accepted > node_cap / 2, "{sent:?}");
            assert_eq!(fixture.sends()[refusals.len()]["nonce"], "0x3");
            assert_eq!(
                fixture.chain.lock().unwrap().fee_capped_sends,
                refusals.len()
            );
            let status = service.status();
            let submitted = obligation(&status, 0);
            assert_eq!(submitted.state, ObligationState::Submitted);
            assert_ne!(
                submitted.blocked_reason,
                Some(BlockedReason::UpstreamTxFeeCap)
            );
            // The bound stays in force and on /status until restart.
            let bound = headroom(*refusals.last().unwrap());
            assert_eq!(
                status.sender.node_tx_fee_cap_bound_wei,
                Some(bound.to_string())
            );
            assert_eq!(status.sender.effective_tx_fee_cap_wei, bound.to_string());
            assert!(status
                .config_warnings
                .iter()
                .any(|warning| warning.contains(&format!(
                    "the signer's node refused a transaction fee of {} wei",
                    refusals.last().unwrap()
                )) && warning
                    .contains("recreate both containers (docker compose up -d")));
        }

        // A non-critical spike: the reserve-limited bid of 109.7 gwei (0.83
        // ether) is refused, while about 66 gwei would be included.
        let fixture = Fixture::new().await;
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.tx_fee_cap = Some((node_cap, "upstream_tx_fee_cap"));
            chain.signer_status = Some(json!({ "tx_fee_cap_wei": hex_quantity(ONE_ETHER) }));
            chain.estimate = 6_278_618;
            chain.base_fee = Some(60 * GWEI);
            chain.deadline += 10_000;
        }
        let mut service = fixture.service_with(mainnet_fees);
        for _ in 0..4 {
            let _ = service.poll_once().await;
            fixture.chain.lock().unwrap().head_number += 1;
        }
        let sent = sent_tx_fees(&fixture, node_cap);
        let refused = sent.iter().take_while(|(_, accepted)| !accepted).count();
        assert!((1..=3).contains(&refused), "{sent:?}");
        assert!(sent.len() > refused, "{sent:?}");
        assert!(fee(&fixture.sends()[refused], "maxFeePerGas") > 60 * GWEI);
        assert!(sent[refused..].iter().all(|(_, accepted)| *accepted));
        let o = obligation(&service.status(), 0);
        assert_eq!(o.state, ObligationState::Submitted);
        assert_eq!(o.blocked_reason, None);
        assert_eq!(o.severity, Severity::Ok);
    }

    #[tokio::test]
    async fn re_escape_without_an_indexer_listing_is_followed_from_the_vault() {
        // An indexer that predates /v1/escapes/pending (404), or lists nothing:
        // only the per-poll vault read finds the re-escape.
        for listing in [None, Some(vec![])] {
            let (store, first, second) = two_finalized_v2_requests().await;
            let fixture = Fixture::with_store(store, &first).await;
            let b = second.public_inputs.request_nullifier;
            let mut service = fixture.service();
            service.poll_once().await.unwrap();
            assert_eq!(fixture.sends().len(), 1, "escape A challenged");
            {
                // The challenge of A mined, and in the same block the owner
                // escaped again with B, whose log the scan drops.
                let mut chain = fixture.chain.lock().unwrap();
                chain.mined_nonce = 4;
                chain.nullifier = RE_ESCAPED;
                chain.next_nullifier = b;
                chain.head_number += 3;
                chain.drop_logs = true;
                chain.escapes = listing.clone();
            }
            for _ in 0..3 {
                let _ = service.poll_once().await;
                fixture.chain.lock().unwrap().head_number += 1;
            }
            let sends = fixture.sends();
            assert_eq!(sends.len(), 2, "B is challenged: {listing:?}");
            assert_eq!(sends[1]["nonce"], "0x4");
            assert_eq!(decode_call(&sends[1]).1[8 * 32..9 * 32], b.as_bytes()[..]);
            assert_eq!(service.checkpoint.pending[&0].nullifier, RE_ESCAPED);
            assert_eq!(service.status().missed_total, 0);
        }
    }

    #[tokio::test]
    async fn observe_only_follows_the_vaults_escape_while_the_queue_is_blocked() {
        let (store, first, second) = two_finalized_v2_requests().await;
        let fixture = Fixture::with_store(store, &first).await;
        let b = second.public_inputs.request_nullifier;
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        assert_eq!(fixture.sends().len(), 1, "escape A challenged");
        let deadline_b = {
            let mut chain = fixture.chain.lock().unwrap();
            // A's challenge mined and the owner escaped again with B; neither
            // the scan nor the indexer reports B.
            chain.mined_nonce = 4;
            chain.nullifier = RE_ESCAPED;
            chain.next_nullifier = b;
            chain.deadline += 500;
            chain.head_number += 3;
            chain.drop_logs = true;
            chain.escapes = None;
            // Note 9 holds a nonce reserved without a known hash, so every
            // poll stops there and only observes note 0.
            let deadline = chain.deadline;
            chain
                .withdrawals
                .insert(9, (true, Felt252::from_u64(12345), deadline + 50));
            chain.concessions.insert(9, (NO_EVIDENCE, 0));
            deadline
        };
        service.checkpoint.pending.insert(
            9,
            PendingChallenge {
                nullifier: Felt252::from_u64(12345),
                nonce: Some(5),
                ..Default::default()
            },
        );
        service.persist().unwrap();
        for _ in 0..2 {
            let _ = service.poll_once().await;
            fixture.chain.lock().unwrap().head_number += 1;
        }
        assert_eq!(service.checkpoint.pending[&0].nullifier, RE_ESCAPED);
        let o = obligation(&service.status(), 0);
        assert_eq!(o.challenge_deadline, Some(deadline_b));
        assert_eq!(o.state, ObligationState::Ready);
        assert_eq!(o.blocked_reason, Some(BlockedReason::NonceBlocked));
    }

    #[tokio::test]
    async fn plan_refusal_releases_a_never_broadcast_reservation_at_once() {
        let fixture = Fixture::new().await;
        let nullifier = {
            let mut chain = fixture.chain.lock().unwrap();
            // Above the 100 gwei fee cap: the plan refuses to send.
            chain.base_fee = Some(150 * GWEI);
            chain.drop_logs = true;
            chain.nullifier
        };
        let mut service = fixture.service();
        // An earlier daemon's record of an attempt that failed before
        // broadcast on nonce 3.
        service.checkpoint.pending.insert(
            0,
            PendingChallenge {
                nullifier,
                nonce: Some(3),
                attempt: NonceAttempts {
                    attempts: 1,
                    ..Default::default()
                },
                ..Default::default()
            },
        );
        service.persist().unwrap();
        service.poll_once().await.unwrap();
        assert!(fixture.sends().is_empty());
        assert_eq!(service.checkpoint.pending[&0].nonce, None);
        assert_eq!(
            obligation(&service.status(), 0).blocked_reason,
            Some(BlockedReason::BaseFeeAboveFeeCap)
        );
    }

    #[tokio::test]
    async fn held_fee_reserve_is_reported_and_escalates_with_blocked_time() {
        let fixture = Fixture::new().await;
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.base_fee = Some(10 * GWEI);
            chain.deadline += 10_000;
        }
        // The documented minimum tip cap, twice the 2 gwei first tip, with
        // the blocked-time thresholds collapsed.
        let mut service = fixture.service_with(|config| {
            config.fee = FeePolicy {
                tx_fee_cap_wei: 10 * ONE_ETHER,
                ..FeePolicy::new(130 * GWEI, 4 * GWEI)
            };
            config.alarms.blocked_warning_seconds = 0;
            config.alarms.critical_blocked_seconds = 0;
        });
        service.poll_once().await.unwrap();
        fixture.chain.lock().unwrap().drop_logs = true;
        for _ in 0..12 {
            // Not mined for three blocks each time.
            fixture.chain.lock().unwrap().head_number += 3;
            service.poll_once().await.unwrap();
        }
        // Five replacements, then the rest is held for the critical threshold.
        let sends = fixture.sends();
        assert_eq!(sends.len(), 6);
        assert!(sends
            .iter()
            .all(|send| fee(send, "maxPriorityFeePerGas") <= headroom(headroom(4 * GWEI))));
        let status = service.status();
        let held = obligation(&status, 0);
        assert_eq!(held.state, ObligationState::Submitted);
        assert_eq!(held.blocked_reason, Some(BlockedReason::FeeReserveHeld));
        assert!(held
            .detail
            .unwrap()
            .contains("the remaining fee headroom is reserved for the critical threshold"));
        // The hold is not re-armed by each poll: its blocked time runs on.
        assert!(held.consecutive_failures > 1);
        assert_eq!(held.severity, Severity::Critical);
        assert!(status
            .alarms
            .contains(&"critical: note 0 submitted (fee_reserve_held)".to_string()));
        // At the critical threshold the reserve is spent at once.
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.head_timestamp = chain.deadline - 5;
            chain.head_number += 3;
        }
        service.poll_once().await.unwrap();
        assert_eq!(fixture.sends().len(), 7);
        assert_eq!(obligation(&service.status(), 0).blocked_reason, None);
    }

    #[test]
    fn critical_escalation_keeps_a_valid_replacement_under_a_ceiling_below_the_tip_cap() {
        // A ceiling of 6 gwei per gas, below the 10 gwei tip cap.
        let policy = FeePolicy::new(100 * GWEI, 10 * GWEI);
        let plan = |plan| plan_fees(&policy, plan, Some(GWEI), true, Some(6 * GWEI), None);
        let first = plan(FeePlan::First).unwrap().unwrap();
        let reserve = headroom(6 * GWEI);
        assert_eq!(
            first,
            Fees {
                max_fee: reserve,
                tip: reserve
            }
        );
        let next = plan(FeePlan::Bump(first)).unwrap().unwrap();
        assert_eq!(
            next,
            Fees {
                max_fee: 6 * GWEI,
                tip: 6 * GWEI
            }
        );
        assert!(is_valid_bump(first, next));
        assert_eq!(
            plan(FeePlan::Bump(next)),
            Err(BlockedReason::TxFeeCapReached)
        );
    }

    #[tokio::test]
    async fn fee_cap_lock_detached_before_the_upgrade_shows_its_bid_for_the_runbook() {
        // An earlier daemon locked nonce 3 at a 142 gwei bid its node refused
        // (an earlier signer reported a candidate hash no node knows), and
        // the escape was finalized before the upgrade. The nonce cannot be
        // told apart from a broadcast one, so it needs the manual runbook.
        let fixture = Fixture::new().await;
        let refused_hash = format!("0x{:064x}", 0xdead_0000_0000u64);
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.fee_capped_hashes.insert(refused_hash.clone());
            chain.estimate = 6_278_618;
            chain.deadline += 10_000;
        }
        let mut service = fixture.service_with(mainnet_fees);
        service.checkpoint.detached_nonces.insert(
            3,
            DetachedNonce {
                note_id: 5,
                nullifier: Felt252::from_u64(5),
                transaction_hash: None,
                attempt: NonceAttempts {
                    superseded_hashes: vec![refused_hash.clone()],
                    max_fee_per_gas: Some(format!("0x{:x}", 142 * GWEI)),
                    max_priority_fee_per_gas: Some(format!("0x{:x}", 2 * GWEI)),
                    attempts: 21,
                    ..Default::default()
                },
            },
        );
        service.persist().unwrap();
        let error = service.poll_once().await.unwrap_err().to_string();
        assert!(error.contains("requires signer intervention"), "{error}");
        assert!(fixture.sends().is_empty());
        let status = service.status();
        assert_eq!(status.status, Severity::Critical);
        let detached = &status.detached_nonces[0];
        assert_eq!(detached.nonce, 3);
        assert!(!detached.mined);
        assert_eq!(detached.superseded_hashes, vec![refused_hash]);
        assert_eq!(detached.max_fee_per_gas_wei, Some((142 * GWEI).to_string()));
        assert_eq!(detached.gas_limit, None);
    }

    /// Review regression (node fee bound): a signer other than the bundled
    /// one can refuse with upstream_tx_fee_cap while reporting a zero gas
    /// limit or fee per gas. As with a zero signer cap, that zero is
    /// ignored: the refused send's own gas x maxFeePerGas is learned, so
    /// later refusals keep lowering the bid until the node accepts one, and
    /// the node-refusal warning shows.
    #[tokio::test]
    async fn refusal_reporting_a_zero_fee_still_lowers_the_bids() {
        let node_cap = ONE_ETHER / 2;
        let fixture = Fixture::new().await;
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.tx_fee_cap = Some((node_cap, "upstream_tx_fee_cap"));
            chain.estimate = 6_278_618;
            chain.base_fee = Some(10 * GWEI);
            chain.head_timestamp = chain.deadline - 9;
            chain.send_errors.push_back(json!({ "code": -32003,
                "message": "Upstream RPC refused the transaction fee",
                "data": { "reason": "upstream_tx_fee_cap", "gas_limit": "0x0", "max_fee_per_gas": "0x0" } }));
        }
        let mut service = fixture.service_with(mainnet_fees);
        assert!(service.poll_once().await.is_err());
        let sends = fixture.sends();
        let refused = fee(&sends[0], "gas") * fee(&sends[0], "maxFeePerGas");
        assert_eq!(service.node_refused_tx_fee, Some(refused));
        assert_eq!(
            service.status().sender.node_tx_fee_cap_bound_wei,
            Some(headroom(refused).to_string())
        );
        for _ in 0..5 {
            let _ = service.poll_once().await;
            fixture.chain.lock().unwrap().head_number += 1;
        }
        let sent = sent_tx_fees(&fixture, node_cap);
        let accepted = sent.iter().position(|(_, accepted)| *accepted);
        let accepted = accepted.unwrap_or_else(|| panic!("no bid was accepted: {sent:?}"));
        assert!(
            sent[..=accepted]
                .windows(2)
                .all(|pair| pair[1].0 <= headroom(pair[0].0)),
            "{sent:?}"
        );
        let status = service.status();
        assert_eq!(obligation(&status, 0).state, ObligationState::Submitted);
        assert!(status
            .config_warnings
            .iter()
            .any(|warning| warning.contains("upstream_tx_fee_cap")));
    }

    /// An escape of `note`, as the indexer's pending-escapes list names it.
    fn listed(note: u32, nullifier: Felt252, deadline: u64) -> Value {
        json!({ "note_id": note, "withdrawal_nullifier": nullifier, "challenge_deadline": deadline })
    }

    /// Review regression (pending-escapes backstop): a listed note whose
    /// vault record does not exist (a dead entry, which a lossy log source
    /// leaves in the indexer until a resync) stays due until reads
    /// DEAD_ESCAPE_CONFIRM_SECONDS apart find no escape, and each poll's
    /// reads resume where the previous poll's budget ran out. So 100 dead
    /// entries at low note IDs never starve a live escape listed after them:
    /// it is tracked within ceil(101 / 64) polls. Once confirmed, they are
    /// no longer read on every poll.
    #[tokio::test]
    async fn dead_listed_escapes_never_starve_a_live_one() {
        let fixture = Fixture::new().await;
        {
            let mut chain = fixture.chain.lock().unwrap();
            // Only the indexer lists the live escape.
            chain.drop_logs = true;
            let (nullifier, deadline) = (chain.nullifier, chain.deadline);
            let mut escapes = Vec::new();
            for note in 0..100 {
                // Paid out or closed in the vault; the indexer missed it.
                chain.withdrawals.insert(note, (false, Felt252::ZERO, 0));
                escapes.push(listed(note, Felt252::from_u64(0x384), deadline));
            }
            chain.withdrawals.insert(500, (true, nullifier, deadline));
            escapes.push(listed(500, nullifier, deadline));
            chain.escapes = Some(escapes);
        }
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        // The budget ran out at note 64; the next poll starts there.
        assert_eq!(service.escape_cursor, 64);
        assert!(!service.checkpoint.pending.contains_key(&500));
        for _ in 1..101usize.div_ceil(MAX_ESCAPE_CHECKS_PER_POLL) {
            service.poll_once().await.unwrap();
        }
        assert!(
            service.checkpoint.pending.contains_key(&500),
            "the live escape was starved by dead entries"
        );
        assert_eq!(fixture.sends().len(), 1, "the live escape is challenged");
        assert_eq!(
            obligation(&service.status(), 500).state,
            ObligationState::Submitted
        );
        // Confirmed dead entries are not read again on every poll.
        for dead in service.dead_escapes.values_mut() {
            dead.first_seen -= DEAD_ESCAPE_CONFIRM_SECONDS;
        }
        let reads = |fixture: &Fixture| -> Vec<usize> {
            (0..100)
                .map(|note| fixture.withdrawal_reads(note))
                .collect()
        };
        let before = reads(&fixture);
        for _ in 0..3 {
            service.poll_once().await.unwrap();
        }
        assert_eq!(reads(&fixture), before);
    }

    /// Review regression (cursor): listed notes whose vault escape is live
    /// under another nullifier than listed (stale hints) are read on every
    /// listing, as the vault's escape is tracked for them. 70 of them at low
    /// note IDs never starve an untracked live escape listed after them:
    /// each poll's reads resume where the previous poll's budget ran out.
    #[tokio::test]
    async fn stale_hints_never_starve_a_live_escape() {
        let fixture = Fixture::new().await;
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.drop_logs = true;
            let (nullifier, deadline) = (chain.nullifier, chain.deadline);
            let mut escapes = Vec::new();
            for note in 0..70 {
                // The owner escaped again; the indexer lists the old escape.
                chain
                    .withdrawals
                    .insert(note, (true, Felt252::from_u64(78), deadline));
                escapes.push(listed(note, Felt252::from_u64(0x384), deadline));
            }
            chain.withdrawals.insert(500, (true, nullifier, deadline));
            escapes.push(listed(500, nullifier, deadline));
            chain.escapes = Some(escapes);
        }
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        assert_eq!(service.escape_cursor, 64);
        assert_eq!(service.checkpoint.pending.len(), 64);
        service.poll_once().await.unwrap();
        assert!(
            service.checkpoint.pending.contains_key(&500),
            "the live escape was starved by stale hints"
        );
        assert!((0..70)
            .all(|note| service.checkpoint.pending[&note].nullifier == Felt252::from_u64(78)));
        // This poll read notes 64 to 69, note 500 and notes 0 to 56.
        assert_eq!(service.escape_cursor, 57);
        let detail = service
            .status()
            .indexer
            .pending_escapes_disagreement
            .unwrap();
        assert!(
            detail.starts_with("note 64 listed with nullifier 0x384"),
            "{detail}"
        );
    }

    /// Review regression (stale first read): this daemon's RPC can lag the
    /// indexer's head view, so a fresh escape the event scan missed can read
    /// as absent at first; and an indexer that missed a challenge and
    /// re-escape pair lists the ended escape's nullifier while the vault
    /// held none for a moment. Neither waits for the dead-entry back-off:
    /// both are read again at the next listing and tracked.
    #[tokio::test]
    async fn dead_entries_stay_due_until_confirmed() {
        let fixture = Fixture::new().await;
        let (nullifier, deadline) = {
            let mut chain = fixture.chain.lock().unwrap();
            chain.drop_logs = true;
            let (nullifier, deadline) = (chain.nullifier, chain.deadline);
            chain.withdrawals.insert(500, (false, Felt252::ZERO, 0));
            chain.withdrawals.insert(7, (false, Felt252::ZERO, 0));
            chain.escapes = Some(vec![
                listed(7, Felt252::from_u64(0x384), deadline),
                listed(500, nullifier, deadline),
            ]);
            (nullifier, deadline)
        };
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        assert!(service.checkpoint.pending.is_empty());
        assert_eq!(service.dead_escapes.len(), 2);
        {
            let mut chain = fixture.chain.lock().unwrap();
            // This RPC now shows the escape, and the owner escaped again.
            chain.withdrawals.insert(500, (true, nullifier, deadline));
            chain
                .withdrawals
                .insert(7, (true, Felt252::from_u64(78), deadline + 5));
            chain.concessions.insert(7, (NO_EVIDENCE, 0));
        }
        service.poll_once().await.unwrap();
        assert_eq!(service.checkpoint.pending[&500].nullifier, nullifier);
        assert_eq!(
            service.checkpoint.pending[&7].nullifier,
            Felt252::from_u64(78)
        );
        assert!(service.dead_escapes.is_empty());
        assert_eq!(fixture.sends().len(), 1, "the fresh escape is challenged");
        // Once confirmed, it rests between re-reads: a later re-escape is
        // tracked at the DEAD_ESCAPE_RECHECK_POLLS-th listing.
        fixture.chain.lock().unwrap().escapes =
            Some(vec![listed(9, Felt252::from_u64(0x384), deadline)]);
        fixture
            .chain
            .lock()
            .unwrap()
            .withdrawals
            .insert(9, (false, Felt252::ZERO, 0));
        service.poll_once().await.unwrap();
        service.dead_escapes.get_mut(&9).unwrap().first_seen -= DEAD_ESCAPE_CONFIRM_SECONDS;
        fixture
            .chain
            .lock()
            .unwrap()
            .withdrawals
            .insert(9, (true, Felt252::from_u64(79), deadline));
        for _ in 1..DEAD_ESCAPE_RECHECK_POLLS {
            service.poll_once().await.unwrap();
        }
        assert_eq!(fixture.withdrawal_reads(9), 1);
        assert!(!service.checkpoint.pending.contains_key(&9));
        service.poll_once().await.unwrap();
        assert_eq!(
            service.checkpoint.pending[&9].nullifier,
            Felt252::from_u64(79)
        );
    }

    /// A dead entry is reported under the indexer's
    /// pending_escapes_disagreement once reads --blocked-warning-seconds
    /// apart found no escape, so the "resync the indexer" alarm reaches the
    /// operator. The read that completes the period is made as soon as it is
    /// due, and no report goes out without it. The entry is then read again
    /// every DEAD_ESCAPE_RECHECK_POLLS listings, stays reported, and is
    /// forgotten once unlisted.
    #[tokio::test]
    async fn dead_listed_escape_is_reported_once_it_persists() {
        let fixture = Fixture::new().await;
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.drop_logs = true;
            chain.withdrawals.insert(1, (false, Felt252::ZERO, 0));
            let deadline = chain.deadline;
            chain.escapes = Some(vec![listed(1, Felt252::from_u64(0x384), deadline)]);
        }
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        // The list may only lag the vault: nothing is reported yet.
        let status = service.status();
        assert_eq!(status.indexer.pending_escapes_disagreement, None);
        assert_eq!(status.status, Severity::Ok, "{:?}", status.alarms);
        // Confirmed a minute after the first read, and the warning period
        // has passed since the first read: its report waits for a read.
        let warning = service.config.alarms.blocked_warning_seconds;
        {
            let dead = service.dead_escapes.get_mut(&1).unwrap();
            dead.first_seen -= warning;
            dead.last_seen -= warning - DEAD_ESCAPE_CONFIRM_SECONDS;
        }
        // A read that fails confirms nothing.
        fixture.chain.lock().unwrap().fail_note_one = true;
        service.poll_once().await.unwrap();
        assert_eq!(service.status().indexer.pending_escapes_disagreement, None);
        fixture.chain.lock().unwrap().fail_note_one = false;
        service.poll_once().await.unwrap();
        assert_eq!(fixture.withdrawal_reads(1), 2);
        let reported = |service: &ChallengeService| {
            let status = service.status();
            let detail = status.indexer.pending_escapes_disagreement.clone().unwrap();
            assert!(
                detail.contains("note 1 listed with nullifier 0x384")
                    && detail.contains("no pending escape"),
                "{detail}"
            );
            assert!(
                status.alarms.iter().any(|alarm| alarm
                    .contains("pending-escapes list disagrees with the vault")
                    && alarm.contains("resync the indexer")),
                "{:?}",
                status.alarms
            );
            assert_eq!(status.status, Severity::Warning);
        };
        reported(&service);
        // Read again only every DEAD_ESCAPE_RECHECK_POLLS listings.
        for _ in 1..DEAD_ESCAPE_RECHECK_POLLS {
            service.poll_once().await.unwrap();
        }
        assert_eq!(fixture.withdrawal_reads(1), 2);
        reported(&service);
        service.poll_once().await.unwrap();
        assert_eq!(
            fixture.withdrawal_reads(1),
            3,
            "a dead entry is still read now and then"
        );
        reported(&service);
        // A resynced indexer no longer lists it.
        fixture.chain.lock().unwrap().escapes = Some(vec![]);
        service.poll_once().await.unwrap();
        assert!(service.dead_escapes.is_empty());
        assert_eq!(service.status().indexer.pending_escapes_disagreement, None);
    }

    /// Review regression (report without a confirming read): a dead entry
    /// whose warning period has passed since its first read is read before
    /// it is reported. Here the vault holds an escape by then, which is
    /// tracked; nothing is reported as missing from the vault.
    #[tokio::test]
    async fn a_dead_entry_found_live_at_its_report_read_is_tracked() {
        let fixture = Fixture::new().await;
        let (nullifier, deadline) = {
            let mut chain = fixture.chain.lock().unwrap();
            chain.drop_logs = true;
            let (nullifier, deadline) = (chain.nullifier, chain.deadline);
            chain.withdrawals.insert(500, (false, Felt252::ZERO, 0));
            chain.escapes = Some(vec![listed(500, nullifier, deadline)]);
            (nullifier, deadline)
        };
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        let warning = service.config.alarms.blocked_warning_seconds;
        {
            let dead = service.dead_escapes.get_mut(&500).unwrap();
            dead.first_seen -= warning;
            dead.last_seen -= warning - DEAD_ESCAPE_CONFIRM_SECONDS;
        }
        fixture
            .chain
            .lock()
            .unwrap()
            .withdrawals
            .insert(500, (true, nullifier, deadline));
        service.poll_once().await.unwrap();
        assert!(service.checkpoint.pending.contains_key(&500));
        assert!(service.dead_escapes.is_empty());
        let status = service.status();
        assert_eq!(status.indexer.pending_escapes_disagreement, None);
        assert!(
            !status
                .alarms
                .iter()
                .any(|alarm| alarm.contains("no pending escape in the vault")),
            "{:?}",
            status.alarms
        );
    }

    /// Review regression (lag or loss): a list served at a block that may
    /// lie below a vault read that found no escape may only lag the vault,
    /// as the list of an indexer whose view stalled before a payout does
    /// (its root is unchanged, so its status stays consistent). However long
    /// reads keep finding no escape, that is not reported and asks for no
    /// resync, and neither is a list served at a block this daemon's RPC has
    /// not reached. Once a list served between two reads that found no
    /// escape still names the note, the indexer has processed a block in
    /// which the vault held none: it is reported at once.
    #[tokio::test]
    async fn a_lagging_list_is_reported_only_once_served_past_an_absent_read() {
        let fixture = Fixture::new().await;
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.drop_logs = true;
            // Paid out; the indexer's view is a block behind the head.
            chain.withdrawals.insert(1, (false, Felt252::ZERO, 0));
            let deadline = chain.deadline;
            chain.escapes = Some(vec![listed(1, Felt252::from_u64(0x384), deadline)]);
            chain.escapes_block = Some(chain.head_number - 1);
        }
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        // Confirmed, and the warning period has passed since the first read.
        let warning = service.config.alarms.blocked_warning_seconds;
        {
            let dead = service.dead_escapes.get_mut(&1).unwrap();
            dead.first_seen -= warning;
            dead.last_seen -= warning - DEAD_ESCAPE_CONFIRM_SECONDS;
        }
        let not_reported = |service: &ChallengeService| {
            let status = service.status();
            assert_eq!(status.indexer.pending_escapes_disagreement, None);
            assert_eq!(status.status, Severity::Ok, "{:?}", status.alarms);
        };
        // The first read ran at block 5 or above, which only the next poll's
        // head (8) bounds; the indexer's view stalls at block 6.
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.head_number = 8;
            chain.escapes_block = Some(6);
        }
        // The entry rests; its re-read spans the warning period.
        for _ in 0..DEAD_ESCAPE_RECHECK_POLLS {
            service.poll_once().await.unwrap();
            not_reported(&service);
        }
        assert_eq!(fixture.withdrawal_reads(1), 2);
        assert!(service.dead_escapes[&1].absent_for(warning));
        // A list served beyond this daemon's head may hold an escape its
        // RPC does not show yet.
        fixture.chain.lock().unwrap().escapes_block = Some(10);
        service.poll_once().await.unwrap();
        not_reported(&service);
        assert_eq!(fixture.withdrawal_reads(1), 2);
        // The RPC reaches that block, and the vault still holds no escape.
        fixture.chain.lock().unwrap().head_number = 10;
        service.poll_once().await.unwrap();
        assert_eq!(fixture.withdrawal_reads(1), 3);
        let status = service.status();
        let detail = status.indexer.pending_escapes_disagreement.unwrap();
        assert!(
            detail.contains("note 1 listed with nullifier 0x384"),
            "{detail}"
        );
        assert!(
            status
                .alarms
                .iter()
                .any(|alarm| alarm.contains("no pending escape")
                    && alarm.contains("resync the indexer")),
            "{:?}",
            status.alarms
        );
        // Shown once, it stays reported while the note is listed, also after
        // a re-read in a listing served beyond this daemon's head.
        fixture.chain.lock().unwrap().escapes_block = Some(12);
        for _ in 0..DEAD_ESCAPE_RECHECK_POLLS {
            service.poll_once().await.unwrap();
        }
        assert_eq!(fixture.withdrawal_reads(1), 4);
        assert!(service
            .status()
            .indexer
            .pending_escapes_disagreement
            .is_some());
    }

    /// Review regression (relisted note): a confirmed dead entry rests only
    /// while its note is listed under the same nullifier. Once the indexer
    /// lists the note's live escape, which the event scan missed, the note
    /// is read at the next listing and tracked, without waiting for the
    /// DEAD_ESCAPE_RECHECK_POLLS back-off.
    #[tokio::test]
    async fn a_dead_entry_relisted_under_another_nullifier_is_read_at_once() {
        let fixture = Fixture::new().await;
        let deadline = {
            let mut chain = fixture.chain.lock().unwrap();
            chain.drop_logs = true;
            chain.withdrawals.insert(9, (false, Felt252::ZERO, 0));
            let deadline = chain.deadline;
            chain.escapes = Some(vec![listed(9, Felt252::from_u64(0x384), deadline)]);
            deadline
        };
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        service.dead_escapes.get_mut(&9).unwrap().first_seen -= DEAD_ESCAPE_CONFIRM_SECONDS;
        // Confirmed: it rests.
        service.poll_once().await.unwrap();
        assert_eq!(fixture.withdrawal_reads(9), 1);
        let renewed = Felt252::from_u64(0x4f);
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.withdrawals.insert(9, (true, renewed, deadline));
            chain.escapes = Some(vec![listed(9, renewed, deadline)]);
        }
        service.poll_once().await.unwrap();
        assert_eq!(service.checkpoint.pending[&9].nullifier, renewed);
        assert!(service.dead_escapes.is_empty());
    }

    /// Review regression: a note tracked under the vault's escape, while the
    /// indexer still lists an older nullifier the vault once held no escape
    /// for, is not reported as missing from the vault. Reconcile reads a
    /// tracked note every poll, so no dead entry is kept for it.
    #[tokio::test]
    async fn a_tracked_note_is_never_reported_as_dead() {
        let fixture = Fixture::new().await;
        let deadline = {
            let mut chain = fixture.chain.lock().unwrap();
            chain.drop_logs = true;
            chain.withdrawals.insert(7, (false, Felt252::ZERO, 0));
            let deadline = chain.deadline;
            chain.escapes = Some(vec![listed(7, Felt252::from_u64(0x384), deadline)]);
            deadline
        };
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        let warning = service.config.alarms.blocked_warning_seconds;
        service.dead_escapes.get_mut(&7).unwrap().first_seen -= warning;
        // The event scan tracks the owner's new escape.
        let renewed = Felt252::from_u64(78);
        fixture
            .chain
            .lock()
            .unwrap()
            .withdrawals
            .insert(7, (true, renewed, deadline));
        service.checkpoint.pending.insert(
            7,
            PendingChallenge {
                nullifier: renewed,
                challenge_deadline: Some(deadline),
                ..Default::default()
            },
        );
        service.poll_once().await.unwrap();
        assert!(service.dead_escapes.is_empty());
        let detail = service
            .status()
            .indexer
            .pending_escapes_disagreement
            .unwrap();
        assert!(
            detail.contains("note 7 listed with nullifier 0x384")
                && detail.contains("the vault holds")
                && !detail.contains("no pending escape"),
            "{detail}"
        );
        // Its escape ends; it is retired, never kept as a dead entry while
        // tracked.
        fixture
            .chain
            .lock()
            .unwrap()
            .withdrawals
            .insert(7, (false, Felt252::ZERO, 0));
        service.poll_once().await.unwrap();
        assert!(service.dead_escapes.is_empty());
        assert!(!service.checkpoint.pending.contains_key(&7));
    }

    /// The proof bytes of a fixture request.
    fn proof_bytes(request: &ApiRequestV2) -> Vec<u8> {
        base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &request.proof.proof,
        )
        .unwrap()
    }

    /// File `request`'s proof as evidence (a later reservation at its
    /// nullifier), written `created_at`.
    fn file_evidence(store: &NullifierStore, request: &ApiRequestV2, created_at: u64) {
        crate::watcher::tests::append_raw_evidence(
            store,
            &request.public_inputs.request_nullifier,
            &serde_json::to_string(&request.public_inputs).unwrap(),
            &request.public_inputs.solvency_bound.to_string(),
            &proof_bytes(request),
            created_at,
        );
    }

    fn kinds(sends: &[Value]) -> Vec<CallKind> {
        sends.iter().map(|send| sent_call(send).0).collect()
    }

    #[tokio::test]
    async fn successor_evidence_defeats_whatever_its_lease_status() {
        let (_, request) = finalized_v2_request().await;
        let nullifier = request.public_inputs.request_nullifier;
        // A reservation without a lease row, a key never issued, an issued
        // key, a cancelled lease, a settled charge awaiting its signature
        // (deferred, the exit consuming it), and a Finalized transcript.
        for case in [
            "no lease row",
            "provisioning",
            "active",
            "cancelled",
            "deferred",
            "finalized",
        ] {
            let store = Arc::new(NullifierStore::in_memory().unwrap());
            store.reserve_openrouter_lease(&request).unwrap();
            if case != "no lease row" {
                store
                    .create_openrouter_lease(&request, "oa_org", 1, 2, 3, 1.0)
                    .unwrap();
            }
            match case {
                "active" | "cancelled" => {
                    store
                        .activate_openrouter_lease(&request.client_request_id, "key-hash")
                        .unwrap();
                    if case == "cancelled" {
                        store.execute_for_test(
                            "UPDATE openrouter_leases SET status = 'cancelled'",
                            [],
                        );
                    }
                }
                "deferred" => {
                    settle(&store, &request, 1);
                    store.execute_for_test(
                        "UPDATE nullifiers SET exit_deferred_since = 5 WHERE nullifier = ?1",
                        [nullifier.to_hex()],
                    );
                }
                "finalized" => store
                    .finalize(&nullifier, &finalized_transcript(&request, 0))
                    .unwrap(),
                _ => {}
            }
            let fixture = Fixture::with_store(store, &request).await;
            let mut service = fixture.service();
            service.poll_once().await.unwrap();
            let sends = fixture.sends();
            assert_eq!(kinds(&sends), [CallKind::Defeat], "{case}");
            assert_eq!(
                sends[0]["data"],
                format!("0x{}", hex::encode(defeat_of(&request, 0))),
                "{case}"
            );
            // The default defeat gas limit, unless the estimate is higher.
            assert_eq!(sends[0]["gas"], format!("0x{:x}", 12_000_000), "{case}");
            let status = obligation(&service.status(), 0);
            assert_eq!(status.evidence, Some(EvidenceKind::Successor), "{case}");
            assert_eq!(status.action, Some(CallKind::Defeat), "{case}");
        }
        // With a cheap estimate the defeat goes at the 600,000 default.
        let fixture = Fixture::new().await;
        fixture.chain.lock().unwrap().estimate = 350_000;
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        assert_eq!(
            fixture.sends()[0]["gas"],
            format!("0x{:x}", DEFAULT_DEFEAT_GAS_LIMIT)
        );
    }

    #[tokio::test]
    async fn evidence_only_at_the_escaped_nullifier_never_yields_a_defeat() {
        // Every row at N: Finalized, settled, unsettled; none at N⁺. A
        // request at the escaped state only ever raises.
        let (_, request) = finalized_v2_request().await;
        for settled in [false, true] {
            let store = Arc::new(NullifierStore::in_memory().unwrap());
            issued_lease(&store, &request);
            if settled {
                settle(&store, &request, 1);
            }
            let fixture = escape_at_request(store, &request).await;
            let mut service = fixture.service();
            for _ in 0..3 {
                service.poll_once().await.unwrap();
                fixture.chain.lock().unwrap().head_timestamp += 20;
            }
            let sends = fixture.sends();
            assert!(
                kinds(&sends).iter().all(|kind| *kind != CallKind::Defeat),
                "settled {settled}: {:?}",
                kinds(&sends)
            );
            assert!(!sends.is_empty(), "a raise is due by the raise lead");
        }
    }

    /// An escape at `first`'s nullifier, charged 1 (a raise is due at once),
    /// whose successor is `second`'s nullifier: evidence at it appears only
    /// when the test files it.
    async fn raise_then_successor() -> (Fixture, Arc<NullifierStore>, ApiRequestV2, ApiRequestV2) {
        let (_, first, second) = two_finalized_v2_requests().await;
        let store = Arc::new(NullifierStore::in_memory().unwrap());
        issued_lease(&store, &first);
        settle(&store, &first, 1);
        let fixture = escape_at_request(store.clone(), &first).await;
        fixture.chain.lock().unwrap().next_nullifier = second.public_inputs.request_nullifier;
        (fixture, store, first, second)
    }

    #[tokio::test]
    async fn a_defeat_replaces_a_pending_raise_at_its_nonce_and_is_mined_before_the_deadline() {
        let (fixture, store, _first, second) = raise_then_successor().await;
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        let sends = fixture.sends();
        assert_eq!(kinds(&sends), [CallKind::Raise]);
        assert_eq!(sends[0]["nonce"], "0x3");
        let raise_hash = service.checkpoint.pending[&0]
            .transaction_hash
            .clone()
            .unwrap();
        // The owner spent the successor state: evidence at N⁺ appears while
        // the raise is unmined.
        file_evidence(&store, &second, unix_now());
        service.poll_once().await.unwrap();
        let sends = fixture.sends();
        assert_eq!(kinds(&sends), [CallKind::Raise, CallKind::Defeat]);
        assert_eq!(sends[1]["nonce"], "0x3", "the defeat replaces the raise");
        for field in ["maxFeePerGas", "maxPriorityFeePerGas"] {
            assert!(
                fee(&sends[1], field) >= min_bump(fee(&sends[0], field)),
                "{field}"
            );
        }
        assert_eq!(
            sends[1]["data"],
            format!("0x{}", hex::encode(defeat_of(&second, 0)))
        );
        let attempt = &service.checkpoint.pending[&0].attempt;
        assert_eq!(attempt.action, Some(CallKind::Defeat));
        assert!(attempt.replaced_raise);
        assert!(attempt.superseded_hashes.contains(&raise_hash));
        assert_eq!(attempt.raise_amount, None);
        // A pending defeat is never replaced by a raise, and is only bumped.
        service.poll_once().await.unwrap();
        assert_eq!(fixture.sends().len(), 2);
        assert_eq!(
            obligation(&service.status(), 0).action,
            Some(CallKind::Defeat)
        );
        // The defeat mines before the deadline and ends the escape.
        {
            let mut chain = fixture.chain.lock().unwrap();
            assert!(chain.head_timestamp < chain.deadline);
            chain.mined_nonce = 4;
            chain.active = false;
            chain.confirmed_active = false;
            let nullifier = chain.nullifier;
            chain.challenged.insert(nullifier);
            chain.head_number += 3;
        }
        service.poll_once().await.unwrap();
        assert!(service.checkpoint.pending.is_empty());
        let status = service.status();
        assert_eq!(status.missed_total, 0);
        assert_eq!(kinds(&fixture.sends()), [CallKind::Raise, CallKind::Defeat]);
    }

    /// §5.4: a raise goes at the 450,000 default gas limit, unless its
    /// estimate plus 20% is higher.
    #[tokio::test]
    async fn a_raise_goes_at_the_default_gas_limit_unless_the_estimate_is_higher() {
        for (estimate, gas) in [(300_000, 450_000), (500_000, 600_000)] {
            let (fixture, ..) = raise_then_successor().await;
            fixture.chain.lock().unwrap().estimate = estimate;
            let mut service = fixture.service();
            service.poll_once().await.unwrap();
            let sends = fixture.sends();
            assert_eq!(kinds(&sends), [CallKind::Raise], "estimate {estimate}");
            assert_eq!(sends[0]["gas"], format!("0x{gas:x}"), "estimate {estimate}");
        }
        assert_eq!(format!("0x{DEFAULT_RAISE_GAS_LIMIT:x}"), "0x6ddd0");
    }

    /// Review regression: evidence at `N⁺` that does not verify defeats
    /// nothing, so it must not hold back the raise owed at `N`. The raise
    /// goes out, and the invalid row still raises the critical
    /// evidence_invalid alarm and fails the poll.
    #[tokio::test]
    async fn invalid_successor_evidence_alarms_but_never_blocks_the_raise() {
        let (fixture, store, _first, second) = raise_then_successor().await;
        let mut tampered = proof_bytes(&second);
        tampered[40] ^= 1;
        crate::watcher::tests::append_raw_evidence(
            &store,
            &second.public_inputs.request_nullifier,
            &serde_json::to_string(&second.public_inputs).unwrap(),
            &second.public_inputs.solvency_bound.to_string(),
            &tampered,
            unix_now(),
        );
        let mut service = fixture.service();
        let error = service.poll_once().await.unwrap_err().to_string();
        assert!(
            error.contains("evidence at the successor nullifier does not verify"),
            "{error}"
        );
        let sends = fixture.sends();
        assert_eq!(kinds(&sends), [CallKind::Raise]);
        let status = service.status();
        let raised = obligation(&status, 0);
        assert_eq!(raised.action, Some(CallKind::Raise));
        assert_eq!(raised.state, ObligationState::Submitted);
        assert_eq!(raised.blocked_reason, Some(BlockedReason::EvidenceInvalid));
        assert_eq!(raised.severity, Severity::Critical);
        assert_eq!(status.status, Severity::Critical);
        // A verified row at N⁺ still takes precedence: the defeat replaces
        // the raise on its nonce.
        file_evidence(&store, &second, unix_now());
        service.poll_once().await.unwrap();
        let sends = fixture.sends();
        assert_eq!(kinds(&sends), [CallKind::Raise, CallKind::Defeat]);
        assert_eq!(sends[1]["nonce"], sends[0]["nonce"]);
        assert_eq!(obligation(&service.status(), 0).blocked_reason, None);
    }

    /// Review regression: with nothing owed at `N`, an unverifiable row at
    /// `N⁺` is still reported, and a payout at the deadline is still
    /// counted as a possible missed defeat.
    #[tokio::test]
    async fn invalid_successor_evidence_with_nothing_owed_is_critical_and_missed_at_the_deadline() {
        let (_, first, second) = two_finalized_v2_requests().await;
        let store = Arc::new(NullifierStore::in_memory().unwrap());
        let fixture = escape_at_request(store.clone(), &first).await;
        fixture.chain.lock().unwrap().next_nullifier = second.public_inputs.request_nullifier;
        let mut tampered = proof_bytes(&second);
        tampered[40] ^= 1;
        crate::watcher::tests::append_raw_evidence(
            &store,
            &second.public_inputs.request_nullifier,
            &serde_json::to_string(&second.public_inputs).unwrap(),
            &second.public_inputs.solvency_bound.to_string(),
            &tampered,
            1,
        );
        let mut service = fixture.service();
        assert!(service.poll_once().await.is_err());
        assert!(fixture.sends().is_empty());
        let invalid = obligation(&service.status(), 0);
        assert_eq!(invalid.blocked_reason, Some(BlockedReason::EvidenceInvalid));
        assert_eq!(invalid.evidence, Some(EvidenceKind::Corrupt));
        assert_eq!(invalid.severity, Severity::Critical);
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.head_timestamp = chain.deadline;
        }
        service.poll_once().await.unwrap();
        let status = service.status();
        let missed = obligation(&status, 0);
        assert_eq!(missed.state, ObligationState::Missed);
        assert_eq!(missed.evidence, Some(EvidenceKind::Corrupt));
        assert_eq!(status.missed_total, 1);
        assert_eq!(status.last_missed.unwrap().kind, Some(CallKind::Defeat));
    }

    #[tokio::test]
    async fn a_restart_in_the_middle_of_the_replacement_resends_the_defeat_never_the_raise() {
        let (fixture, store, _first, second) = raise_then_successor().await;
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        assert_eq!(kinds(&fixture.sends()), [CallKind::Raise]);
        file_evidence(&store, &second, unix_now());
        // The defeat's send has an unknown outcome, and the daemon stops.
        fixture
            .chain
            .lock()
            .unwrap()
            .send_errors
            .push_back(json!({ "code": -32000, "message": "connection reset" }));
        assert!(service.poll_once().await.is_err());
        let persisted = service.checkpoint.pending[&0].attempt.clone();
        assert_eq!(persisted.action, Some(CallKind::Defeat));
        assert!(persisted.replaced_raise);
        assert!(persisted.unknown_attempt);
        let defeat_fees = (
            parse_hex_u128(persisted.max_fee_per_gas.as_deref().unwrap()).unwrap(),
            parse_hex_u128(persisted.max_priority_fee_per_gas.as_deref().unwrap()).unwrap(),
        );
        drop(service);
        let mut restarted = fixture.service();
        restarted.poll_once().await.unwrap();
        // Either attempt may hold the nonce: nothing is sent before the bump
        // interval, and then only the defeat, outbidding its own persisted
        // bid on the same nonce.
        assert_eq!(fixture.sends().len(), 2);
        fixture.chain.lock().unwrap().head_number += 3;
        restarted.poll_once().await.unwrap();
        let sends = fixture.sends();
        assert_eq!(
            kinds(&sends),
            [CallKind::Raise, CallKind::Defeat, CallKind::Defeat]
        );
        assert_eq!(sends[2]["nonce"], "0x3");
        assert_eq!(sends[2]["data"], sends[1]["data"]);
        assert!(fee(&sends[2], "maxFeePerGas") >= min_bump(defeat_fees.0));
        assert!(fee(&sends[2], "maxPriorityFeePerGas") >= min_bump(defeat_fees.1));
        let attempt = &restarted.checkpoint.pending[&0].attempt;
        assert_eq!(attempt.action, Some(CallKind::Defeat));
        assert!(attempt.replaced_raise);
    }

    #[tokio::test]
    async fn a_raise_mined_first_leaves_the_defeat_to_the_next_nonce() {
        let (fixture, store, _first, second) = raise_then_successor().await;
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        assert_eq!(kinds(&fixture.sends()), [CallKind::Raise]);
        // The raise lands (unconfirmed) and successor evidence appears.
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.mined_nonce = 4;
            chain.confirmed_nonce = Some(3);
            chain.conceded = 1;
        }
        file_evidence(&store, &second, unix_now());
        service.poll_once().await.unwrap();
        let sends = fixture.sends();
        assert_eq!(kinds(&sends), [CallKind::Raise, CallKind::Defeat]);
        assert_eq!(
            sends[1]["nonce"], "0x4",
            "the defeat goes on the next nonce"
        );
        // The raise's nonce stays tracked until its confirmation.
        assert!(service.checkpoint.detached_nonces.contains_key(&3));
        assert_eq!(service.checkpoint.pending[&0].nonce, Some(4));
        assert!(!service.checkpoint.pending[&0].attempt.replaced_raise);
        fixture.chain.lock().unwrap().confirmed_nonce = Some(4);
        service.poll_once().await.unwrap();
        assert!(service.checkpoint.detached_nonces.is_empty());
    }

    #[tokio::test]
    async fn a_raise_mined_after_the_escape_was_defeated_reverts_harmlessly() {
        let (fixture, _store, _first, _second) = raise_then_successor().await;
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        let raise_hash = service.checkpoint.pending[&0]
            .transaction_hash
            .clone()
            .unwrap();
        // Someone else defeats the escape before the raise mines.
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.active = false;
            let nullifier = chain.nullifier;
            chain.challenged.insert(nullifier);
        }
        service.poll_once().await.unwrap();
        assert_eq!(
            obligation(&service.status(), 0).state,
            ObligationState::ResolvedUnconfirmed
        );
        // Then the raise mines, and reverts (NotPendingWithdrawal).
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.mined_nonce = 4;
            chain.confirmed_active = false;
            chain
                .receipts
                .insert(raise_hash, json!({ "status": "0x0" }));
            chain.head_number += 3;
        }
        service.poll_once().await.unwrap();
        assert!(service.checkpoint.pending.is_empty());
        assert!(service.checkpoint.detached_nonces.is_empty());
        let status = service.status();
        assert_eq!(status.missed_total, 0);
        assert_eq!(status.status, Severity::Ok, "{:?}", status.alarms);
        assert_eq!(kinds(&fixture.sends()), [CallKind::Raise]);
    }

    #[tokio::test]
    async fn a_raise_no_longer_due_whose_nonce_no_attempt_holds_is_released() {
        let (_, request) = finalized_v2_request().await;
        let store = Arc::new(NullifierStore::in_memory().unwrap());
        issued_lease(&store, &request);
        settle(&store, &request, 1);
        let fixture = escape_at_request(store, &request).await;
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        assert_eq!(kinds(&fixture.sends()), [CallKind::Raise]);
        // The raise was dropped from every pool, and another raise already
        // conceded what is owed.
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.transaction_known = false;
            chain.pending_nonce = None;
            chain.conceded = 1;
        }
        service.poll_once().await.unwrap();
        assert_eq!(service.checkpoint.pending[&0].nonce, None);
        assert_eq!(
            obligation(&service.status(), 0).state,
            ObligationState::Raised
        );
        assert_eq!(fixture.sends().len(), 1);
    }

    #[tokio::test]
    async fn a_missed_defeat_is_counted_and_its_closed_leaf_retired() {
        let fixture = Fixture::new().await;
        // Every defeat simulation reverts: the defeat is missed.
        fixture.chain.lock().unwrap().simulation_error =
            Some(json!({ "code": -32000, "message": "execution reverted" }));
        let mut service = fixture.service_with(|config| config.retire_on_miss = true);
        assert!(service.poll_once().await.is_err());
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.head_timestamp = chain.deadline;
            chain.head_number += 1;
        }
        service.poll_once().await.unwrap();
        let status = service.status();
        assert_eq!(status.escapes_finalized_with_successor_evidence_total, 1);
        assert_eq!(status.missed_raises_total, 0);
        assert_eq!(
            status.last_missed.as_ref().unwrap().kind,
            Some(CallKind::Defeat)
        );
        // The escape is paid out: the obligation turns to the note's leaf.
        let siblings: [Felt252; MERKLE_DEPTH] = zkapi_core::v2::zero_hashes()[..MERKLE_DEPTH]
            .try_into()
            .unwrap();
        let leaf = Felt252::from_u64(0x1eaf);
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.pay_out(5);
            chain.head_number += 3;
            chain.simulation_error = None;
            chain.leaf_paths.insert(0, (leaf, siblings));
            chain.root = zkapi_core::v2::merkle_root(0, &leaf, &siblings);
        }
        service.poll_once().await.unwrap();
        assert!(service.checkpoint.pending[&0].retire_leaf);
        // The retirement goes with the indexer's path at the live root.
        service.poll_once().await.unwrap();
        let sends = fixture.sends();
        assert_eq!(kinds(&sends), [CallKind::Retire]);
        let expected = VaultCall::Retire {
            note_id: 0,
            siblings: Box::new(siblings),
        };
        assert_eq!(
            sends[0]["data"],
            format!("0x{}", hex::encode(expected.calldata().unwrap()))
        );
        let retiring = obligation(&service.status(), 0);
        assert_eq!(retiring.action, Some(CallKind::Retire));
        assert_eq!(
            retiring.severity,
            Severity::Critical,
            "the missed defeat still alarms"
        );
        // Mined: the leaf is zero at the live root, and the obligation ends.
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.mined_nonce = 4;
            chain.leaf_paths.insert(0, (Felt252::ZERO, siblings));
            chain.root = zkapi_core::v2::merkle_root(0, &Felt252::ZERO, &siblings);
            chain.head_number += 3;
        }
        service.poll_once().await.unwrap();
        assert!(service.checkpoint.pending.is_empty());
        assert_eq!(service.checkpoint.retired_leaves_total, 1);
        assert_eq!(kinds(&fixture.sends()), [CallKind::Retire]);
    }

    #[tokio::test]
    async fn a_stale_indexer_path_never_sends_a_retirement() {
        let fixture = Fixture::new().await;
        let mut service = fixture.service_with(|config| config.retire_on_miss = true);
        let siblings: [Felt252; MERKLE_DEPTH] = zkapi_core::v2::zero_hashes()[..MERKLE_DEPTH]
            .try_into()
            .unwrap();
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain
                .leaf_paths
                .insert(0, (Felt252::from_u64(0x1eaf), siblings));
            // The vault's root moved past the indexer's view.
            chain.root = Felt252::from_u64(0x5ca1e);
        }
        service.checkpoint.pending.insert(
            0,
            PendingChallenge {
                nullifier: ESCAPED,
                retire_leaf: true,
                ..Default::default()
            },
        );
        service.persist().unwrap();
        assert!(service.poll_once().await.is_err());
        assert!(fixture.sends().is_empty());
        let blocked = obligation(&service.status(), 0);
        assert_eq!(blocked.state, ObligationState::RetiringLeaf);
        assert_eq!(
            blocked.blocked_reason,
            Some(BlockedReason::IndexerPathBehind)
        );
    }

    #[tokio::test]
    async fn both_getters_are_read_at_one_block_and_decoded_strictly() {
        let fixture = Fixture::new().await;
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        let reads = fixture.chain.lock().unwrap().escape_reads.clone();
        assert!(!reads.is_empty());
        for (kind, block) in reads.iter().filter(|(kind, _)| *kind == "concession") {
            assert_ne!(block, "latest", "{kind} at {block}");
            assert!(
                reads
                    .iter()
                    .any(|(other, at)| *other == "withdrawal" && at == block),
                "pendingConcessions read at {block} without pendingWithdrawals at it"
            );
        }
        let status = obligation(&service.status(), 0);
        assert_eq!(
            status.next_nullifier,
            Some(fixture.chain.lock().unwrap().next_nullifier)
        );
        assert_eq!(
            (status.state_balance, status.conceded),
            (Some(100), Some(0))
        );

        // A concession that does not add up to the pending withdrawal, or
        // that is not three words, fails the poll; nothing is sent.
        for words in [
            vec![Felt252::from_u64(9), Felt252::from_u64(99), Felt252::ZERO],
            vec![Felt252::from_u64(9), Felt252::from_u64(100)],
            vec![Felt252::ZERO, Felt252::from_u64(100), Felt252::ZERO],
        ] {
            let fixture = Fixture::new().await;
            fixture.chain.lock().unwrap().concession_words = Some(words.clone());
            let mut service = fixture.service();
            assert!(service.poll_once().await.is_err(), "{words:?}");
            assert!(fixture.sends().is_empty(), "{words:?}");
        }
        // A malformed concession event fails the scan of its range.
        let fixture = Fixture::new().await;
        fixture.chain.lock().unwrap().malformed_concession_event = true;
        let mut service = fixture.service();
        let error = service.poll_once().await.unwrap_err().to_string();
        assert!(
            error.contains("malformed EscapeConcessionRecorded"),
            "{error}"
        );
        assert_eq!(service.checkpoint.next_block, 0);
    }

    #[tokio::test]
    async fn the_scan_records_the_concession_and_raises_of_an_escape() {
        let fixture = Fixture::new().await;
        // The vault's reads fail, so only the scan's events are applied.
        fixture.chain.lock().unwrap().fail_note_one = false;
        let mut service = fixture.service();
        service.scan_events(5).await.unwrap();
        let pending = &service.checkpoint.pending[&0];
        assert_eq!(pending.nullifier, ESCAPED);
        assert_eq!(
            pending.next_nullifier,
            Some(fixture.chain.lock().unwrap().next_nullifier)
        );
        assert_eq!(
            (pending.state_balance, pending.conceded),
            (Some(100), Some(0))
        );
        let event = |topic: &str, words: &[Felt252]| {
            json!({ "topics": [format!("0x{}", hex::encode(Keccak256::digest(topic.as_bytes()))),
                format!("0x{:064x}", 0)], "data": encoded(words) })
        };
        assert_eq!(
            decode_scan_event(&event(
                CONCESSION_RAISED_EVENT,
                &[ESCAPED, Felt252::from_u64(7), Felt252::from_u64(93)]
            ))
            .unwrap(),
            ScanEvent::Raised {
                note: 0,
                nullifier: ESCAPED,
                conceded: 7
            }
        );
        // Strict: a uint128 word with high bytes, an extra word, a third topic.
        let mut wide = Felt252::from_u64(7);
        wide.0[0] = 1;
        assert!(decode_scan_event(&event(
            CONCESSION_RAISED_EVENT,
            &[ESCAPED, wide, Felt252::from_u64(93)]
        ))
        .is_err());
        assert!(decode_scan_event(&event(CHALLENGED_EVENT, &[ESCAPED, ESCAPED, ESCAPED])).is_err());
        let mut three_topics = event(CHALLENGED_EVENT, &[ESCAPED, ESCAPED]);
        three_topics["topics"]
            .as_array_mut()
            .unwrap()
            .push(json!(format!("0x{:064x}", 1)));
        assert!(decode_scan_event(&three_topics).is_err());
    }

    /// The challenger's reads and its event scan follow the real vault
    /// (vault_calldata_golden.json, from the compiled protocol/contracts
    /// sources): the getters' selectors and word counts, and each scanned
    /// event's topic and data layout, decoded from the vault's own log.
    #[test]
    fn reads_and_scan_follow_the_real_vault() {
        use crate::test_support::{real_event, real_getter_words, real_selector};
        for (name, signature) in [
            ("pendingWithdrawals", "pendingWithdrawals(uint32)"),
            ("pendingConcessions", "pendingConcessions(uint32)"),
            ("notes", "notes(uint32)"),
            ("challengedNullifiers", "challengedNullifiers(uint256)"),
            ("currentRoot", "currentRoot()"),
            ("challengePeriod", "challengePeriod()"),
        ] {
            assert_eq!(
                real_selector(name),
                format!("0x{}", hex::encode(selector(signature))),
                "{name}"
            );
        }
        // escape_state's and note_closed_at's strict word counts.
        assert_eq!(real_getter_words("pendingWithdrawals"), 6);
        assert_eq!(real_getter_words("pendingConcessions"), 3);
        assert_eq!(real_getter_words("notes"), 4);
        let log = |name: &str| {
            let (topics, data) = real_event(name);
            json!({ "topics": topics, "data": data })
        };
        let n = Felt252::from_u64;
        assert_eq!(
            decode_scan_event(&log("EscapeWithdrawalInitiated")).unwrap(),
            ScanEvent::Initiated {
                note: 7,
                nullifier: n(0x0101),
                deadline: 2_000_086_400
            }
        );
        assert_eq!(
            decode_scan_event(&log("EscapeConcessionRecorded")).unwrap(),
            ScanEvent::Recorded {
                note: 7,
                next_nullifier: n(0x0202),
                state_balance: 1_000_000,
                conceded: 100_000
            }
        );
        assert_eq!(
            decode_scan_event(&log("EscapeConcessionRaised")).unwrap(),
            ScanEvent::Raised {
                note: 7,
                nullifier: n(0x0101),
                conceded: 150_000
            }
        );
        assert_eq!(
            decode_scan_event(&log("EscapeWithdrawalChallenged")).unwrap(),
            ScanEvent::Challenged {
                note: 7,
                nullifier: n(0x0101)
            }
        );
        let (finalized, _) = real_event("EscapeWithdrawalFinalized");
        assert_eq!(
            finalized[0],
            format!(
                "0x{}",
                hex::encode(Keccak256::digest(FINALIZED_EVENT.as_bytes()))
            )
        );
    }

    /// A manifest of the fixture's deployment and mock vault code.
    fn mock_manifest(fixture: &Fixture, request: &ApiRequestV2) -> DeploymentManifest {
        let identity = &fixture.service().identity.clone();
        let keys = crate::native_billing::VaultSigningKeys {
            state: CurvePointWire {
                x: request.public_inputs.state_signing_key_x,
                y: request.public_inputs.state_signing_key_y,
            },
            clearance: CurvePointWire {
                x: Felt252::from_u64(1),
                y: Felt252::from_u64(2),
            },
        };
        let json =
            crate::deployment::tests::manifest_json(&format!("0x{:040x}", 0xdead), &keys, identity);
        DeploymentManifest::parse(&json.to_string()).unwrap()
    }

    /// The mock vault and adapter answer the startup probes as `manifest`
    /// pins them, and the database is bound to it.
    fn answer_probes(fixture: &Fixture, manifest: &DeploymentManifest) {
        use crate::deployment::*;
        let identity = fixture.service().identity.clone();
        // A raw 32-byte word: hashes need not be field elements.
        let word = |hex: &str| {
            let mut bytes = [0u8; 32];
            hex::decode_to_slice(format!("{:0>64}", hex.trim_start_matches("0x")), &mut bytes)
                .unwrap();
            Felt252(bytes)
        };
        let mut chain = fixture.chain.lock().unwrap();
        for (selector, value) in [
            (CONCESSION_ESCAPE_VERSION_SELECTOR, Felt252::from_u64(1)),
            (ROOT_HISTORY_WINDOW_SELECTOR, Felt252::from_u64(86_400)),
            (
                PROOF_ADAPTER_SELECTOR,
                word(&manifest.proof_adapter_address),
            ),
            (
                CIRCUIT_ID_HASH_SELECTOR,
                Felt252(zkapi_proof::compact::CIRCUIT_ID_HASH),
            ),
            (
                REQUEST_VK_HASH_SELECTOR,
                word(&identity.request_vk_keccak256),
            ),
            (
                WITHDRAWAL_VK_HASH_SELECTOR,
                word(&identity.withdrawal_vk_keccak256),
            ),
        ] {
            chain.probe_words.insert(selector.to_string(), value);
        }
        for (address, code) in [
            (&manifest.contract_address, b"vault code".as_slice()),
            (&manifest.proof_adapter_address, b"adapter code".as_slice()),
            (
                &manifest.poseidon_library_address,
                b"poseidon code".as_slice(),
            ),
        ] {
            chain
                .code
                .insert(address.clone(), format!("0x{}", hex::encode(code)));
        }
        drop(chain);
        fixture
            .store
            .write_deployment_binding(&manifest.binding(1))
            .unwrap();
    }

    #[tokio::test]
    async fn the_deployment_is_verified_by_binding_probes_and_timing() {
        let (_, request) = finalized_v2_request().await;
        let timing = ChallengeTiming {
            settlement_window_seconds: 21_905,
            settlement_poll_seconds: 2,
        };
        let mismatch = |result: Result<DeploymentBinding, DeploymentCheckError>| match result {
            Err(DeploymentCheckError::Mismatch(message)) => message,
            other => panic!("expected a mismatch, got {other:?}"),
        };
        let fixture = Fixture::new().await;
        let manifest = mock_manifest(&fixture, &request);
        answer_probes(&fixture, &manifest);
        let mut service = fixture.service();
        let binding = service.verify_deployment(&manifest, timing).await.unwrap();
        assert_eq!(
            binding.circuit_id.as_deref(),
            Some(zkapi_proof::compact::CIRCUIT_ID)
        );
        assert!(service.status().config_warnings.is_empty());

        // A raise lead the challenge period cannot hold is refused.
        let mut late = fixture.service_with(|config| config.raise_lead_seconds = 70_000);
        assert!(mismatch(late.verify_deployment(&manifest, timing).await)
            .contains("--raise-lead-seconds"));
        // A vault before revision 3, another adapter verifying key, or other
        // runtime code is refused, each before anything is polled.
        for (change, message) in [
            (
                (|chain: &mut MockChain| {
                    chain.probe_words.insert(
                        crate::deployment::CONCESSION_ESCAPE_VERSION_SELECTOR.into(),
                        Felt252::ZERO,
                    );
                }) as fn(&mut MockChain),
                "CONCESSION_ESCAPE_VERSION",
            ),
            (
                |chain| {
                    chain.probe_words.insert(
                        crate::deployment::REQUEST_VK_HASH_SELECTOR.into(),
                        Felt252::from_u64(5),
                    );
                },
                "REQUEST_VK_HASH",
            ),
            (
                |chain| {
                    for code in chain.code.values_mut() {
                        *code = "0x00".into();
                    }
                },
                "runtime codehash",
            ),
        ] {
            let fixture = Fixture::new().await;
            answer_probes(&fixture, &manifest);
            change(&mut fixture.chain.lock().unwrap());
            let mut service = fixture.service();
            assert!(
                mismatch(service.verify_deployment(&manifest, timing).await).contains(message),
                "{message}"
            );
            assert!(service
                .status()
                .config_warnings
                .iter()
                .any(|warning| warning.contains("deployment not verified")));
        }
        // A manifest of another vault, or a database bound to another
        // challenge period, is refused.
        let fixture = Fixture::new().await;
        answer_probes(&fixture, &manifest);
        let mut other = manifest.clone();
        other.contract_address = format!("0x{:040x}", 0xbeef);
        assert!(
            mismatch(fixture.service().verify_deployment(&other, timing).await)
                .contains("not vault")
        );
        let mut period = manifest.clone();
        period.challenge_period = 7_200;
        assert!(
            mismatch(fixture.service().verify_deployment(&period, timing).await)
                .contains("challenge period")
        );
        // An unreachable RPC is retried, never taken for a verdict.
        fixture.chain.lock().unwrap().fail_all = true;
        assert!(matches!(
            fixture.service().verify_deployment(&manifest, timing).await,
            Err(DeploymentCheckError::Unavailable(_))
        ));
    }
}
