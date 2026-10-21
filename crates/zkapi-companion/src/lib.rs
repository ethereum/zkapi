pub mod chain;
pub mod compat;
pub mod config;
pub mod error;
pub mod exit_kit;
pub mod indexer;
mod oa_withdrawal;
pub mod routes;
pub mod service;
pub mod wallet_lock;

pub use config::{AuthConfig, ModelDescriptor, RequestMode};
pub use routes::{build_router, run};
pub use service::{
    AuthService, ConfirmDepositRequest, CoreRequest, CoreResponse, DemoOverview, DepositPlan,
    DirectLeaseStatus, FundingConfig, IndexerSnapshot, NoteStatus, PreparedWithdrawalStatus,
    ProtocolResponseTrace, RecoverResult, RequestDemoResult, RequestPreview, RetiredNote,
    ServerAttestationSnapshot, ServerHealthSnapshot, ServerSnapshot, WalletStatus,
    WithdrawalChainStatus, WithdrawalMode, WithdrawalPlan, ZkapiConfig, CREDITS_PER_USD,
};
pub use wallet_lock::WalletLock;

mod oa_native;

mod oa_events;

mod oa_station_trust;
