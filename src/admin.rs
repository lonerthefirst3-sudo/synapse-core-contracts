//! # Admin
//!
//! Role-based access control helpers.  The contract has two privileged roles:
//!
//! | Role          | Storage key       | Capabilities                              |
//! |---------------|-------------------|-------------------------------------------|
//! | `admin`       | `StorageKey::Admin`       | Propose/accept admin transfer, rotate relay signer, pause/unpause, upgrade; also permitted to drive status transitions |
//! | `relay_signer`| `StorageKey::RelaySigner` | Register callbacks, drive status transitions |
//!
//! Both roles are initialised once and can be rotated by the admin.

use soroban_sdk::{Address, Env};

use crate::storage::StorageClient;
use crate::types::ContractError;

pub struct AdminClient;

impl AdminClient {
    /// Require the calling transaction to be authorised by the current admin.
    ///
    /// Returns `Err(ContractError::Unauthorised)` when auth fails.
    pub fn require_admin(env: &Env) -> Result<Address, ContractError> {
        let admin = StorageClient::get_admin(env)?;
        admin.require_auth();
        Ok(admin)
    }

    /// Assert that `caller` is either the admin or the trusted relay signer.
    ///
    /// Used by status-transition methods which are callable by both roles.
    pub fn assert_is_relay_or_admin(env: &Env, caller: &Address) -> Result<(), ContractError> {
        let admin = StorageClient::get_admin(env)?;
        let relay = StorageClient::get_relay_signer(env)?;
        if caller != &admin && caller != &relay {
            return Err(ContractError::Unauthorised);
        }
        caller.require_auth();
        Ok(())
    }

    /// Assert that `caller` is specifically the relay signer (not the admin).
    ///
    /// Used by `register_callback` — only the relay may ingest callbacks.
    pub fn require_relay_signer(env: &Env, caller: &Address) -> Result<(), ContractError> {
        let relay = StorageClient::get_relay_signer(env)?;
        if caller != &relay {
            return Err(ContractError::NotRelaySigner);
        }
        caller.require_auth();
        Ok(())
    }

impl AdminClient {
    /// Reject `signer` with [`ContractError::SignerQuarantined`] when its last
    /// heartbeat is older than the configured window.
    ///
    /// A signer that has never heartbeated, or a window of `0`, is never
    /// quarantined (backward compatible). Staleness is strict: a signer is
    /// quarantined only when `now - last_heartbeat > window`.
    pub fn assert_not_quarantined(env: &Env, signer: &Address) -> Result<(), ContractError> {
        let window = StorageClient::get_heartbeat_window(env);
        if window == 0 {
            return Ok(());
        }
        if let Some(last) = StorageClient::get_last_heartbeat(env, signer) {
            if env.ledger().timestamp().saturating_sub(last) > window {
                return Err(ContractError::SignerQuarantined);
            }
        }
        Ok(())
    }
}
}
