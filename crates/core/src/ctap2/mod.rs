//! CTAP 2.1 command processing (MVP-2).

mod authn;
mod client_pin;
mod common;
mod cred_mgmt;
mod get_assertion;
mod info;
mod make_credential;
mod state;

pub use authn::{Authenticator, Pending, Step, UserInfo, UvOutcome};
pub use common::{status, ClientPinSub, Command, CredMgmtSub, AAGUID, ES256, MAX_MSG_SIZE};
pub use make_credential::APPLIED_CRED_PROTECT;

#[cfg(test)]
mod tests;
