pub mod backend;
pub mod config;
pub mod connection;
pub mod dotenv;
pub mod policy;
pub mod store;

pub use config::{Config, Resolved, SecretRef, check, resolve};
pub use connection::ConnectionMetadata;
pub use policy::{
    ApprovalRequirement, DeliveryMode, SecretAccessRequest, SecretGrant, SecretPolicy,
};
pub use store::{
    Vault, backup_vault, create_vault, recover_vault, restore_vault, rotate_vault_key,
};
