//! I2P SAM (Simple Anonymous Messaging) protocol implementation.
//!
//! This crate provides the building blocks for implementing the SAM v1/v2/v3
//! protocol bridge in Rust.  It is a port of the Java implementation found in
//! `apps/sam/` of the I2P Java router, maintained with idiomatic Rust
//! practices (strong typing, `Result`-based error handling, `async`/`await`).
//!
//! # Modules
//!
//! | Module | Java equivalent |
//! |--------|-----------------|
//! | [`error`] | `SAMException`, `DataFormatException`, `I2PSessionException` |
//! | [`types`] | `net.i2p.data.Destination` |
//! | [`params`] | `SAMUtils.parseParams` |
//! | [`naming`] | `SAMUtils.getDest`, `SAMMessageSession.lookupDest` |
//! | [`session`] | `SAMMessageSess`, `SAMMessageSession`, `SAMStreamSession` |
//! | [`handler`] | `SAMv1Handler.execNamingMessage` |
//!
//! # Key feature: in-session b32 lookups (since 0.9.69)
//!
//! When a SAM client issues a `NAMING LOOKUP NAME=<b32>.b32.i2p` command and
//! an active session exists, the lookup is routed *through that session's
//! I2CP connection* so that the router uses the client's tunnels to fetch the
//! lease-set.  This keeps the lease-set in the client's netDB partition and
//! avoids a redundant lookup when a message is subsequently sent.
//!
//! See [`naming::resolve`] and [`handler::SamV1Handler::exec_naming_message`]
//! for the implementation.

pub mod error;
pub mod handler;
pub mod naming;
pub mod params;
pub mod session;
pub mod types;

// Convenience re-exports of the most commonly used items.
pub use error::{Result, SamError};
pub use handler::SamV1Handler;
pub use naming::{get_dest, lookup_dest, resolve};
pub use params::{parse_params, Params, COMMAND_KEY, OPCODE_KEY};
pub use session::{I2cpSession, MessageSession, SamSession, StreamSession};
pub use types::Destination;
