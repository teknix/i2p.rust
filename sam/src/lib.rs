//! I2P SAM (Simple Anonymous Messaging) **server/router** implementation.
//!
//! This crate ports the SAM bridge *server* from the Java I2P router
//! (`apps/sam/java/src/net/i2p/sam/`) to idiomatic, async Rust.
//!
//! # Scope
//!
//! **Server side only.**  SAM *client* code (the Java classes in
//! `net.i2p.sam.client.*` — `SAMReader`, `SAMEventHandler`,
//! `SAMStreamSend`, `SAMStreamSink`, …) is intentionally *not* ported here;
//! those remain in Java.
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
//! | [`connection`] | `SAMHandler` + `SAMHandlerFactory` |
//! | [`bridge`] | `SAMBridge` |
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

pub mod bridge;
pub mod connection;
pub mod error;
pub mod handler;
pub mod naming;
pub mod params;
pub mod session;
pub mod types;

// Convenience re-exports of the most commonly used items.
pub use bridge::{BridgeConfig, SamBridge};
pub use connection::SamConnection;
pub use error::{Result, SamError};
pub use handler::SamV1Handler;
pub use naming::{get_dest, lookup_dest, resolve};
pub use params::{parse_params, Params, COMMAND_KEY, OPCODE_KEY};
pub use session::{I2cpSession, MessageSession, SamSession, StreamSession};
pub use types::Destination;
