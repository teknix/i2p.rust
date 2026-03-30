//! Core I2P data structures.
//!
//! This module contains the fundamental data types used throughout the I2P
//! router: identifiers, router descriptors, destination endpoints, and
//! lease sets.  These correspond to the classes in
//! `net.i2p.data` and `net.i2p.data.router` in the Java implementation.

pub mod destination;
pub mod hash;
pub mod lease_set;
pub mod router_address;
pub mod router_identity;
pub mod router_info;

pub use destination::Destination;
pub use hash::Hash;
pub use lease_set::{Lease, LeaseSet};
pub use router_address::RouterAddress;
pub use router_identity::RouterIdentity;
pub use router_info::RouterInfo;
