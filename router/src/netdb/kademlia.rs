//! Kademlia k-bucket for the NetDB DHT.
//!
//! The NetDB uses the XOR metric to measure distance between router hashes.
//! A [`KBucket`] holds up to [`KBUCKET_SIZE`] peer hashes that share a common
//! prefix with the local router.  Closest peers have the shortest XOR distance
//! to the local key.
//!
//! Java equivalent: `KademliaNetworkDatabaseFacade` + `FloodfillPeerSelector`

use crate::data::hash::Hash;

/// Maximum number of entries per k-bucket (standard Kademlia value: 20).
pub const KBUCKET_SIZE: usize = 20;

/// A single Kademlia k-bucket holding peer hashes ordered by XOR distance.
///
/// The bucket covers the key space within a specific XOR distance prefix from
/// the local router.  When full, the least-recently-contacted peer is evicted
/// if the new peer is closer.
#[derive(Debug, Default, Clone)]
pub struct KBucket {
    /// Peer hashes, ordered from least recently contacted (index 0) to most
    /// recently contacted (last index).
    peers: Vec<Hash>,
}

impl KBucket {
    /// Create an empty k-bucket.
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the number of peers currently in this bucket.
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// Return `true` when the bucket contains no peers.
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// Return `true` when the bucket has reached capacity.
    pub fn is_full(&self) -> bool {
        self.peers.len() >= KBUCKET_SIZE
    }

    /// Attempt to insert `peer` into this bucket.
    ///
    /// - If `peer` is already present it is moved to the tail (most recent).
    /// - If the bucket is not full the peer is appended.
    /// - If the bucket is full the peer is **not** inserted (the caller should
    ///   ping the head peer to see if it is still alive before evicting it).
    ///
    /// Returns `true` when the peer was inserted or updated.
    pub fn insert(&mut self, peer: Hash) -> bool {
        if let Some(pos) = self.peers.iter().position(|h| h == &peer) {
            // Refresh: move to tail.
            self.peers.remove(pos);
            self.peers.push(peer);
            return true;
        }
        if self.is_full() {
            return false;
        }
        self.peers.push(peer);
        true
    }

    /// Remove a peer from the bucket (e.g. after confirming it is unreachable).
    pub fn remove(&mut self, peer: &Hash) {
        self.peers.retain(|h| h != peer);
    }

    /// Return the *head* peer (least recently contacted), which is the
    /// eviction candidate when the bucket is full.
    pub fn head(&self) -> Option<&Hash> {
        self.peers.first()
    }

    /// Return all peer hashes in this bucket.
    pub fn peers(&self) -> &[Hash] {
        &self.peers
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(seed: &[u8]) -> Hash {
        Hash::sha256(seed)
    }

    #[test]
    fn insert_and_len() {
        let mut b = KBucket::new();
        assert!(b.insert(h(b"a")));
        assert!(b.insert(h(b"b")));
        assert_eq!(b.len(), 2);
    }

    #[test]
    fn duplicate_refreshes_position() {
        let mut b = KBucket::new();
        let peer = h(b"x");
        b.insert(h(b"a"));
        b.insert(peer.clone());
        b.insert(h(b"c"));
        // Refresh peer — it should now be at the tail.
        b.insert(peer.clone());
        assert_eq!(b.peers().last(), Some(&peer));
    }

    #[test]
    fn full_bucket_rejects_new_peer() {
        let mut b = KBucket::new();
        for i in 0u8..KBUCKET_SIZE as u8 {
            b.insert(h(&[i]));
        }
        assert!(b.is_full());
        let new_peer = h(b"new");
        assert!(!b.insert(new_peer.clone()));
        assert!(!b.peers().contains(&new_peer));
    }

    #[test]
    fn remove_peer() {
        let mut b = KBucket::new();
        let peer = h(b"p");
        b.insert(peer.clone());
        b.remove(&peer);
        assert!(b.is_empty());
    }
}
