use std::collections::HashMap;

use crate::udp_transport::PeerAddress;

use super::types::{RouteId, RoutingError};

/// A stateful multi-hop path through the mesh.
///
/// `advance()` returns the next `PeerAddress` and mutates `current_hop_index`
/// and `ttl`.  On any error the state is left unchanged.
pub struct RoutePath {
    pub route_id: RouteId,
    /// Ordered list of next-hop peers that make up the full path.
    pub hops: Vec<PeerAddress>,
    /// Index of the hop that will be returned on the next call to `advance`.
    pub current_hop_index: usize,
    /// Upper bound on the number of hops that may be traversed (≤ `hops.len()`).
    pub max_hops: usize,
    /// Remaining forwarding budget; decremented on every successful `advance`.
    pub ttl: u32,
}

impl RoutePath {
    /// Construct a path where `max_hops` defaults to `hops.len()`.
    pub fn new(route_id: RouteId, hops: Vec<PeerAddress>, ttl: u32) -> Self {
        let max_hops = hops.len();
        Self {
            route_id,
            hops,
            current_hop_index: 0,
            max_hops,
            ttl,
        }
    }

    /// Construct a path with an explicit hop-count ceiling.
    pub fn with_max_hops(
        route_id: RouteId,
        hops: Vec<PeerAddress>,
        max_hops: usize,
        ttl: u32,
    ) -> Self {
        Self {
            route_id,
            hops,
            current_hop_index: 0,
            max_hops,
            ttl,
        }
    }

    /// Advance to the next hop.
    ///
    /// Checks (in order):
    ///   1. `ttl == 0`                      → `RouteExpired`
    ///   2. `current_hop_index >= limit`    → `RouteComplete`
    ///   3. next hop already in path prefix → `RoutingLoop`
    ///
    /// On success: increments `current_hop_index`, decrements `ttl`, returns
    /// the peer.  On any error: state is unchanged.
    pub fn advance(&mut self) -> Result<PeerAddress, RoutingError> {
        if self.ttl == 0 {
            return Err(RoutingError::RouteExpired(self.route_id));
        }

        let limit = self.max_hops.min(self.hops.len());
        if self.current_hop_index >= limit {
            return Err(RoutingError::RouteComplete(self.route_id));
        }

        // Loop detection: next hop must not repeat any already-visited peer.
        for i in 0..self.current_hop_index {
            if self.hops[i] == self.hops[self.current_hop_index] {
                return Err(RoutingError::RoutingLoop(self.route_id));
            }
        }

        let next = self.hops[self.current_hop_index].clone();
        self.current_hop_index += 1;
        self.ttl -= 1;
        Ok(next)
    }

    pub fn is_complete(&self) -> bool {
        self.current_hop_index >= self.max_hops.min(self.hops.len())
    }

    pub fn is_expired(&self) -> bool {
        self.ttl == 0
    }

    pub fn remaining_hops(&self) -> usize {
        self.max_hops
            .min(self.hops.len())
            .saturating_sub(self.current_hop_index)
    }
}

// ── PathTable ─────────────────────────────────────────────────────────────────

/// Stores and advances `RoutePath` entries keyed by `RouteId`.
pub struct PathTable {
    paths: HashMap<u64, RoutePath>,
}

impl PathTable {
    pub fn new() -> Self {
        Self {
            paths: HashMap::new(),
        }
    }

    /// Insert a path.  Returns `RouteAlreadyExists` if the id is taken.
    pub fn add_path(&mut self, path: RoutePath) -> Result<(), RoutingError> {
        let id = path.route_id.0;
        if self.paths.contains_key(&id) {
            return Err(RoutingError::RouteAlreadyExists(path.route_id));
        }
        self.paths.insert(id, path);
        Ok(())
    }

    /// Advance the named path by one hop and return the next peer.
    pub fn advance(&mut self, route_id: RouteId) -> Result<PeerAddress, RoutingError> {
        self.paths
            .get_mut(&route_id.0)
            .ok_or(RoutingError::RouteNotFound(route_id))?
            .advance()
    }

    pub fn get_path(&self, route_id: RouteId) -> Result<&RoutePath, RoutingError> {
        self.paths
            .get(&route_id.0)
            .ok_or(RoutingError::RouteNotFound(route_id))
    }

    pub fn remove_path(&mut self, route_id: RouteId) -> Result<RoutePath, RoutingError> {
        self.paths
            .remove(&route_id.0)
            .ok_or(RoutingError::RouteNotFound(route_id))
    }
}

impl Default for PathTable {
    fn default() -> Self {
        Self::new()
    }
}
