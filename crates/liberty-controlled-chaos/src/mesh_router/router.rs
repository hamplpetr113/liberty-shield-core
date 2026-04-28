use crate::noise_link::EncryptedCell;
use crate::udp_transport::PeerAddress;

use super::route_path::PathTable;
use super::routing_table::RoutingTable;
use super::types::{RouteId, RoutingError};

/// Decides which peer an `EncryptedCell` should be forwarded to.
///
/// Supports both single-hop `Route` lookups (`forward`) and stateful multi-hop
/// `RoutePath` traversal (`forward_path`).  The encrypted cell payload is never
/// inspected in either mode.
pub struct MeshRouter {
    table: RoutingTable,
    path_table: PathTable,
}

impl MeshRouter {
    pub fn new(table: RoutingTable) -> Self {
        Self {
            table,
            path_table: PathTable::new(),
        }
    }

    pub fn routing_table(&self) -> &RoutingTable {
        &self.table
    }

    pub fn routing_table_mut(&mut self) -> &mut RoutingTable {
        &mut self.table
    }

    pub fn path_table(&self) -> &PathTable {
        &self.path_table
    }

    pub fn path_table_mut(&mut self) -> &mut PathTable {
        &mut self.path_table
    }

    /// Single-hop forward: look up `route_id` in the `RoutingTable` and return
    /// its `next_hop`.  The encrypted payload is never read.
    pub fn forward(
        &self,
        _cell: &EncryptedCell,
        route_id: RouteId,
    ) -> Result<PeerAddress, RoutingError> {
        let route = self.table.get_route(route_id)?;
        Ok(route.next_hop.clone())
    }

    /// Multi-hop forward: advance the `RoutePath` identified by `route_id` by
    /// one step and return the next peer.
    ///
    /// Steps:
    ///   1. Look up `RoutePath` by `route_id`.
    ///   2. Check TTL > 0 (else `RouteExpired`).
    ///   3. Check that hops remain (else `RouteComplete`).
    ///   4. Check next hop is not a repeat (else `RoutingLoop`).
    ///   5. Increment hop index, decrement TTL, return peer.
    ///
    /// The encrypted payload of `cell` is never read.
    pub fn forward_path(
        &mut self,
        _cell: &EncryptedCell,
        route_id: RouteId,
    ) -> Result<PeerAddress, RoutingError> {
        self.path_table.advance(route_id)
    }

    /// Update the latency estimate for a single-hop route using EWMA (α = 1/8).
    pub fn update_route_metrics(
        &mut self,
        route_id: RouteId,
        latency_us: u64,
    ) -> Result<(), RoutingError> {
        let route = self.table.get_route_mut(route_id)?;
        route.latency_estimate = (route.latency_estimate / 8) * 7 + latency_us / 8;
        Ok(())
    }
}
