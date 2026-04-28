use crate::noise_link::EncryptedCell;
use crate::udp_transport::PeerAddress;

use super::routing_table::RoutingTable;
use super::types::{RouteId, RoutingError};

/// Decides which peer an `EncryptedCell` should be forwarded to.
///
/// Routing decisions are based exclusively on `RouteId` metadata — the
/// encrypted payload is never inspected.
pub struct MeshRouter {
    table: RoutingTable,
}

impl MeshRouter {
    pub fn new(table: RoutingTable) -> Self {
        Self { table }
    }

    pub fn routing_table(&self) -> &RoutingTable {
        &self.table
    }

    pub fn routing_table_mut(&mut self) -> &mut RoutingTable {
        &mut self.table
    }

    /// Return the next-hop `PeerAddress` for `cell` based on `route_id`.
    ///
    /// The encrypted payload of `cell` is never read; it passes to `UDPTransport`
    /// unchanged.  Only `route_id` is used to look up the forwarding entry.
    pub fn forward(
        &self,
        _cell: &EncryptedCell,
        route_id: RouteId,
    ) -> Result<PeerAddress, RoutingError> {
        let route = self.table.get_route(route_id)?;
        Ok(route.next_hop.clone())
    }

    /// Update the latency estimate for a route with one new measurement.
    ///
    /// Uses an EWMA with α = 1/8:
    ///   new_estimate = (7 × old_estimate + sample) / 8
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
