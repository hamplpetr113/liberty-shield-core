use crate::udp_transport::PeerAddress;

/// Identifies a node in the mesh network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeId(pub u64);

/// Identifies a route in the routing table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RouteId(pub u64);

/// A single routing entry describing how to reach a destination.
#[derive(Debug, Clone)]
pub struct Route {
    pub route_id: RouteId,
    /// Next-hop peer to which the packet is forwarded.
    pub next_hop: PeerAddress,
    /// Number of hops to the destination (lower is better).
    pub hop_count: u32,
    /// Smoothed round-trip latency estimate in microseconds (lower is better).
    pub latency_estimate: u64,
    /// Fraction of packets delivered successfully, in [0.0, 1.0] (higher is better).
    pub reliability_score: f64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RoutingError {
    /// No route with the given `RouteId` exists in the table.
    RouteNotFound(RouteId),
    /// The routing table is empty; no best route can be selected.
    NoRoutesAvailable,
    /// A route with the same `RouteId` already exists.
    RouteAlreadyExists(RouteId),
}
