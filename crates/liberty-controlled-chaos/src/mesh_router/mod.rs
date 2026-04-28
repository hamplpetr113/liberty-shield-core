//! MeshRouter — selects the next-hop peer for each `EncryptedCell`.
//!
//! Sits between `NoiseLink` and `UDPTransport`:
//!   NoiseLink → MeshRouter → UDPTransport
//!
//! Routing decisions are based solely on route metadata (`RouteId`, hop count,
//! latency, reliability).  The encrypted cell payload is never inspected.
//!
//! Contains no socket logic and no unsafe code.

mod router;
mod routing_table;
pub mod types;

pub use router::MeshRouter;
pub use routing_table::RoutingTable;
pub use types::{NodeId, Route, RouteId, RoutingError};

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use crate::cell_encoder::CELL_SIZE;
    use crate::noise_link::EncryptedCell;
    use crate::udp_transport::PeerAddress;

    use super::*;

    fn peer(port: u16) -> PeerAddress {
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        PeerAddress::new(addr)
    }

    fn make_route(id: u64, hops: u32, latency_us: u64, reliability: f64, port: u16) -> Route {
        Route {
            route_id: RouteId(id),
            next_hop: peer(port),
            hop_count: hops,
            latency_estimate: latency_us,
            reliability_score: reliability,
        }
    }

    fn dummy_cell() -> EncryptedCell {
        EncryptedCell {
            path_id: 0,
            nonce: 0,
            ciphertext: [0u8; CELL_SIZE],
            auth_tag: [0u8; 16],
        }
    }

    // ── R1: add and remove ────────────────────────────────────────────────────

    #[test]
    fn r1_add_remove_route() {
        let mut table = RoutingTable::new();
        table.add_route(make_route(1, 2, 100, 0.9, 1001)).unwrap();
        assert!(table.get_route(RouteId(1)).is_ok());
        table.remove_route(RouteId(1)).unwrap();
        assert!(matches!(
            table.get_route(RouteId(1)),
            Err(RoutingError::RouteNotFound(RouteId(1)))
        ));
    }

    // ── R2: duplicate route rejected ─────────────────────────────────────────

    #[test]
    fn r2_duplicate_route_rejected() {
        let mut table = RoutingTable::new();
        table.add_route(make_route(2, 1, 50, 1.0, 1002)).unwrap();
        assert!(matches!(
            table.add_route(make_route(2, 1, 50, 1.0, 1003)),
            Err(RoutingError::RouteAlreadyExists(RouteId(2)))
        ));
    }

    // ── R3: best route selection ──────────────────────────────────────────────

    #[test]
    fn r3_best_route_selection() {
        let mut table = RoutingTable::new();
        // High latency, low reliability — worst
        table
            .add_route(make_route(10, 3, 1_000, 0.50, 2001))
            .unwrap();
        // Low latency, high reliability — best
        table.add_route(make_route(11, 1, 10, 0.99, 2002)).unwrap();
        // Medium — middle
        table.add_route(make_route(12, 2, 200, 0.70, 2003)).unwrap();

        assert_eq!(
            table.best_route().unwrap().route_id,
            RouteId(11),
            "route 11 (low latency, high reliability) must win"
        );
    }

    // ── R4: empty table returns error ─────────────────────────────────────────

    #[test]
    fn r4_empty_table_no_best_route() {
        assert!(matches!(
            RoutingTable::new().best_route(),
            Err(RoutingError::NoRoutesAvailable)
        ));
    }

    // ── R5: forward returns correct PeerAddress ───────────────────────────────

    #[test]
    fn r5_forward_returns_correct_peer() {
        let expected = peer(3001);
        let mut table = RoutingTable::new();
        table
            .add_route(Route {
                route_id: RouteId(100),
                next_hop: expected.clone(),
                hop_count: 1,
                latency_estimate: 50,
                reliability_score: 0.95,
            })
            .unwrap();

        let router = MeshRouter::new(table);
        let result = router.forward(&dummy_cell(), RouteId(100)).unwrap();
        assert_eq!(result, expected);
    }

    // ── R6: unknown route returns error ───────────────────────────────────────

    #[test]
    fn r6_unknown_route_returns_error() {
        let router = MeshRouter::new(RoutingTable::new());
        assert!(matches!(
            router.forward(&dummy_cell(), RouteId(999)),
            Err(RoutingError::RouteNotFound(RouteId(999)))
        ));
    }

    // ── R7: update_metrics adjusts latency via EWMA ───────────────────────────

    #[test]
    fn r7_update_metrics_adjusts_latency() {
        let mut table = RoutingTable::new();
        table.add_route(make_route(200, 1, 800, 0.9, 4001)).unwrap();
        let mut router = MeshRouter::new(table);

        // (800 / 8) * 7 + 0 / 8 = 100 * 7 + 0 = 700
        router.update_route_metrics(RouteId(200), 0).unwrap();
        let latency = router
            .routing_table()
            .get_route(RouteId(200))
            .unwrap()
            .latency_estimate;
        assert_eq!(
            latency, 700,
            "EWMA must lower latency toward the new sample"
        );
    }

    // ── R8: update_metrics on missing route returns error ────────────────────

    #[test]
    fn r8_update_metrics_unknown_route_returns_error() {
        let mut router = MeshRouter::new(RoutingTable::new());
        assert!(matches!(
            router.update_route_metrics(RouteId(404), 100),
            Err(RoutingError::RouteNotFound(RouteId(404)))
        ));
    }

    // ── R9: remove non-existent route returns error ───────────────────────────

    #[test]
    fn r9_remove_nonexistent_route_returns_error() {
        let mut table = RoutingTable::new();
        assert!(matches!(
            table.remove_route(RouteId(42)),
            Err(RoutingError::RouteNotFound(RouteId(42)))
        ));
    }

    // ── R10: routing is deterministic (same inputs, same result) ─────────────

    #[test]
    fn r10_routing_deterministic() {
        let build_table = || {
            let mut t = RoutingTable::new();
            t.add_route(make_route(1, 2, 500, 0.8, 5001)).unwrap();
            t.add_route(make_route(2, 1, 100, 0.95, 5002)).unwrap();
            t
        };

        let r1 = MeshRouter::new(build_table());
        let r2 = MeshRouter::new(build_table());

        let hop1 = r1.forward(&dummy_cell(), RouteId(2)).unwrap();
        let hop2 = r2.forward(&dummy_cell(), RouteId(2)).unwrap();
        assert_eq!(hop1, hop2, "same inputs must always yield same next-hop");
    }
}
