//! MeshRouter — selects the next-hop peer for each `EncryptedCell`.
//!
//! Sits between `NoiseLink` and `UDPTransport`:
//!   NoiseLink → MeshRouter → UDPTransport
//!
//! Routing decisions are based solely on route metadata (`RouteId`, hop count,
//! latency, reliability).  The encrypted cell payload is never inspected.
//!
//! Contains no socket logic and no unsafe code.

mod route_path;
mod router;
mod routing_table;
pub mod types;

pub use route_path::{PathTable, RoutePath};
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

    // ═══════════════════════════════════════════════════════════════════════════
    // Multi-hop RoutePath tests
    // ═══════════════════════════════════════════════════════════════════════════

    fn make_path(id: u64, ports: &[u16], ttl: u32) -> RoutePath {
        let hops = ports.iter().map(|&p| peer(p)).collect();
        RoutePath::new(RouteId(id), hops, ttl)
    }

    // ── M1: multi-hop forward sequence ───────────────────────────────────────

    #[test]
    fn m1_multi_hop_forward_sequence() {
        let mut router = MeshRouter::new(RoutingTable::new());
        router
            .path_table_mut()
            .add_path(make_path(1, &[6001, 6002, 6003], 10))
            .unwrap();

        let cell = dummy_cell();
        assert_eq!(router.forward_path(&cell, RouteId(1)).unwrap(), peer(6001));
        assert_eq!(router.forward_path(&cell, RouteId(1)).unwrap(), peer(6002));
        assert_eq!(router.forward_path(&cell, RouteId(1)).unwrap(), peer(6003));

        // After all hops, the path is complete.
        assert!(matches!(
            router.forward_path(&cell, RouteId(1)),
            Err(RoutingError::RouteComplete(RouteId(1)))
        ));
    }

    // ── M2: TTL expiration ────────────────────────────────────────────────────

    #[test]
    fn m2_ttl_expiration() {
        let mut router = MeshRouter::new(RoutingTable::new());
        // TTL=1 — only one hop may be taken.
        router
            .path_table_mut()
            .add_path(make_path(2, &[7001, 7002, 7003], 1))
            .unwrap();

        let cell = dummy_cell();
        assert_eq!(router.forward_path(&cell, RouteId(2)).unwrap(), peer(7001));

        // TTL is now 0 — all subsequent calls return RouteExpired.
        assert!(matches!(
            router.forward_path(&cell, RouteId(2)),
            Err(RoutingError::RouteExpired(RouteId(2)))
        ));
        // State is sticky: repeated calls still return RouteExpired.
        assert!(matches!(
            router.forward_path(&cell, RouteId(2)),
            Err(RoutingError::RouteExpired(RouteId(2)))
        ));
    }

    // ── M3: route completion via max_hops ceiling ────────────────────────────

    #[test]
    fn m3_route_completion_max_hops() {
        let mut router = MeshRouter::new(RoutingTable::new());
        // 4 hops in the vec but max_hops capped at 2.
        let path = RoutePath::with_max_hops(
            RouteId(3),
            vec![peer(8001), peer(8002), peer(8003), peer(8004)],
            2,
            10,
        );
        router.path_table_mut().add_path(path).unwrap();

        let cell = dummy_cell();
        assert_eq!(router.forward_path(&cell, RouteId(3)).unwrap(), peer(8001));
        assert_eq!(router.forward_path(&cell, RouteId(3)).unwrap(), peer(8002));

        // max_hops reached — complete even though hops remain in the vec.
        assert!(matches!(
            router.forward_path(&cell, RouteId(3)),
            Err(RoutingError::RouteComplete(RouteId(3)))
        ));
    }

    // ── M4: loop prevention ───────────────────────────────────────────────────

    #[test]
    fn m4_loop_prevention() {
        let mut router = MeshRouter::new(RoutingTable::new());
        // A → B → A (loop at index 2): port 9001 appears twice.
        let path = RoutePath::new(
            RouteId(4),
            vec![peer(9001), peer(9002), peer(9001), peer(9003)],
            10,
        );
        router.path_table_mut().add_path(path).unwrap();

        let cell = dummy_cell();
        assert_eq!(router.forward_path(&cell, RouteId(4)).unwrap(), peer(9001)); // hop 0 OK
        assert_eq!(router.forward_path(&cell, RouteId(4)).unwrap(), peer(9002)); // hop 1 OK

        // hop 2 would revisit 9001 — loop detected.
        assert!(matches!(
            router.forward_path(&cell, RouteId(4)),
            Err(RoutingError::RoutingLoop(RouteId(4)))
        ));
        // State unchanged after RoutingLoop: hop index still at 2.
        assert_eq!(
            router
                .path_table()
                .get_path(RouteId(4))
                .unwrap()
                .current_hop_index,
            2
        );
    }

    // ── M5: forward_path on unknown route returns RouteNotFound ──────────────

    #[test]
    fn m5_unknown_path_returns_not_found() {
        let mut router = MeshRouter::new(RoutingTable::new());
        assert!(matches!(
            router.forward_path(&dummy_cell(), RouteId(999)),
            Err(RoutingError::RouteNotFound(RouteId(999)))
        ));
    }

    // ── M6: zero-TTL path is immediately expired ─────────────────────────────

    #[test]
    fn m6_zero_ttl_immediately_expired() {
        let mut router = MeshRouter::new(RoutingTable::new());
        router
            .path_table_mut()
            .add_path(make_path(6, &[1111], 0))
            .unwrap();
        assert!(matches!(
            router.forward_path(&dummy_cell(), RouteId(6)),
            Err(RoutingError::RouteExpired(RouteId(6)))
        ));
    }

    // ── M7: is_complete / is_expired helpers ──────────────────────────────────

    #[test]
    fn m7_path_state_helpers() {
        let mut path = make_path(7, &[2001, 2002], 2);
        assert!(!path.is_complete());
        assert!(!path.is_expired());
        assert_eq!(path.remaining_hops(), 2);

        path.advance().unwrap();
        assert_eq!(path.remaining_hops(), 1);

        path.advance().unwrap();
        assert!(path.is_complete());
        assert!(path.is_expired()); // TTL also hits 0 after 2 advances from TTL=2
    }
}
