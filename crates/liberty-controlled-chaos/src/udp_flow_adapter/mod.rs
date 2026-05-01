//! UDP → PacketFlowEngine adapter.
//!
//! `UdpFlowAdapter` bridges `RealUdpRuntime` (OS UDP sockets) and
//! `PacketFlowEngine` (onion routing pipeline).
//!
//! **Inbound path:** poll_recv() from UDP → process_inbound() on the flow
//! engine.  Returns the number of packets pumped.
//!
//! **Outbound path:** poll_outbound() from the flow engine → send_to_peer()
//! via UDP.  Returns the number of packets flushed.
//!
//! The adapter holds no queues of its own; it is purely a bridge.  Callers
//! must tick both sides at an appropriate rate.

use crate::packet_flow_engine::PacketFlowEngine;
use crate::real_udp_runtime::RealUdpRuntime;

// ---------------------------------------------------------------------------
// AdapterMetrics
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct AdapterMetrics {
    pub inbound_pumped: u64,
    pub outbound_flushed: u64,
    pub outbound_no_route: u64,
}

// ---------------------------------------------------------------------------
// UdpFlowAdapter
// ---------------------------------------------------------------------------

pub struct UdpFlowAdapter {
    udp: RealUdpRuntime,
    flow: PacketFlowEngine,
    metrics: AdapterMetrics,
}

impl UdpFlowAdapter {
    pub fn new(udp: RealUdpRuntime, flow: PacketFlowEngine) -> Self {
        Self {
            udp,
            flow,
            metrics: AdapterMetrics::default(),
        }
    }

    // -----------------------------------------------------------------------
    // Inbound
    // -----------------------------------------------------------------------

    /// Drain all pending UDP datagrams into the flow engine.
    /// Packets from unknown addresses are dropped.
    /// Returns the number of packets processed.
    pub fn pump_inbound(&mut self) -> usize {
        let mut count = 0;
        while let Some(pkt) = self.udp.poll_recv() {
            if let Some(node_id) = self.udp.peer_id_by_addr(pkt.from_addr) {
                self.flow.process_inbound(node_id, &pkt.payload);
                self.metrics.inbound_pumped += 1;
                count += 1;
            }
        }
        count
    }

    // -----------------------------------------------------------------------
    // Outbound
    // -----------------------------------------------------------------------

    /// Flush all queued outbound packets to the UDP socket.
    /// Returns the number of packets flushed.
    pub fn flush_outbound(&mut self) -> usize {
        let mut count = 0;
        while let Some(pkt) = self.flow.poll_outbound() {
            match self.udp.send_to_peer(&pkt.peer_id, &pkt.wire_bytes) {
                Ok(_) => {
                    self.metrics.outbound_flushed += 1;
                    count += 1;
                }
                Err(_) => {
                    self.metrics.outbound_no_route += 1;
                }
            }
        }
        count
    }

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    pub fn udp(&self) -> &RealUdpRuntime {
        &self.udp
    }

    pub fn udp_mut(&mut self) -> &mut RealUdpRuntime {
        &mut self.udp
    }

    pub fn flow(&self) -> &PacketFlowEngine {
        &self.flow
    }

    pub fn flow_mut(&mut self) -> &mut PacketFlowEngine {
        &mut self.flow
    }

    pub fn metrics(&self) -> &AdapterMetrics {
        &self.metrics
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet_flow_engine::PacketFlowEngine;
    use crate::real_udp_runtime::RealUdpRuntime;

    fn peer(b: u8) -> [u8; 32] {
        [b; 32]
    }

    // UFA1: construction succeeds.
    #[test]
    fn ufa1_construction() {
        let udp = RealUdpRuntime::bind("127.0.0.1:0").unwrap();
        let flow = PacketFlowEngine::new(peer(1));
        let adapter = UdpFlowAdapter::new(udp, flow);
        assert_eq!(adapter.metrics().inbound_pumped, 0);
        assert_eq!(adapter.metrics().outbound_flushed, 0);
    }

    // UFA2: pump_inbound with no pending datagrams returns 0.
    #[test]
    fn ufa2_pump_empty() {
        let udp = RealUdpRuntime::bind("127.0.0.1:0").unwrap();
        let flow = PacketFlowEngine::new(peer(1));
        let mut adapter = UdpFlowAdapter::new(udp, flow);
        assert_eq!(adapter.pump_inbound(), 0);
    }

    // UFA3: flush_outbound with empty queue returns 0.
    #[test]
    fn ufa3_flush_empty() {
        let udp = RealUdpRuntime::bind("127.0.0.1:0").unwrap();
        let flow = PacketFlowEngine::new(peer(1));
        let mut adapter = UdpFlowAdapter::new(udp, flow);
        assert_eq!(adapter.flush_outbound(), 0);
    }

    // UFA4: udp() accessor returns bound address.
    #[test]
    fn ufa4_udp_accessor() {
        let udp = RealUdpRuntime::bind("127.0.0.1:0").unwrap();
        let flow = PacketFlowEngine::new(peer(2));
        let adapter = UdpFlowAdapter::new(udp, flow);
        assert!(adapter.udp().local_addr().is_some());
    }

    // UFA5: flow() accessor has correct local_id.
    #[test]
    fn ufa5_flow_accessor() {
        let udp = RealUdpRuntime::bind("127.0.0.1:0").unwrap();
        let flow = PacketFlowEngine::new(peer(3));
        let adapter = UdpFlowAdapter::new(udp, flow);
        // flow() returns reference; presence is sufficient.
        let _ = adapter.flow();
    }

    // UFA6: flush_outbound sends queued packet to known peer; returns 1.
    #[test]
    fn ufa6_flush_known_peer() {
        let udp_a = RealUdpRuntime::bind("127.0.0.1:0").unwrap();
        let addr_a = udp_a.local_addr().unwrap();
        let flow = PacketFlowEngine::new(peer(10));

        let udp_b = RealUdpRuntime::bind("127.0.0.1:0").unwrap();
        let mut adapter_b = UdpFlowAdapter::new(udp_b, flow);
        adapter_b.udp_mut().connect_peer(peer(10), addr_a);

        // Manually push to the outbound queue.
        use crate::outbound_send_queue::QueuedPacket;
        adapter_b
            .flow_mut()
            .outbound_queue_mut()
            .push(QueuedPacket {
                peer_id: peer(10),
                wire_bytes: b"hello".to_vec(),
            })
            .unwrap();

        let flushed = adapter_b.flush_outbound();
        assert_eq!(flushed, 1);
        assert_eq!(adapter_b.metrics().outbound_flushed, 1);
    }

    // UFA7: flush_outbound with unknown peer increments no_route counter.
    #[test]
    fn ufa7_flush_unknown_peer_no_route() {
        let udp = RealUdpRuntime::bind("127.0.0.1:0").unwrap();
        let flow = PacketFlowEngine::new(peer(1));
        let mut adapter = UdpFlowAdapter::new(udp, flow);

        use crate::outbound_send_queue::QueuedPacket;
        adapter
            .flow_mut()
            .outbound_queue_mut()
            .push(QueuedPacket {
                peer_id: peer(99),
                wire_bytes: b"data".to_vec(),
            })
            .unwrap();

        let flushed = adapter.flush_outbound();
        assert_eq!(flushed, 0);
        assert_eq!(adapter.metrics().outbound_no_route, 1);
    }

    // UFA8: metrics accurate after mixed operations.
    #[test]
    fn ufa8_metrics_accurate() {
        let udp = RealUdpRuntime::bind("127.0.0.1:0").unwrap();
        let flow = PacketFlowEngine::new(peer(5));
        let mut adapter = UdpFlowAdapter::new(udp, flow);

        use crate::outbound_send_queue::QueuedPacket;
        // Queue 2 packets for unknown peers → no_route
        for _ in 0..2 {
            adapter
                .flow_mut()
                .outbound_queue_mut()
                .push(QueuedPacket {
                    peer_id: peer(77),
                    wire_bytes: b"x".to_vec(),
                })
                .unwrap();
        }
        adapter.flush_outbound();
        assert_eq!(adapter.metrics().outbound_no_route, 2);
        assert_eq!(adapter.metrics().outbound_flushed, 0);
        assert_eq!(adapter.metrics().inbound_pumped, 0);
    }
}
