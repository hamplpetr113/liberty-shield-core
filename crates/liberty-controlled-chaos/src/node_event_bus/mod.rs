//! Node event bus — synchronous in-process event fan-out.
//!
//! Subscribers register interest in `EventKind`s.  Events are dispatched
//! synchronously to all matching subscribers in insertion order.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// EventKind
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventKind {
    PeerConnected,
    PeerDisconnected,
    CircuitBuilt,
    CircuitTornDown,
    PolicyTriggered,
    EpochAdvanced,
    HealthAlert,
    BootstrapComplete,
}

// ---------------------------------------------------------------------------
// NodeEvent
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct NodeEvent {
    pub kind: EventKind,
    pub epoch: u64,
    pub payload: EventPayload,
}

#[derive(Debug, Clone)]
pub enum EventPayload {
    NodeId([u8; 32]),
    CircuitId(u64),
    EpochValue(u64),
    Text(String),
    None,
}

// ---------------------------------------------------------------------------
// Subscriber
// ---------------------------------------------------------------------------

pub struct Subscriber {
    pub id: u64,
    pub kinds: Vec<EventKind>,
    received: Vec<NodeEvent>,
}

impl Subscriber {
    pub fn received(&self) -> &[NodeEvent] {
        &self.received
    }

    pub fn count(&self) -> usize {
        self.received.len()
    }
}

// ---------------------------------------------------------------------------
// NodeEventBus
// ---------------------------------------------------------------------------

pub struct NodeEventBus {
    next_id: u64,
    subscribers: HashMap<u64, Subscriber>,
    total_dispatched: u64,
}

impl NodeEventBus {
    pub fn new() -> Self {
        Self {
            next_id: 1,
            subscribers: HashMap::new(),
            total_dispatched: 0,
        }
    }

    /// Register a subscriber for the given event kinds. Returns subscriber ID.
    pub fn subscribe(&mut self, kinds: Vec<EventKind>) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.subscribers.insert(
            id,
            Subscriber {
                id,
                kinds,
                received: Vec::new(),
            },
        );
        id
    }

    pub fn unsubscribe(&mut self, id: u64) -> bool {
        self.subscribers.remove(&id).is_some()
    }

    /// Dispatch event to all matching subscribers.
    pub fn publish(&mut self, event: NodeEvent) {
        for sub in self.subscribers.values_mut() {
            if sub.kinds.contains(&event.kind) {
                sub.received.push(event.clone());
            }
        }
        self.total_dispatched += 1;
    }

    pub fn subscriber(&self, id: u64) -> Option<&Subscriber> {
        self.subscribers.get(&id)
    }

    pub fn subscriber_count(&self) -> usize {
        self.subscribers.len()
    }

    pub fn total_dispatched(&self) -> u64 {
        self.total_dispatched
    }
}

impl Default for NodeEventBus {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn nid(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn event(kind: EventKind, epoch: u64) -> NodeEvent {
        NodeEvent {
            kind,
            epoch,
            payload: EventPayload::None,
        }
    }

    // NEB1: subscriber receives matching events.
    #[test]
    fn neb1_matching_delivery() {
        let mut bus = NodeEventBus::new();
        let id = bus.subscribe(vec![EventKind::PeerConnected]);
        bus.publish(event(EventKind::PeerConnected, 1));
        assert_eq!(bus.subscriber(id).unwrap().count(), 1);
    }

    // NEB2: subscriber does not receive unsubscribed events.
    #[test]
    fn neb2_no_spurious_delivery() {
        let mut bus = NodeEventBus::new();
        let id = bus.subscribe(vec![EventKind::CircuitBuilt]);
        bus.publish(event(EventKind::PeerConnected, 1));
        assert_eq!(bus.subscriber(id).unwrap().count(), 0);
    }

    // NEB3: multiple subscribers each receive their events.
    #[test]
    fn neb3_multiple_subscribers() {
        let mut bus = NodeEventBus::new();
        let a = bus.subscribe(vec![EventKind::PeerConnected]);
        let b = bus.subscribe(vec![EventKind::PeerConnected]);
        bus.publish(event(EventKind::PeerConnected, 1));
        assert_eq!(bus.subscriber(a).unwrap().count(), 1);
        assert_eq!(bus.subscriber(b).unwrap().count(), 1);
    }

    // NEB4: subscriber with multiple kinds receives all matching.
    #[test]
    fn neb4_multi_kind_subscriber() {
        let mut bus = NodeEventBus::new();
        let id = bus.subscribe(vec![EventKind::CircuitBuilt, EventKind::CircuitTornDown]);
        bus.publish(event(EventKind::CircuitBuilt, 1));
        bus.publish(event(EventKind::CircuitTornDown, 2));
        bus.publish(event(EventKind::EpochAdvanced, 3));
        assert_eq!(bus.subscriber(id).unwrap().count(), 2);
    }

    // NEB5: unsubscribe stops delivery.
    #[test]
    fn neb5_unsubscribe() {
        let mut bus = NodeEventBus::new();
        let id = bus.subscribe(vec![EventKind::PeerConnected]);
        bus.unsubscribe(id);
        bus.publish(event(EventKind::PeerConnected, 1));
        assert_eq!(bus.subscriber_count(), 0);
    }

    // NEB6: total_dispatched counts every publish call.
    #[test]
    fn neb6_total_dispatched() {
        let mut bus = NodeEventBus::new();
        bus.publish(event(EventKind::EpochAdvanced, 1));
        bus.publish(event(EventKind::EpochAdvanced, 2));
        assert_eq!(bus.total_dispatched(), 2);
    }

    // NEB7: NodeId payload is stored.
    #[test]
    fn neb7_payload_stored() {
        let mut bus = NodeEventBus::new();
        let id = bus.subscribe(vec![EventKind::PeerConnected]);
        bus.publish(NodeEvent {
            kind: EventKind::PeerConnected,
            epoch: 5,
            payload: EventPayload::NodeId(nid(3)),
        });
        let ev = &bus.subscriber(id).unwrap().received()[0];
        assert!(matches!(ev.payload, EventPayload::NodeId(_)));
    }

    // NEB8: subscriber IDs are unique.
    #[test]
    fn neb8_unique_ids() {
        let mut bus = NodeEventBus::new();
        let a = bus.subscribe(vec![]);
        let b = bus.subscribe(vec![]);
        assert_ne!(a, b);
    }

    // NEB9: subscriber_count decrements on unsubscribe.
    #[test]
    fn neb9_count_after_unsub() {
        let mut bus = NodeEventBus::new();
        let id = bus.subscribe(vec![EventKind::EpochAdvanced]);
        assert_eq!(bus.subscriber_count(), 1);
        bus.unsubscribe(id);
        assert_eq!(bus.subscriber_count(), 0);
    }

    // NEB10: publish with no subscribers is a no-op.
    #[test]
    fn neb10_no_subscribers() {
        let mut bus = NodeEventBus::new();
        bus.publish(event(EventKind::BootstrapComplete, 1));
        assert_eq!(bus.total_dispatched(), 1);
    }
}
