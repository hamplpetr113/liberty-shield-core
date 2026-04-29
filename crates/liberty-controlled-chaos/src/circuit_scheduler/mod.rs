//! Circuit scheduler — weighted round-robin over per-circuit packet queues.
//!
//! Each `ScheduledCircuit` has a `priority` weight and a count of
//! `queued_packets`.  `select_next` picks the circuit with the most queued
//! packets (ties broken by lower circuit_id first) and decrements its queue.
//! `drop_idle` removes circuits that have no queued packets and have not been
//! selected for `idle_threshold` rounds.

use std::collections::VecDeque;

// ---------------------------------------------------------------------------
// ScheduledCircuit
// ---------------------------------------------------------------------------

/// One circuit entry in the scheduler.
#[derive(Debug, Clone)]
pub struct ScheduledCircuit {
    /// The circuit's identifier.
    pub circuit_id: u64,
    /// Higher priority → more scheduling weight (not currently used for
    /// weighted selection, reserved for future).
    pub priority: u32,
    /// Number of packets waiting to be sent on this circuit.
    pub queued_packets: u32,
    /// Number of consecutive select rounds in which this circuit was skipped.
    rounds_idle: u32,
}

// ---------------------------------------------------------------------------
// CircuitScheduler
// ---------------------------------------------------------------------------

/// Weighted round-robin circuit scheduler.
pub struct CircuitScheduler {
    circuits: VecDeque<ScheduledCircuit>,
}

impl CircuitScheduler {
    pub fn new() -> Self {
        Self {
            circuits: VecDeque::new(),
        }
    }

    /// Register a new circuit or increment its queue if already present.
    pub fn enqueue_packet(&mut self, circuit_id: u64) {
        if let Some(sc) = self
            .circuits
            .iter_mut()
            .find(|c| c.circuit_id == circuit_id)
        {
            sc.queued_packets = sc.queued_packets.saturating_add(1);
            sc.rounds_idle = 0;
        } else {
            self.circuits.push_back(ScheduledCircuit {
                circuit_id,
                priority: 1,
                queued_packets: 1,
                rounds_idle: 0,
            });
        }
    }

    /// Set the priority for an existing circuit.  No-op if not found.
    pub fn update_priority(&mut self, circuit_id: u64, priority: u32) {
        if let Some(sc) = self
            .circuits
            .iter_mut()
            .find(|c| c.circuit_id == circuit_id)
        {
            sc.priority = priority;
        }
    }

    /// Select the next circuit to send from.
    ///
    /// Returns the `circuit_id` of the circuit with the most queued packets
    /// (ties broken by lower `circuit_id`).  Decrements `queued_packets` for
    /// the selected circuit.  Increments `rounds_idle` for all others.
    ///
    /// Returns `None` if no circuits have queued packets.
    pub fn select_next(&mut self) -> Option<u64> {
        // Find index of the circuit to send from.
        let selected = self
            .circuits
            .iter()
            .enumerate()
            .filter(|(_, c)| c.queued_packets > 0)
            .max_by_key(|(_, c)| (c.queued_packets, c.priority, u64::MAX - c.circuit_id));

        match selected {
            None => None,
            Some((idx, _)) => {
                let cid = self.circuits[idx].circuit_id;
                // Decrement the winner.
                self.circuits[idx].queued_packets -= 1;
                self.circuits[idx].rounds_idle = 0;
                // Increment idle counters for everyone else.
                for (i, sc) in self.circuits.iter_mut().enumerate() {
                    if i != idx {
                        sc.rounds_idle = sc.rounds_idle.saturating_add(1);
                    }
                }
                Some(cid)
            }
        }
    }

    /// Remove circuits that have zero queued packets and have been idle for
    /// at least `idle_threshold` rounds.
    ///
    /// Returns the number of circuits removed.
    pub fn drop_idle(&mut self, idle_threshold: u32) -> usize {
        let before = self.circuits.len();
        self.circuits
            .retain(|c| c.queued_packets > 0 || c.rounds_idle < idle_threshold);
        before - self.circuits.len()
    }

    /// Remove a specific circuit by ID.
    pub fn remove_circuit(&mut self, circuit_id: u64) {
        self.circuits.retain(|c| c.circuit_id != circuit_id);
    }

    /// Number of registered circuits.
    pub fn len(&self) -> usize {
        self.circuits.len()
    }

    pub fn is_empty(&self) -> bool {
        self.circuits.is_empty()
    }

    /// Total queued packets across all circuits.
    pub fn total_queued(&self) -> u32 {
        self.circuits.iter().map(|c| c.queued_packets).sum()
    }

    /// Peek at the circuit list (for testing).
    pub fn circuits(&self) -> &VecDeque<ScheduledCircuit> {
        &self.circuits
    }
}

impl Default for CircuitScheduler {
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

    // CS1: enqueue_packet registers a new circuit.
    #[test]
    fn cs1_enqueue_packet() {
        let mut s = CircuitScheduler::new();
        s.enqueue_packet(1);
        assert_eq!(s.len(), 1);
        assert_eq!(s.total_queued(), 1);
    }

    // CS2: select_next returns the circuit with the most queued packets.
    #[test]
    fn cs2_select_next() {
        let mut s = CircuitScheduler::new();
        s.enqueue_packet(1);
        let cid = s.select_next();
        assert_eq!(cid, Some(1));
        assert_eq!(s.total_queued(), 0);
    }

    // CS3: fairness — two circuits each get one turn per two packets.
    #[test]
    fn cs3_fairness() {
        let mut s = CircuitScheduler::new();
        s.enqueue_packet(1);
        s.enqueue_packet(2);
        let first = s.select_next().unwrap();
        let second = s.select_next().unwrap();
        // Both circuits should have been scheduled once.
        assert_ne!(first, second);
    }

    // CS4: multiple circuits in the queue all get scheduled.
    #[test]
    fn cs4_multiple_circuits() {
        let mut s = CircuitScheduler::new();
        for cid in 1u64..=5 {
            s.enqueue_packet(cid);
        }
        let mut seen = std::collections::HashSet::new();
        for _ in 0..5 {
            seen.insert(s.select_next().unwrap());
        }
        assert_eq!(seen.len(), 5);
    }

    // CS5: update_priority changes priority field.
    #[test]
    fn cs5_priority_handling() {
        let mut s = CircuitScheduler::new();
        s.enqueue_packet(1);
        s.update_priority(1, 10);
        let c = s.circuits().iter().find(|c| c.circuit_id == 1).unwrap();
        assert_eq!(c.priority, 10);
    }

    // CS6: drop_idle removes circuits that are idle long enough.
    #[test]
    fn cs6_idle_drop() {
        let mut s = CircuitScheduler::new();
        s.enqueue_packet(1);
        s.enqueue_packet(2);
        // Drain circuit 1 completely.
        s.select_next();
        // Circuit 1 now has 0 packets, rounds_idle increments each select.
        // Drain circuit 2 to advance rounds_idle for circuit 1.
        s.select_next();
        // Now circuit 1 has rounds_idle=1, queued=0 → drop at threshold=1.
        let dropped = s.drop_idle(1);
        assert_eq!(dropped, 1);
    }

    // CS7: starvation prevention — enqueuing on an idle circuit resets its idle count.
    #[test]
    fn cs7_starvation_prevention() {
        let mut s = CircuitScheduler::new();
        s.enqueue_packet(1);
        s.select_next(); // drains circuit 1
        // Re-enqueue resets rounds_idle.
        s.enqueue_packet(1);
        let c = s.circuits().iter().find(|c| c.circuit_id == 1).unwrap();
        assert_eq!(c.rounds_idle, 0);
    }

    // CS8: large queue — 100 packets on one circuit all drain in order.
    #[test]
    fn cs8_large_queue() {
        let mut s = CircuitScheduler::new();
        for _ in 0..100 {
            s.enqueue_packet(42);
        }
        assert_eq!(s.total_queued(), 100);
        for _ in 0..100 {
            assert_eq!(s.select_next(), Some(42));
        }
        assert_eq!(s.total_queued(), 0);
    }

    // CS9: fairness long run — two circuits each get half the selections.
    #[test]
    fn cs9_fairness_long_run() {
        let mut s = CircuitScheduler::new();
        for _ in 0..50 {
            s.enqueue_packet(1);
            s.enqueue_packet(2);
        }
        let mut count1 = 0u32;
        let mut count2 = 0u32;
        for _ in 0..100 {
            match s.select_next().unwrap() {
                1 => count1 += 1,
                2 => count2 += 1,
                _ => unreachable!(),
            }
        }
        // Each circuit should have been selected ~50 times.
        assert_eq!(count1, 50);
        assert_eq!(count2, 50);
    }

    // CS10: mixed priorities — higher priority circuit is preferred when queues are equal.
    #[test]
    fn cs10_mixed_priorities() {
        let mut s = CircuitScheduler::new();
        s.enqueue_packet(1);
        s.enqueue_packet(2);
        s.update_priority(2, 10); // circuit 2 has higher priority
        // Both have 1 queued packet; priority breaks the tie.
        let selected = s.select_next().unwrap();
        assert_eq!(selected, 2);
    }
}
