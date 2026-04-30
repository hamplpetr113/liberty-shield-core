//! Epoch scheduler — fires one-shot and recurring callbacks at specified epochs.
//!
//! All scheduling is deterministic; no real timers are involved.  Callers
//! drive time by calling `advance(epoch)`.

use std::cmp::Reverse;
use std::collections::BinaryHeap;

// ---------------------------------------------------------------------------
// ScheduledTask
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduledTask {
    pub id: u64,
    pub label: String,
    pub fire_at: u64,
    /// None = one-shot; Some(n) = repeat every n epochs.
    pub repeat_every: Option<u64>,
}

impl PartialOrd for ScheduledTask {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ScheduledTask {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Min-heap by fire_at, then by id for stability.
        self.fire_at
            .cmp(&other.fire_at)
            .then(self.id.cmp(&other.id))
    }
}

// ---------------------------------------------------------------------------
// EpochScheduler
// ---------------------------------------------------------------------------

pub struct EpochScheduler {
    next_id: u64,
    queue: BinaryHeap<Reverse<ScheduledTask>>,
    current_epoch: u64,
    total_fired: u64,
    cancelled: std::collections::HashSet<u64>,
}

impl EpochScheduler {
    pub fn new() -> Self {
        Self {
            next_id: 1,
            queue: BinaryHeap::new(),
            current_epoch: 0,
            total_fired: 0,
            cancelled: std::collections::HashSet::new(),
        }
    }

    /// Schedule a one-shot task at `fire_at`. Returns task ID.
    pub fn schedule_once(&mut self, label: String, fire_at: u64) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.queue.push(Reverse(ScheduledTask {
            id,
            label,
            fire_at,
            repeat_every: None,
        }));
        id
    }

    /// Schedule a repeating task starting at `first_fire`, every `interval` epochs.
    pub fn schedule_repeat(&mut self, label: String, first_fire: u64, interval: u64) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.queue.push(Reverse(ScheduledTask {
            id,
            label,
            fire_at: first_fire,
            repeat_every: Some(interval.max(1)),
        }));
        id
    }

    pub fn cancel(&mut self, id: u64) {
        self.cancelled.insert(id);
    }

    /// Advance to `epoch`, returning all tasks that fired.
    pub fn advance(&mut self, epoch: u64) -> Vec<ScheduledTask> {
        self.current_epoch = epoch;
        let mut fired = Vec::new();
        let mut reschedule = Vec::new();

        while let Some(Reverse(task)) = self.queue.peek() {
            if task.fire_at > epoch {
                break;
            }
            let Reverse(task) = self.queue.pop().unwrap();
            if self.cancelled.contains(&task.id) {
                continue;
            }
            self.total_fired += 1;
            if let Some(interval) = task.repeat_every {
                reschedule.push(ScheduledTask {
                    id: task.id,
                    label: task.label.clone(),
                    fire_at: task.fire_at + interval,
                    repeat_every: Some(interval),
                });
            }
            fired.push(task);
        }
        for t in reschedule {
            self.queue.push(Reverse(t));
        }
        fired
    }

    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }

    pub fn total_fired(&self) -> u64 {
        self.total_fired
    }

    pub fn pending_count(&self) -> usize {
        self.queue.len()
    }
}

impl Default for EpochScheduler {
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

    // ES1: one-shot task fires at correct epoch.
    #[test]
    fn es1_one_shot() {
        let mut s = EpochScheduler::new();
        s.schedule_once("ping".into(), 5);
        assert!(s.advance(4).is_empty());
        let fired = s.advance(5);
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0].label, "ping");
    }

    // ES2: one-shot does not fire twice.
    #[test]
    fn es2_no_repeat() {
        let mut s = EpochScheduler::new();
        s.schedule_once("x".into(), 3);
        s.advance(3);
        assert!(s.advance(4).is_empty());
    }

    // ES3: repeating task fires at every interval.
    #[test]
    fn es3_repeat() {
        let mut s = EpochScheduler::new();
        s.schedule_repeat("tick".into(), 2, 3);
        assert!(s.advance(1).is_empty());
        assert_eq!(s.advance(2).len(), 1);
        assert!(s.advance(4).is_empty());
        assert_eq!(s.advance(5).len(), 1);
    }

    // ES4: cancel prevents a task from firing.
    #[test]
    fn es4_cancel() {
        let mut s = EpochScheduler::new();
        let id = s.schedule_once("y".into(), 10);
        s.cancel(id);
        assert!(s.advance(10).is_empty());
    }

    // ES5: multiple tasks fire in epoch order.
    #[test]
    fn es5_ordering() {
        let mut s = EpochScheduler::new();
        s.schedule_once("b".into(), 2);
        s.schedule_once("a".into(), 1);
        let fired = s.advance(2);
        assert_eq!(fired.len(), 2);
        assert_eq!(fired[0].fire_at, 1);
        assert_eq!(fired[1].fire_at, 2);
    }

    // ES6: total_fired accumulates.
    #[test]
    fn es6_total_fired() {
        let mut s = EpochScheduler::new();
        s.schedule_once("a".into(), 1);
        s.schedule_once("b".into(), 2);
        s.advance(2);
        assert_eq!(s.total_fired(), 2);
    }

    // ES7: pending_count reflects queue size.
    #[test]
    fn es7_pending_count() {
        let mut s = EpochScheduler::new();
        s.schedule_once("a".into(), 5);
        s.schedule_once("b".into(), 6);
        assert_eq!(s.pending_count(), 2);
        s.advance(5);
        assert_eq!(s.pending_count(), 1);
    }

    // ES8: advance with no tasks is safe.
    #[test]
    fn es8_empty_advance() {
        let mut s = EpochScheduler::new();
        assert!(s.advance(100).is_empty());
        assert_eq!(s.current_epoch(), 100);
    }

    // ES9: task fired at epoch 0.
    #[test]
    fn es9_epoch_zero() {
        let mut s = EpochScheduler::new();
        s.schedule_once("zero".into(), 0);
        let fired = s.advance(0);
        assert_eq!(fired.len(), 1);
    }

    // ES10: cancel a repeating task stops future fires.
    #[test]
    fn es10_cancel_repeat() {
        let mut s = EpochScheduler::new();
        let id = s.schedule_repeat("r".into(), 1, 1);
        s.advance(1);
        s.cancel(id);
        assert!(s.advance(2).is_empty());
    }
}
