use liberty_controlled_chaos::mesh_simulator::{MeshMetrics, MeshSimulator};

pub struct TopologySummary {
    pub node_count: usize,
    pub guard_count: usize,
    pub relay_count: usize,
    pub exit_count: usize,
    pub link_count: usize,
}

pub struct RunResult {
    pub rounds: usize,
    pub delivered: u64,
    pub dropped: u64,
    pub avg_path_length: f64,
    pub elapsed_us: u64,
}

pub struct NodeRuntime {
    sim: MeshSimulator,
}

impl NodeRuntime {
    pub fn new(node_count: usize) -> Self {
        Self {
            sim: MeshSimulator::new(node_count),
        }
    }

    pub fn build_circuits(&mut self, count: usize) {
        self.sim.build_random_circuits(count);
    }

    pub fn run_rounds(&mut self, rounds: usize) -> RunResult {
        let start = std::time::Instant::now();
        self.sim.run_simulation(rounds);
        let elapsed_us = start.elapsed().as_micros() as u64;
        let m = self.sim.metrics();
        RunResult {
            rounds,
            delivered: m.paths_completed,
            dropped: m.packets_dropped,
            avg_path_length: m.average_path_length(),
            elapsed_us,
        }
    }

    pub fn metrics(&self) -> &MeshMetrics {
        self.sim.metrics()
    }

    pub fn topology_summary(&self) -> TopologySummary {
        let t = &self.sim.topology;
        TopologySummary {
            node_count: t.node_count(),
            guard_count: t.guard_count(),
            relay_count: t.relay_count(),
            exit_count: t.exit_count(),
            link_count: t.link_count(),
        }
    }
}
