use std::collections::HashMap;

use super::types::{Route, RouteId, RoutingError};

/// In-memory routing table keyed by `RouteId`.
pub struct RoutingTable {
    routes: HashMap<u64, Route>,
}

impl RoutingTable {
    pub fn new() -> Self {
        Self {
            routes: HashMap::new(),
        }
    }

    /// Insert a route.  Returns `RouteAlreadyExists` if the `route_id` is taken.
    pub fn add_route(&mut self, route: Route) -> Result<(), RoutingError> {
        let id = route.route_id.0;
        if self.routes.contains_key(&id) {
            return Err(RoutingError::RouteAlreadyExists(route.route_id));
        }
        self.routes.insert(id, route);
        Ok(())
    }

    /// Remove and return the route.  Returns `RouteNotFound` if absent.
    pub fn remove_route(&mut self, route_id: RouteId) -> Result<Route, RoutingError> {
        self.routes
            .remove(&route_id.0)
            .ok_or(RoutingError::RouteNotFound(route_id))
    }

    /// Borrow a route by id.
    pub fn get_route(&self, route_id: RouteId) -> Result<&Route, RoutingError> {
        self.routes
            .get(&route_id.0)
            .ok_or(RoutingError::RouteNotFound(route_id))
    }

    /// Mutably borrow a route by id (used by the router to update metrics).
    pub(super) fn get_route_mut(&mut self, route_id: RouteId) -> Result<&mut Route, RoutingError> {
        self.routes
            .get_mut(&route_id.0)
            .ok_or(RoutingError::RouteNotFound(route_id))
    }

    /// Select the best route using a composite score:
    ///   score = reliability / ((hop_count + 1) × (latency_us + 1))
    ///
    /// Higher score wins.  Ties are broken deterministically by lowest `RouteId`.
    pub fn best_route(&self) -> Result<&Route, RoutingError> {
        if self.routes.is_empty() {
            return Err(RoutingError::NoRoutesAvailable);
        }
        let mut best_score = f64::NEG_INFINITY;
        let mut best_id = u64::MAX;
        let mut best: Option<&Route> = None;

        for route in self.routes.values() {
            let score = route.reliability_score
                / ((route.hop_count as f64 + 1.0) * (route.latency_estimate as f64 + 1.0));
            if score > best_score || (score == best_score && route.route_id.0 < best_id) {
                best_score = score;
                best_id = route.route_id.0;
                best = Some(route);
            }
        }
        Ok(best.unwrap())
    }

    pub fn len(&self) -> usize {
        self.routes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }
}

impl Default for RoutingTable {
    fn default() -> Self {
        Self::new()
    }
}
