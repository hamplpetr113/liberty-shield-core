/// Lifecycle state of a circuit being constructed or maintained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitExtensionState {
    /// Circuit registered; no hops added yet.
    Building,
    /// An extension request has been sent; awaiting response.
    Extending,
    /// At least one hop confirmed; circuit is usable.
    Active,
    /// Circuit has been destroyed and is no longer usable.
    Destroyed,
}
