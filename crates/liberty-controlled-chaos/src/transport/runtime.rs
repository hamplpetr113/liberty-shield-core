//! `NodeRuntime` — wires together `NodeIdentity`, `PeerTable`, `TcpLink`
//! connections, and `RelayPipeline` into a single runtime handle.
//!
//! NON-PRODUCTION: no concurrency, no graceful shutdown, no timeouts beyond
//! those set on the underlying `TcpLink`.

use std::collections::HashMap;
use std::net::TcpStream;

use crate::crypto::SessionKeys;
use crate::encrypted_relay::{PipelineResult, RelayCellPlaintext, RelayPipeline};
use crate::node_descriptor::{NodeDescriptor, PeerTable};
use crate::node_identity::NodeIdentity;

use super::tcp_link::{TcpLink, TcpLinkError};

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors from `NodeRuntime` operations.
#[derive(Debug)]
pub enum RuntimeError {
    /// No `TcpLink` registered for this circuit.
    NoLink(u64),
    /// No `SessionKeys` registered for this circuit.
    NoSession(u64),
    /// TCP link error.
    Link(TcpLinkError),
    /// Pipeline returned a non-`Accepted` result.
    PipelineRejected(PipelineResult),
}

impl std::fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuntimeError::NoLink(c) => write!(f, "no link for circuit {c}"),
            RuntimeError::NoSession(c) => write!(f, "no session for circuit {c}"),
            RuntimeError::Link(e) => write!(f, "link error: {e}"),
            RuntimeError::PipelineRejected(r) => write!(f, "pipeline rejected: {r:?}"),
        }
    }
}

impl From<TcpLinkError> for RuntimeError {
    fn from(e: TcpLinkError) -> Self {
        RuntimeError::Link(e)
    }
}

// ---------------------------------------------------------------------------
// NodeRuntime
// ---------------------------------------------------------------------------

/// In-process runtime for one mesh node.
///
/// Holds the node's long-term identity, a peer table, per-circuit TCP links,
/// and a shared `RelayPipeline` for encryption/decryption.
pub struct NodeRuntime {
    pub identity: NodeIdentity,
    pub peer_table: PeerTable,
    /// Per-circuit TCP links (circuit_id → TcpLink).
    links: HashMap<u64, TcpLink>,
    pub pipeline: RelayPipeline,
}

impl NodeRuntime {
    /// Create a new runtime with no peers or circuits.
    pub fn new(identity: NodeIdentity) -> Self {
        Self {
            identity,
            peer_table: PeerTable::new(),
            links: HashMap::new(),
            pipeline: RelayPipeline::new(),
        }
    }

    /// Add a known peer to the peer table.
    pub fn add_peer(&mut self, desc: NodeDescriptor) {
        self.peer_table.add_peer(desc);
    }

    /// Register a `TcpLink` for a circuit (the link is already connected/accepted).
    pub fn register_link(&mut self, circuit_id: u64, link: TcpLink) {
        self.links.insert(circuit_id, link);
    }

    /// Register send/receive sessions for a circuit in the pipeline.
    pub fn register_circuit(&mut self, circuit_id: u64, send: SessionKeys, recv: SessionKeys) {
        self.pipeline.register_circuit(circuit_id, send, recv);
    }

    /// Encrypt and send `plaintext` on `circuit_id`.
    pub fn forward_cell(
        &mut self,
        circuit_id: u64,
        stream_id: u64,
        plaintext: RelayCellPlaintext,
    ) -> Result<(), RuntimeError> {
        let enc = self
            .pipeline
            .send_cell(circuit_id, stream_id, plaintext)
            .map_err(|_| RuntimeError::NoSession(circuit_id))?;
        let link = self
            .links
            .get_mut(&circuit_id)
            .ok_or(RuntimeError::NoLink(circuit_id))?;
        link.send_cell(&enc)?;
        Ok(())
    }

    /// Receive one cell on `circuit_id`, decrypt, and return the pipeline result.
    pub fn recv_cell(
        &mut self,
        circuit_id: u64,
        stream_id: u64,
    ) -> Result<RelayCellPlaintext, RuntimeError> {
        let link = self
            .links
            .get_mut(&circuit_id)
            .ok_or(RuntimeError::NoLink(circuit_id))?;
        let enc = link.recv_cell()?;
        match self.pipeline.receive_cell(circuit_id, stream_id, &enc) {
            PipelineResult::Accepted(pt) => Ok(pt),
            other => Err(RuntimeError::PipelineRejected(other)),
        }
    }

    /// Accept an incoming TCP stream and register it for `circuit_id`.
    ///
    /// The caller must separately register session keys via `register_circuit`.
    pub fn handle_incoming(
        &mut self,
        stream: TcpStream,
        circuit_id: u64,
    ) -> Result<(), RuntimeError> {
        let link = TcpLink::accept(stream)?;
        self.links.insert(circuit_id, link);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::net::TcpListener;

    use super::*;
    use crate::encrypted_relay::{RelayCellCommand, RelayCellPlaintext};
    use crate::node_identity::NodeIdentity;

    fn make_runtime(seed: u8) -> NodeRuntime {
        NodeRuntime::new(NodeIdentity::generate_from_seed([seed; 32]))
    }

    fn loopback_pair() -> (TcpLink, TcpLink) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client_handle = std::thread::spawn(move || TcpLink::connect(addr).unwrap());
        let (server_stream, _) = listener.accept().unwrap();
        let server = TcpLink::accept(server_stream).unwrap();
        let client = client_handle.join().unwrap();
        (client, server)
    }

    fn sym_keys(byte: u8) -> SessionKeys {
        SessionKeys::new([byte; 32], [byte; 32])
    }

    // TR11: NodeRuntime::forward_cell + recv_cell over loopback TCP.
    #[test]
    fn tr11_runtime_forward_recv() {
        let (link_a, link_b) = loopback_pair();
        let key = [0x11u8; 32];

        let mut rt_a = make_runtime(0xAA);
        rt_a.register_circuit(1, sym_keys(key[0]), sym_keys(key[0]));
        rt_a.register_link(1, link_a);

        let mut rt_b = make_runtime(0xBB);
        rt_b.register_circuit(1, sym_keys(key[0]), sym_keys(key[0]));
        rt_b.register_link(1, link_b);

        let payload = b"runtime test".to_vec();
        let pt = RelayCellPlaintext::new(1, 1, RelayCellCommand::Data, 0, payload.clone());

        let handle = std::thread::spawn(move || rt_b.recv_cell(1, 1).unwrap());
        rt_a.forward_cell(1, 1, pt).unwrap();
        let received = handle.join().unwrap();

        assert_eq!(received.payload, payload);
    }

    // TR12: NodeRuntime::handle_incoming registers a link for a circuit.
    #[test]
    fn tr12_handle_incoming_registers_link() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let client_handle = std::thread::spawn(move || TcpLink::connect(addr).unwrap());
        let (server_stream, _) = listener.accept().unwrap();

        let mut rt = make_runtime(0x01);
        rt.handle_incoming(server_stream, 42).unwrap();
        assert!(rt.links.contains_key(&42));

        let _ = client_handle.join().unwrap();
    }

    // TR13: forward_cell fails when no link registered.
    #[test]
    fn tr13_forward_no_link() {
        let mut rt = make_runtime(0x02);
        let key = [0x22u8; 32];
        rt.register_circuit(99, sym_keys(key[0]), sym_keys(key[0]));
        let pt = RelayCellPlaintext::new(99, 1, RelayCellCommand::Data, 0, vec![]);
        assert!(matches!(
            rt.forward_cell(99, 1, pt),
            Err(RuntimeError::NoLink(99))
        ));
    }
}
