//! Android VPN bridge contract — Rust-side type definitions for the boundary
//! between the Android VPN service (Kotlin) and the Rust runtime.
//!
//! These types mirror the data exchanged via the C FFI layer and provide a
//! typed, validated representation on the Rust side.  They are intentionally
//! `#[repr(C)]`-free; conversion to/from C-ABI types happens in
//! `android_ffi_boundary`.

// ---------------------------------------------------------------------------
// VpnPacketIn — data arriving from the Android TUN interface
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct VpnPacketIn {
    /// Raw IP packet bytes read from the TUN fd.
    pub raw_ip: Vec<u8>,
    /// Monotonic timestamp in milliseconds (caller-provided).
    pub timestamp_ms: u64,
}

impl VpnPacketIn {
    pub fn new(raw_ip: Vec<u8>, timestamp_ms: u64) -> Self {
        Self {
            raw_ip,
            timestamp_ms,
        }
    }

    /// Returns true if the packet length is plausible (≥ 20 bytes for IPv4 header).
    pub fn is_plausible(&self) -> bool {
        self.raw_ip.len() >= 20
    }
}

// ---------------------------------------------------------------------------
// VpnPacketOut — data to be written back to the TUN interface
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct VpnPacketOut {
    /// Decrypted/decapsulated IP packet bytes to write to the TUN fd.
    pub raw_ip: Vec<u8>,
}

impl VpnPacketOut {
    pub fn new(raw_ip: Vec<u8>) -> Self {
        Self { raw_ip }
    }
}

// ---------------------------------------------------------------------------
// VpnRuntimeCommand — commands the Android side can send to the Rust runtime
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VpnRuntimeCommand {
    /// Bring up the VPN: initialize circuits and start accepting traffic.
    Start,
    /// Tear down all circuits and stop accepting traffic.
    Stop,
    /// Pause traffic processing (keep circuits alive).
    Pause,
    /// Resume from Paused state.
    Resume,
    /// Rotate circuits immediately (e.g., network change event).
    RotateCircuits,
}

// ---------------------------------------------------------------------------
// VpnRuntimeStatus — status the Rust runtime reports to Android
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VpnRuntimeStatus {
    /// Not yet started.
    Idle,
    /// Bootstrapping: connecting to guard nodes.
    Connecting,
    /// Fully operational: circuits are established.
    Connected,
    /// Temporarily paused; circuits intact.
    Paused,
    /// Shutting down or shut down.
    Stopped,
    /// Runtime encountered a non-recoverable error.
    Error(String),
}

impl VpnRuntimeStatus {
    pub fn is_active(&self) -> bool {
        matches!(self, VpnRuntimeStatus::Connected | VpnRuntimeStatus::Paused)
    }
}

// ---------------------------------------------------------------------------
// PermissionState — Android VPN permission grant status
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionState {
    /// VPN permission not yet requested.
    NotRequested,
    /// Permission granted; TUN fd is available.
    Granted,
    /// Permission denied by user.
    Denied,
    /// Permission was revoked after grant.
    Revoked,
}

// ---------------------------------------------------------------------------
// TunnelState — whether the TUN interface is open and usable
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelState {
    /// TUN interface is not open.
    Closed,
    /// TUN interface is open and ready.
    Open,
    /// TUN interface failed (I/O error).
    Error,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // VBC1: VpnPacketIn::is_plausible true for 20+ bytes.
    #[test]
    fn vbc1_packet_in_plausible() {
        let p = VpnPacketIn::new(vec![0u8; 20], 0);
        assert!(p.is_plausible());
    }

    // VBC2: VpnPacketIn::is_plausible false for < 20 bytes.
    #[test]
    fn vbc2_packet_in_not_plausible() {
        let p = VpnPacketIn::new(vec![0u8; 19], 0);
        assert!(!p.is_plausible());
    }

    // VBC3: VpnPacketIn round-trip preserves bytes and timestamp.
    #[test]
    fn vbc3_packet_in_fields() {
        let p = VpnPacketIn::new(vec![1, 2, 3, 4], 999);
        assert_eq!(p.raw_ip, [1, 2, 3, 4]);
        assert_eq!(p.timestamp_ms, 999);
    }

    // VBC4: VpnPacketOut preserves bytes.
    #[test]
    fn vbc4_packet_out_fields() {
        let p = VpnPacketOut::new(vec![5, 6, 7]);
        assert_eq!(p.raw_ip, [5, 6, 7]);
    }

    // VBC5: VpnRuntimeStatus::is_active returns true only for Connected/Paused.
    #[test]
    fn vbc5_status_is_active() {
        assert!(!VpnRuntimeStatus::Idle.is_active());
        assert!(!VpnRuntimeStatus::Connecting.is_active());
        assert!(VpnRuntimeStatus::Connected.is_active());
        assert!(VpnRuntimeStatus::Paused.is_active());
        assert!(!VpnRuntimeStatus::Stopped.is_active());
        assert!(!VpnRuntimeStatus::Error("x".into()).is_active());
    }

    // VBC6: VpnRuntimeCommand variants are distinct.
    #[test]
    fn vbc6_command_variants() {
        let cmds = [
            VpnRuntimeCommand::Start,
            VpnRuntimeCommand::Stop,
            VpnRuntimeCommand::Pause,
            VpnRuntimeCommand::Resume,
            VpnRuntimeCommand::RotateCircuits,
        ];
        assert_eq!(cmds.len(), 5);
        assert_ne!(cmds[0], cmds[1]);
    }

    // VBC7: PermissionState variants are Copy.
    #[test]
    fn vbc7_permission_state_copy() {
        let s = PermissionState::Granted;
        let t = s;
        assert_eq!(s, t);
    }

    // VBC8: TunnelState::Closed != Open.
    #[test]
    fn vbc8_tunnel_state_distinct() {
        assert_ne!(TunnelState::Closed, TunnelState::Open);
        assert_ne!(TunnelState::Open, TunnelState::Error);
    }

    // VBC9: VpnRuntimeStatus::Error stores message.
    #[test]
    fn vbc9_error_message() {
        let s = VpnRuntimeStatus::Error("timeout".into());
        match &s {
            VpnRuntimeStatus::Error(msg) => assert_eq!(msg, "timeout"),
            _ => panic!("wrong variant"),
        }
    }

    // VBC10: VpnRuntimeCommand::RotateCircuits is distinct from Stop.
    #[test]
    fn vbc10_rotate_not_stop() {
        assert_ne!(VpnRuntimeCommand::RotateCircuits, VpnRuntimeCommand::Stop);
    }
}
