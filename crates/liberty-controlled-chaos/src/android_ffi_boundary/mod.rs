//! Android FFI boundary — C-compatible surface for the Liberty Shield node
//! runtime, intended to be called from Kotlin/Java via JNI or from a Rust
//! `cdylib` target.
//!
//! Enabled by the `android-ffi` feature flag. At the moment this module uses
//! a process-global static node runtime (Mutex-guarded) to keep the FFI
//! surface simple. A real implementation would pass an opaque handle pointer
//! instead.
//!
//! ## Exported functions (C ABI)
//! - `liberty_init_node(node_id: *const u8)` — initialise and configure
//! - `liberty_start_node() -> i32` — bootstrap and move to Running (0=ok, <0=err)
//! - `liberty_stop_node() -> i32`
//! - `liberty_runtime_status() -> i32` — 0=New,1=Configured,2=Bootstrap,3=Running,4=Degraded,5=Stopped
//! - `liberty_ingest_packet(data: *const u8, len: u32) -> i32`
//! - `liberty_poll_send_intent(buf: *mut u8, buf_len: u32) -> i32` — bytes written, -1=empty
//!
//! NON-PRODUCTION: no thread safety audit beyond the Mutex; no async I/O.

#![cfg(feature = "android-ffi")]

use std::sync::{Mutex, OnceLock};

use crate::integrated_node_runtime::{IntegratedNodeRuntime, RuntimeState};
use crate::node_config::NodeConfig;

// ---------------------------------------------------------------------------
// Global runtime state
// ---------------------------------------------------------------------------

static RT: OnceLock<Mutex<Option<IntegratedNodeRuntime>>> = OnceLock::new();

fn global_rt() -> &'static Mutex<Option<IntegratedNodeRuntime>> {
    RT.get_or_init(|| Mutex::new(None))
}

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

pub const FFI_OK: i32 = 0;
pub const FFI_ERR_WRONG_STATE: i32 = -1;
pub const FFI_ERR_NOT_INIT: i32 = -2;
pub const FFI_ERR_MALFORMED: i32 = -3;
pub const FFI_ERR_LOCK: i32 = -4;
pub const FFI_ERR_NO_PACKET: i32 = -5;

// ---------------------------------------------------------------------------
// Internal helpers (not exported to C)
// ---------------------------------------------------------------------------

fn state_to_code(state: RuntimeState) -> i32 {
    match state {
        RuntimeState::New => 0,
        RuntimeState::Configured => 1,
        RuntimeState::Bootstrapping => 2,
        RuntimeState::Running => 3,
        RuntimeState::Degraded => 4,
        RuntimeState::Stopped => 5,
    }
}

// ---------------------------------------------------------------------------
// FFI surface
// ---------------------------------------------------------------------------

/// Initialise the global node runtime with a 32-byte node ID.
///
/// # Safety
/// `node_id` must point to at least 32 readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn liberty_init_node(node_id: *const u8) -> i32 {
    let id_slice = unsafe { std::slice::from_raw_parts(node_id, 32) };
    let mut id = [0u8; 32];
    id.copy_from_slice(id_slice);

    let config = NodeConfig::new(id);
    let mut rt = IntegratedNodeRuntime::new(config);
    match rt.configure() {
        Ok(()) => {}
        Err(_) => return FFI_ERR_WRONG_STATE,
    }

    let lock = global_rt();
    match lock.lock() {
        Ok(mut guard) => {
            *guard = Some(rt);
            FFI_OK
        }
        Err(_) => FFI_ERR_LOCK,
    }
}

/// Bootstrap the node and advance it to Running state (epoch=1).
#[unsafe(no_mangle)]
pub extern "C" fn liberty_start_node() -> i32 {
    let lock = global_rt();
    let mut guard = match lock.lock() {
        Ok(g) => g,
        Err(_) => return FFI_ERR_LOCK,
    };
    let rt = match guard.as_mut() {
        Some(r) => r,
        None => return FFI_ERR_NOT_INIT,
    };
    if rt.start_bootstrap(1).is_err() {
        return FFI_ERR_WRONG_STATE;
    }
    if rt.complete_bootstrap(1).is_err() {
        return FFI_ERR_WRONG_STATE;
    }
    FFI_OK
}

/// Stop the node runtime (epoch=current+1).
#[unsafe(no_mangle)]
pub extern "C" fn liberty_stop_node() -> i32 {
    let lock = global_rt();
    let mut guard = match lock.lock() {
        Ok(g) => g,
        Err(_) => return FFI_ERR_LOCK,
    };
    let rt = match guard.as_mut() {
        Some(r) => r,
        None => return FFI_ERR_NOT_INIT,
    };
    match rt.stop(999) {
        Ok(()) => FFI_OK,
        Err(_) => FFI_ERR_WRONG_STATE,
    }
}

/// Return an integer code for the current runtime state.
/// 0=New, 1=Configured, 2=Bootstrapping, 3=Running, 4=Degraded, 5=Stopped.
#[unsafe(no_mangle)]
pub extern "C" fn liberty_runtime_status() -> i32 {
    let lock = global_rt();
    let guard = match lock.lock() {
        Ok(g) => g,
        Err(_) => return FFI_ERR_LOCK,
    };
    match guard.as_ref() {
        Some(rt) => state_to_code(rt.state()),
        None => FFI_ERR_NOT_INIT,
    }
}

/// Ingest a raw packet into the running node (must be in Running state).
///
/// # Safety
/// `data` must point to `len` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn liberty_ingest_packet(data: *const u8, len: u32) -> i32 {
    let bytes = unsafe { std::slice::from_raw_parts(data, len as usize) };
    let lock = global_rt();
    let mut guard = match lock.lock() {
        Ok(g) => g,
        Err(_) => return FFI_ERR_LOCK,
    };
    let rt = match guard.as_mut() {
        Some(r) => r,
        None => return FFI_ERR_NOT_INIT,
    };
    match rt.ingest_packet(bytes, 1) {
        Ok(_) => FFI_OK,
        Err(crate::integrated_node_runtime::RuntimeError::WrongState(_)) => FFI_ERR_WRONG_STATE,
        Err(crate::integrated_node_runtime::RuntimeError::MalformedPacket) => FFI_ERR_MALFORMED,
        Err(_) => FFI_ERR_WRONG_STATE,
    }
}

/// Copy the next pending outbound packet into `buf`.
/// Returns the number of bytes written, or `FFI_ERR_NO_PACKET` (-5) if empty.
///
/// # Safety
/// `buf` must point to at least `buf_len` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn liberty_poll_send_intent(buf: *mut u8, buf_len: u32) -> i32 {
    // The current IntegratedNodeRuntime has no outbound queue; this stub
    // always returns FFI_ERR_NO_PACKET until a send queue is wired in.
    let _ = (buf, buf_len);
    FFI_ERR_NO_PACKET
}

// ---------------------------------------------------------------------------
// Tests (compile with `--features android-ffi`)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const EPOCH: u64 = 1;

    fn nid(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn make_running_rt(id: u8) -> IntegratedNodeRuntime {
        let config = NodeConfig::new(nid(id));
        let mut rt = IntegratedNodeRuntime::new(config);
        rt.configure().unwrap();
        rt.start_bootstrap(EPOCH).unwrap();
        rt.complete_bootstrap(EPOCH).unwrap();
        rt
    }

    // AFFI1: state_to_code maps all states correctly.
    #[test]
    fn affi1_state_codes() {
        assert_eq!(state_to_code(RuntimeState::New), 0);
        assert_eq!(state_to_code(RuntimeState::Configured), 1);
        assert_eq!(state_to_code(RuntimeState::Bootstrapping), 2);
        assert_eq!(state_to_code(RuntimeState::Running), 3);
        assert_eq!(state_to_code(RuntimeState::Degraded), 4);
        assert_eq!(state_to_code(RuntimeState::Stopped), 5);
    }

    // AFFI2: FFI constants have expected values.
    #[test]
    fn affi2_error_codes() {
        assert_eq!(FFI_OK, 0);
        assert!(FFI_ERR_WRONG_STATE < 0);
        assert!(FFI_ERR_NOT_INIT < 0);
        assert!(FFI_ERR_MALFORMED < 0);
        assert!(FFI_ERR_LOCK < 0);
        assert!(FFI_ERR_NO_PACKET < 0);
    }

    // AFFI3: new runtime starts in New state.
    #[test]
    fn affi3_new_state() {
        let config = NodeConfig::new(nid(1));
        let rt = IntegratedNodeRuntime::new(config);
        assert_eq!(state_to_code(rt.state()), 0); // New
    }

    // AFFI4: configure moves to Configured.
    #[test]
    fn affi4_configure_state() {
        let config = NodeConfig::new(nid(2));
        let mut rt = IntegratedNodeRuntime::new(config);
        rt.configure().unwrap();
        assert_eq!(state_to_code(rt.state()), 1); // Configured
    }

    // AFFI5: bootstrap reaches Running.
    #[test]
    fn affi5_bootstrap_running() {
        let rt = make_running_rt(3);
        assert_eq!(state_to_code(rt.state()), 3); // Running
    }

    // AFFI6: stop transitions to Stopped.
    #[test]
    fn affi6_stop_state() {
        let mut rt = make_running_rt(4);
        rt.stop(2).unwrap();
        assert_eq!(state_to_code(rt.state()), 5); // Stopped
    }

    // AFFI7: poll_send_intent stub returns FFI_ERR_NO_PACKET.
    #[test]
    fn affi7_poll_send_intent_empty() {
        let mut buf = [0u8; 2048];
        let result = unsafe { liberty_poll_send_intent(buf.as_mut_ptr(), buf.len() as u32) };
        assert_eq!(result, FFI_ERR_NO_PACKET);
    }

    // AFFI8: ingest_packet in non-Running state returns WrongState error.
    #[test]
    fn affi8_ingest_wrong_state() {
        let config = NodeConfig::new(nid(5));
        let mut rt = IntegratedNodeRuntime::new(config);
        rt.configure().unwrap();
        // Configured, not Running.
        let pkt = [0u8; 32];
        let err = rt.ingest_packet(&pkt, EPOCH).unwrap_err();
        assert!(matches!(
            err,
            crate::integrated_node_runtime::RuntimeError::WrongState(_)
        ));
    }

    // AFFI9: ingest_packet with too-short data returns MalformedPacket.
    #[test]
    fn affi9_ingest_malformed() {
        let mut rt = make_running_rt(6);
        let tiny = [0u8; 3]; // less than 8 bytes (circuit_id header)
        let err = rt.ingest_packet(&tiny, EPOCH).unwrap_err();
        assert!(matches!(
            err,
            crate::integrated_node_runtime::RuntimeError::MalformedPacket
        ));
    }

    // AFFI10: stop then ingest returns WrongState.
    #[test]
    fn affi10_ingest_after_stop() {
        let mut rt = make_running_rt(7);
        rt.stop(2).unwrap();
        let pkt = [0u8; 32];
        let err = rt.ingest_packet(&pkt, EPOCH).unwrap_err();
        assert!(matches!(
            err,
            crate::integrated_node_runtime::RuntimeError::WrongState(_)
        ));
    }
}
