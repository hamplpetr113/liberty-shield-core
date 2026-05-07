use liberty_exit_node::auth::compute_hello_mac;
use liberty_exit_node::config::parse_psk;
use liberty_exit_node::packet::{Frame, MessageType, VERSION_1, encode_frame};
use tokio::net::UdpSocket;

#[tokio::main]
async fn main() {
    let target =
        std::env::var("LIBERTY_HELLO_TARGET").unwrap_or_else(|_| "127.0.0.1:51820".to_string());

    let session_id: u64 = std::env::var("LIBERTY_HELLO_SESSION_ID")
        .unwrap_or_else(|_| "1".to_string())
        .parse()
        .expect("LIBERTY_HELLO_SESSION_ID must be a u64");

    let sequence: u64 = 1;
    let original_payload = b"hello";

    let dev_mode = std::env::var("LIBERTY_ALLOW_UNAUTHENTICATED_DEV").is_ok();
    let psk_hex = std::env::var("LIBERTY_HELLO_PSK").ok();

    let (payload, auth_label) = match (psk_hex, dev_mode) {
        (Some(hex), _) => {
            let psk = parse_psk(&hex);
            let mac = compute_hello_mac(&psk, session_id, sequence, original_payload);
            let mut p = mac.to_vec();
            p.extend_from_slice(original_payload);
            (p, "HMAC-SHA256")
        }
        (None, true) => (
            original_payload.to_vec(),
            "none (LIBERTY_ALLOW_UNAUTHENTICATED_DEV=1)",
        ),
        (None, false) => {
            eprintln!(
                "error: LIBERTY_HELLO_PSK is not set and LIBERTY_ALLOW_UNAUTHENTICATED_DEV is not set.\n\
                 Set LIBERTY_HELLO_PSK to a 64-hex-character 32-byte key, or set \
                 LIBERTY_ALLOW_UNAUTHENTICATED_DEV=1 for local testing only."
            );
            std::process::exit(1);
        }
    };

    let frame = Frame {
        version: VERSION_1,
        msg_type: MessageType::Hello,
        flags: 0,
        session_id,
        sequence,
        payload,
    };

    let mut buf = Vec::new();
    encode_frame(&frame, &mut buf).expect("encode_frame failed");

    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .expect("failed to bind local UDP socket");

    socket
        .send_to(&buf, &target)
        .await
        .expect("send_to failed — is the server running?");

    println!("target:     {target}");
    println!("frame_len:  {}", buf.len());
    println!("session_id: {session_id}");
    println!("sequence:   {sequence}");
    println!("msg_type:   Hello");
    println!("auth:       {auth_label}");
    println!("sent OK");
}
