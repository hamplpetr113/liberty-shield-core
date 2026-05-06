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

    let frame = Frame {
        version: VERSION_1,
        msg_type: MessageType::Hello,
        flags: 0,
        session_id,
        sequence: 1,
        payload: b"hello".to_vec(),
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
    println!("sequence:   1");
    println!("msg_type:   Hello");
    println!("sent OK");
}
