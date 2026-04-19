use axum::{
    extract::State,
    http::StatusCode,
    routing::post,
    Json, Router,
};
use serde::Deserialize;
use std::sync::mpsc;

use crate::engine::SensorEvent;

#[derive(Deserialize)]
pub struct SensorRequest {
    pub device_id: String,
    pub event: SensorEventDTO,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SensorEventDTO {
    AppStart {
        name: String,
        pid: u32,
        parent_pid: u32,
    },
    NetworkConnection {
        remote_ip: String,
        remote_port: u16,
        pid: Option<u32>,
    },
    SensorAccess {
        sensor: String,
        pid: u32,
        app_name: String,
    },
    PermissionGranted {
        permission: String,
        pid: u32,
        app_name: String,
    },
    Ipv6Connection,
}

impl From<SensorEventDTO> for SensorEvent {
    fn from(dto: SensorEventDTO) -> Self {
        match dto {
            SensorEventDTO::AppStart { name, pid, parent_pid } =>
                SensorEvent::ProcessStarted { name, pid, parent_pid },
            SensorEventDTO::NetworkConnection { remote_ip, remote_port, pid } =>
                SensorEvent::NetworkConnection { remote_ip, remote_port, pid },
            SensorEventDTO::SensorAccess { sensor, pid, .. } =>
                SensorEvent::ProcessStarted {
                    name: format!("sensor:{}", sensor),
                    pid,
                    parent_pid: 0,
                },
            SensorEventDTO::PermissionGranted { permission, pid, .. } =>
                SensorEvent::ProcessStarted {
                    name: format!("permission:{}", permission),
                    pid,
                    parent_pid: 0,
                },
            SensorEventDTO::Ipv6Connection =>
                SensorEvent::ProcessStarted {
                    name: "ipv6_connection".to_string(),
                    pid: 0,
                    parent_pid: 0,
                },
        }
    }
}

async fn ingest_event(
    State(tx): State<mpsc::Sender<SensorEvent>>,
    Json(req): Json<SensorRequest>,
) -> StatusCode {
    match tx.send(req.event.into()) {
        Ok(_)  => StatusCode::ACCEPTED,
        Err(_) => StatusCode::SERVICE_UNAVAILABLE,
    }
}

pub async fn start(tx: mpsc::Sender<SensorEvent>) {
    let app = Router::new()
        .route("/sensor/event", post(ingest_event))
        .with_state(tx);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080")
        .await
        .expect("gateway: bind failed");

    crate::logger::log("Gateway listening on 0.0.0.0:8080");
    axum::serve(listener, app).await.expect("gateway: server error");
}
