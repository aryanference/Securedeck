use rusqlite::Connection;
use std::sync::Mutex;
use std::sync::Arc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{transport::Server, Request, Response, Status};
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;
use prost_types::Timestamp;

pub mod killswitch_v1 {
    tonic::include_proto!("killswitch.v1");
}

use killswitch_v1::killswitch_service_server::{KillSwitchService, KillSwitchServiceServer};
use killswitch_v1::{
    DenyListEntry, DenyListUpdate, GetDenyListRequest, LockdownAllRequest, LockdownAllResponse,
    SubscribeDenyListRequest, SuspendRequest, SuspendResponse, TerminateRequest, TerminateResponse,
    DenyStatus,
};

mod commands;
mod crypto;
mod denylist;

pub struct SecureKillSwitch {
    db: Arc<Mutex<Connection>>,
    operator_pub_key: ed25519_dalek::VerifyingKey,
}

#[tonic::async_trait]
impl KillSwitchService for SecureKillSwitch {
    async fn suspend(
        &self,
        request: Request<SuspendRequest>,
    ) -> Result<Response<SuspendResponse>, Status> {
        let req = request.into_inner();
        
        match commands::execute_suspend(
            &self.db,
            &self.operator_pub_key,
            &req.agent_id,
            &req.operator_signature,
            &req.command_payload,
        ) {
            Ok(_) => Ok(Response::new(SuspendResponse { accepted: true, reason: "".to_string() })),
            Err(e) => Ok(Response::new(SuspendResponse { accepted: false, reason: e })),
        }
    }

    async fn terminate(
        &self,
        request: Request<TerminateRequest>,
    ) -> Result<Response<TerminateResponse>, Status> {
        let req = request.into_inner();
        
        match commands::execute_terminate(
            &self.db,
            &self.operator_pub_key,
            &req.agent_id,
            &req.operator_signature,
            &req.command_payload,
        ) {
            Ok(_) => Ok(Response::new(TerminateResponse { accepted: true, reason: "".to_string() })),
            Err(e) => Ok(Response::new(TerminateResponse { accepted: false, reason: e })),
        }
    }

    async fn lockdown_all(
        &self,
        request: Request<LockdownAllRequest>,
    ) -> Result<Response<LockdownAllResponse>, Status> {
        let req = request.into_inner();
        
        match commands::execute_lockdown(
            &self.db,
            &self.operator_pub_key,
            &req.operator_signature,
            &req.command_payload,
        ) {
            Ok(count) => Ok(Response::new(LockdownAllResponse { accepted: true, reason: "".to_string(), agents_affected: count })),
            Err(e) => Ok(Response::new(LockdownAllResponse { accepted: false, reason: e, agents_affected: 0 })),
        }
    }

    type GetDenyListStream = ReceiverStream<Result<DenyListEntry, Status>>;

    async fn get_deny_list(
        &self,
        _request: Request<GetDenyListRequest>,
    ) -> Result<Response<Self::GetDenyListStream>, Status> {
        let (tx, rx) = tokio::sync::mpsc::channel(100);
        
        let entries = {
            let conn = self.db.lock().unwrap();
            denylist::get_all(&conn).unwrap_or_default()
        };

        tokio::spawn(async move {
            for entry in entries {
                let status = if entry.status == "suspended" { DenyStatus::Suspended as i32 } else { DenyStatus::Terminated as i32 };
                let pb_entry = DenyListEntry {
                    agent_id: entry.agent_id,
                    status,
                    updated_at: Some(Timestamp {
                        seconds: entry.timestamp,
                        nanos: 0,
                    }),
                };
                if tx.send(Ok(pb_entry)).await.is_err() {
                    break;
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    type SubscribeDenyListStream = ReceiverStream<Result<DenyListUpdate, Status>>;

    async fn subscribe_deny_list(
        &self,
        _request: Request<SubscribeDenyListRequest>,
    ) -> Result<Response<Self::SubscribeDenyListStream>, Status> {
        let (tx, rx) = tokio::sync::mpsc::channel(100);
        
        let entries = {
            let conn = self.db.lock().unwrap();
            denylist::get_all(&conn).unwrap_or_default()
        };

        tokio::spawn(async move {
            for entry in entries {
                let status = if entry.status == "suspended" { DenyStatus::Suspended as i32 } else { DenyStatus::Terminated as i32 };
                let pb_update = DenyListUpdate {
                    entry: Some(DenyListEntry {
                        agent_id: entry.agent_id,
                        status,
                        updated_at: Some(Timestamp {
                            seconds: entry.timestamp,
                            nanos: 0,
                        }),
                    }),
                    is_full_sync_marker: false,
                };
                if tx.send(Ok(pb_update)).await.is_err() {
                    return;
                }
            }
            
            let marker = DenyListUpdate {
                entry: None,
                is_full_sync_marker: true,
            };
            let _ = tx.send(Ok(marker)).await;
            
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let subscriber = FmtSubscriber::builder().with_max_level(Level::INFO).finish();
    tracing::subscriber::set_global_default(subscriber)?;

    info!("Starting Securedeck Kill Switch (Isolated Mode)");

    let db_path = std::env::var("KS_DB_PATH").unwrap_or_else(|_| "killswitch.db".to_string());
    let conn = Connection::open(db_path)?;
    denylist::init_db(&conn)?;

    let pub_key_bytes = [0u8; 32];
    let operator_pub_key = ed25519_dalek::VerifyingKey::from_bytes(&pub_key_bytes)?;

    let service = SecureKillSwitch {
        db: Arc::new(Mutex::new(conn)),
        operator_pub_key,
    };

    let addr = "[::]:50053".parse()?;
    Server::builder()
        .add_service(KillSwitchServiceServer::new(service))
        .serve(addr)
        .await?;

    Ok(())
}
