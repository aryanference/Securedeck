use crate::crypto;
use crate::denylist;
use ed25519_dalek::VerifyingKey;
use rusqlite::Connection;
use std::sync::Mutex;
use tracing::{info, error};

pub fn execute_suspend(
    db: &Mutex<Connection>,
    pub_key: &VerifyingKey,
    agent_id: &str,
    signature: &[u8],
    payload: &[u8],
) -> Result<(), String> {
    if let Err(_) = crypto::verify_command(pub_key, payload, signature) {
        error!("Invalid signature for suspend command: {}", agent_id);
        return Err("Cryptographic verification failed".to_string());
    }

    let conn = db.lock().unwrap();
    denylist::add_to_denylist(&conn, agent_id, "suspended", signature)
        .map_err(|e| e.to_string())?;

    info!("Agent {} suspended locally.", agent_id);
    Ok(())
}

pub fn execute_terminate(
    db: &Mutex<Connection>,
    pub_key: &VerifyingKey,
    agent_id: &str,
    signature: &[u8],
    payload: &[u8],
) -> Result<(), String> {
    if let Err(_) = crypto::verify_command(pub_key, payload, signature) {
        error!("Invalid signature for terminate command: {}", agent_id);
        return Err("Cryptographic verification failed".to_string());
    }

    let conn = db.lock().unwrap();
    denylist::add_to_denylist(&conn, agent_id, "terminated", signature)
        .map_err(|e| e.to_string())?;

    info!("Agent {} terminated locally.", agent_id);
    Ok(())
}

pub fn execute_lockdown(
    db: &Mutex<Connection>,
    pub_key: &VerifyingKey,
    signature: &[u8],
    payload: &[u8],
) -> Result<i64, String> {
    if let Err(_) = crypto::verify_command(pub_key, payload, signature) {
        return Err("Cryptographic verification failed".to_string());
    }
    
    // In a full implementation, this would mark all agents in the DB or a global flag
    Ok(0)
}
