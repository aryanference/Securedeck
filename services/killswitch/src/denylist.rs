use rusqlite::{params, Connection, Result};

#[derive(Clone)]
pub struct DenyEntry {
    pub agent_id: String,
    pub status: String,
    pub timestamp: i64,
}

pub fn init_db(conn: &Connection) -> Result<()> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS denylist (
            agent_id TEXT PRIMARY KEY,
            status TEXT NOT NULL,
            timestamp INTEGER NOT NULL,
            operator_signature BLOB NOT NULL
        )",
        [],
    )?;
    Ok(())
}

pub fn add_to_denylist(
    conn: &Connection,
    agent_id: &str,
    status: &str,
    signature: &[u8],
) -> Result<()> {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
        
    conn.execute(
        "INSERT OR REPLACE INTO denylist (agent_id, status, timestamp, operator_signature) 
         VALUES (?1, ?2, ?3, ?4)",
        params![agent_id, status, ts, signature],
    )?;
    Ok(())
}

pub fn get_all(conn: &Connection) -> Result<Vec<DenyEntry>> {
    let mut stmt = conn.prepare("SELECT agent_id, status, timestamp FROM denylist")?;
    let iter = stmt.query_map([], |row| {
        Ok(DenyEntry { agent_id: row.get(0)?, status: row.get(1)?, timestamp: row.get(2)? })
    })?;
    iter.collect()
}
