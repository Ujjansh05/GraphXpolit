use anyhow::{bail, Result};
use std::fs;

fn valid(id: &str) -> bool {
    id.len() == 24 && id.chars().all(|c| c.is_ascii_hexdigit())
}
pub fn stats() -> Result<Vec<serde_json::Value>> {
    let dir = crate::store::app_data_dir()?.join("projects");
    let mut result = Vec::new();
    if !dir.exists() {
        return Ok(result);
    }
    for item in fs::read_dir(dir)? {
        let item = item?;
        let path = item.path();
        let id = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        if path.extension().is_some_and(|s| s == "db")
            && valid(id)
            && !crate::safety::linked(&item.metadata()?)
        {
            let mut size = item.metadata()?.len();
            for suffix in ["-wal", "-shm"] {
                size += fs::metadata(format!("{}{suffix}", path.display()))
                    .map(|m| m.len())
                    .unwrap_or(0);
            }
            result.push(serde_json::json!({"project":id,"bytes_including_wal":size,"path":path}));
        }
    }
    Ok(result)
}
pub fn prune(id: &str, confirmed: bool) -> Result<()> {
    if !valid(id) {
        bail!("project must be the 24-character ID from gx cache stats");
    }
    let dir = crate::store::app_data_dir()?
        .join("projects")
        .canonicalize()?;
    let path =
        crate::safety::workspace_path(&dir, std::path::Path::new(&format!("{id}.db")), false)?;
    println!("Generated index: {}", path.display());
    if !confirmed {
        println!("Preview only. Close other GraphXploit processes, then repeat with --yes to remove this rebuildable index.");
        return Ok(());
    }
    let _lease = crate::store::index_lease(&path, true)?;
    let conn = rusqlite::Connection::open(&path)?;
    conn.busy_timeout(std::time::Duration::ZERO)?;
    conn.execute_batch(
        "PRAGMA locking_mode=EXCLUSIVE; BEGIN EXCLUSIVE; COMMIT; PRAGMA wal_checkpoint(TRUNCATE);",
    )?;
    drop(conn);
    fs::remove_file(&path)?;
    println!("Removed generated index; run gx ix to rebuild. Source and saved sessions were not removed.");
    Ok(())
}
#[cfg(test)]
mod tests {
    #[test]
    fn rejects_arbitrary_targets() {
        for id in ["..", "../projects", "", "abc", "00000000000000000000000/"] {
            assert!(!super::valid(id));
        }
    }
}
