use crate::model::{Candidate, ParsedFile, ProjectSummary};
use anyhow::{anyhow, Context, Result};
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

pub const SCHEMA_VERSION: i64 = 2;

#[derive(Debug, Clone)]
pub(crate) struct FileRecord {
    pub id: i64,
    pub hash: String,
    pub modified_ns: i64,
}

#[derive(Debug, Clone)]
pub(crate) struct SymbolRecord {
    pub id: i64,
    pub file_id: i64,
    pub name: String,
    pub qualified_name: String,
    pub kind: String,
    pub path: String,
    pub line: u32,
    pub end_line: u32,
}

#[derive(Debug, Clone)]
pub(crate) struct EdgeRecord {
    pub source_id: i64,
    pub target_id: i64,
    pub kind: String,
}

pub struct Store {
    conn: Connection,
    project_id: i64,
    root: PathBuf,
    database: PathBuf,
}

pub fn app_data_dir() -> Result<PathBuf> {
    let base = if let Some(path) = env::var_os("GRAPHXPLOIT_DATA_DIR") {
        PathBuf::from(path)
    } else if let Some(path) = env::var_os("LOCALAPPDATA") {
        PathBuf::from(path)
    } else if let Some(path) = env::var_os("XDG_DATA_HOME") {
        PathBuf::from(path)
    } else if let Some(path) = env::var_os("HOME") {
        PathBuf::from(path).join(".local").join("share")
    } else {
        env::current_dir()?.join(".graphxploit-data")
    };
    let result = base.join("GraphXploit");
    fs::create_dir_all(&result).context("could not create GraphXploit data directory")?;
    Ok(result)
}

fn project_database_path(root: &Path) -> Result<PathBuf> {
    let normalized = root.to_string_lossy().replace('\\', "/");
    let digest = Sha256::digest(normalized.as_bytes());
    let dir = app_data_dir()?.join("projects");
    fs::create_dir_all(&dir)?;
    Ok(dir.join(format!("{}.db", hex::encode(&digest[..12]))))
}

impl Store {
    pub fn open(root: &Path) -> Result<Self> {
        let root = root
            .canonicalize()
            .with_context(|| format!("project path does not exist: {}", root.display()))?;
        if !root.is_dir() {
            return Err(anyhow!(
                "project path is not a directory: {}",
                root.display()
            ));
        }
        let database = project_database_path(&root)?;
        let conn = Connection::open(&database)
            .with_context(|| format!("could not open {}", database.display()))?;
        conn.execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA temp_store = MEMORY;
             PRAGMA cache_size = -16384;",
        )?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS projects (
                id INTEGER PRIMARY KEY,
                root TEXT NOT NULL UNIQUE,
                schema_version INTEGER NOT NULL,
                created_at INTEGER NOT NULL DEFAULT (unixepoch()),
                updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
                generation INTEGER NOT NULL DEFAULT 0
              );
              CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY,
                project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                rel_path TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                modified_ns INTEGER NOT NULL,
                language TEXT NOT NULL,
                UNIQUE(project_id, rel_path)
              );
              CREATE INDEX IF NOT EXISTS files_path_idx ON files(project_id, rel_path);
              CREATE TABLE IF NOT EXISTS symbols (
                id INTEGER PRIMARY KEY,
                project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
                name TEXT NOT NULL,
                qualified_name TEXT NOT NULL,
                kind TEXT NOT NULL,
                start_line INTEGER NOT NULL,
                end_line INTEGER NOT NULL,
                UNIQUE(project_id, qualified_name)
              );
              CREATE INDEX IF NOT EXISTS symbols_name_idx ON symbols(project_id, name);
              CREATE INDEX IF NOT EXISTS symbols_qualified_idx ON symbols(project_id, qualified_name);
              CREATE INDEX IF NOT EXISTS symbols_file_idx ON symbols(file_id);
              CREATE TABLE IF NOT EXISTS symbol_references (
                id INTEGER PRIMARY KEY,
                project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                source_symbol_id INTEGER NOT NULL REFERENCES symbols(id) ON DELETE CASCADE,
                raw_target TEXT NOT NULL,
                line INTEGER NOT NULL
              );
              CREATE INDEX IF NOT EXISTS references_source_idx ON symbol_references(source_symbol_id);
              CREATE TABLE IF NOT EXISTS imports (
                id INTEGER PRIMARY KEY,
                project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                source_file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
                raw_target TEXT NOT NULL,
                line INTEGER NOT NULL
              );
              CREATE TABLE IF NOT EXISTS edges (
                project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                source_id INTEGER NOT NULL REFERENCES symbols(id) ON DELETE CASCADE,
                target_id INTEGER NOT NULL REFERENCES symbols(id) ON DELETE CASCADE,
                kind TEXT NOT NULL,
                evidence_line INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY(project_id, source_id, target_id, kind)
              );
              CREATE INDEX IF NOT EXISTS edges_source_idx ON edges(project_id, source_id, kind);
              CREATE INDEX IF NOT EXISTS edges_target_idx ON edges(project_id, target_id, kind);
              CREATE TABLE IF NOT EXISTS diagnostics (
                id INTEGER PRIMARY KEY,
                project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                file_id INTEGER REFERENCES files(id) ON DELETE CASCADE,
                message TEXT NOT NULL,
                severity TEXT NOT NULL DEFAULT 'warning'
              );",
        )?;
        let has_generation = {
            let mut statement = conn.prepare("PRAGMA table_info(projects)")?;
            let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
            let mut found = false;
            for column in columns {
                if column? == "generation" {
                    found = true;
                    break;
                }
            }
            found
        };
        if !has_generation {
            conn.execute(
                "ALTER TABLE projects ADD COLUMN generation INTEGER NOT NULL DEFAULT 0",
                [],
            )?;
        }
        let root_string = root.to_string_lossy();
        conn.execute(
            "INSERT INTO projects(root, schema_version) VALUES (?1, ?2)
             ON CONFLICT(root) DO UPDATE SET schema_version=excluded.schema_version, updated_at=unixepoch()",
            params![root_string.as_ref(), SCHEMA_VERSION],
        )?;
        let project_id = conn.query_row(
            "SELECT id FROM projects WHERE root=?1",
            [root_string.as_ref()],
            |row| row.get(0),
        )?;
        Ok(Self {
            conn,
            project_id,
            root,
            database,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
    pub fn database(&self) -> &Path {
        &self.database
    }

    pub(crate) fn existing_files(&self) -> Result<HashMap<String, FileRecord>> {
        let mut statement = self.conn.prepare(
            "SELECT id, rel_path, content_hash, modified_ns FROM files WHERE project_id=?1",
        )?;
        let rows = statement.query_map([self.project_id], |row| {
            Ok((
                row.get::<_, String>(1)?,
                FileRecord {
                    id: row.get(0)?,
                    hash: row.get(2)?,
                    modified_ns: row.get(3)?,
                },
            ))
        })?;
        let mut result = HashMap::new();
        for row in rows {
            let (path, record) = row?;
            result.insert(path, record);
        }
        Ok(result)
    }

    pub(crate) fn delete_file(&mut self, file_id: i64) -> Result<()> {
        self.conn
            .execute("DELETE FROM files WHERE id=?1", [file_id])?;
        Ok(())
    }

    pub(crate) fn replace_file(
        &mut self,
        rel_path: &str,
        hash: &str,
        modified_ns: i64,
        language: &str,
        parsed: &ParsedFile,
    ) -> Result<()> {
        let transaction = self.conn.savepoint()?;
        transaction.execute(
            "DELETE FROM files WHERE project_id=?1 AND rel_path=?2",
            params![self.project_id, rel_path],
        )?;
        transaction.execute(
            "INSERT INTO files(project_id, rel_path, content_hash, modified_ns, language) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![self.project_id, rel_path, hash, modified_ns, language],
        )?;
        let file_id = transaction.last_insert_rowid();
        transaction.execute(
            "INSERT INTO symbols(project_id, file_id, name, qualified_name, kind, start_line, end_line) VALUES (?1, ?2, ?3, ?4, 'File', 1, 1)",
            params![self.project_id, file_id, rel_path, rel_path],
        )?;
        let mut ids = HashMap::new();
        for symbol in &parsed.symbols {
            transaction.execute(
                "INSERT INTO symbols(project_id, file_id, name, qualified_name, kind, start_line, end_line) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![self.project_id, file_id, symbol.name, symbol.qualified_name, symbol.kind, symbol.start_line, symbol.end_line],
            )?;
            ids.insert(
                symbol.qualified_name.as_str(),
                transaction.last_insert_rowid(),
            );
        }
        for reference in &parsed.references {
            if let Some(source_id) = ids.get(reference.source_qualified_name.as_str()) {
                transaction.execute(
                    "INSERT INTO symbol_references(project_id, source_symbol_id, raw_target, line) VALUES (?1, ?2, ?3, ?4)",
                    params![self.project_id, source_id, reference.raw_target, reference.line],
                )?;
            }
        }
        for (raw_target, line) in &parsed.imports {
            transaction.execute(
                "INSERT INTO imports(project_id, source_file_id, raw_target, line) VALUES (?1, ?2, ?3, ?4)",
                params![self.project_id, file_id, raw_target, line],
            )?;
        }
        if let Some(message) = &parsed.diagnostic {
            transaction.execute(
                "INSERT INTO diagnostics(project_id, file_id, message) VALUES (?1, ?2, ?3)",
                params![self.project_id, file_id, message],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn rebuild_edges(
        &mut self,
        cancelled: Option<&AtomicBool>,
    ) -> Result<Option<usize>> {
        if cancellation_requested(cancelled) {
            return Ok(None);
        }

        const EDGE_BATCH: i64 = 512;
        let transaction = self.conn.savepoint()?;
        transaction.execute("DELETE FROM edges WHERE project_id=?1", [self.project_id])?;
        let mut edges = transaction.execute(
            "INSERT OR IGNORE INTO edges(project_id, source_id, target_id, kind)
             SELECT ?1, file_node.id, member.id, 'CONTAINS'
             FROM symbols member
             JOIN symbols file_node
               ON file_node.project_id=member.project_id
              AND file_node.file_id=member.file_id
              AND file_node.kind='File'
             WHERE member.project_id=?1 AND member.kind!='File'",
            [self.project_id],
        )?;

        let mut file_nodes = HashMap::new();
        let mut file_modules: HashMap<String, i64> = HashMap::new();
        {
            let mut statement = transaction.prepare(
                "SELECT s.file_id, s.id, f.rel_path
                 FROM symbols s JOIN files f ON f.id=s.file_id
                 WHERE s.project_id=?1 AND s.kind='File'",
            )?;
            let rows = statement.query_map([self.project_id], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?;
            for row in rows {
                if cancellation_requested(cancelled) {
                    return Ok(None);
                }
                let (file_id, symbol_id, path) = row?;
                file_nodes.insert(file_id, symbol_id);
                for key in module_keys(&path) {
                    file_modules.entry(key).or_insert(symbol_id);
                }
            }
        }

        {
            let mut same_file_lookup = transaction.prepare(
                "SELECT id FROM symbols
                 WHERE project_id=?1 AND kind!='File' AND name=?2 AND file_id=?3
                 ORDER BY id LIMIT 2",
            )?;
            let mut global_lookup = transaction.prepare(
                "SELECT id FROM symbols
                 WHERE project_id=?1 AND kind!='File' AND name=?2
                 ORDER BY id LIMIT 2",
            )?;
            let mut cursor = 0i64;
            loop {
                let batch = {
                    let mut statement = transaction.prepare(
                        "SELECT r.rowid, r.source_symbol_id, s.file_id, r.raw_target, r.line
                         FROM symbol_references r
                         JOIN symbols s ON s.id=r.source_symbol_id
                         WHERE r.project_id=?1 AND r.rowid>?2
                         ORDER BY r.rowid LIMIT ?3",
                    )?;
                    let rows = statement.query_map(
                        params![self.project_id, cursor, EDGE_BATCH],
                        |row| {
                            Ok((
                                row.get::<_, i64>(0)?,
                                row.get::<_, i64>(1)?,
                                row.get::<_, i64>(2)?,
                                row.get::<_, String>(3)?,
                                row.get::<_, u32>(4)?,
                            ))
                        },
                    )?;
                    rows.collect::<rusqlite::Result<Vec<_>>>()?
                };
                if batch.is_empty() {
                    break;
                }
                for (row_id, source_id, source_file_id, raw_target, line) in batch {
                    cursor = row_id;
                    if cancellation_requested(cancelled) {
                        return Ok(None);
                    }
                    let name = terminal_name(&raw_target);
                    let same_file = same_file_lookup
                        .query_map(params![self.project_id, name, source_file_id], |row| {
                            row.get::<_, i64>(0)
                        })?
                        .collect::<rusqlite::Result<Vec<_>>>()?;
                    let target_id = match same_file.as_slice() {
                        [target] => Some(*target),
                        [] => {
                            let global = global_lookup
                                .query_map(params![self.project_id, name], |row| {
                                    row.get::<_, i64>(0)
                                })?
                                .collect::<rusqlite::Result<Vec<_>>>()?;
                            match global.as_slice() {
                                [target] => Some(*target),
                                _ => None,
                            }
                        }
                        _ => None,
                    };
                    if let Some(target_id) = target_id {
                        edges += transaction.execute(
                            "INSERT OR IGNORE INTO edges(project_id, source_id, target_id, kind, evidence_line)
                             VALUES (?1, ?2, ?3, 'CALLS', ?4)",
                            params![self.project_id, source_id, target_id, line],
                        )?;
                    }
                }
            }
        }

        let mut cursor = 0i64;
        loop {
            let batch = {
                let mut statement = transaction.prepare(
                    "SELECT rowid, source_file_id, raw_target, line
                     FROM imports
                     WHERE project_id=?1 AND rowid>?2
                     ORDER BY rowid LIMIT ?3",
                )?;
                let rows =
                    statement.query_map(params![self.project_id, cursor, EDGE_BATCH], |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, u32>(3)?,
                        ))
                    })?;
                rows.collect::<rusqlite::Result<Vec<_>>>()?
            };
            if batch.is_empty() {
                break;
            }
            for (row_id, source_file_id, raw_target, line) in batch {
                cursor = row_id;
                if cancellation_requested(cancelled) {
                    return Ok(None);
                }
                let Some(source_id) = file_nodes.get(&source_file_id) else {
                    continue;
                };
                let module = import_module_name(&raw_target);
                let target = file_modules.get(&module).copied().or_else(|| {
                    module
                        .rsplit('.')
                        .next()
                        .and_then(|part| file_modules.get(part).copied())
                });
                if let Some(target_id) = target.filter(|target| *target != *source_id) {
                    edges += transaction.execute(
                        "INSERT OR IGNORE INTO edges(project_id, source_id, target_id, kind, evidence_line)
                         VALUES (?1, ?2, ?3, 'IMPORTS', ?4)",
                        params![self.project_id, source_id, target_id, line],
                    )?;
                }
            }
        }

        transaction.commit()?;
        Ok(Some(edges))
    }
    pub(crate) fn find_symbols(&self, target: &str) -> Result<Vec<SymbolRecord>> {
        let exact = self.conn.prepare(
            "SELECT s.id, s.file_id, s.name, s.qualified_name, s.kind, f.rel_path, s.start_line, s.end_line FROM symbols s JOIN files f ON f.id=s.file_id WHERE s.project_id=?1 AND s.qualified_name=?2",
        )?.query_map(params![self.project_id, target], |row| {
            Ok(SymbolRecord { id: row.get(0)?, file_id: row.get(1)?, name: row.get(2)?, qualified_name: row.get(3)?, kind: row.get(4)?, path: row.get(5)?, line: row.get(6)?, end_line: row.get(7)? })
        })?.collect::<rusqlite::Result<Vec<_>>>()?;
        if !exact.is_empty() {
            return Ok(exact);
        }
        let mut statement = self.conn.prepare(
            "SELECT s.id, s.file_id, s.name, s.qualified_name, s.kind, f.rel_path, s.start_line, s.end_line FROM symbols s JOIN files f ON f.id=s.file_id WHERE s.project_id=?1 AND (s.name=?2 OR s.qualified_name LIKE ?3)",
        )?;
        let query = format!("%::{target}");
        let rows = statement.query_map(params![self.project_id, target, query], |row| {
            Ok(SymbolRecord {
                id: row.get(0)?,
                file_id: row.get(1)?,
                name: row.get(2)?,
                qualified_name: row.get(3)?,
                kind: row.get(4)?,
                path: row.get(5)?,
                line: row.get(6)?,
                end_line: row.get(7)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    pub(crate) fn file_members(&self, file_id: i64, limit: usize) -> Result<Vec<i64>> {
        let mut statement = self.conn.prepare(
            "SELECT id FROM symbols WHERE project_id=?1 AND file_id=?2 AND kind != 'File' ORDER BY id LIMIT ?3",
        )?;
        let rows = statement.query_map(params![self.project_id, file_id, limit as i64], |row| {
            row.get(0)
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    pub(crate) fn neighbors(
        &self,
        node_id: i64,
        reverse: bool,
        limit: usize,
    ) -> Result<Vec<EdgeRecord>> {
        let sql = if reverse {
            "SELECT source_id, target_id, kind FROM edges WHERE project_id=?1 AND target_id=?2 AND kind IN ('CALLS','IMPORTS') ORDER BY source_id, target_id LIMIT ?3"
        } else {
            "SELECT source_id, target_id, kind FROM edges WHERE project_id=?1 AND source_id=?2 AND kind IN ('CALLS','IMPORTS') ORDER BY source_id, target_id LIMIT ?3"
        };
        let mut statement = self.conn.prepare(sql)?;
        let rows = statement.query_map(params![self.project_id, node_id, limit as i64], |row| {
            Ok(EdgeRecord {
                source_id: row.get(0)?,
                target_id: row.get(1)?,
                kind: row.get(2)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }
    pub(crate) fn count(&self, table: &str) -> Result<usize> {
        let allowed = match table {
            "files" | "symbols" | "edges" | "diagnostics" => table,
            _ => return Err(anyhow!("invalid count table")),
        };
        let sql = format!("SELECT count(*) FROM {allowed} WHERE project_id=?1");
        Ok(self
            .conn
            .query_row(&sql, [self.project_id], |row| row.get::<_, i64>(0))? as usize)
    }

    pub(crate) fn begin_scan(&self) -> Result<()> {
        self.conn.execute_batch("BEGIN IMMEDIATE")?;
        Ok(())
    }

    pub(crate) fn commit_scan(&self) -> Result<()> {
        self.conn.execute(
            "UPDATE projects SET updated_at=unixepoch(), generation=generation+1 WHERE id=?1",
            [self.project_id],
        )?;
        self.conn.execute_batch("COMMIT")?;
        Ok(())
    }

    pub(crate) fn rollback_scan(&self) -> Result<()> {
        self.conn.execute_batch("ROLLBACK")?;
        Ok(())
    }

    pub(crate) fn generation(&self) -> Result<u64> {
        Ok(self.conn.query_row(
            "SELECT generation FROM projects WHERE id=?1",
            [self.project_id],
            |row| row.get::<_, i64>(0),
        )? as u64)
    }

    pub(crate) fn symbol(&self, id: i64) -> Result<Option<SymbolRecord>> {
        let mut statement = self.conn.prepare(
            "SELECT s.id, s.file_id, s.name, s.qualified_name, s.kind, f.rel_path, s.start_line, s.end_line FROM symbols s JOIN files f ON f.id=s.file_id WHERE s.project_id=?1 AND s.id=?2",
        )?;
        let mut rows = statement.query(params![self.project_id, id])?;
        let Some(row) = rows.next()? else {
            return Ok(None);
        };
        Ok(Some(SymbolRecord {
            id: row.get(0)?,
            file_id: row.get(1)?,
            name: row.get(2)?,
            qualified_name: row.get(3)?,
            kind: row.get(4)?,
            path: row.get(5)?,
            line: row.get(6)?,
            end_line: row.get(7)?,
        }))
    }

    pub(crate) fn symbols_for_path(&self, path: &str, limit: usize) -> Result<Vec<SymbolRecord>> {
        let mut statement = self.conn.prepare(
            "SELECT s.id, s.file_id, s.name, s.qualified_name, s.kind, f.rel_path, s.start_line, s.end_line FROM symbols s JOIN files f ON f.id=s.file_id WHERE s.project_id=?1 AND f.rel_path=?2 ORDER BY s.start_line LIMIT ?3",
        )?;
        let rows = statement.query_map(params![self.project_id, path, limit as i64], |row| {
            Ok(SymbolRecord {
                id: row.get(0)?,
                file_id: row.get(1)?,
                name: row.get(2)?,
                qualified_name: row.get(3)?,
                kind: row.get(4)?,
                path: row.get(5)?,
                line: row.get(6)?,
                end_line: row.get(7)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    pub(crate) fn search_symbols(
        &self,
        query: &str,
        limit: usize,
    ) -> Result<(Vec<SymbolRecord>, bool)> {
        let escaped = query
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_");
        let pattern = format!("%{escaped}%");
        let mut statement = self.conn.prepare(
            "SELECT s.id, s.file_id, s.name, s.qualified_name, s.kind, f.rel_path, s.start_line, s.end_line FROM symbols s JOIN files f ON f.id=s.file_id WHERE s.project_id=?1 AND (s.name LIKE ?2 ESCAPE '\\' OR s.qualified_name LIKE ?2 ESCAPE '\\' OR f.rel_path LIKE ?2 ESCAPE '\\') ORDER BY CASE WHEN lower(s.name)=lower(?3) THEN 0 WHEN lower(s.name) LIKE lower(?3 || '%') THEN 1 ELSE 2 END, length(s.qualified_name), s.qualified_name LIMIT ?4",
        )?;
        let rows = statement.query_map(
            params![self.project_id, pattern, query, (limit + 1) as i64],
            |row| {
                Ok(SymbolRecord {
                    id: row.get(0)?,
                    file_id: row.get(1)?,
                    name: row.get(2)?,
                    qualified_name: row.get(3)?,
                    kind: row.get(4)?,
                    path: row.get(5)?,
                    line: row.get(6)?,
                    end_line: row.get(7)?,
                })
            },
        )?;
        let mut records = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        let complete = records.len() <= limit;
        records.truncate(limit);
        Ok((records, complete))
    }
    pub(crate) fn candidates(records: &[SymbolRecord]) -> Vec<Candidate> {
        records
            .iter()
            .map(|symbol| Candidate {
                qualified_name: symbol.qualified_name.clone(),
                kind: symbol.kind.clone(),
                path: symbol.path.clone(),
                line: symbol.line,
            })
            .collect()
    }

    pub fn summary(
        &self,
        files_seen: usize,
        files_parsed: usize,
        files_skipped: usize,
        relationships: usize,
        cancelled: bool,
    ) -> Result<ProjectSummary> {
        Ok(ProjectSummary {
            root: self.root.clone(),
            database: self.database.clone(),
            files_seen,
            files_parsed,
            files_skipped,
            symbols: self.count("symbols")?,
            relationships,
            diagnostics: self.count("diagnostics")?,
            cancelled,
            generation: self.generation()?,
        })
    }
}

fn terminal_name(value: &str) -> String {
    value
        .trim()
        .trim_matches(|c: char| !c.is_alphanumeric() && c != '_' && c != '.' && c != ':')
        .rsplit(['.', ':'])
        .find(|part| !part.is_empty())
        .unwrap_or(value)
        .to_owned()
}

fn cancellation_requested(cancelled: Option<&AtomicBool>) -> bool {
    cancelled.is_some_and(|flag| flag.load(Ordering::Relaxed))
}

fn module_keys(path: &str) -> Vec<String> {
    let normalized = path.replace('\\', "/");
    let stem = normalized
        .rsplit_once('.')
        .map(|(before, _)| before)
        .unwrap_or(&normalized);
    let dotted = stem.replace('/', ".");
    let mut keys = vec![
        dotted.clone(),
        stem.rsplit('/').next().unwrap_or(stem).to_owned(),
    ];
    if let Some(base) = dotted.strip_suffix(".__init__") {
        keys.push(base.to_owned());
    }
    keys.sort();
    keys.dedup();
    keys
}

fn import_module_name(raw: &str) -> String {
    let trimmed = raw.trim();
    if let Some(quoted) = trimmed.split(['\"', '\'']).nth(1) {
        return quoted
            .trim_start_matches("./")
            .trim_start_matches("../")
            .trim_end_matches(".ts")
            .trim_end_matches(".tsx")
            .trim_end_matches(".js")
            .replace('/', ".");
    }
    let tokens: Vec<&str> = trimmed.split_whitespace().collect();
    let value = tokens
        .iter()
        .find(|part| {
            !matches!(
                **part,
                "import" | "from" | "use" | "crate" | "pub" | "static"
            )
        })
        .copied()
        .unwrap_or(trimmed);
    value
        .trim_matches(|c: char| !c.is_alphanumeric() && c != '_' && c != '.' && c != ':')
        .replace("::", ".")
}
