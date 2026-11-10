use crate::model::{ChangeImpact, ChangedSymbol};
use crate::store::Store;
use anyhow::{bail, Context, Result};
#[cfg(test)]
use std::collections::HashMap;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

const MAX_GIT_OUTPUT_BYTES: usize = 8 * 1024 * 1024;
const MAX_CHANGED_SYMBOLS: usize = 50;
const MAX_AFFECTED_PER_SYMBOL: usize = 20;
const GIT_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug)]
struct FileChange {
    status: String,
    path: String,
    old_path: Option<String>,
}

pub fn working_changes(root: &Path) -> Result<ChangeImpact> {
    let base = git_text(root, &["rev-parse", "--verify", "HEAD"])?
        .trim()
        .to_owned();
    build_change_impact(root, "working", &base, "WORKTREE", &["HEAD"])
}

pub fn branch_changes(root: &Path, base: &str) -> Result<ChangeImpact> {
    validate_revision(base)?;
    let base_commit = git_text(
        root,
        &[
            "rev-parse",
            "--verify",
            "--end-of-options",
            &format!("{base}^{{commit}}"),
        ],
    )?;
    let base_commit = base_commit.trim();
    let merge_base = git_text(root, &["merge-base", "HEAD", base_commit])?;
    let merge_base = merge_base.trim().to_owned();
    let head = git_text(root, &["rev-parse", "--verify", "HEAD"])?
        .trim()
        .to_owned();
    build_change_impact(root, "branch", &merge_base, &head, &[&merge_base, "HEAD"])
}

// Build bounded, disposable indexes for both sides. Git objects are read as data;
// no checkout, hooks, project scripts, submodules, or links are executed.
fn build_change_impact(
    root: &Path,
    mode: &str,
    base_revision: &str,
    head_revision: &str,
    range: &[&str],
) -> Result<ChangeImpact> {
    let top = git_text(root, &["rev-parse", "--show-toplevel"])?;
    if Path::new(top.trim()).canonicalize()? != root.canonicalize()? {
        bail!(
            "Git impact requires the repository root; select {}",
            top.trim()
        );
    }
    let mut name_args = vec![
        "diff",
        "--name-status",
        "-z",
        "-M",
        "--no-ext-diff",
        "--no-textconv",
    ];
    name_args.extend_from_slice(range);
    name_args.push("--");
    let changes = parse_name_status(&git_text(root, &name_args)?);
    if changes.is_empty() {
        return Ok(ChangeImpact {
            mode: mode.into(),
            base_revision: base_revision.into(),
            head_revision: head_revision.into(),
            changes: vec![],
            complete: true,
            message: Some("No tracked changes found; untracked files are excluded.".into()),
        });
    }
    let before = Snapshot::commit(root, base_revision)?;
    let after = if mode == "working" {
        Snapshot::worktree(root)?
    } else {
        Snapshot::commit(root, head_revision)?
    };
    let mut output = Vec::new();
    let mut complete = before.complete && after.complete;
    'files: for change in changes {
        // Both sides matter even when only lines were deleted inside a retained file.
        for (side, snapshot, path) in [
            (
                "before",
                &before,
                change.old_path.as_deref().unwrap_or(&change.path),
            ),
            ("after", &after, change.path.as_str()),
        ] {
            if (side == "before" && change.status == "added")
                || (side == "after" && change.status == "deleted")
            {
                continue;
            }
            let symbols = snapshot
                .store
                .symbols_for_path(path, MAX_CHANGED_SYMBOLS + 2)?;
            let members = symbols
                .into_iter()
                .filter(|s| s.kind != "File")
                .collect::<Vec<_>>();
            if members.len() > MAX_CHANGED_SYMBOLS {
                complete = false;
            }
            if members.is_empty() {
                if crate::analysis::language_for_path(Path::new(path)).is_some() {
                    complete = false;
                }
                continue;
            }
            for symbol in members.into_iter().take(MAX_CHANGED_SYMBOLS) {
                if output.len() >= MAX_CHANGED_SYMBOLS {
                    complete = false;
                    break 'files;
                }
                let query =
                    crate::analysis::query_store(&snapshot.store, &symbol.qualified_name, 3, true)?;
                complete &= query.complete && query.results.len() <= MAX_AFFECTED_PER_SYMBOL;
                output.push(ChangedSymbol {
                    status: change.status.clone(),
                    path: symbol.path,
                    old_path: change.old_path.clone(),
                    qualified_name: symbol.qualified_name,
                    kind: symbol.kind,
                    line: symbol.line,
                    basis: side.into(),
                    affected: query
                        .results
                        .into_iter()
                        .take(MAX_AFFECTED_PER_SYMBOL)
                        .collect(),
                });
            }
        }
    }
    Ok(ChangeImpact { mode:mode.into(), base_revision:base_revision.into(), head_revision:head_revision.into(),
        changes:output, complete,
        message:Some(if complete {
            "Compared before/after indexes. All symbols in changed files are included conservatively; static relationships do not prove runtime coverage."
        } else {
            "Before/after report is incomplete because files were skipped or a result/resource limit was reached. This is not an indication of safety."
        }.into()) })
}

const SNAPSHOT_BYTES: usize = 64 * 1024 * 1024;
const SNAPSHOT_FILES: usize = 10_000;
struct Snapshot {
    store: Store,
    complete: bool,
    _temp: tempfile::TempDir,
}

fn snapshot_path(path: &str) -> bool {
    !crate::safety::sensitive(Path::new(path))
        && Path::new(path)
            .components()
            .all(|c| matches!(c, std::path::Component::Normal(_)))
        && !path.contains(':')
        && (crate::analysis::language_for_path(Path::new(path)).is_some()
            || matches!(
                Path::new(path).file_name().and_then(|s| s.to_str()),
                Some(".gitignore" | ".graphxploitignore")
            ))
}

impl Snapshot {
    fn finish(temp: tempfile::TempDir, complete: bool) -> Result<Self> {
        let source = temp.path().join("source");
        let db = temp.path().join("index.db");
        let summary = crate::analysis::scan_store(
            Store::open_at(&source, db.clone())?,
            crate::ScanOptions::default(),
        )?;
        let store = Store::open_at(&source, db)?;
        Ok(Self {
            store,
            complete: complete && summary.diagnostics == 0,
            _temp: temp,
        })
    }
    fn write(source: &Path, path: &str, content: &[u8]) -> Result<()> {
        if !snapshot_path(path) {
            bail!("invalid snapshot path");
        }
        let dest = source.join(path);
        std::fs::create_dir_all(dest.parent().context("missing snapshot parent")?)?;
        let checked = crate::safety::workspace_path(source, Path::new(path), true)?;
        std::fs::write(checked, content)?;
        Ok(())
    }
    fn commit(root: &Path, revision: &str) -> Result<Self> {
        let temp = tempfile::tempdir()?;
        let source = temp.path().join("source");
        std::fs::create_dir(&source)?;
        let listing = git_text(root, &["ls-tree", "-r", "-l", "-z", revision])?;
        let mut blobs = Vec::new();
        let mut bytes = 0usize;
        let mut complete = true;
        for item in listing.split('\0').filter(|s| !s.is_empty()) {
            let Some((meta, path)) = item.split_once('\t') else {
                bail!("invalid Git tree record");
            };
            if !snapshot_path(path) {
                continue;
            }
            let cols = meta.split_whitespace().collect::<Vec<_>>();
            if cols.len() != 4 || cols[1] != "blob" || !matches!(cols[0], "100644" | "100755") {
                complete = false;
                continue;
            }
            let size = cols[3].parse::<usize>()?;
            if size > 2 * 1024 * 1024 {
                complete = false;
                continue;
            }
            bytes = bytes.saturating_add(size);
            if bytes > SNAPSHOT_BYTES || blobs.len() >= SNAPSHOT_FILES {
                bail!("Git snapshot exceeds 10,000 files or 64 MiB; narrow the repository");
            }
            blobs.push((cols[2].to_owned(), path.to_owned(), size));
        }
        let mut cursor = 0;
        while cursor < blobs.len() {
            let start = cursor;
            let mut size = 0;
            while cursor < blobs.len()
                && cursor - start < 64
                && size + blobs[cursor].2 <= 4 * 1024 * 1024
            {
                size += blobs[cursor].2;
                cursor += 1;
            }
            let input = blobs[start..cursor]
                .iter()
                .map(|(id, _, _)| format!("{id}\n"))
                .collect::<String>();
            let mut cmd = git_command(root)?;
            cmd.args(["cat-file", "--batch"]);
            let (status, out, err) = crate::process::capture_input(
                &mut cmd,
                GIT_TIMEOUT,
                MAX_GIT_OUTPUT_BYTES,
                Some(input.into_bytes()),
            )?;
            if !status.success() {
                bail!(
                    "Git object read failed: {}",
                    crate::safety::terminal(&String::from_utf8_lossy(&err))
                );
            }
            let mut rest = out.as_slice();
            for (id, path, expected) in &blobs[start..cursor] {
                let end = rest
                    .iter()
                    .position(|c| *c == b'\n')
                    .context("invalid Git blob header")?;
                let header = std::str::from_utf8(&rest[..end])?;
                if header != format!("{id} blob {expected}") {
                    bail!("unexpected Git blob response");
                }
                rest = &rest[end + 1..];
                if rest.len() <= *expected || rest[*expected] != b'\n' {
                    bail!("truncated Git blob");
                }
                Self::write(&source, path, &rest[..*expected])?;
                rest = &rest[*expected + 1..];
            }
        }
        Self::finish(temp, complete)
    }
    fn worktree(root: &Path) -> Result<Self> {
        let temp = tempfile::tempdir()?;
        let source = temp.path().join("source");
        std::fs::create_dir(&source)?;
        let listing = git_text(root, &["ls-files", "-z"])?;
        let mut seen = std::collections::HashSet::new();
        let mut bytes = 0usize;
        let mut complete = true;
        for path in listing.split('\0').filter(|s| !s.is_empty()) {
            if !snapshot_path(path) || !seen.insert(path) {
                continue;
            }
            if seen.len() > SNAPSHOT_FILES {
                bail!("Git snapshot exceeds 10,000 files");
            }
            if !root.join(path).exists() {
                continue;
            } // Tracked but deleted in worktree.
            let content = match crate::safety::read(root, Path::new(path), 2 * 1024 * 1024) {
                Ok(bytes) => bytes,
                Err(_) => {
                    complete = false;
                    continue;
                }
            };
            bytes = bytes.saturating_add(content.len());
            if bytes > SNAPSHOT_BYTES {
                bail!("Git snapshot exceeds 64 MiB");
            }
            Self::write(&source, path, &content)?;
        }
        Self::finish(temp, complete)
    }
}

fn validate_revision(value: &str) -> Result<()> {
    if value.trim().is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        bail!("Git base revision is invalid");
    }
    Ok(())
}

fn parse_name_status(value: &str) -> Vec<FileChange> {
    if value.contains('\0') {
        let mut fields = value.split('\0');
        let mut changes = Vec::new();
        while let Some(code) = fields.next().filter(|s| !s.is_empty()) {
            let Some(first) = fields.next() else {
                break;
            };
            let renamed = code.starts_with('R') || code.starts_with('C');
            let path = if renamed {
                let Some(next) = fields.next() else {
                    break;
                };
                next
            } else {
                first
            };
            changes.push(FileChange {
                status: match code.chars().next() {
                    Some('A') => "added",
                    Some('D') => "deleted",
                    Some('R' | 'C') => "renamed",
                    _ => "modified",
                }
                .into(),
                path: path.into(),
                old_path: if renamed || code.starts_with('D') {
                    Some(first.into())
                } else {
                    None
                },
            });
        }
        return changes;
    }
    value
        .lines()
        .filter_map(|line| {
            let fields = line.split('\t').collect::<Vec<_>>();
            let code = fields.first()?.chars().next()?;
            let (status, old_path, path) = match code {
                'A' => ("added", None, *fields.get(1)?),
                'D' => (
                    "deleted",
                    Some((*fields.get(1)?).to_owned()),
                    *fields.get(1)?,
                ),
                'R' | 'C' => (
                    "renamed",
                    Some((*fields.get(1)?).to_owned()),
                    *fields.get(2)?,
                ),
                _ => ("modified", None, *fields.get(1)?),
            };
            Some(FileChange {
                status: status.to_owned(),
                path: path.replace('\\', "/"),
                old_path,
            })
        })
        .collect()
}

#[cfg(test)]
fn parse_new_ranges(patch: &str) -> HashMap<String, Vec<(u32, u32)>> {
    let mut result: HashMap<String, Vec<(u32, u32)>> = HashMap::new();
    let mut path = None;
    for line in patch.lines() {
        if let Some(value) = line.strip_prefix("+++ b/") {
            path = Some(value.to_owned());
        } else if line.starts_with("+++ /dev/null") {
            path = None;
        } else if let (Some(current), Some(hunk)) = (path.as_ref(), line.strip_prefix("@@ ")) {
            if let Some(plus) = hunk.split_whitespace().find(|part| part.starts_with('+')) {
                let range = plus.trim_start_matches('+');
                let mut parts = range.split(',');
                if let Ok(start) = parts.next().unwrap_or_default().parse::<u32>() {
                    let count = parts
                        .next()
                        .and_then(|part| part.parse::<u32>().ok())
                        .unwrap_or(1);
                    if count > 0 {
                        result
                            .entry(current.clone())
                            .or_default()
                            .push((start, start + count - 1));
                    }
                }
            }
        }
    }
    result
}

fn git_command(root: &Path) -> Result<Command> {
    let mut command = Command::new(crate::process::trusted_program("git", root)?);
    command.current_dir(root).args([
        "--no-pager",
        "-c",
        "core.quotepath=false",
        "-c",
        "diff.external=",
        "-c",
        "core.fsmonitor=false",
    ]);
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("GIT_") {
            command.env_remove(key);
        }
    }
    Ok(command)
}
fn git_text(root: &Path, args: &[&str]) -> Result<String> {
    let mut command = git_command(root)?;
    command.args(args);
    let (status, output, errors) =
        crate::process::capture(&mut command, GIT_TIMEOUT, MAX_GIT_OUTPUT_BYTES)?;
    if !status.success() {
        bail!(
            "Git command failed: {}",
            crate::safety::terminal(&String::from_utf8_lossy(&errors))
        );
    }
    String::from_utf8(output).context("Git output is not UTF-8")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_renames_and_hunks() {
        let changes = parse_name_status("R100\told.rs\tnew.rs\nM\tsrc/lib.rs\n");
        assert_eq!(changes[0].status, "renamed");
        assert_eq!(changes[0].old_path.as_deref(), Some("old.rs"));
        let ranges = parse_new_ranges("+++ b/src/lib.rs\n@@ -2,0 +3,4 @@\n");
        assert_eq!(ranges["src/lib.rs"], vec![(3, 6)]);
    }
}
