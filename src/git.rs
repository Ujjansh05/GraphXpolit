use crate::analysis::impact;
use crate::model::{ChangeImpact, ChangedSymbol};
use crate::store::Store;
use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const MAX_GIT_OUTPUT_BYTES: usize = 8 * 1024 * 1024;
const MAX_CHANGED_SYMBOLS: usize = 50;
const MAX_AFFECTED_PER_SYMBOL: usize = 20;
const GIT_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug)]
struct FileChange {
    status: String,
    path: String,
    old_path: Option<String>,
    ranges: Vec<(u32, u32)>,
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

fn build_change_impact(
    root: &Path,
    mode: &str,
    base_revision: &str,
    head_revision: &str,
    range: &[&str],
) -> Result<ChangeImpact> {
    let mut name_args = vec!["diff", "--name-status", "-M", "--no-ext-diff"];
    name_args.extend_from_slice(range);
    name_args.push("--");
    let names = git_text(root, &name_args)?;

    let mut patch_args = vec![
        "diff",
        "--unified=0",
        "-M",
        "--no-ext-diff",
        "--no-textconv",
    ];
    patch_args.extend_from_slice(range);
    patch_args.push("--");
    let patch = git_text(root, &patch_args)?;

    let mut changes = parse_name_status(&names);
    let ranges = parse_new_ranges(&patch);
    for change in &mut changes {
        if let Some(found) = ranges.get(&change.path) {
            change.ranges = found.clone();
        }
    }

    let store = Store::open(root)?;
    let mut output = Vec::new();
    let mut complete = true;
    for change in changes {
        let mut matched = if change.status == "deleted" {
            Vec::new()
        } else {
            store
                .symbols_for_path(&change.path, MAX_CHANGED_SYMBOLS + 1)?
                .into_iter()
                .filter(|symbol| {
                    symbol.kind != "File"
                        && (change.ranges.is_empty()
                            || change.ranges.iter().any(|(start, end)| {
                                symbol.line <= *end && symbol.end_line >= *start
                            }))
                })
                .collect::<Vec<_>>()
        };
        if matched.len() > MAX_CHANGED_SYMBOLS {
            complete = false;
            matched.truncate(MAX_CHANGED_SYMBOLS);
        }
        if matched.is_empty() {
            let query_target = if change.status == "deleted" {
                change.old_path.as_deref().unwrap_or(&change.path)
            } else {
                &change.path
            };
            let affected = impact(root, query_target, 3)
                .map(|result| {
                    result
                        .results
                        .into_iter()
                        .take(MAX_AFFECTED_PER_SYMBOL)
                        .collect()
                })
                .unwrap_or_default();
            output.push(ChangedSymbol {
                status: change.status,
                path: change.path.clone(),
                old_path: change.old_path,
                qualified_name: change.path,
                kind: "File".to_owned(),
                line: 1,
                affected,
            });
        } else {
            for symbol in matched {
                if output.len() >= MAX_CHANGED_SYMBOLS {
                    complete = false;
                    break;
                }
                let query = impact(root, &symbol.qualified_name, 3)?;
                if !query.complete || query.results.len() > MAX_AFFECTED_PER_SYMBOL {
                    complete = false;
                }
                output.push(ChangedSymbol {
                    status: change.status.clone(),
                    path: symbol.path,
                    old_path: change.old_path.clone(),
                    qualified_name: symbol.qualified_name,
                    kind: symbol.kind,
                    line: symbol.line,
                    affected: query
                        .results
                        .into_iter()
                        .take(MAX_AFFECTED_PER_SYMBOL)
                        .collect(),
                });
            }
        }
        if output.len() >= MAX_CHANGED_SYMBOLS {
            complete = false;
            break;
        }
    }
    let message = if output.is_empty() {
        Some(if mode == "working" {
            "No tracked staged or unstaged changes were found. Untracked files are excluded."
                .to_owned()
        } else {
            "No changes were found between the merge base and HEAD.".to_owned()
        })
    } else if !complete {
        Some("The change report reached a safety limit and is incomplete.".to_owned())
    } else {
        None
    };
    Ok(ChangeImpact {
        mode: mode.to_owned(),
        base_revision: base_revision.to_owned(),
        head_revision: head_revision.to_owned(),
        changes: output,
        complete,
        message,
    })
}

fn validate_revision(value: &str) -> Result<()> {
    if value.trim().is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        bail!("Git base revision is invalid");
    }
    Ok(())
}

fn parse_name_status(value: &str) -> Vec<FileChange> {
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
                ranges: Vec::new(),
            })
        })
        .collect()
}

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

fn git_text(root: &Path, args: &[&str]) -> Result<String> {
    let mut child = Command::new("git")
        .current_dir(root)
        .args(["-c", "core.quotepath=false", "-c", "diff.external="])
        .args(args)
        .env_remove("GIT_EXTERNAL_DIFF")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("Git is required for change analysis")?;
    let stdout = child.stdout.take().context("could not read Git output")?;
    let stderr = child.stderr.take().context("could not read Git errors")?;
    let output_reader = thread::spawn(move || read_bounded(stdout, MAX_GIT_OUTPUT_BYTES));
    let error_reader = thread::spawn(move || read_bounded(stderr, 64 * 1024));
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() > GIT_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            bail!("Git command exceeded the 15 second limit");
        }
        thread::sleep(Duration::from_millis(20));
    };
    let output = output_reader
        .join()
        .map_err(|_| anyhow::anyhow!("Git output reader failed"))??;
    let errors = error_reader
        .join()
        .map_err(|_| anyhow::anyhow!("Git error reader failed"))??;
    if !status.success() {
        bail!(
            "Git command failed: {}",
            String::from_utf8_lossy(&errors).trim()
        );
    }
    String::from_utf8(output).context("Git output is not UTF-8")
}

fn read_bounded(mut reader: impl Read, limit: usize) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    reader
        .by_ref()
        .take(limit as u64 + 1)
        .read_to_end(&mut output)?;
    if output.len() > limit {
        bail!("Git output exceeds the configured safety limit");
    }
    Ok(output)
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
