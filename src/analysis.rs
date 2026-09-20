use crate::model::{ImpactNode, Language, ParsedFile, ParsedReference, ParsedSymbol, QueryResult};
use crate::store::{Store, SymbolRecord};
use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::UNIX_EPOCH;
use tree_sitter::{Language as TsLanguage, Node, Parser};

const DEFAULT_MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_RETURNED_NODES: usize = 500;
const MAX_VISITED_NODES: usize = 10_000;

#[derive(Clone)]
pub struct ScanOptions {
    pub verify: bool,
    pub max_file_bytes: u64,
    pub cancelled: Option<Arc<AtomicBool>>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            verify: false,
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            cancelled: None,
        }
    }
}

#[derive(Debug)]
struct SourceFile {
    absolute: PathBuf,
    relative: String,
    language: Language,
    modified_ns: i64,
    length: u64,
}

pub fn scan_project(root: &Path, options: ScanOptions) -> Result<crate::model::ProjectSummary> {
    let mut store = Store::open(root)?;
    let sources = discover_source_files(store.root())?;
    let existing = store.existing_files()?;
    let mut seen = HashSet::new();
    let mut parsed_count = 0usize;
    let mut skipped_count = 0usize;
    let mut cancelled = false;

    for source in &sources {
        if is_cancelled(&options) {
            cancelled = true;
            break;
        }
        seen.insert(source.relative.clone());
        if source.length > options.max_file_bytes {
            let parsed = ParsedFile {
                diagnostic: Some(format!(
                    "Skipped {} because it exceeds the configured {} byte limit.",
                    source.relative, options.max_file_bytes
                )),
                ..Default::default()
            };
            store.replace_file(
                &source.relative,
                "oversized",
                source.modified_ns,
                source.language.label(),
                &parsed,
            )?;
            parsed_count += 1;
            continue;
        }
        let unchanged = existing
            .get(&source.relative)
            .filter(|record| record.modified_ns == source.modified_ns);
        if unchanged.is_some() && !options.verify {
            skipped_count += 1;
            continue;
        }
        let content = fs::read(&source.absolute)
            .with_context(|| format!("could not read {}", source.absolute.display()))?;
        let hash = hex::encode(Sha256::digest(&content));
        if unchanged.is_some_and(|record| record.hash == hash) {
            skipped_count += 1;
            continue;
        }
        let parsed = parse_source(&content, source.language, &source.relative);
        store.replace_file(
            &source.relative,
            &hash,
            source.modified_ns,
            source.language.label(),
            &parsed,
        )?;
        parsed_count += 1;
    }

    if !cancelled {
        for (path, record) in existing {
            if !seen.contains(&path) {
                store.delete_file(record.id)?;
            }
        }
    }
    let relationships = store.rebuild_edges()?;
    store.touch()?;
    store.summary(
        sources.len(),
        parsed_count,
        skipped_count,
        relationships,
        cancelled,
    )
}

pub fn impact(root: &Path, target: &str, depth: u32) -> Result<QueryResult> {
    run_query(root, target, depth, true)
}

pub fn dependencies(root: &Path, target: &str, depth: u32) -> Result<QueryResult> {
    run_query(root, target, depth, false)
}

fn run_query(root: &Path, target: &str, depth: u32, reverse: bool) -> Result<QueryResult> {
    let store = Store::open(root)?;
    let target_records = store.find_symbols(target)?;
    let mode = if reverse { "impact" } else { "dependencies" }.to_owned();
    if target_records.is_empty() {
        return Ok(QueryResult { mode, target: target.to_owned(), results: vec![], candidates: vec![], complete: true, visited: 0, message: Some("No indexed symbol or file matches this target. Run `graphxploit scan` first or use a fully qualified name.".to_owned()) });
    }
    if target_records.len() > 1 {
        return Ok(QueryResult {
            mode,
            target: target.to_owned(),
            results: vec![],
            candidates: Store::candidates(&target_records),
            complete: true,
            visited: 0,
            message: Some("More than one symbol matches this name.".to_owned()),
        });
    }
    let symbols = store.symbols()?;
    let by_id: HashMap<i64, &SymbolRecord> =
        symbols.iter().map(|symbol| (symbol.id, symbol)).collect();
    let selected = &target_records[0];
    let mut seed_ids = vec![selected.id];
    if selected.kind == "File" {
        seed_ids.extend(store.file_members(selected.file_id)?);
    }
    let mut queue = VecDeque::new();
    let mut visited = HashSet::new();
    for seed in seed_ids {
        if visited.insert(seed) {
            queue.push_back((seed, 0u32, vec![seed]));
        }
    }
    let mut results = Vec::new();
    let mut complete = true;
    while let Some((current, current_depth, route)) = queue.pop_front() {
        if current_depth >= depth {
            continue;
        }
        if visited.len() >= MAX_VISITED_NODES || results.len() >= MAX_RETURNED_NODES {
            complete = false;
            break;
        }
        for edge in store.neighbors(current, reverse)? {
            let next = if reverse {
                edge.source_id
            } else {
                edge.target_id
            };
            if !visited.insert(next) {
                continue;
            }
            let Some(symbol) = by_id.get(&next) else {
                continue;
            };
            let next_route = if reverse {
                let mut value = vec![next];
                value.extend(route.iter().copied());
                value
            } else {
                let mut value = route.clone();
                value.push(next);
                value
            };
            let evidence_path = next_route
                .iter()
                .filter_map(|id| by_id.get(id).map(|s| s.qualified_name.clone()))
                .collect();
            results.push(ImpactNode {
                qualified_name: symbol.qualified_name.clone(),
                name: symbol.name.clone(),
                kind: symbol.kind.clone(),
                path: symbol.path.clone(),
                line: symbol.line,
                depth: current_depth + 1,
                evidence_path,
            });
            queue.push_back((next, current_depth + 1, next_route));
        }
    }
    let message = if results.is_empty() {
        Some("No indexed dependency path was found. Dynamic calls, reflection, generated code, and ambiguous names are intentionally reported as unresolved rather than guessed.".to_owned())
    } else {
        None
    };
    Ok(QueryResult {
        mode,
        target: selected.qualified_name.clone(),
        results,
        candidates: vec![],
        complete,
        visited: visited.len(),
        message,
    })
}

pub fn source_excerpt(
    root: &Path,
    relative_path: &str,
    start_line: usize,
    end_line: usize,
) -> Result<String> {
    let root = root.canonicalize()?;
    let candidate = root.join(relative_path).canonicalize()?;
    if !candidate.starts_with(&root) {
        anyhow::bail!("source path is outside the selected project");
    }
    let text = fs::read_to_string(candidate)?;
    Ok(text
        .lines()
        .enumerate()
        .filter(|(index, _)| *index >= start_line.saturating_sub(1) && *index < end_line)
        .map(|(index, line)| format!("{:>5}  {line}", index + 1))
        .collect::<Vec<_>>()
        .join("\n"))
}

fn is_cancelled(options: &ScanOptions) -> bool {
    options
        .cancelled
        .as_ref()
        .is_some_and(|value| value.load(Ordering::Relaxed))
}

fn discover_source_files(root: &Path) -> Result<Vec<SourceFile>> {
    let ignores = read_ignore_rules(root);
    let mut result = Vec::new();
    visit_directory(root, root, &ignores, &mut result)?;
    result.sort_by(|a, b| a.relative.cmp(&b.relative));
    Ok(result)
}

fn visit_directory(
    root: &Path,
    directory: &Path,
    ignores: &[String],
    result: &mut Vec<SourceFile>,
) -> Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        let relative_path = path
            .strip_prefix(root)?
            .to_string_lossy()
            .replace('\\', "/");
        let file_type = entry.file_type()?;
        if file_type.is_symlink() || ignored(&name, &relative_path, ignores) {
            continue;
        }
        if file_type.is_dir() {
            if should_skip_directory(&name) {
                continue;
            }
            visit_directory(root, &path, ignores, result)?;
        } else if file_type.is_file() {
            let Some(language) = language_for_path(&path) else {
                continue;
            };
            let metadata = entry.metadata()?;
            let modified_ns = metadata
                .modified()
                .ok()
                .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
                .map(|duration| duration.as_nanos().min(i64::MAX as u128) as i64)
                .unwrap_or(0);
            result.push(SourceFile {
                absolute: path,
                relative: relative_path,
                language,
                modified_ns,
                length: metadata.len(),
            });
        }
    }
    Ok(())
}

fn should_skip_directory(name: &str) -> bool {
    matches!(
        name,
        ".git"
            | ".hg"
            | ".svn"
            | "node_modules"
            | "target"
            | "dist"
            | "build"
            | "vendor"
            | ".venv"
            | "venv"
            | "__pycache__"
            | ".graphxploit"
    ) || name.starts_with('.')
}

fn read_ignore_rules(root: &Path) -> Vec<String> {
    let mut rules = vec!["*.min.js".to_owned()];
    for filename in [".gitignore", ".graphxploitignore"] {
        if let Ok(text) = fs::read_to_string(root.join(filename)) {
            rules.extend(
                text.lines()
                    .map(str::trim)
                    .filter(|line| {
                        !line.is_empty() && !line.starts_with('#') && !line.starts_with('!')
                    })
                    .map(ToOwned::to_owned),
            );
        }
    }
    rules
}

fn ignored(name: &str, relative: &str, rules: &[String]) -> bool {
    rules.iter().any(|rule| {
        let rule = rule.trim_end_matches('/');
        if let Some(suffix) = rule.strip_prefix('*') {
            name.ends_with(suffix)
        } else {
            relative == rule || relative.starts_with(&format!("{rule}/")) || name == rule
        }
    })
}

fn language_for_path(path: &Path) -> Option<Language> {
    match path
        .extension()?
        .to_string_lossy()
        .to_ascii_lowercase()
        .as_str()
    {
        "py" => Some(Language::Python),
        "js" | "jsx" | "mjs" | "cjs" => Some(Language::JavaScript),
        "ts" | "tsx" => Some(Language::TypeScript),
        "go" => Some(Language::Go),
        "rs" => Some(Language::Rust),
        "java" => Some(Language::Java),
        _ => None,
    }
}

fn parse_source(source: &[u8], language: Language, relative_path: &str) -> ParsedFile {
    let mut parser = Parser::new();
    let ts_language = grammar(language);
    if parser.set_language(&ts_language).is_err() {
        return ParsedFile {
            diagnostic: Some(format!("Could not initialize {} parser.", language.label())),
            ..Default::default()
        };
    }
    let Some(tree) = parser.parse(source, None) else {
        return ParsedFile {
            diagnostic: Some("Parser did not return a syntax tree.".to_owned()),
            ..Default::default()
        };
    };
    let mut result = ParsedFile::default();
    if tree.root_node().has_error() {
        result.diagnostic = Some(
            "Syntax errors were found; symbols from valid parts of this file may still be indexed."
                .to_owned(),
        );
    }
    walk(
        tree.root_node(),
        source,
        language,
        relative_path,
        &mut Vec::new(),
        &mut result,
    );
    result
}

fn grammar(language: Language) -> TsLanguage {
    match language {
        Language::Python => tree_sitter_python::LANGUAGE.into(),
        Language::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
        Language::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        Language::Go => tree_sitter_go::LANGUAGE.into(),
        Language::Rust => tree_sitter_rust::LANGUAGE.into(),
        Language::Java => tree_sitter_java::LANGUAGE.into(),
    }
}

fn walk(
    node: Node<'_>,
    source: &[u8],
    language: Language,
    relative_path: &str,
    scopes: &mut Vec<String>,
    parsed: &mut ParsedFile,
) {
    if is_import(node.kind(), language) {
        parsed.imports.push((
            node_text(node, source),
            node.start_position().row as u32 + 1,
        ));
    }
    if let Some((kind, name)) = declaration(node, source, language) {
        let local_qualified = if scopes.is_empty() {
            name.clone()
        } else {
            format!("{}.{}", scopes.join("."), name)
        };
        let qualified_name = format!("{relative_path}::{local_qualified}");
        parsed.symbols.push(ParsedSymbol {
            name: name.clone(),
            qualified_name,
            kind,
            start_line: node.start_position().row as u32 + 1,
            end_line: node.end_position().row as u32 + 1,
        });
        scopes.push(name);
        walk_children(node, source, language, relative_path, scopes, parsed);
        scopes.pop();
        return;
    }
    if is_call(node.kind(), language) && !scopes.is_empty() {
        let raw_target = call_target(node, source);
        if !raw_target.is_empty() {
            let qualified = format!("{relative_path}::{}", scopes.join("."));
            parsed.references.push(ParsedReference {
                source_qualified_name: qualified,
                raw_target,
                line: node.start_position().row as u32 + 1,
            });
        }
    }
    walk_children(node, source, language, relative_path, scopes, parsed);
}

fn walk_children(
    node: Node<'_>,
    source: &[u8],
    language: Language,
    relative_path: &str,
    scopes: &mut Vec<String>,
    parsed: &mut ParsedFile,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk(child, source, language, relative_path, scopes, parsed);
    }
}

fn declaration(node: Node<'_>, source: &[u8], language: Language) -> Option<(String, String)> {
    let kind = node.kind();
    let mapped = match language {
        Language::Python => match kind {
            "function_definition" => "Function",
            "class_definition" => "Class",
            _ => return None,
        },
        Language::JavaScript | Language::TypeScript => match kind {
            "function_declaration" | "generator_function_declaration" | "method_definition" => {
                "Function"
            }
            "class_declaration" => "Class",
            "interface_declaration" => "Interface",
            _ => return None,
        },
        Language::Go => match kind {
            "function_declaration" | "method_declaration" => "Function",
            "type_declaration" => "Type",
            _ => return None,
        },
        Language::Rust => match kind {
            "function_item" => "Function",
            "struct_item" => "Struct",
            "enum_item" => "Enum",
            "trait_item" => "Trait",
            "impl_item" => "Impl",
            _ => return None,
        },
        Language::Java => match kind {
            "method_declaration" | "constructor_declaration" => "Function",
            "class_declaration" => "Class",
            "interface_declaration" => "Interface",
            "enum_declaration" => "Enum",
            _ => return None,
        },
    };
    let name_node = node
        .child_by_field_name("name")
        .or_else(|| first_identifier(node));
    let name = name_node
        .map(|value| node_text(value, source))
        .filter(|value| !value.is_empty())?;
    Some((mapped.to_owned(), name))
}

fn first_identifier(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    let value = node.children(&mut cursor).find(|child| {
        matches!(
            child.kind(),
            "identifier" | "type_identifier" | "field_identifier"
        )
    });
    value
}

fn is_call(kind: &str, _language: Language) -> bool {
    matches!(
        kind,
        "call"
            | "call_expression"
            | "method_invocation"
            | "macro_invocation"
            | "object_creation_expression"
            | "new_expression"
    )
}

fn is_import(kind: &str, _language: Language) -> bool {
    matches!(
        kind,
        "import_statement"
            | "import_from_statement"
            | "import_declaration"
            | "use_declaration"
            | "import_spec_list"
    )
}

fn call_target(node: Node<'_>, source: &[u8]) -> String {
    let target = node
        .child_by_field_name("function")
        .or_else(|| node.child_by_field_name("name"));
    let text = target
        .map(|value| node_text(value, source))
        .unwrap_or_else(|| node_text(node, source));
    text.split('(').next().unwrap_or_default().trim().to_owned()
}

fn node_text(node: Node<'_>, source: &[u8]) -> String {
    node.utf8_text(source).unwrap_or_default().trim().to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn creates_reverse_impact_paths_for_python() {
        let temp = tempdir().unwrap();
        fs::write(
            temp.path().join("app.py"),
            "def target():\n    return 1\n\ndef caller():\n    return target()\n",
        )
        .unwrap();
        scan_project(temp.path(), ScanOptions::default()).unwrap();
        let result = impact(temp.path(), "target", 5).unwrap();
        assert!(result
            .results
            .iter()
            .any(|node| node.qualified_name.ends_with("::caller")));
    }

    #[test]
    fn skips_unchanged_files_on_second_scan() {
        let temp = tempdir().unwrap();
        fs::write(temp.path().join("main.rs"), "fn hello() {}\n").unwrap();
        scan_project(temp.path(), ScanOptions::default()).unwrap();
        let second = scan_project(temp.path(), ScanOptions::default()).unwrap();
        assert_eq!(second.files_parsed, 0);
        assert_eq!(second.files_skipped, 1);
    }
    #[test]
    fn indexes_direct_calls_in_all_supported_languages() {
        let temp = tempdir().unwrap();
        let files = [
            (
                "web.js",
                "function jsTarget() {}\nfunction jsCaller() { jsTarget(); }\n",
                "jsTarget",
                "jsCaller",
            ),
            (
                "typed.ts",
                "function tsTarget() {}\nfunction tsCaller() { tsTarget(); }\n",
                "tsTarget",
                "tsCaller",
            ),
            (
                "main.go",
                "package main\nfunc goTarget() {}\nfunc goCaller() { goTarget() }\n",
                "goTarget",
                "goCaller",
            ),
            (
                "lib.rs",
                "fn rust_target() {}\nfn rust_caller() { rust_target(); }\n",
                "rust_target",
                "rust_caller",
            ),
            (
                "Demo.java",
                "class Demo { void javaTarget() {} void javaCaller() { javaTarget(); } }\n",
                "javaTarget",
                "javaCaller",
            ),
        ];
        for (name, source, _, _) in files {
            fs::write(temp.path().join(name), source).unwrap();
        }
        scan_project(temp.path(), ScanOptions::default()).unwrap();
        for (_, _, target, caller) in files {
            let result = impact(temp.path(), target, 5).unwrap();
            assert!(
                result
                    .results
                    .iter()
                    .any(|node| node.qualified_name.ends_with(caller)),
                "missing {caller}"
            );
        }
    }
}
