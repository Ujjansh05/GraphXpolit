use crate::model::{
    ContextEvidence, ContextPreview, GraphEdge, GraphNode, GraphResult, ImpactNode, Language,
    ParsedFile, ParsedReference, ParsedSymbol, QueryResult, SearchResult,
};
use crate::store::Store;
use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::{self, File};
use std::io::Read;
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
const MAX_QUERY_DEPTH: u32 = 25;
const MAX_SOURCE_EXCERPT_LINES: usize = 200;
const MAX_SOURCE_EXCERPT_BYTES: u64 = 256 * 1024;
const MAX_DISCOVERED_FILES: usize = 100_000;
const MAX_IGNORE_FILE_BYTES: u64 = 1024 * 1024;
const MAX_TARGET_BYTES: usize = 4096;
const MAX_CONTEXT_EVIDENCE: usize = 12;
const DEFAULT_CONTEXT_TOKENS: usize = 4_000;
const MAX_CONTEXT_TOKENS: usize = 8_000;
const MAX_GRAPH_NODES: usize = 300;

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
    let sources = discover_source_files(store.root(), &options)?;
    let existing = store.existing_files()?;
    store.begin_scan()?;
    let mut seen = HashSet::new();
    let mut parsed_count = 0usize;
    let mut skipped_count = 0usize;
    let mut cancelled = is_cancelled(&options);

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
        let mut content = Vec::with_capacity(source.length.min(options.max_file_bytes) as usize);
        File::open(&source.absolute)
            .with_context(|| format!("could not open {}", source.absolute.display()))?
            .take(options.max_file_bytes + 1)
            .read_to_end(&mut content)
            .with_context(|| format!("could not read {}", source.absolute.display()))?;
        if content.len() as u64 > options.max_file_bytes {
            let parsed = ParsedFile {
                diagnostic: Some(format!(
                    "Skipped {} because it grew beyond the configured {} byte limit.",
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
    let relationships = if cancelled {
        store.rollback_scan()?;
        store.count("edges")?
    } else {
        match store.rebuild_edges(options.cancelled.as_deref())? {
            Some(count) => {
                store.commit_scan()?;
                count
            }
            None => {
                cancelled = true;
                store.rollback_scan()?;
                store.count("edges")?
            }
        }
    };
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
    let target = target.trim();
    if target.is_empty() || target.len() > MAX_TARGET_BYTES {
        anyhow::bail!("target must contain between 1 and {MAX_TARGET_BYTES} bytes");
    }
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
    let requested_depth = depth;
    let depth = depth.min(MAX_QUERY_DEPTH);
    let selected = target_records[0].clone();
    let mut seed_ids = vec![selected.id];
    let mut complete = requested_depth <= MAX_QUERY_DEPTH;
    if selected.kind == "File" {
        let members = store.file_members(selected.file_id, MAX_RETURNED_NODES + 1)?;
        if members.len() > MAX_RETURNED_NODES {
            complete = false;
        }
        seed_ids.extend(members.into_iter().take(MAX_RETURNED_NODES));
    }
    let mut known = HashMap::new();
    known.insert(selected.id, selected.clone());
    let mut queue = VecDeque::new();
    let mut visited = HashSet::new();
    for seed in seed_ids {
        if visited.insert(seed) {
            if let std::collections::hash_map::Entry::Vacant(entry) = known.entry(seed) {
                if let Some(symbol) = store.symbol(seed)? {
                    entry.insert(symbol);
                }
            }
            queue.push_back((seed, 0u32, vec![seed]));
        }
    }
    let mut results = Vec::new();
    'search: while let Some((current, current_depth, route)) = queue.pop_front() {
        if current_depth >= depth {
            continue;
        }
        if visited.len() >= MAX_VISITED_NODES || results.len() >= MAX_RETURNED_NODES {
            complete = false;
            break;
        }
        let edges = store.neighbors(current, reverse, MAX_RETURNED_NODES + 1)?;
        if edges.len() > MAX_RETURNED_NODES {
            complete = false;
        }
        for edge in edges {
            if visited.len() >= MAX_VISITED_NODES || results.len() >= MAX_RETURNED_NODES {
                complete = false;
                break 'search;
            }
            let next = if reverse {
                edge.source_id
            } else {
                edge.target_id
            };
            if !visited.insert(next) {
                continue;
            }
            let Some(symbol) = store.symbol(next)? else {
                continue;
            };
            known.insert(next, symbol.clone());
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
                .filter_map(|id| known.get(id).map(|s| s.qualified_name.clone()))
                .collect();
            results.push(ImpactNode {
                qualified_name: symbol.qualified_name.clone(),
                name: symbol.name.clone(),
                kind: symbol.kind.clone(),
                path: symbol.path.clone(),
                line: symbol.line,
                depth: current_depth + 1,
                relationship: edge.kind,
                evidence_path,
            });
            queue.push_back((next, current_depth + 1, next_route));
        }
    }
    let message = if !complete {
        Some(format!("The result was safely truncated at {MAX_RETURNED_NODES} nodes, {MAX_VISITED_NODES} visited nodes, or depth {MAX_QUERY_DEPTH}. Narrow the target or depth for a complete result."))
    } else if results.is_empty() {
        Some("No indexed dependency path was found. Dynamic calls, reflection, generated code, and ambiguous names are intentionally reported as unresolved rather than guessed.".to_owned())
    } else {
        None
    };
    Ok(QueryResult {
        mode,
        target: selected.qualified_name,
        results,
        candidates: vec![],
        complete,
        visited: visited.len(),
        message,
    })
}

pub fn search(root: &Path, query: &str, limit: usize) -> Result<SearchResult> {
    let query = query.trim();
    if query.is_empty() || query.len() > MAX_TARGET_BYTES {
        anyhow::bail!("search query must contain between 1 and {MAX_TARGET_BYTES} bytes");
    }
    let limit = limit.clamp(1, 100);
    let store = Store::open(root)?;
    let (records, complete) = store.search_symbols(query, limit)?;
    Ok(SearchResult {
        items: Store::candidates(&records),
        complete,
    })
}

pub fn graph(root: &Path, target: &str, depth: u32, reverse: bool) -> Result<GraphResult> {
    let query = run_query(root, target, depth, reverse)?;
    if !query.candidates.is_empty() {
        return Ok(GraphResult {
            target: query.target,
            nodes: vec![],
            edges: vec![],
            complete: true,
            message: query.message,
        });
    }
    let store = Store::open(root)?;
    let selected = store.find_symbols(&query.target)?.into_iter().next();
    let mut nodes = Vec::new();
    if let Some(symbol) = selected {
        nodes.push(GraphNode {
            id: symbol.qualified_name.clone(),
            label: symbol.name,
            kind: symbol.kind,
            path: symbol.path,
            line: symbol.line,
            depth: 0,
            selected: true,
        });
    }
    let mut seen = nodes
        .iter()
        .map(|node| node.id.clone())
        .collect::<HashSet<_>>();
    for item in query
        .results
        .iter()
        .take(MAX_GRAPH_NODES.saturating_sub(nodes.len()))
    {
        if seen.insert(item.qualified_name.clone()) {
            nodes.push(GraphNode {
                id: item.qualified_name.clone(),
                label: item.name.clone(),
                kind: item.kind.clone(),
                path: item.path.clone(),
                line: item.line,
                depth: item.depth,
                selected: false,
            });
        }
    }
    let node_ids = nodes
        .iter()
        .map(|node| node.id.as_str())
        .collect::<HashSet<_>>();
    let mut edge_keys = HashSet::new();
    let mut edges = Vec::new();
    for item in &query.results {
        for pair in item.evidence_path.windows(2) {
            if node_ids.contains(pair[0].as_str()) && node_ids.contains(pair[1].as_str()) {
                let key = (pair[0].clone(), pair[1].clone());
                if edge_keys.insert(key.clone()) {
                    edges.push(GraphEdge {
                        source: key.0,
                        target: key.1,
                        kind: item.relationship.clone(),
                    });
                }
            }
        }
    }
    Ok(GraphResult {
        target: query.target,
        nodes,
        edges,
        complete: query.complete && query.results.len() <= MAX_GRAPH_NODES,
        message: query.message,
    })
}

pub fn context_preview(
    root: &Path,
    question: &str,
    target: Option<&str>,
    include_source: bool,
    budget_tokens: Option<usize>,
    model_endpoint: Option<String>,
) -> Result<ContextPreview> {
    let question = question.trim();
    if question.is_empty() || question.len() > MAX_TARGET_BYTES {
        anyhow::bail!("question must contain between 1 and {MAX_TARGET_BYTES} bytes");
    }
    let budget_tokens = budget_tokens
        .unwrap_or(DEFAULT_CONTEXT_TOKENS)
        .clamp(1_000, MAX_CONTEXT_TOKENS);
    let store = Store::open(root)?;
    let mut records = Vec::new();
    let mut seen = HashSet::new();
    let mut selection_complete = true;
    if let Some(target) = target.map(str::trim).filter(|value| !value.is_empty()) {
        let target_records = store.find_symbols(target)?;
        if target_records.len() > 4 {
            selection_complete = false;
        }
        for record in target_records.into_iter().take(4) {
            let selected_id = record.id;
            if seen.insert(selected_id) {
                records.push((record, "selected target".to_owned()));
            }
            for reverse in [false, true] {
                let adjacent = store.neighbors(selected_id, reverse, 5)?;
                if adjacent.len() > 4 {
                    selection_complete = false;
                }
                for edge in adjacent.into_iter().take(4) {
                    let adjacent_id = if reverse {
                        edge.source_id
                    } else {
                        edge.target_id
                    };
                    if !seen.insert(adjacent_id) {
                        continue;
                    }
                    if let Some(symbol) = store.symbol(adjacent_id)? {
                        let direction = if reverse { "dependant" } else { "dependency" };
                        records.push((
                            symbol,
                            format!(
                                "direct {} {direction} of selected target",
                                edge.kind.to_ascii_lowercase()
                            ),
                        ));
                    }
                    if records.len() >= MAX_CONTEXT_EVIDENCE {
                        selection_complete = false;
                        break;
                    }
                }
                if records.len() >= MAX_CONTEXT_EVIDENCE {
                    break;
                }
            }
            if records.len() >= MAX_CONTEXT_EVIDENCE {
                break;
            }
        }
    }
    for term in context_terms(question) {
        let (matches, search_complete) = store.search_symbols(&term, 4)?;
        selection_complete &= search_complete;
        for record in matches {
            if record.kind != "File" && seen.insert(record.id) {
                records.push((record, format!("matched question term '{term}'")));
            }
            if records.len() >= MAX_CONTEXT_EVIDENCE {
                selection_complete = false;
                break;
            }
        }
        if records.len() >= MAX_CONTEXT_EVIDENCE {
            break;
        }
    }
    let mut estimated_tokens = estimate_tokens(question) + 120;
    let mut complete = selection_complete;
    let mut evidence = Vec::new();
    for (index, (record, relationship)) in records.into_iter().enumerate() {
        let metadata_tokens =
            24 + estimate_tokens(&record.qualified_name) + estimate_tokens(&record.path);
        if estimated_tokens + metadata_tokens >= budget_tokens {
            complete = false;
            break;
        }
        let mut source = None;
        let mut item_tokens = metadata_tokens;
        if include_source {
            let end_line = record
                .end_line
                .saturating_add(1)
                .min(record.line.saturating_add(80));
            if let Ok(mut excerpt) =
                source_excerpt(root, &record.path, record.line as usize, end_line as usize)
            {
                let available = budget_tokens.saturating_sub(estimated_tokens + metadata_tokens);
                let max_chars = available.saturating_mul(4).min(4_000);
                if excerpt.len() > max_chars {
                    const MARKER: &str = "
… excerpt truncated …";
                    excerpt = truncate_utf8(&excerpt, max_chars.saturating_sub(MARKER.len()));
                    if max_chars >= MARKER.len() {
                        excerpt.push_str(MARKER);
                    }
                    complete = false;
                }
                item_tokens += estimate_tokens(&excerpt);
                source = Some(excerpt);
            }
        }
        estimated_tokens += item_tokens;
        evidence.push(ContextEvidence {
            id: format!("E{}", index + 1),
            qualified_name: record.qualified_name,
            kind: record.kind,
            path: record.path,
            start_line: record.line,
            end_line: record.end_line,
            relationship,
            source,
            estimated_tokens: item_tokens,
        });
    }
    let revision = format!("index:{}", store.generation()?);
    let target = target
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let fingerprint =
        serde_json::to_vec(&(question, &target, &revision, &evidence, &model_endpoint))?;
    let digest = Sha256::digest(&fingerprint);
    Ok(ContextPreview {
        preview_id: hex::encode(&digest[..16]),
        question: question.to_owned(),
        target,
        revision,
        evidence,
        estimated_tokens,
        budget_tokens,
        complete,
        model_endpoint,
    })
}

fn context_terms(question: &str) -> Vec<String> {
    const STOP: &[&str] = &[
        "what", "where", "which", "when", "does", "this", "that", "with", "from", "into", "code",
        "function", "class", "explain", "show", "find", "could", "would", "about",
    ];
    let mut terms = question
        .split(|character: char| {
            !character.is_alphanumeric() && character != '_' && character != '/' && character != '.'
        })
        .map(|term| term.trim_matches(['/', '.']).to_ascii_lowercase())
        .filter(|term| term.len() >= 3 && !STOP.contains(&term.as_str()))
        .collect::<Vec<_>>();
    terms.sort();
    terms.dedup();
    terms.sort_by_key(|term| std::cmp::Reverse(term.len()));
    terms.truncate(8);
    terms
}

fn estimate_tokens(value: &str) -> usize {
    value.chars().count().div_ceil(4)
}

fn truncate_utf8(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_owned();
    }
    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}
pub fn source_excerpt(
    root: &Path,
    relative_path: &str,
    start_line: usize,
    end_line: usize,
) -> Result<String> {
    if start_line == 0 || end_line < start_line {
        anyhow::bail!("source line range is invalid");
    }
    if end_line.saturating_sub(start_line) > MAX_SOURCE_EXCERPT_LINES {
        anyhow::bail!("source excerpt is limited to {MAX_SOURCE_EXCERPT_LINES} lines");
    }
    let root = root.canonicalize()?;
    let candidate = root.join(relative_path).canonicalize()?;
    if !candidate.starts_with(&root) || !candidate.is_file() {
        anyhow::bail!("source path is outside the selected project or is not a file");
    }
    let metadata = candidate.metadata()?;
    if metadata.len() > DEFAULT_MAX_FILE_BYTES {
        anyhow::bail!("source file exceeds the safe preview size");
    }
    let mut text = String::new();
    File::open(candidate)?
        .take(DEFAULT_MAX_FILE_BYTES + 1)
        .read_to_string(&mut text)?;
    let excerpt = text
        .lines()
        .enumerate()
        .filter(|(index, _)| *index >= start_line - 1 && *index < end_line)
        .map(|(index, line)| format!("{:>5}  {line}", index + 1))
        .collect::<Vec<_>>()
        .join("\n");
    if excerpt.len() as u64 > MAX_SOURCE_EXCERPT_BYTES {
        anyhow::bail!("source excerpt exceeds the safe response size");
    }
    Ok(excerpt)
}
fn is_cancelled(options: &ScanOptions) -> bool {
    options
        .cancelled
        .as_ref()
        .is_some_and(|value| value.load(Ordering::Relaxed))
}

fn discover_source_files(root: &Path, options: &ScanOptions) -> Result<Vec<SourceFile>> {
    let ignores = read_ignore_rules(root);
    let mut result = Vec::new();
    visit_directory(root, root, &ignores, options, &mut result)?;
    result.sort_by(|a, b| a.relative.cmp(&b.relative));
    Ok(result)
}

fn visit_directory(
    root: &Path,
    directory: &Path,
    ignores: &[String],
    options: &ScanOptions,
    result: &mut Vec<SourceFile>,
) -> Result<()> {
    for entry in fs::read_dir(directory)? {
        if is_cancelled(options) {
            return Ok(());
        }
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
            visit_directory(root, &path, ignores, options, result)?;
        } else if file_type.is_file() {
            let Some(language) = language_for_path(&path) else {
                continue;
            };
            if result.len() >= MAX_DISCOVERED_FILES {
                anyhow::bail!(
                    "project exceeds the {MAX_DISCOVERED_FILES} source-file safety limit; add dependency or generated directories to .graphxploitignore"
                );
            }
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
        let path = root.join(filename);
        let mut bytes = Vec::new();
        let readable = File::open(path)
            .and_then(|file| file.take(MAX_IGNORE_FILE_BYTES + 1).read_to_end(&mut bytes))
            .is_ok();
        if !readable || bytes.len() as u64 > MAX_IGNORE_FILE_BYTES {
            continue;
        }
        if let Ok(text) = String::from_utf8(bytes) {
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
        "ts" => Some(Language::TypeScript),
        "tsx" => Some(Language::Tsx),
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
        Language::Tsx => tree_sitter_typescript::LANGUAGE_TSX.into(),
        Language::Go => tree_sitter_go::LANGUAGE.into(),
        Language::Rust => tree_sitter_rust::LANGUAGE.into(),
        Language::Java => tree_sitter_java::LANGUAGE.into(),
    }
}

#[derive(Clone)]
struct Scope {
    name: String,
    qualified_name: String,
}

fn walk(
    node: Node<'_>,
    source: &[u8],
    language: Language,
    relative_path: &str,
    scopes: &mut Vec<Scope>,
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
            format!(
                "{}.{}",
                scopes
                    .iter()
                    .map(|scope| scope.name.as_str())
                    .collect::<Vec<_>>()
                    .join("."),
                name
            )
        };
        let base_qualified = format!("{relative_path}::{local_qualified}");
        let qualified_name = if parsed
            .symbols
            .iter()
            .any(|symbol| symbol.qualified_name == base_qualified)
        {
            format!(
                "{base_qualified}@{}:{}",
                node.start_position().row + 1,
                node.start_position().column + 1
            )
        } else {
            base_qualified
        };
        parsed.symbols.push(ParsedSymbol {
            name: name.clone(),
            qualified_name: qualified_name.clone(),
            kind,
            start_line: node.start_position().row as u32 + 1,
            end_line: node.end_position().row as u32 + 1,
        });
        scopes.push(Scope {
            name,
            qualified_name,
        });
        walk_children(node, source, language, relative_path, scopes, parsed);
        scopes.pop();
        return;
    }
    if is_call(node.kind(), language) {
        if let Some(scope) = scopes.last() {
            let raw_target = call_target(node, source);
            if !raw_target.is_empty() {
                parsed.references.push(ParsedReference {
                    source_qualified_name: scope.qualified_name.clone(),
                    raw_target,
                    line: node.start_position().row as u32 + 1,
                });
            }
        }
    }
    walk_children(node, source, language, relative_path, scopes, parsed);
}

fn walk_children(
    node: Node<'_>,
    source: &[u8],
    language: Language,
    relative_path: &str,
    scopes: &mut Vec<Scope>,
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
        Language::JavaScript | Language::TypeScript | Language::Tsx => match kind {
            "function_declaration" | "generator_function_declaration" | "method_definition" => {
                "Function"
            }
            "class_declaration" => "Class",
            "interface_declaration" => "Interface",
            "variable_declarator"
                if node.child_by_field_name("value").is_some_and(|value| {
                    matches!(value.kind(), "arrow_function" | "function_expression")
                }) =>
            {
                "Function"
            }
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
            "variable_declarator"
                if node.child_by_field_name("value").is_some_and(|value| {
                    matches!(value.kind(), "arrow_function" | "function_expression")
                }) =>
            {
                "Function"
            }
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

    #[test]
    fn caps_large_query_results_exactly() {
        let temp = tempdir().unwrap();
        let mut source = "def target():\n    return 1\n\n".to_owned();
        for index in 0..600 {
            source.push_str(&format!("def caller_{index}():\n    return target()\n\n"));
        }
        fs::write(temp.path().join("large.py"), source).unwrap();
        scan_project(temp.path(), ScanOptions::default()).unwrap();
        let result = impact(temp.path(), "target", 5).unwrap();
        assert_eq!(result.results.len(), MAX_RETURNED_NODES);
        assert!(!result.complete);
    }

    #[test]
    fn enforces_source_preview_boundaries() {
        let temp = tempdir().unwrap();
        fs::write(temp.path().join("small.rs"), "fn main() {}\n").unwrap();
        assert!(source_excerpt(temp.path(), "small.rs", 0, 1).is_err());
        assert!(source_excerpt(temp.path(), "small.rs", 1, 202).is_err());
        fs::write(
            temp.path().join("large.rs"),
            vec![b'a'; DEFAULT_MAX_FILE_BYTES as usize + 1],
        )
        .unwrap();
        assert!(source_excerpt(temp.path(), "large.rs", 1, 2).is_err());
        let outside = tempfile::NamedTempFile::new().unwrap();
        assert!(
            source_excerpt(temp.path(), outside.path().to_string_lossy().as_ref(), 1, 2).is_err()
        );
    }

    #[test]
    fn indexes_tsx_arrow_function_calls() {
        let temp = tempdir().unwrap();
        fs::write(
            temp.path().join("widget.tsx"),
            "const target = () => 1;\nexport const caller = () => target();\n",
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
    fn search_graph_and_context_stay_bounded() {
        let temp = tempdir().unwrap();
        fs::write(
            temp.path().join("service.py"),
            "def authenticate(user):\n    return user is not None\n\ndef login(user):\n    return authenticate(user)\n",
        )
        .unwrap();
        scan_project(temp.path(), ScanOptions::default()).unwrap();

        let matches = search(temp.path(), "auth", 10).unwrap();
        assert!(matches
            .items
            .iter()
            .any(|item| item.qualified_name.ends_with("::authenticate")));

        let result = graph(temp.path(), "authenticate", 3, true).unwrap();
        assert!(result.nodes.iter().any(|node| node.selected));
        assert!(result.nodes.iter().any(|node| node.id.ends_with("::login")));

        let preview = context_preview(
            temp.path(),
            "How does authenticate affect login?",
            Some("authenticate"),
            true,
            Some(1_000),
            None,
        )
        .unwrap();
        assert!(!preview.evidence.is_empty());
        assert!(preview.estimated_tokens <= preview.budget_tokens);
        assert!(preview.evidence.iter().any(|item| item.source.is_some()));
        assert!(preview
            .evidence
            .iter()
            .any(|item| item.qualified_name.ends_with("::login")));
    }

    #[test]
    fn cancelled_scan_preserves_previous_generation() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("app.py");
        fs::write(&path, "def stable():\n    return 1\n").unwrap();
        let initial = scan_project(temp.path(), ScanOptions::default()).unwrap();
        fs::write(&path, "def replacement():\n    return 2\n").unwrap();

        let cancelled = Arc::new(AtomicBool::new(true));
        let summary = scan_project(
            temp.path(),
            ScanOptions {
                cancelled: Some(cancelled),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(summary.cancelled);
        assert_eq!(summary.generation, initial.generation);
        assert!(!search(temp.path(), "stable", 10).unwrap().items.is_empty());
        assert!(search(temp.path(), "replacement", 10)
            .unwrap()
            .items
            .is_empty());
    }
    #[test]
    fn keeps_overloads_distinct_and_ambiguous() {
        let temp = tempdir().unwrap();
        fs::write(
            temp.path().join("Demo.java"),
            "class Demo { void call(int value) {} void call(String value) {} }\n",
        )
        .unwrap();
        scan_project(temp.path(), ScanOptions::default()).unwrap();
        let result = impact(temp.path(), "call", 5).unwrap();
        assert_eq!(result.candidates.len(), 2);
        assert!(result.results.is_empty());
    }
}
