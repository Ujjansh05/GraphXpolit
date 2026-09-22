use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Language {
    Python,
    JavaScript,
    TypeScript,
    Tsx,
    Go,
    Rust,
    Java,
}

impl Language {
    pub fn label(self) -> &'static str {
        match self {
            Self::Python => "Python",
            Self::JavaScript => "JavaScript",
            Self::TypeScript | Self::Tsx => "TypeScript",
            Self::Go => "Go",
            Self::Rust => "Rust",
            Self::Java => "Java",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ParsedSymbol {
    pub name: String,
    pub qualified_name: String,
    pub kind: String,
    pub start_line: u32,
    pub end_line: u32,
}

#[derive(Debug, Clone)]
pub(crate) struct ParsedReference {
    pub source_qualified_name: String,
    pub raw_target: String,
    pub line: u32,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ParsedFile {
    pub symbols: Vec<ParsedSymbol>,
    pub references: Vec<ParsedReference>,
    pub imports: Vec<(String, u32)>,
    pub diagnostic: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProjectSummary {
    pub root: PathBuf,
    pub database: PathBuf,
    pub files_seen: usize,
    pub files_parsed: usize,
    pub files_skipped: usize,
    pub symbols: usize,
    pub relationships: usize,
    pub diagnostics: usize,
    pub cancelled: bool,
    pub generation: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Candidate {
    pub qualified_name: String,
    pub kind: String,
    pub path: String,
    pub line: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct ImpactNode {
    pub qualified_name: String,
    pub name: String,
    pub kind: String,
    pub path: String,
    pub line: u32,
    pub depth: u32,
    pub relationship: String,
    /// The dependency route from this result towards the selected target.
    pub evidence_path: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct QueryResult {
    pub mode: String,
    pub target: String,
    pub results: Vec<ImpactNode>,
    pub candidates: Vec<Candidate>,
    pub complete: bool,
    pub visited: usize,
    pub message: Option<String>,
}
#[derive(Debug, Clone, Serialize)]
pub struct SearchResult {
    pub items: Vec<Candidate>,
    pub complete: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct GraphNode {
    pub id: String,
    pub label: String,
    pub kind: String,
    pub path: String,
    pub line: u32,
    pub depth: u32,
    pub selected: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct GraphEdge {
    pub source: String,
    pub target: String,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct GraphResult {
    pub target: String,
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    pub complete: bool,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextEvidence {
    pub id: String,
    pub qualified_name: String,
    pub kind: String,
    pub path: String,
    pub start_line: u32,
    pub end_line: u32,
    pub relationship: String,
    pub source: Option<String>,
    pub estimated_tokens: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextPreview {
    pub preview_id: String,
    pub question: String,
    pub target: Option<String>,
    pub revision: String,
    pub evidence: Vec<ContextEvidence>,
    pub estimated_tokens: usize,
    pub budget_tokens: usize,
    pub complete: bool,
    pub model_endpoint: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChatAnswer {
    pub answer: String,
    pub citations: Vec<String>,
    pub estimated_input_tokens: usize,
    pub provider_input_tokens: Option<usize>,
    pub provider_output_tokens: Option<usize>,
    pub citation_warning: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChangedSymbol {
    pub status: String,
    pub path: String,
    pub old_path: Option<String>,
    pub qualified_name: String,
    pub kind: String,
    pub line: u32,
    pub affected: Vec<ImpactNode>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChangeImpact {
    pub mode: String,
    pub base_revision: String,
    pub head_revision: String,
    pub changes: Vec<ChangedSymbol>,
    pub complete: bool,
    pub message: Option<String>,
}
