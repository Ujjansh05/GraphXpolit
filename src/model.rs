use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Language {
    Python,
    JavaScript,
    TypeScript,
    Go,
    Rust,
    Java,
}

impl Language {
    pub fn label(self) -> &'static str {
        match self {
            Self::Python => "Python",
            Self::JavaScript => "JavaScript",
            Self::TypeScript => "TypeScript",
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
