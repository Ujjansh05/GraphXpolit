use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use graphxploit::{
    agent::{self, AgentOptions},
    ai::{self, ModelConfig, Provider},
    branch_changes, context_preview, dependencies, impact, scan_project, search, web,
    working_changes, ScanOptions,
};
use std::{
    env,
    io::{self, Write},
    path::PathBuf,
    process::Command as ProcessCommand,
};

#[derive(Parser)]
#[command(
    name = "graphxploit",
    version,
    about = "Local code impact analysis and approval-based code agent."
)]
struct Cli {
    /// Use this workspace for interactive and short commands.
    #[arg(short = 'C', long, global = true, default_value = ".")]
    cwd: PathBuf,
    /// Skip the incremental startup scan.
    #[arg(long, global = true)]
    no_scan: bool,
    /// Maximum local context sent to a configured model.
    #[arg(long, global = true, default_value_t = 4_000)]
    budget: usize,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Scan a project and build or update its local index.
    Scan {
        path: PathBuf,
        #[arg(long)]
        verify: bool,
    },
    /// Show components that may be affected by changing a symbol or file.
    Impact {
        path: PathBuf,
        target: String,
        #[arg(long, default_value_t = 5)]
        depth: u32,
        #[arg(long)]
        json: bool,
    },
    /// Show components used by a symbol or file.
    Dependencies {
        path: PathBuf,
        target: String,
        #[arg(long, default_value_t = 5)]
        depth: u32,
        #[arg(long)]
        json: bool,
    },
    /// Search indexed symbols and files without loading the full graph.
    Search {
        path: PathBuf,
        query: String,
        #[arg(long, default_value_t = 25)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
    /// Build compact local evidence for a codebase question without calling a model.
    Context {
        path: PathBuf,
        question: String,
        #[arg(long)]
        target: Option<String>,
        #[arg(long)]
        include_source: bool,
        #[arg(long, default_value_t = 4_000)]
        budget: usize,
        #[arg(long)]
        json: bool,
    },
    /// Preview and approve compact evidence before asking a configured model.
    Ask {
        path: PathBuf,
        question: String,
        #[arg(long)]
        target: Option<String>,
        #[arg(long, default_value_t = 4_000)]
        budget: usize,
        /// Approve all displayed evidence without an interactive prompt.
        #[arg(long)]
        approve: bool,
    },
    /// Analyze tracked Git changes and their indexed impact.
    Diff {
        path: PathBuf,
        #[arg(long)]
        working: bool,
        #[arg(long)]
        base: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Ask a configured existing model to explain bounded, local impact evidence.
    Explain {
        path: PathBuf,
        target: String,
        #[arg(long, default_value_t = 5)]
        depth: u32,
        #[arg(long)]
        question: Option<String>,
    },
    /// Configure or inspect an optional existing model endpoint. API keys stay in environment variables.
    #[command(alias = "m")]
    Model {
        #[command(subcommand)]
        command: ModelCommand,
    },
    /// Start the read-only local dashboard.
    Serve {
        path: Option<PathBuf>,
        #[arg(long, default_value_t = 0)]
        port: u16,
    },
    /// Run one agent request and emit normal text or NDJSON events.
    Run {
        #[arg(long)]
        json: bool,
        #[arg(required = true, trailing_var_arg = true)]
        prompt: Vec<String>,
    },
    /// Scan the current workspace.
    Ix {
        #[arg(long)]
        verify: bool,
    },
    /// Find symbols in the current workspace.
    F {
        query: String,
        #[arg(long, default_value_t = 25)]
        limit: usize,
    },
    /// Show impact in the current workspace.
    I {
        target: String,
        #[arg(long, default_value_t = 5)]
        depth: u32,
    },
    /// Show dependencies in the current workspace.
    D {
        target: String,
        #[arg(long, default_value_t = 5)]
        depth: u32,
    },
    /// Show Git change impact in the current workspace.
    Ch { base: Option<String> },
    /// Ask once about the current workspace.
    Q {
        #[arg(required = true, trailing_var_arg = true)]
        prompt: Vec<String>,
    },
    /// Start the dashboard for the current workspace.
    Ui {
        #[arg(long, default_value_t = 0)]
        port: u16,
    },
    /// Run lightweight environment diagnostics.
    Check,
    /// Print environment and storage diagnostics.
    Doctor,
}

#[derive(Subcommand)]
enum ModelCommand {
    /// Save a non-secret connection profile for an existing endpoint.
    Configure {
        #[arg(value_enum)]
        provider: ProviderArg,
        endpoint: String,
        model: String,
        #[arg(long)]
        api_key_env: Option<String>,
    },
    /// Print the configured endpoint without exposing any credential.
    Status,
}

#[derive(Clone, ValueEnum)]
enum ProviderArg {
    Ollama,
    Openai,
}

impl From<ProviderArg> for Provider {
    fn from(value: ProviderArg) -> Self {
        match value {
            ProviderArg::Ollama => Provider::Ollama,
            ProviderArg::Openai => Provider::Openai,
        }
    }
}

fn print_result(result: &graphxploit::QueryResult, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(result)?);
        return Ok(());
    }
    if !result.candidates.is_empty() {
        println!("The target is ambiguous. Select one of:");
        for candidate in &result.candidates {
            println!(
                "  {}:{}  {} ({})",
                candidate.path, candidate.line, candidate.qualified_name, candidate.kind
            );
        }
        return Ok(());
    }
    println!("{}: {}", result.mode, result.target);
    if let Some(message) = &result.message {
        println!("{message}");
    }
    for node in &result.results {
        println!(
            "  [{}] {}:{}  {}",
            node.depth, node.path, node.line, node.qualified_name
        );
        if node.evidence_path.len() > 1 {
            println!("      {}", node.evidence_path.join(" -> "));
        }
    }
    if !result.complete {
        println!("Result limit reached; this is a partial analysis.");
    }
    Ok(())
}

fn direct_agent_prompt() -> Result<Option<(AgentOptions, String)>> {
    const COMMANDS: &[&str] = &[
        "scan",
        "impact",
        "dependencies",
        "search",
        "context",
        "ask",
        "diff",
        "explain",
        "model",
        "m",
        "serve",
        "run",
        "ix",
        "f",
        "i",
        "d",
        "ch",
        "q",
        "ui",
        "check",
        "doctor",
        "help",
    ];
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() {
        return Ok(None);
    }
    let mut root = PathBuf::from(".");
    let mut budget = 4_000usize;
    let mut no_scan = false;
    let mut prompt = Vec::new();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "-C" | "--cwd" => {
                index += 1;
                root = PathBuf::from(
                    args.get(index)
                        .context("missing workspace after -C/--cwd")?,
                );
            }
            "--budget" => {
                index += 1;
                budget = args
                    .get(index)
                    .context("missing value after --budget")?
                    .parse()
                    .context("budget must be a number")?;
            }
            "--no-scan" => no_scan = true,
            "-h" | "--help" | "-V" | "--version" => return Ok(None),
            value if prompt.is_empty() && COMMANDS.contains(&value) => return Ok(None),
            value => prompt.push(value.to_owned()),
        }
        index += 1;
    }
    if prompt.is_empty() {
        return Ok(None);
    }
    Ok(Some((
        AgentOptions {
            root,
            no_scan,
            budget,
            json: false,
        },
        prompt.join(" "),
    )))
}
#[tokio::main]
async fn main() -> Result<()> {
    if let Some((options, prompt)) = direct_agent_prompt()? {
        agent::one_shot(options, prompt).await?;
        return Ok(());
    }
    let cli = Cli::parse();
    let options = || AgentOptions {
        root: cli.cwd.clone(),
        no_scan: cli.no_scan,
        budget: cli.budget,
        json: false,
    };
    if cli.command.is_none() {
        agent::interactive(options()).await?;
        return Ok(());
    }
    match cli.command {
        Some(Command::Scan { path, verify }) => {
            let summary = scan_project(
                &path,
                ScanOptions {
                    verify,
                    ..Default::default()
                },
            )?;
            println!(
                "Indexed {} files ({} parsed, {} unchanged).",
                summary.files_seen, summary.files_parsed, summary.files_skipped
            );
            println!(
                "{} symbols, {} relationships, {} diagnostics.",
                summary.symbols, summary.relationships, summary.diagnostics
            );
            println!("Index: {}", summary.database.display());
        }
        Some(Command::Impact {
            path,
            target,
            depth,
            json,
        }) => print_result(&impact(&path, &target, depth)?, json)?,
        Some(Command::Dependencies {
            path,
            target,
            depth,
            json,
        }) => print_result(&dependencies(&path, &target, depth)?, json)?,
        Some(Command::Search {
            path,
            query,
            limit,
            json,
        }) => {
            let result = search(&path, &query, limit)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                for item in result.items {
                    println!(
                        "{}:{}  {} ({})",
                        item.path, item.line, item.qualified_name, item.kind
                    );
                }
                if !result.complete {
                    println!("More matches exist; narrow the query.");
                }
            }
        }
        Some(Command::Context {
            path,
            question,
            target,
            include_source,
            budget,
            json,
        }) => {
            let preview = context_preview(
                &path,
                &question,
                target.as_deref(),
                include_source,
                Some(budget),
                ai::configured_endpoint(),
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&preview)?);
            } else {
                print_context_preview(&preview);
            }
        }
        Some(Command::Ask {
            path,
            question,
            target,
            budget,
            approve,
        }) => {
            let preview = context_preview(
                &path,
                &question,
                target.as_deref(),
                true,
                Some(budget),
                ai::configured_endpoint(),
            )?;
            print_context_preview(&preview);
            if !approve && !confirm_send()? {
                println!("Model request cancelled; no source was sent.");
                return Ok(());
            }
            let selected = preview
                .evidence
                .iter()
                .map(|item| item.id.clone())
                .collect::<Vec<_>>();
            let answer = ai::ask_preview(&preview, &selected).await?;
            println!("\n{}", answer.answer);
            if let Some(warning) = answer.citation_warning {
                println!("\nCitation warning: {warning}");
            }
            println!(
                "\nEstimated input: {} tokens",
                answer.estimated_input_tokens
            );
        }
        Some(Command::Diff {
            path,
            working,
            base,
            json,
        }) => {
            if working && base.is_some() {
                anyhow::bail!("choose either --working or --base, not both");
            }
            let result = if let Some(base) = base {
                branch_changes(&path, &base)?
            } else {
                working_changes(&path)?
            };
            if json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!(
                    "{} changes: {} -> {}",
                    result.mode, result.base_revision, result.head_revision
                );
                if let Some(message) = result.message {
                    println!("{message}");
                }
                for change in result.changes {
                    println!(
                        "  {}  {}:{}  {}",
                        change.status, change.path, change.line, change.qualified_name
                    );
                    for affected in change.affected.iter().take(5) {
                        println!(
                            "      affects {}:{}  {}",
                            affected.path, affected.line, affected.qualified_name
                        );
                    }
                }
            }
        }
        Some(Command::Explain {
            path,
            target,
            depth,
            question,
        }) => {
            let question = question
                .unwrap_or_else(|| format!("What is the potential impact of changing {target}?"));
            println!("{}", ai::explain(&path, &target, depth, &question).await?);
        }
        Some(Command::Model { command }) => {
            match command {
                ModelCommand::Configure {
                    provider,
                    endpoint,
                    model,
                    api_key_env,
                } => {
                    let config = ModelConfig {
                        provider: provider.into(),
                        endpoint,
                        model,
                        api_key_env,
                        send_source: false,
                        tool_protocol: ai::ToolProtocol::Auto,
                    };
                    ai::save_config(&config)?;
                    println!("Saved {} model configuration at {}. API keys are never stored by GraphXploit.", match config.provider { Provider::Ollama => "Ollama", Provider::Openai => "OpenAI-compatible" }, ai::config_path()?.display());
                }
                ModelCommand::Status => match ai::load_config() {
                    Ok(config) => println!(
                        "Configured {:?} model '{}' at {}. Automatic source sharing is disabled; source-backed chat always requires preview approval.",
                        config.provider, config.model, config.endpoint
                    ),
                    Err(error) => println!("No usable model configuration: {error}"),
                },
            }
        }
        Some(Command::Serve { path, port }) => web::serve(path, port).await?,
        Some(Command::Run { json, prompt }) => {
            let mut value = options();
            value.json = json;
            agent::one_shot(value, prompt.join(" ")).await?;
        }
        Some(Command::Ix { verify }) => {
            let summary = scan_project(&cli.cwd, ScanOptions { verify, ..Default::default() })?;
            println!("{} files · {} parsed · {} unchanged · {} symbols · generation {}", summary.files_seen, summary.files_parsed, summary.files_skipped, summary.symbols, summary.generation);
        }
        Some(Command::F { query, limit }) => {
            let result = search(&cli.cwd, &query, limit)?;
            for item in result.items { println!("{}:{}  {} ({})", item.path, item.line, item.qualified_name, item.kind); }
        }
        Some(Command::I { target, depth }) => print_result(&impact(&cli.cwd, &target, depth)?, false)?,
        Some(Command::D { target, depth }) => print_result(&dependencies(&cli.cwd, &target, depth)?, false)?,
        Some(Command::Ch { base }) => {
            let result = if let Some(base) = base { branch_changes(&cli.cwd, &base)? } else { working_changes(&cli.cwd)? };
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Some(Command::Q { prompt }) => agent::one_shot(options(), prompt.join(" ")).await?,
        Some(Command::Ui { port }) => web::serve(Some(cli.cwd.clone()), port).await?,
        Some(Command::Check) => {
            println!("GraphXploit {} · {} edition", env!("CARGO_PKG_VERSION"), if cfg!(feature = "ai") { "AI" } else { "Lite" });
            println!("Workspace: {}", cli.cwd.display());
            println!("Storage: {}", graphxploit::store::app_data_dir()?.display());
        },
        Some(Command::Doctor) => {
            println!("GraphXploit {}", env!("CARGO_PKG_VERSION"));
            println!("Storage: {}", graphxploit::store::app_data_dir()?.display());
            println!("Supported parsers: Python, JavaScript/TypeScript/TSX, Go, Rust, Java");
            println!("No Docker, TigerGraph, Ollama, Node.js, or GPU is required.");
            println!(
                "Edition: {}",
                if cfg!(feature = "ai") { "AI" } else { "Lite" }
            );
            let git = ProcessCommand::new("git")
                .arg("--version")
                .output()
                .ok()
                .filter(|output| output.status.success())
                .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned());
            println!(
                "Git change analysis: {}",
                git.as_deref().unwrap_or("unavailable")
            );
        }
        None => unreachable!(),
    }
    Ok(())
}
fn print_context_preview(preview: &graphxploit::model::ContextPreview) {
    println!(
        "Context preview {}: approximately {} / {} tokens, revision {}",
        preview.preview_id, preview.estimated_tokens, preview.budget_tokens, preview.revision
    );
    if let Some(endpoint) = &preview.model_endpoint {
        println!("Destination: {endpoint}");
    } else {
        println!("Destination: no model configured");
    }
    for item in &preview.evidence {
        println!(
            "\n[{}] {}:{}-{}  {} ({})\nReason: {}",
            item.id,
            item.path,
            item.start_line,
            item.end_line,
            item.qualified_name,
            item.kind,
            item.relationship
        );
        if let Some(source) = &item.source {
            println!("{source}");
        }
    }
    if !preview.complete {
        println!("\nContext reached its budget; additional evidence was omitted or truncated.");
    }
}

fn confirm_send() -> Result<bool> {
    print!("\nSend the displayed evidence to the configured model? [y/N] ");
    io::stdout().flush()?;
    let mut response = String::new();
    io::stdin().read_line(&mut response)?;
    Ok(matches!(
        response.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}
