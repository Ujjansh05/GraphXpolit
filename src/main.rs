use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use graphxploit::{
    ai::{self, ModelConfig, Provider},
    dependencies, impact, scan_project, web, ScanOptions,
};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "graphxploit",
    version,
    about = "Local code impact analysis. No Docker, database server, or model download required."
)]
struct Cli {
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

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
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
                    };
                    ai::save_config(&config)?;
                    println!("Saved {} model configuration at {}. API keys are never stored by GraphXploit.", match config.provider { Provider::Ollama => "Ollama", Provider::Openai => "OpenAI-compatible" }, ai::config_path()?.display());
                }
                ModelCommand::Status => match ai::load_config() {
                    Ok(config) => println!(
                        "Configured {:?} model '{}' at {}. Source sharing: disabled.",
                        config.provider, config.model, config.endpoint
                    ),
                    Err(error) => println!("No usable model configuration: {error}"),
                },
            }
        }
        Some(Command::Serve { path, port }) => web::serve(path, port).await?,
        Some(Command::Doctor) => {
            println!("GraphXploit {}", env!("CARGO_PKG_VERSION"));
            println!("Storage: {}", graphxploit::store::app_data_dir()?.display());
            println!("Supported parsers: Python, JavaScript/TypeScript, Go, Rust, Java");
            println!("No Docker, TigerGraph, Ollama, Node.js, or GPU is required.");
            println!("Optional existing-model support: build with `--features ai`.");
        }
        None => web::serve(None, 0)
            .await
            .context("failed to start local dashboard")?,
    }
    Ok(())
}
