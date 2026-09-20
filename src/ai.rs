//! Optional adapters for models that the user already runs or subscribes to.
//!
//! Credentials remain outside GraphXploit. The configuration records only an
//! endpoint, model name, and optional environment-variable name for a key.

use crate::{model::QueryResult, store::app_data_dir};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
};

#[cfg(feature = "ai")]
use crate::impact;
#[cfg(feature = "ai")]
use anyhow::anyhow;
#[cfg(feature = "ai")]
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    Ollama,
    Openai,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelConfig {
    pub provider: Provider,
    pub endpoint: String,
    pub model: String,
    pub api_key_env: Option<String>,
    #[serde(default)]
    pub send_source: bool,
}

pub fn config_path() -> Result<PathBuf> {
    Ok(app_data_dir()?.join("model.json"))
}

pub fn save_config(config: &ModelConfig) -> Result<()> {
    validate_config(config)?;
    let path = config_path()?;
    fs::write(&path, serde_json::to_vec_pretty(config)?)
        .with_context(|| format!("could not write {}", path.display()))?;
    Ok(())
}

pub fn load_config() -> Result<ModelConfig> {
    let path = config_path()?;
    let data = fs::read(&path).with_context(|| {
        format!(
            "no model is configured. Run `graphxploit model configure` first ({})",
            path.display()
        )
    })?;
    let config: ModelConfig =
        serde_json::from_slice(&data).context("model configuration is invalid")?;
    validate_config(&config)?;
    Ok(config)
}

fn validate_config(config: &ModelConfig) -> Result<()> {
    let endpoint = config.endpoint.trim_end_matches('/');
    let loopback = endpoint.starts_with("http://127.0.0.1")
        || endpoint.starts_with("http://localhost")
        || endpoint.starts_with("http://[::1]");
    if !endpoint.starts_with("https://") && !loopback {
        bail!("model endpoints must use HTTPS unless they are on loopback");
    }
    if config.model.trim().is_empty() {
        bail!("a model name is required");
    }
    if config
        .api_key_env
        .as_deref()
        .is_some_and(|name| name.trim().is_empty() || name.contains('='))
    {
        bail!("API-key environment variable name is invalid");
    }
    Ok(())
}

pub fn prompt(question: &str, result: &QueryResult) -> String {
    let evidence = serde_json::to_string(result).unwrap_or_else(|_| "{}".to_owned());
    format!(
        "Explain this deterministic code-impact evidence. Do not claim certainty beyond indexed relationships. Do not suggest running code. Mention unresolved dynamic behavior as a limitation.\n\nQuestion: {question}\n\nEvidence JSON:\n{evidence}"
    )
}

#[cfg(feature = "ai")]
pub async fn explain(root: &Path, target: &str, depth: u32, question: &str) -> Result<String> {
    let config = load_config()?;
    let evidence = prompt(question, &impact(root, target, depth)?);
    let endpoint = config.endpoint.trim_end_matches('/');
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()?;
    let mut request = match config.provider {
        Provider::Ollama => {
            let url = if endpoint.ends_with("/api/chat") {
                endpoint.to_owned()
            } else {
                format!("{endpoint}/api/chat")
            };
            client.post(url).json(&serde_json::json!({
                "model": config.model, "stream": false,
                "messages": [{"role": "user", "content": evidence}],
                "options": {"temperature": 0.2}
            }))
        }
        Provider::Openai => {
            let url = if endpoint.ends_with("/chat/completions") {
                endpoint.to_owned()
            } else {
                format!("{endpoint}/chat/completions")
            };
            client.post(url).json(&serde_json::json!({
                "model": config.model, "temperature": 0.2, "max_tokens": 600,
                "messages": [
                    {"role": "system", "content": "Explain only the supplied local dependency evidence."},
                    {"role": "user", "content": evidence}
                ]
            }))
        }
    };
    if let Some(variable) = config.api_key_env.as_deref() {
        request = request.bearer_auth(
            env::var(variable)
                .with_context(|| format!("environment variable {variable} is not set"))?,
        );
    }
    let value: serde_json::Value = request.send().await?.error_for_status()?.json().await?;
    let output = match config.provider {
        Provider::Ollama => value
            .pointer("/message/content")
            .and_then(|value| value.as_str()),
        Provider::Openai => value
            .pointer("/choices/0/message/content")
            .and_then(|value| value.as_str()),
    };
    output
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow!("model response did not contain an explanation"))
}

#[cfg(not(feature = "ai"))]
pub async fn explain(_root: &Path, _target: &str, _depth: u32, _question: &str) -> Result<String> {
    bail!("AI is an optional build feature. Use a release built with `--features ai` to connect to an existing Ollama or OpenAI-compatible endpoint.")
}
