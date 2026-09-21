//! Optional adapters for models that the user already runs or subscribes to.
//!
//! Credentials remain outside GraphXploit. The configuration records only an
//! endpoint, model name, and optional environment-variable name for a key.

use crate::{model::QueryResult, store::app_data_dir};
use anyhow::{bail, Context, Result};
use axum::http::Uri;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    net::IpAddr,
    path::{Path, PathBuf},
};

#[cfg(feature = "ai")]
use crate::impact;
#[cfg(feature = "ai")]
use anyhow::anyhow;
#[cfg(feature = "ai")]
use std::env;

const MAX_ENDPOINT_LENGTH: usize = 2_048;
const MAX_MODEL_NAME_LENGTH: usize = 256;
const MAX_QUESTION_LENGTH: usize = 4_096;
#[cfg(feature = "ai")]
const MAX_MODEL_REQUEST_BYTES: usize = 512 * 1024;
#[cfg(feature = "ai")]
const MAX_MODEL_RESPONSE_BYTES: usize = 1024 * 1024;

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
    let (_, loopback) = parse_endpoint(&config.endpoint)?;
    if config.endpoint.starts_with("http://") && !loopback {
        bail!("model endpoints must use HTTPS unless their parsed host is loopback");
    }
    let model = config.model.trim();
    if model.is_empty()
        || model.len() > MAX_MODEL_NAME_LENGTH
        || model.chars().any(char::is_control)
    {
        bail!("model name is missing or invalid");
    }
    if config.api_key_env.as_deref().is_some_and(|name| {
        name.is_empty()
            || name.len() > 128
            || !name.chars().enumerate().all(|(index, character)| {
                character == '_'
                    || character.is_ascii_alphanumeric()
                        && (index > 0 || character.is_ascii_alphabetic())
            })
    }) {
        bail!("API-key environment variable name is invalid");
    }
    if config.send_source {
        bail!("source sharing is not supported; send_source must remain false");
    }
    Ok(())
}

fn parse_endpoint(endpoint: &str) -> Result<(Uri, bool)> {
    let endpoint = endpoint.trim_end_matches('/');
    if endpoint.is_empty() || endpoint.len() > MAX_ENDPOINT_LENGTH {
        bail!("model endpoint is missing or too long");
    }
    let uri: Uri = endpoint
        .parse()
        .context("model endpoint is not a valid URL")?;
    let scheme = uri
        .scheme_str()
        .ok_or_else(|| anyhow::anyhow!("model endpoint requires a URL scheme"))?;
    if scheme != "http" && scheme != "https" {
        bail!("model endpoint must use HTTP or HTTPS");
    }
    if uri.query().is_some() {
        bail!("model endpoint must not contain a query string");
    }
    let authority = uri
        .authority()
        .ok_or_else(|| anyhow::anyhow!("model endpoint requires a host"))?;
    if authority.as_str().contains('@') {
        bail!("model endpoint must not contain embedded credentials");
    }
    let host = authority.host().trim_matches(['[', ']']);
    let loopback = host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback());
    if scheme == "http" && !loopback {
        bail!("model endpoints must use HTTPS unless their parsed host is loopback");
    }
    Ok((uri, loopback))
}

pub fn prompt(question: &str, result: &QueryResult) -> Result<String> {
    let question = question.trim();
    if question.is_empty() || question.len() > MAX_QUESTION_LENGTH {
        bail!("model question is missing or too long");
    }
    let evidence = serde_json::to_string(result)?;
    Ok(format!(
        "Explain this deterministic code-impact evidence. Do not claim certainty beyond indexed relationships. Do not suggest running code. Mention unresolved dynamic behavior as a limitation.\n\nQuestion: {question}\n\nEvidence JSON:\n{evidence}"
    ))
}

#[cfg(feature = "ai")]
pub async fn explain(root: &Path, target: &str, depth: u32, question: &str) -> Result<String> {
    let config = load_config()?;
    let (_, loopback) = parse_endpoint(&config.endpoint)?;
    let evidence = prompt(question, &impact(root, target, depth)?)?;
    if evidence.len() > MAX_MODEL_REQUEST_BYTES {
        bail!("bounded impact evidence is too large for a model request");
    }
    let endpoint = config.endpoint.trim_end_matches('/');
    let mut client_builder = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(60))
        .redirect(reqwest::redirect::Policy::none());
    if loopback {
        client_builder = client_builder.no_proxy();
    }
    let client = client_builder.build()?;
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
    let mut response = request.send().await?.error_for_status()?;
    if response
        .content_length()
        .is_some_and(|length| length > MAX_MODEL_RESPONSE_BYTES as u64)
    {
        bail!("model response exceeds the one MiB limit");
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if body.len().saturating_add(chunk.len()) > MAX_MODEL_RESPONSE_BYTES {
            bail!("model response exceeds the one MiB limit");
        }
        body.extend_from_slice(&chunk);
    }
    let value: serde_json::Value =
        serde_json::from_slice(&body).context("model response is not valid JSON")?;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn config(endpoint: &str) -> ModelConfig {
        ModelConfig {
            provider: Provider::Ollama,
            endpoint: endpoint.to_owned(),
            model: "existing-model".to_owned(),
            api_key_env: None,
            send_source: false,
        }
    }

    #[test]
    fn accepts_https_and_exact_loopback_http_endpoints() {
        assert!(validate_config(&config("https://models.example.com/v1")).is_ok());
        assert!(validate_config(&config("http://localhost:11434")).is_ok());
        assert!(validate_config(&config("http://127.0.0.1:11434")).is_ok());
        assert!(validate_config(&config("http://[::1]:11434")).is_ok());
    }

    #[test]
    fn rejects_lookalike_loopback_and_unsafe_endpoints() {
        assert!(validate_config(&config("http://localhost.attacker.invalid")).is_err());
        assert!(validate_config(&config("http://127.0.0.1.attacker.invalid")).is_err());
        assert!(validate_config(&config("http://192.168.1.10:11434")).is_err());
        assert!(validate_config(&config("file:///tmp/model")).is_err());
        assert!(validate_config(&config("https://user:pass@example.com")).is_err());
    }

    #[test]
    fn rejects_invalid_secret_names_and_source_sharing() {
        let mut value = config("https://models.example.com/v1");
        value.api_key_env = Some("BAD=VALUE".to_owned());
        assert!(validate_config(&value).is_err());
        value.api_key_env = Some("MODEL_API_KEY".to_owned());
        value.send_source = true;
        assert!(validate_config(&value).is_err());
    }
}
