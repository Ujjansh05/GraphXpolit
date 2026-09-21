use crate::analysis::{dependencies, impact, scan_project, source_excerpt, ScanOptions};
use crate::model::{ProjectSummary, QueryResult};
use axum::{
    body::Body,
    extract::{DefaultBodyLimit, Path, State},
    http::{
        header::{CONTENT_TYPE, HOST, ORIGIN},
        uri::Authority,
        HeaderMap, HeaderName, HeaderValue, Request, StatusCode, Uri,
    },
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    path::{Path as FsPath, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use tokio::net::TcpListener;

static NEXT_JOB_ID: AtomicU64 = AtomicU64::new(1);
const MAX_JSON_BODY_BYTES: usize = 64 * 1024;
const MAX_ACTIVE_SCANS: usize = 1;
const MAX_STORED_JOBS: usize = 32;
const JOB_TTL: Duration = Duration::from_secs(10 * 60);

#[derive(Clone)]
struct AppState {
    token: Arc<String>,
    default_root: Option<String>,
    jobs: Arc<Mutex<HashMap<String, Job>>>,
}

#[derive(Clone)]
struct Job {
    status: String,
    cancel: Arc<AtomicBool>,
    summary: Option<ProjectSummary>,
    error: Option<String>,
    completed_at: Option<Instant>,
}

#[derive(Deserialize)]
struct ScanRequest {
    root: String,
    #[serde(default)]
    verify: bool,
}

#[derive(Deserialize)]
struct QueryRequest {
    root: String,
    target: String,
    #[serde(default = "default_depth")]
    depth: u32,
}

fn default_depth() -> u32 {
    5
}

#[derive(Deserialize)]
struct SourceRequest {
    root: String,
    path: String,
    start_line: usize,
    end_line: usize,
}

#[derive(Serialize)]
struct JobResponse {
    id: String,
    status: String,
    summary: Option<ProjectSummary>,
    error: Option<String>,
}

struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(serde_json::json!({"error": self.1}))).into_response()
    }
}

type ApiResult<T> = Result<Json<T>, ApiError>;

pub async fn serve(default_root: Option<PathBuf>, port: u16) -> anyhow::Result<()> {
    let token = random_token()?;
    let default_root = default_root
        .map(|path| canonical_project_root(&path))
        .transpose()?
        .map(|path| path.to_string_lossy().to_string());
    let state = AppState {
        token: Arc::new(token),
        default_root,
        jobs: Arc::new(Mutex::new(HashMap::new())),
    };
    let app = Router::new()
        .route("/", get(index))
        .route("/bootstrap.js", get(bootstrap))
        .route("/app.js", get(script))
        .route("/app.css", get(styles))
        .route("/api/v1/scan", post(start_scan))
        .route("/api/v1/jobs/{id}", get(job_status))
        .route("/api/v1/jobs/{id}/cancel", post(cancel_job))
        .route("/api/v1/impact", post(run_impact))
        .route("/api/v1/dependencies", post(run_dependencies))
        .route("/api/v1/source", post(read_source))
        .layer(DefaultBodyLimit::max(MAX_JSON_BODY_BYTES))
        .layer(middleware::from_fn(local_request_guard))
        .with_state(state);
    let listener = TcpListener::bind(("127.0.0.1", port)).await?;
    let address = listener.local_addr()?;
    println!("GraphXploit dashboard: http://{address}");
    println!("Press Ctrl+C to stop. All analysis remains on this computer.");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

async fn local_request_guard(request: Request<Body>, next: Next) -> Response {
    if !valid_host(request.headers())
        || !valid_origin(request.headers())
        || !valid_fetch_metadata(request.headers())
    {
        let mut response = (
            StatusCode::FORBIDDEN,
            "Only same-origin requests to the local GraphXploit server are allowed.",
        )
            .into_response();
        add_security_headers(&mut response);
        return response;
    }
    let mut response = next.run(request).await;
    add_security_headers(&mut response);
    response
}

fn valid_host(headers: &HeaderMap) -> bool {
    headers
        .get(HOST)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<Authority>().ok())
        .is_some_and(|authority| is_loopback_host(authority.host()))
}

fn valid_origin(headers: &HeaderMap) -> bool {
    let Some(origin) = headers.get(ORIGIN) else {
        return true;
    };
    let Some(host) = headers.get(HOST).and_then(|value| value.to_str().ok()) else {
        return false;
    };
    let Ok(uri) = origin.to_str().unwrap_or_default().parse::<Uri>() else {
        return false;
    };
    let Some(authority) = uri.authority() else {
        return false;
    };
    uri.scheme_str() == Some("http")
        && is_loopback_host(authority.host())
        && authority.as_str().eq_ignore_ascii_case(host)
        && uri
            .path_and_query()
            .is_none_or(|value| value.as_str() == "/")
}

fn valid_fetch_metadata(headers: &HeaderMap) -> bool {
    headers
        .get("sec-fetch-site")
        .and_then(|value| value.to_str().ok())
        .is_none_or(|value| !value.eq_ignore_ascii_case("cross-site"))
}
fn is_loopback_host(host: &str) -> bool {
    let normalized = host.trim_matches(['[', ']']);
    normalized.eq_ignore_ascii_case("localhost") || normalized == "127.0.0.1" || normalized == "::1"
}

fn add_security_headers(response: &mut Response) {
    let headers = response.headers_mut();
    headers.insert(
        HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"),
    );
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    headers.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
    );
    headers.insert(
        HeaderName::from_static("cache-control"),
        HeaderValue::from_static("no-store"),
    );
}

async fn index() -> Html<&'static str> {
    Html(include_str!("static/index.html"))
}

async fn bootstrap(State(state): State<AppState>) -> Response {
    let token = serde_json::to_string(state.token.as_str()).unwrap_or_else(|_| "\"\"".to_owned());
    let root = serde_json::to_string(&state.default_root.unwrap_or_default())
        .unwrap_or_else(|_| "\"\"".to_owned());
    (
        [(CONTENT_TYPE, "application/javascript; charset=utf-8")],
        format!("window.GRAPHXPLOIT_TOKEN = {token};\nwindow.GRAPHXPLOIT_ROOT = {root};\n"),
    )
        .into_response()
}

async fn script() -> Response {
    (
        [(CONTENT_TYPE, "application/javascript; charset=utf-8")],
        include_str!("static/app.js"),
    )
        .into_response()
}

async fn styles() -> Response {
    (
        [(CONTENT_TYPE, "text/css; charset=utf-8")],
        include_str!("static/app.css"),
    )
        .into_response()
}

fn authenticate(headers: &HeaderMap, state: &AppState) -> Result<(), ApiError> {
    let supplied = headers
        .get("x-graphxploit-token")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if constant_time_eq(supplied.as_bytes(), state.token.as_bytes()) {
        Ok(())
    } else {
        Err(ApiError(
            StatusCode::UNAUTHORIZED,
            "This request is not from the GraphXploit dashboard.".to_owned(),
        ))
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

async fn start_scan(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ScanRequest>,
) -> ApiResult<JobResponse> {
    authenticate(&headers, &state)?;
    let root = canonical_project_root(FsPath::new(request.root.trim()))
        .map_err(|error| ApiError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let id = format!("job-{}", NEXT_JOB_ID.fetch_add(1, Ordering::Relaxed));
    let cancelled = Arc::new(AtomicBool::new(false));
    {
        let mut entries = state.jobs.lock().map_err(|_| job_storage_error())?;
        prune_jobs(&mut entries);
        let active = entries
            .values()
            .filter(|job| job.status == "running")
            .count();
        if active >= MAX_ACTIVE_SCANS {
            return Err(ApiError(
                StatusCode::TOO_MANY_REQUESTS,
                "A scan is already running. Wait for it to finish or cancel it.".to_owned(),
            ));
        }
        if entries.len() >= MAX_STORED_JOBS {
            return Err(ApiError(
                StatusCode::TOO_MANY_REQUESTS,
                "The local job queue is full. Try again after completed jobs expire.".to_owned(),
            ));
        }
        entries.insert(
            id.clone(),
            Job {
                status: "running".to_owned(),
                cancel: cancelled.clone(),
                summary: None,
                error: None,
                completed_at: None,
            },
        );
    }

    let jobs = state.jobs.clone();
    let job_id = id.clone();
    let spawn_result = std::thread::Builder::new()
        .name("graphxploit-scan".to_owned())
        .spawn(move || {
            let result = scan_project(
                &root,
                ScanOptions {
                    verify: request.verify,
                    max_file_bytes: 2 * 1024 * 1024,
                    cancelled: Some(cancelled.clone()),
                },
            );
            if let Ok(mut entries) = jobs.lock() {
                if let Some(job) = entries.get_mut(&job_id) {
                    match result {
                        Ok(summary) => {
                            job.status = if summary.cancelled {
                                "cancelled"
                            } else {
                                "completed"
                            }
                            .to_owned();
                            job.summary = Some(summary);
                        }
                        Err(error) => {
                            job.status = "failed".to_owned();
                            job.error = Some(error.to_string());
                        }
                    }
                    job.completed_at = Some(Instant::now());
                }
            }
        });
    if let Err(error) = spawn_result {
        if let Ok(mut entries) = state.jobs.lock() {
            entries.remove(&id);
        }
        return Err(ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Could not start scan worker: {error}"),
        ));
    }

    Ok(Json(JobResponse {
        id,
        status: "running".to_owned(),
        summary: None,
        error: None,
    }))
}

async fn job_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<JobResponse> {
    authenticate(&headers, &state)?;
    let mut entries = state.jobs.lock().map_err(|_| job_storage_error())?;
    prune_jobs(&mut entries);
    let job = entries
        .get(&id)
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "Scan job not found.".to_owned()))?;
    Ok(Json(job_response(id, job)))
}

async fn cancel_job(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<JobResponse> {
    authenticate(&headers, &state)?;
    let mut entries = state.jobs.lock().map_err(|_| job_storage_error())?;
    prune_jobs(&mut entries);
    let job = entries
        .get_mut(&id)
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "Scan job not found.".to_owned()))?;
    if job.status == "running" {
        job.cancel.store(true, Ordering::Relaxed);
    }
    Ok(Json(job_response(id, job)))
}

async fn run_impact(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<QueryRequest>,
) -> Result<Json<QueryResult>, ApiError> {
    authenticate(&headers, &state)?;
    let root = canonical_project_root(FsPath::new(request.root.trim()))
        .map_err(|error| ApiError(StatusCode::BAD_REQUEST, error.to_string()))?;
    impact(&root, request.target.trim(), request.depth)
        .map(Json)
        .map_err(|error| ApiError(StatusCode::BAD_REQUEST, error.to_string()))
}

async fn run_dependencies(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<QueryRequest>,
) -> Result<Json<QueryResult>, ApiError> {
    authenticate(&headers, &state)?;
    let root = canonical_project_root(FsPath::new(request.root.trim()))
        .map_err(|error| ApiError(StatusCode::BAD_REQUEST, error.to_string()))?;
    dependencies(&root, request.target.trim(), request.depth)
        .map(Json)
        .map_err(|error| ApiError(StatusCode::BAD_REQUEST, error.to_string()))
}

async fn read_source(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<SourceRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    authenticate(&headers, &state)?;
    let root = canonical_project_root(FsPath::new(request.root.trim()))
        .map_err(|error| ApiError(StatusCode::BAD_REQUEST, error.to_string()))?;
    source_excerpt(&root, &request.path, request.start_line, request.end_line)
        .map(|content| Json(serde_json::json!({"content": content})))
        .map_err(|error| ApiError(StatusCode::BAD_REQUEST, error.to_string()))
}

fn job_storage_error() -> ApiError {
    ApiError(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Job storage is unavailable.".to_owned(),
    )
}

fn job_response(id: String, job: &Job) -> JobResponse {
    JobResponse {
        id,
        status: job.status.clone(),
        summary: job.summary.clone(),
        error: job.error.clone(),
    }
}

fn prune_jobs(jobs: &mut HashMap<String, Job>) {
    jobs.retain(|_, job| {
        job.status == "running"
            || job
                .completed_at
                .is_some_and(|finished| finished.elapsed() < JOB_TTL)
    });
}

fn canonical_project_root(path: &FsPath) -> anyhow::Result<PathBuf> {
    if path.as_os_str().is_empty() {
        anyhow::bail!("Choose a local project directory first.");
    }
    let root = path
        .canonicalize()
        .map_err(|_| anyhow::anyhow!("Project directory does not exist: {}", path.display()))?;
    if !root.is_dir() {
        anyhow::bail!("Project path is not a directory: {}", root.display());
    }
    Ok(root)
}

fn random_token() -> anyhow::Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|error| anyhow::anyhow!("OS randomness failed: {error}"))?;
    Ok(hex::encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(host: &str, origin: Option<&str>) -> HeaderMap {
        let mut values = HeaderMap::new();
        values.insert(HOST, HeaderValue::from_str(host).unwrap());
        if let Some(origin) = origin {
            values.insert(ORIGIN, HeaderValue::from_str(origin).unwrap());
        }
        values
    }

    #[test]
    fn accepts_only_exact_loopback_hosts() {
        assert!(valid_host(&headers("127.0.0.1:8080", None)));
        assert!(valid_host(&headers("localhost:8080", None)));
        assert!(!valid_host(&headers(
            "localhost.attacker.invalid:8080",
            None
        )));
        assert!(!valid_host(&headers(
            "127.0.0.1.attacker.invalid:8080",
            None
        )));
        assert!(!valid_host(&HeaderMap::new()));
    }

    #[test]
    fn accepts_only_matching_http_origins() {
        assert!(valid_origin(&headers(
            "127.0.0.1:8080",
            Some("http://127.0.0.1:8080")
        )));
        assert!(!valid_origin(&headers(
            "127.0.0.1:8080",
            Some("https://attacker.invalid")
        )));
        assert!(!valid_origin(&headers(
            "127.0.0.1:8080",
            Some("http://localhost:8080")
        )));
    }

    #[test]
    fn tokens_are_random_and_full_length() {
        let first = random_token().unwrap();
        let second = random_token().unwrap();
        assert_eq!(first.len(), 64);
        assert_ne!(first, second);
        assert!(constant_time_eq(first.as_bytes(), first.as_bytes()));
        assert!(!constant_time_eq(first.as_bytes(), second.as_bytes()));
    }

    #[test]
    fn expired_jobs_are_removed() {
        let mut jobs = HashMap::new();
        jobs.insert(
            "old".to_owned(),
            Job {
                status: "completed".to_owned(),
                cancel: Arc::new(AtomicBool::new(false)),
                summary: None,
                error: None,
                completed_at: Some(Instant::now() - JOB_TTL - Duration::from_secs(1)),
            },
        );
        prune_jobs(&mut jobs);
        assert!(jobs.is_empty());
    }

    #[test]
    fn rejects_cross_site_browser_fetches() {
        let mut values = headers("127.0.0.1:8080", None);
        values.insert("sec-fetch-site", HeaderValue::from_static("cross-site"));
        assert!(!valid_fetch_metadata(&values));
        values.insert("sec-fetch-site", HeaderValue::from_static("same-origin"));
        assert!(valid_fetch_metadata(&values));
        assert!(valid_fetch_metadata(&headers("127.0.0.1:8080", None)));
    }
}
