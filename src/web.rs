use crate::analysis::{dependencies, impact, scan_project, source_excerpt, ScanOptions};
use crate::model::{ProjectSummary, QueryResult};
use axum::{
    extract::{Path, State},
    http::{header::CONTENT_TYPE, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
};
use tokio::net::TcpListener;

static NEXT_JOB_ID: AtomicU64 = AtomicU64::new(1);

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
    let token = format!(
        "{:032x}",
        (NEXT_JOB_ID.fetch_add(1, Ordering::Relaxed) as u128) ^ unix_nanos()
    );
    let state = AppState {
        token: Arc::new(token),
        default_root: default_root.map(|path| path.to_string_lossy().to_string()),
        jobs: Arc::new(Mutex::new(HashMap::new())),
    };
    let app = Router::new()
        .route("/", get(index))
        .route("/app.js", get(script))
        .route("/app.css", get(styles))
        .route("/api/v1/scan", post(start_scan))
        .route("/api/v1/jobs/{id}", get(job_status))
        .route("/api/v1/jobs/{id}/cancel", post(cancel_job))
        .route("/api/v1/impact", post(run_impact))
        .route("/api/v1/dependencies", post(run_dependencies))
        .route("/api/v1/source", post(read_source))
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

async fn index(State(state): State<AppState>) -> Html<String> {
    let token = serde_json::to_string(state.token.as_str()).unwrap_or_else(|_| "\"\"".to_owned());
    let root = serde_json::to_string(&state.default_root.unwrap_or_default())
        .unwrap_or_else(|_| "\"\"".to_owned());
    Html(
        include_str!("static/index.html")
            .replace("__GRAPHXPLOIT_TOKEN__", &token)
            .replace("__GRAPHXPLOIT_ROOT__", &root),
    )
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
    if headers
        .get("x-graphxploit-token")
        .and_then(|value| value.to_str().ok())
        == Some(state.token.as_str())
    {
        Ok(())
    } else {
        Err(ApiError(
            StatusCode::UNAUTHORIZED,
            "This request is not from the GraphXploit dashboard.".to_owned(),
        ))
    }
}

async fn start_scan(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ScanRequest>,
) -> ApiResult<JobResponse> {
    authenticate(&headers, &state)?;
    if request.root.trim().is_empty() {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "Choose a local project directory first.".to_owned(),
        ));
    }
    let id = format!("job-{}", NEXT_JOB_ID.fetch_add(1, Ordering::Relaxed));
    let cancelled = Arc::new(AtomicBool::new(false));
    state
        .jobs
        .lock()
        .map_err(|_| {
            ApiError(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Job storage is unavailable.".to_owned(),
            )
        })?
        .insert(
            id.clone(),
            Job {
                status: "running".to_owned(),
                cancel: cancelled.clone(),
                summary: None,
                error: None,
            },
        );
    let jobs = state.jobs.clone();
    let root = request.root;
    let job_id = id.clone();
    std::thread::spawn(move || {
        let result = scan_project(
            PathBuf::from(root).as_path(),
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
            }
        }
    });
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
    let entries = state.jobs.lock().map_err(|_| {
        ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Job storage is unavailable.".to_owned(),
        )
    })?;
    let job = entries
        .get(&id)
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "Scan job not found.".to_owned()))?;
    Ok(Json(JobResponse {
        id,
        status: job.status.clone(),
        summary: job.summary.clone(),
        error: job.error.clone(),
    }))
}

async fn cancel_job(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<JobResponse> {
    authenticate(&headers, &state)?;
    let mut entries = state.jobs.lock().map_err(|_| {
        ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Job storage is unavailable.".to_owned(),
        )
    })?;
    let job = entries
        .get_mut(&id)
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "Scan job not found.".to_owned()))?;
    job.cancel.store(true, Ordering::Relaxed);
    Ok(Json(JobResponse {
        id,
        status: job.status.clone(),
        summary: job.summary.clone(),
        error: job.error.clone(),
    }))
}

async fn run_impact(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<QueryRequest>,
) -> Result<Json<QueryResult>, ApiError> {
    authenticate(&headers, &state)?;
    impact(
        PathBuf::from(request.root).as_path(),
        &request.target,
        request.depth,
    )
    .map(Json)
    .map_err(|error| ApiError(StatusCode::BAD_REQUEST, error.to_string()))
}

async fn run_dependencies(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<QueryRequest>,
) -> Result<Json<QueryResult>, ApiError> {
    authenticate(&headers, &state)?;
    dependencies(
        PathBuf::from(request.root).as_path(),
        &request.target,
        request.depth,
    )
    .map(Json)
    .map_err(|error| ApiError(StatusCode::BAD_REQUEST, error.to_string()))
}

async fn read_source(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<SourceRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    authenticate(&headers, &state)?;
    source_excerpt(
        PathBuf::from(request.root).as_path(),
        &request.path,
        request.start_line,
        request.end_line,
    )
    .map(|content| Json(serde_json::json!({"content": content})))
    .map_err(|error| ApiError(StatusCode::BAD_REQUEST, error.to_string()))
}

fn unix_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default()
}
