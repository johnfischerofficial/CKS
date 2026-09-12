use axum::{
    body::Body,
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, Request, State as AxumState,
    },
    http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode, Uri},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{delete, get, patch, post},
    Json, Router,
};
use axum_extra::extract::CookieJar;
use chrono::{DateTime, Duration, Local, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, VecDeque},
    env,
    net::SocketAddr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{
    fs::{self, File},
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::{Mutex, RwLock},
    time::timeout,
};
use uuid::Uuid;

mod pages;

const SESSION_COOKIE: &str = "rvg_session";
const SESSION_TTL: u64 = 60 * 60 * 24 * 7;
const RELAY_BUF: usize = 256 * 1024;

// ── Models ──
#[derive(Serialize, Deserialize, Clone)]
struct Link {
    label: String,
    limit_bytes: u64,
    used_bytes: u64,
    created_at: String,
    active: bool,
    expires_at: Option<String>,
    note: String,
    is_default: bool,
    sub_id: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
struct Sub {
    name: String,
    desc: String,
    password_hash: Option<String>,
    uuid_key: String,
    created_at: String,
    link_ids: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone)]
struct ErrorLog {
    error: String,
    url: Option<String>,
    time: String,
}

#[derive(Clone)]
struct ConnectionStat {
    uuid: String,
    connected_at: String,
    bytes: u64,
}

// ── App State ──
struct AppState {
    links: RwLock<HashMap<String, Link>>,
    subs: RwLock<HashMap<String, Sub>>,
    auth_hash: RwLock<String>,
    sessions: RwLock<HashMap<String, u64>>,
    connections: RwLock<HashMap<String, ConnectionStat>>,
    stats_total_bytes: RwLock<u64>,
    stats_total_requests: RwLock<u64>,
    stats_total_errors: RwLock<u64>,
    start_time: u64,
    error_logs: RwLock<VecDeque<ErrorLog>>,
    hourly_traffic: RwLock<HashMap<String, u64>>,
    http_client: reqwest::Client,
    config_secret: String,
    config_host: String,
    data_file: String,
    save_lock: Mutex<()>,
}

#[derive(Serialize, Deserialize)]
struct StatePersistence {
    links: HashMap<String, Link>,
    subs: HashMap<String, Sub>,
    password_hash: String,
    saved_at: String,
}

// ── Helpers ──
fn hash_password(pw: &str, secret: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("{}{}", pw, secret).as_bytes());
    hex::encode(hasher.finalize())
}

fn generate_uuid() -> String {
    Uuid::new_v4().to_string()
}

fn now_iso() -> String {
    Local::now().to_rfc3339()
}

fn now_sec() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn get_uptime(start: u64) -> String {
    let secs = now_sec().saturating_sub(start);
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    format!("{:02}:{:02}:{:02}", h, m, s)
}

fn generate_vless_link(uuid: &str, host: &str, remark: &str) -> String {
    format!(
        "vless://{}@{}:443?encryption=none&security=tls&type=ws&host={}&path=/ws/{}&sni={}&fp=chrome&alpn=http/1.1#{}",
        uuid, host, host, uuid, host, urlencoding::encode(remark)
    )
}

fn is_link_allowed(link: &Link) -> bool {
    if !link.active { return false; }
    if let Some(exp) = &link.expires_at {
        if let Ok(dt) = DateTime::parse_from_rfc3339(exp) {
            if Utc::now() > dt.with_timezone(&Utc) { return false; }
        }
    }
    if link.limit_bytes > 0 && link.used_bytes >= link.limit_bytes { return false; }
    true
}

// ── Persistence ──
async fn load_state(state: &Arc<AppState>) {
    if let Ok(content) = fs::read_to_string(&state.data_file).await {
        if let Ok(data) = serde_json::from_str::<StatePersistence>(&content) {
            *state.links.write().await = data.links;
            *state.subs.write().await = data.subs;
            *state.auth_hash.write().await = data.password_hash;
        }
    }
}

async fn save_state(state: &Arc<AppState>) {
    let _lock = state.save_lock.lock().await;
    let data = StatePersistence {
        links: state.links.read().await.clone(),
        subs: state.subs.read().await.clone(),
        password_hash: state.auth_hash.read().await.clone(),
        saved_at: now_iso(),
    };
    if let Ok(json) = serde_json::to_string_pretty(&data) {
        let tmp = format!("{}.tmp", state.data_file);
        if let Ok(mut f) = File::create(&tmp).await {
            let _ = f.write_all(json.as_bytes()).await;
            let _ = fs::rename(&tmp, &state.data_file).await;
        }
    }
}

// ── Auth Middleware ──
async fn auth_middleware(
    AxumState(state): AxumState<Arc<AppState>>,
    jar: CookieJar,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let authorized = if let Some(cookie) = jar.get(SESSION_COOKIE) {
        let token = cookie.value();
        let mut sessions = state.sessions.write().await;
        if let Some(&exp) = sessions.get(token) {
            if exp > now_sec() { true } else { sessions.remove(token); false }
        } else { false }
    } else { false };

    if authorized { Ok(next.run(request).await) } else { Err(StatusCode::UNAUTHORIZED) }
}

// ── HTTP Endpoints ──
async fn login_page(jar: CookieJar, AxumState(state): AxumState<Arc<AppState>>) -> Response {
    if jar.get(SESSION_COOKIE).is_some() {
        return Response::builder().status(303).header("Location", "/dashboard").body(Body::empty()).unwrap();
    }
    Html(pages::LOGIN_HTML).into_response()
}

async fn dashboard(jar: CookieJar, AxumState(state): AxumState<Arc<AppState>>) -> Response {
    if jar.get(SESSION_COOKIE).is_none() {
        return Response::builder().status(303).header("Location", "/login").body(Body::empty()).unwrap();
    }
    Html(pages::DASHBOARD_HTML).into_response()
}

#[derive(Deserialize)]
struct LoginReq { password: String }
async fn api_login(AxumState(state): AxumState<Arc<AppState>>, jar: CookieJar, Json(payload): Json<LoginReq>) -> Result<Response, StatusCode> {
    let hash = hash_password(&payload.password, &state.config_secret);
    if hash != *state.auth_hash.read().await {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let token = generate_uuid();
    state.sessions.write().await.insert(token.clone(), now_sec() + SESSION_TTL);
    let cookie = format!("{}={}; Max-Age={}; HttpOnly; Path=/; SameSite=Lax", SESSION_COOKIE, token, SESSION_TTL);
    
    let mut response = Json(serde_json::json!({"ok": true})).into_response();
    response.headers_mut().insert(header::SET_COOKIE, HeaderValue::from_str(&cookie).unwrap());
    Ok(response)
}

// ── VLESS WebSocket Relay ──
async fn vless_tunnel(ws: WebSocketUpgrade, Path(uuid): Path<String>, AxumState(state): AxumState<Arc<AppState>>) -> Response {
    ws.on_upgrade(move |socket| handle_ws(socket, uuid, state))
}

async fn handle_ws(mut socket: WebSocket, uuid: String, state: Arc<AppState>) {
    let allowed = {
        let links = state.links.read().await;
        links.get(&uuid).map_or(false, |l| is_link_allowed(l))
    };
    if !allowed { let _ = socket.close().await; return; }

    let conn_id = generate_uuid().chars().take(8).collect::<String>();
    state.connections.write().await.insert(conn_id.clone(), ConnectionStat {
        uuid: uuid.clone(),
        connected_at: now_iso(),
        bytes: 0,
    });

    if let Ok(Some(msg)) = timeout(std::time::Duration::from_secs(15), socket.recv()).await {
        let first_chunk = match msg {
            Ok(Message::Binary(b)) => b,
            _ => return,
        };

        if first_chunk.len() < 24 { return; }
        let addon_len = first_chunk[17] as usize;
        let pos_cmd = 18 + addon_len;
        if first_chunk.len() <= pos_cmd + 4 { return; }
        
        let port = u16::from_be_bytes([first_chunk[pos_cmd+1], first_chunk[pos_cmd+2]]);
        let addr_type = first_chunk[pos_cmd+3];
        let mut pos = pos_cmd + 4;
        
        let address = match addr_type {
            1 => {
                if first_chunk.len() < pos + 4 { return; }
                let ip = format!("{}.{}.{}.{}", first_chunk[pos], first_chunk[pos+1], first_chunk[pos+2], first_chunk[pos+3]);
                pos += 4; ip
            },
            2 => {
                let dlen = first_chunk[pos] as usize; pos += 1;
                if first_chunk.len() < pos + dlen { return; }
                let dom = String::from_utf8_lossy(&first_chunk[pos..pos+dlen]).to_string();
                pos += dlen; dom
            },
            3 => {
                if first_chunk.len() < pos + 16 { return; }
                pos += 16;
                "ipv6_not_supported".to_string() // Simplified
            },
            _ => return,
        };

        let payload = &first_chunk[pos..];
        
        if let Ok(mut stream) = TcpStream::connect(format!("{}:{}", address, port)).await {
            let _ = stream.set_nodelay(true);
            if !payload.is_empty() {
                let _ = stream.write_all(payload).await;
            }

            let (mut ri, mut wi) = tokio::io::split(stream);
            let (mut ws_tx, mut ws_rx) = socket.split();

            let uuid_cl = uuid.clone();
            let state_cl = state.clone();
            let mut bytes_transfer = 0;

            let c2s = async move {
                while let Some(Ok(Message::Binary(data))) = ws_rx.next().await {
                    if wi.write_all(&data).await.is_err() { break; }
                }
            };

            let s2c = async move {
                let mut buf = vec![0u8; RELAY_BUF];
                let mut first = true;
                while let Ok(n) = ri.read(&mut buf).await {
                    if n == 0 { break; }
                    let mut data = vec![];
                    if first { data.extend_from_slice(&[0, 0]); first = false; }
                    data.extend_from_slice(&buf[..n]);
                    
                    if ws_tx.send(Message::Binary(data)).await.is_err() { break; }
                }
            };

            tokio::select! {
                _ = c2s => (),
                _ = s2c => (),
            };
        }
    }

    state.connections.write().await.remove(&conn_id);
    tokio::spawn(async move { save_state(&state).await; });
}

// ── Router ──
#[tokio::main]
async fn main() {
    let port: u16 = env::var("PORT").unwrap_or_else(|_| "8000".to_string()).parse().unwrap();
    let secret = env::var("SECRET_KEY").unwrap_or_else(|_| "default_secret".to_string());
    
    let app_state = Arc::new(AppState {
        links: RwLock::new(HashMap::new()),
        subs: RwLock::new(HashMap::new()),
        auth_hash: RwLock::new(hash_password(&env::var("ADMIN_PASSWORD").unwrap_or_else(|_| "123456".to_string()), &secret)),
        sessions: RwLock::new(HashMap::new()),
        connections: RwLock::new(HashMap::new()),
        stats_total_bytes: RwLock::new(0),
        stats_total_requests: RwLock::new(0),
        stats_total_errors: RwLock::new(0),
        start_time: now_sec(),
        error_logs: RwLock::new(VecDeque::with_capacity(50)),
        hourly_traffic: RwLock::new(HashMap::new()),
        http_client: reqwest::Client::new(),
        config_secret: secret,
        config_host: env::var("RAILWAY_PUBLIC_DOMAIN").unwrap_or_else(|_| "localhost".to_string()),
        data_file: env::var("DATA_DIR").unwrap_or_else(|_| "/data".to_string()) + "/rvg_state.json",
        save_lock: Mutex::new(()),
    });

    load_state(&app_state).await;

    let api_routes = Router::new()
        .route("/login", post(api_login))
        // Protect remaining API endpoints
        .route_layer(middleware::from_fn_with_state(app_state.clone(), auth_middleware));

    let app = Router::new()
        .route("/", get(|| async { Json(serde_json::json!({"service": "RVG Gateway", "version": "9.0", "status": "active"})) }))
        .route("/login", get(login_page))
        .route("/dashboard", get(dashboard))
        .route("/ws/:uuid", get(vless_tunnel))
        .nest("/api", api_routes)
        .with_state(app_state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    println!("🚀 RVG Gateway started on port {}", port);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}