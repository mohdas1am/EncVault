use actix_cors::Cors;
use actix_files as afs;
use actix_web::{web, App, HttpServer, HttpRequest, HttpResponse, middleware};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use std::sync::Mutex;
use uuid::Uuid;
use chrono::Utc;

use crate::{kem, encrypt_data, decrypt_data, utils};

// ─── Data Models ────────────────────────────────────────────────────

#[derive(Clone)]
struct User {
    username: String,
    password_hash: String,
    public_key: Vec<u8>,
    secret_key: Vec<u8>,
}

#[derive(Clone, Serialize)]
struct EncryptedFile {
    id: String,
    filename: String,
    encrypted_payload: String,
    sender: String,
    recipient: String,
    timestamp: String,
}

struct AppState {
    users: HashMap<String, User>,
    files: Vec<EncryptedFile>,
    sessions: HashMap<String, String>, // token -> username
}

// ─── Request / Response Types ───────────────────────────────────────

#[derive(Deserialize)]
struct AuthRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct AuthResponse {
    success: bool,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    token: Option<String>,
}

#[derive(Serialize)]
struct UserInfo {
    username: String,
    public_key: String,
}

#[derive(Deserialize)]
struct EncryptRequest {
    filename: String,
    data: String,
    recipient: String,
}

#[derive(Deserialize)]
struct DecryptRequest {
    file_id: String,
}

#[derive(Serialize)]
struct DecryptResponse {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    plaintext: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    filename: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

// ─── Helpers ────────────────────────────────────────────────────────

fn hash_password(password: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn get_username_from_token(req: &HttpRequest, state: &AppState) -> Option<String> {
    let auth_header = req.headers().get("Authorization")?.to_str().ok()?;
    let token = auth_header.strip_prefix("Bearer ")?;
    state.sessions.get(token).cloned()
}

// ─── Handlers ───────────────────────────────────────────────────────

async fn signup(
    data: web::Data<Mutex<AppState>>,
    body: web::Json<AuthRequest>,
) -> HttpResponse {
    let mut state = data.lock().unwrap();

    if body.username.trim().is_empty() || body.password.trim().is_empty() {
        return HttpResponse::BadRequest().json(AuthResponse {
            success: false,
            message: "Username and password are required".into(),
            token: None,
        });
    }

    if state.users.contains_key(&body.username) {
        return HttpResponse::Conflict().json(AuthResponse {
            success: false,
            message: "Username already exists".into(),
            token: None,
        });
    }

    // Generate ML-KEM 768 keypair for the user
    let (pk, sk) = kem::keygen();

    let user = User {
        username: body.username.clone(),
        password_hash: hash_password(&body.password),
        public_key: pk,
        secret_key: sk,
    };

    state.users.insert(body.username.clone(), user);

    // Auto-login: create session
    let token = Uuid::new_v4().to_string();
    state.sessions.insert(token.clone(), body.username.clone());

    HttpResponse::Ok().json(AuthResponse {
        success: true,
        message: format!("User '{}' created with ML-KEM 768 keypair", body.username),
        token: Some(token),
    })
}

async fn login(
    data: web::Data<Mutex<AppState>>,
    body: web::Json<AuthRequest>,
) -> HttpResponse {
    let mut state = data.lock().unwrap();

    let password_hash = hash_password(&body.password);

    match state.users.get(&body.username) {
        Some(user) if user.password_hash == password_hash => {
            let token = Uuid::new_v4().to_string();
            state.sessions.insert(token.clone(), body.username.clone());

            HttpResponse::Ok().json(AuthResponse {
                success: true,
                message: "Login successful".into(),
                token: Some(token),
            })
        }
        _ => HttpResponse::Unauthorized().json(AuthResponse {
            success: false,
            message: "Invalid username or password".into(),
            token: None,
        }),
    }
}

async fn logout(
    req: HttpRequest,
    data: web::Data<Mutex<AppState>>,
) -> HttpResponse {
    let mut state = data.lock().unwrap();

    if let Some(auth_header) = req.headers().get("Authorization") {
        if let Ok(header_str) = auth_header.to_str() {
            if let Some(token) = header_str.strip_prefix("Bearer ") {
                state.sessions.remove(token);
            }
        }
    }

    HttpResponse::Ok().json(serde_json::json!({"success": true, "message": "Logged out"}))
}

async fn get_me(
    req: HttpRequest,
    data: web::Data<Mutex<AppState>>,
) -> HttpResponse {
    let state = data.lock().unwrap();

    match get_username_from_token(&req, &state) {
        Some(username) => {
            let user = state.users.get(&username).unwrap();
            HttpResponse::Ok().json(UserInfo {
                username: user.username.clone(),
                public_key: utils::b64e(&user.public_key),
            })
        }
        None => HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Not authenticated"
        })),
    }
}

async fn list_users(
    req: HttpRequest,
    data: web::Data<Mutex<AppState>>,
) -> HttpResponse {
    let state = data.lock().unwrap();

    match get_username_from_token(&req, &state) {
        Some(_) => {
            let users: Vec<UserInfo> = state.users.values().map(|u| UserInfo {
                username: u.username.clone(),
                public_key: utils::b64e(&u.public_key),
            }).collect();

            HttpResponse::Ok().json(users)
        }
        None => HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Not authenticated"
        })),
    }
}

async fn encrypt_file(
    req: HttpRequest,
    data: web::Data<Mutex<AppState>>,
    body: web::Json<EncryptRequest>,
) -> HttpResponse {
    let mut state = data.lock().unwrap();

    let sender = match get_username_from_token(&req, &state) {
        Some(u) => u,
        None => return HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Not authenticated"
        })),
    };

    // Get recipient's public key
    let recipient_pk = match state.users.get(&body.recipient) {
        Some(user) => user.public_key.clone(),
        None => return HttpResponse::NotFound().json(serde_json::json!({
            "error": format!("Recipient '{}' not found", body.recipient)
        })),
    };

    // Encrypt the data with the recipient's public key
    match encrypt_data(&body.data, &recipient_pk) {
        Ok(encrypted_payload) => {
            let file = EncryptedFile {
                id: Uuid::new_v4().to_string(),
                filename: body.filename.clone(),
                encrypted_payload,
                sender: sender.clone(),
                recipient: body.recipient.clone(),
                timestamp: Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string(),
            };

            state.files.push(file.clone());

            HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "message": format!("File '{}' encrypted for '{}'", body.filename, body.recipient),
                "file_id": file.id
            }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Encryption failed: {}", e)
        })),
    }
}

async fn get_inbox(
    req: HttpRequest,
    data: web::Data<Mutex<AppState>>,
) -> HttpResponse {
    let state = data.lock().unwrap();

    match get_username_from_token(&req, &state) {
        Some(username) => {
            let inbox: Vec<&EncryptedFile> = state.files.iter()
                .filter(|f| f.recipient == username)
                .collect();

            HttpResponse::Ok().json(inbox)
        }
        None => HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Not authenticated"
        })),
    }
}

async fn get_sent(
    req: HttpRequest,
    data: web::Data<Mutex<AppState>>,
) -> HttpResponse {
    let state = data.lock().unwrap();

    match get_username_from_token(&req, &state) {
        Some(username) => {
            let sent: Vec<&EncryptedFile> = state.files.iter()
                .filter(|f| f.sender == username)
                .collect();

            HttpResponse::Ok().json(sent)
        }
        None => HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Not authenticated"
        })),
    }
}

async fn decrypt_file(
    req: HttpRequest,
    data: web::Data<Mutex<AppState>>,
    body: web::Json<DecryptRequest>,
) -> HttpResponse {
    let state = data.lock().unwrap();

    let username = match get_username_from_token(&req, &state) {
        Some(u) => u,
        None => return HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Not authenticated"
        })),
    };

    // Find the encrypted file
    let file = match state.files.iter().find(|f| f.id == body.file_id) {
        Some(f) => f.clone(),
        None => return HttpResponse::NotFound().json(serde_json::json!({
            "error": "File not found"
        })),
    };

    // Only the recipient can decrypt
    if file.recipient != username {
        return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "You are not the recipient of this file"
        }));
    }

    // Get user's secret key
    let sk = state.users.get(&username).unwrap().secret_key.clone();

    // Decrypt
    match decrypt_data(&file.encrypted_payload, &sk) {
        Ok(plaintext) => HttpResponse::Ok().json(DecryptResponse {
            success: true,
            plaintext: Some(plaintext),
            filename: Some(file.filename),
            message: None,
        }),
        Err(e) => HttpResponse::InternalServerError().json(DecryptResponse {
            success: false,
            plaintext: None,
            filename: None,
            message: Some(format!("Decryption failed: {}", e)),
        }),
    }
}

// ─── Server Startup ─────────────────────────────────────────────────

pub async fn run_server(port: u16) -> std::io::Result<()> {
    let state = web::Data::new(Mutex::new(AppState {
        users: HashMap::new(),
        files: Vec::new(),
        sessions: HashMap::new(),
    }));

    eprintln!("🚀 enc_app server starting on http://localhost:{}", port);
    eprintln!("   Open your browser to http://localhost:{}", port);

    HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
            .max_age(3600);

        App::new()
            .wrap(cors)
            .app_data(state.clone())
            // API Routes
            .route("/api/signup", web::post().to(signup))
            .route("/api/login", web::post().to(login))
            .route("/api/logout", web::post().to(logout))
            .route("/api/me", web::get().to(get_me))
            .route("/api/users", web::get().to(list_users))
            .route("/api/encrypt", web::post().to(encrypt_file))
            .route("/api/files/inbox", web::get().to(get_inbox))
            .route("/api/files/sent", web::get().to(get_sent))
            .route("/api/decrypt", web::post().to(decrypt_file))
            // Serve static frontend
            .service(
                afs::Files::new("/", "./static")
                    .index_file("index.html")
                    .prefer_utf8(true),
            )
    })
    .bind(format!("0.0.0.0:{}", port))?
    .run()
    .await
}
