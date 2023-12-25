async fn get_access_token() -> String {
    use chrono::{DateTime, Utc};
    use tokio::sync::Mutex;

    lazy_static::lazy_static! {
        static ref ACCESS_TOKEN: Mutex<(DateTime<Utc>, String)> =
            Mutex::new((DateTime::<Utc>::MIN_UTC, "".to_string()));
    }

    let now = chrono::Utc::now();
    let mut access_token = ACCESS_TOKEN.lock().await;
    if access_token.0 < now {
        let new_token = authorize::force_update_access_token().await;
        (*access_token).0 = chrono::Utc::now() + chrono::Duration::seconds(3600 - 3);
        (*access_token).1 = new_token;
    }

    (*access_token).1.clone()
}

use serde_json::{Map, Value};

pub async fn play_album(album_id: &str, index: u32) {
    let endpoint = "https://api.spotify.com/v1/me/player/play";

    let spotify_uri = format!("spotify:album:{}", album_id);

    let mut body_json = Map::new();
    body_json.insert("context_uri".to_owned(), Value::String(spotify_uri));
    body_json.insert(
        "offset".to_owned(),
        Value::Object({
            let mut tmp = Map::new();
            tmp.insert("position".to_owned(), Value::Number(index.into()));
            tmp
        }),
    );
    body_json.insert("position_ms".to_owned(), Value::Number(0.into()));

    let access_token = get_access_token().await;
    let response = reqwest::Client::new()
        .put(endpoint)
        .header("Authorization", format!("Bearer {}", access_token))
        .header("Content-Type", "application/json")
        .json(&body_json)
        .send()
        .await
        .expect("play");

    if !response.status().is_success() {
        println!("failed to play");
    }
}

pub async fn pause_playbck() {
    let endpoint = "https://api.spotify.com/v1/me/player/pause";

    let access_token = get_access_token().await;
    let response = reqwest::Client::new()
        .put(endpoint)
        .header("Authorization", format!("Bearer {}", access_token))
        .header("Content-Type", "application/json")
        .json("")
        .send()
        .await
        .expect("pause");

    if !response.status().is_success() {
        println!("failed to pause");
    }
}

mod authorize {
    #[derive(Debug)]
    struct AuthCode {
        code: String,
        state: String,
    }

    fn get_basic_auth() -> String {
        let client_id = "a8df3a7e3a0c48648817193a4958f898";
        let client_secret = "f7f4b33084e94676a579e54d44004bb9";

        use base64::engine::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", client_id, client_secret))
    }

    async fn get_refresh_token() {
        let (tx, rx) = tokio::sync::oneshot::channel::<AuthCode>();
        let server_handle = tokio::spawn(start_localhost_server(tx));

        let client_id = "a8df3a7e3a0c48648817193a4958f898";

        let redirect_uri = "http://localhost:31415/";
        let scope = "user-modify-playback-state user-read-playback-state";
        let state = "0123456789ABCDEF"; // FIXME: use randomly generated value

        let client = reqwest::Client::new();

        let request = client
            .get("https://accounts.spotify.com/authorize")
            .query(&[
                ("response_type", "code"),
                ("client_id", client_id),
                ("redirect_uri", redirect_uri),
                ("scope", scope),
                ("state", state),
            ])
            .build()
            .expect("building a HTTP GET request");
        println!("open this link in your browser: {}", request.url());

        let auth_code = rx.await.unwrap();
        assert_eq!(auth_code.state, state);
        server_handle.abort();

        #[allow(dead_code)]
        #[derive(Debug, serde::Deserialize)]
        struct Response {
            access_token: String,
            token_type: String,
            expires_in: i64,
            refresh_token: String,
            scope: String,
        }

        let response = client
            .post("https://accounts.spotify.com/api/token")
            .header("Authorization", format!("Basic {}", get_basic_auth()))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", &auth_code.code),
                ("redirect_uri", redirect_uri),
            ])
            .send()
            .await
            .expect("failed to send a HTTP POST request, try again")
            .json::<Response>()
            .await
            .expect("got an unexpected response");

        let refresh_token = response.refresh_token;

        std::fs::write("/tmp/spotify_refresh_token", &refresh_token).unwrap();
    }

    pub async fn force_update_access_token() -> String {
        if !std::path::Path::new("/tmp/spotify_refresh_token").exists() {
            get_refresh_token().await;
        }

        let refresh_token = {
            let bytes = std::fs::read("/tmp/spotify_refresh_token").unwrap();
            String::from_utf8(bytes).expect("invalid UTF-8")
        };

        #[allow(dead_code)]
        #[derive(Debug, serde::Deserialize)]
        struct Response {
            access_token: String,
            token_type: String,
            expires_in: i64,
            scope: String,
        }

        println!("updating access_token ...");

        let response = reqwest::Client::new()
            .post("https://accounts.spotify.com/api/token")
            .header("Authorization", format!("Basic {}", get_basic_auth()))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", &refresh_token),
            ])
            .send()
            .await
            .expect("failed to refresh the access token")
            .json::<Response>()
            .await
            .expect("got an unexpected response");

        response.access_token
    }

    async fn start_localhost_server(tx: tokio::sync::oneshot::Sender<AuthCode>) {
        use hyper::server::conn::AddrStream;
        use hyper::service::{make_service_fn, service_fn};
        use hyper::{Body, Request, Response, Server};
        use std::convert::Infallible;

        let tx = std::sync::Arc::new(tokio::sync::Mutex::new(Some(tx)));

        let make_svc = make_service_fn({
            let tx = tx.clone();
            move |_socket: &AddrStream| {
                let tx = tx.clone();
                async move {
                    Ok::<_, Infallible>(service_fn({
                        let tx = tx.clone();
                        move |req: Request<Body>| {
                            let tx = tx.clone();
                            async move {
                                if let Some(queries) = req.uri().query() {
                                    // FIXME: consider ordering of the parameters
                                    // FIXME: consider cases where the user canceled the request
                                    let re = regex::Regex::new(r"^code=(.+)&state=(.+)$").unwrap();
                                    if let Some(groups) = re.captures(queries) {
                                        if groups.len() == 3 {
                                            if let Some(tx) = tx.lock().await.take() {
                                                let auth_code = AuthCode {
                                                    code: groups
                                                        .get(1)
                                                        .unwrap()
                                                        .as_str()
                                                        .to_owned(),
                                                    state: groups
                                                        .get(2)
                                                        .unwrap()
                                                        .as_str()
                                                        .to_owned(),
                                                };
                                                tx.send(auth_code).unwrap();
                                                return Ok::<_, Infallible>(Response::new(Body::from(
                                "<body>Successfully Authorized! You can now close this page and go back to your terminal.</body>",
                            )));
                                            }
                                        }
                                    }
                                }

                                Ok::<_, Infallible>(Response::new(Body::from("")))
                            }
                        }
                    }))
                }
            }
        });

        let addr = ([127, 0, 0, 1], 31415).into();
        if let Err(e) = Server::bind(&addr).serve(make_svc).await {
            eprintln!("server error: {}", e);
        }
    }
}
