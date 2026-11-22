//! What the tests of the running server share: the server as a process,
//! and a browser as far as these tests need one.

#![allow(dead_code, reason = "each test file uses the parts it needs")]

use hodor_adapters_postgres::testing::TestDatabase;
use reqwest::header::{COOKIE, SET_COOKIE};
use reqwest::{Client, Method, Response, StatusCode};
use std::collections::BTreeMap;
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

/// Light hashing parameters, the same for the test's setup and for the
/// server, so that the test is quick. The algorithm is the real one.
pub(crate) const MEMORY_KIBIBYTES: u32 = 1024;
pub(crate) const PASSES: u32 = 1;

pub(crate) struct Server {
    process: Child,
    /// Where the public listener answers.
    pub(crate) base: String,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .and_then(|listener| listener.local_addr())
        .expect("a free port")
        .port()
}

pub(crate) async fn start_server(database: &TestDatabase) -> Server {
    start_server_with(database, &[]).await
}

/// Starts the server with more settings than the tests usually need.
pub(crate) async fn start_server_with(
    database: &TestDatabase,
    settings: &[(&str, &str)],
) -> Server {
    let (public, ops) = (free_port(), free_port());
    let process = Command::new(env!("CARGO_BIN_EXE_hodor-server"))
        .envs(settings.iter().copied())
        .env("HODOR_DATABASE_URL", database.app_url())
        .env("HODOR_LISTEN_ADDR", format!("127.0.0.1:{public}"))
        .env("HODOR_OPS_ADDR", format!("127.0.0.1:{ops}"))
        .env(
            "HODOR_PASSWORD_HASH_MEMORY_KIBIBYTES",
            MEMORY_KIBIBYTES.to_string(),
        )
        .env("HODOR_PASSWORD_HASH_PASSES", PASSES.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("the server should start");
    let server = Server {
        process,
        base: format!("http://127.0.0.1:{public}"),
    };
    let ready = format!("http://127.0.0.1:{ops}/readyz");
    for _ in 0..100 {
        if reqwest::get(&ready)
            .await
            .is_ok_and(|r| r.status().is_success())
        {
            return server;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the server did not become ready");
}

/// A browser, as far as these tests need one.
pub(crate) struct Browser {
    /// The connection the browser sends requests over.
    pub(crate) client: Client,
    base: String,
    /// The cookies the server has set.
    pub(crate) cookies: BTreeMap<String, String>,
    /// The token to send back with requests that change something.
    pub(crate) csrf_token: Option<String>,
}

impl Browser {
    pub(crate) fn new(server: &Server) -> Self {
        Self {
            client: Client::new(),
            base: server.base.clone(),
            cookies: BTreeMap::new(),
            csrf_token: None,
        }
    }

    /// A browser that does not follow redirects, so that a test sees where
    /// each answer sends it.
    pub(crate) fn not_following(server: &Server) -> Self {
        Self {
            client: Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("client"),
            ..Self::new(server)
        }
    }

    fn keep_cookies(&mut self, response: &Response) {
        for cookie in response.headers().get_all(SET_COOKIE) {
            let cookie = cookie.to_str().expect("ascii");
            let (name, value) = cookie
                .split(';')
                .next()
                .and_then(|pair| pair.split_once('='))
                .expect("name=value");
            if cookie.contains("Max-Age=0") {
                self.cookies.remove(name);
            } else {
                self.cookies.insert(name.to_owned(), value.to_owned());
            }
        }
    }

    /// Sends a request as a browser navigates: with its cookies, and a
    /// form body when one is given. Answers the status, where it sends the
    /// browser if anywhere, and the body as text.
    pub(crate) async fn navigate(
        &mut self,
        method: Method,
        path: &str,
        form: Option<&str>,
    ) -> (StatusCode, Option<String>, String) {
        let url = if path.starts_with("http") {
            path.to_owned()
        } else {
            format!("{}{path}", self.base)
        };
        let mut request = self.client.request(method, url);
        if !self.cookies.is_empty() {
            let cookies: Vec<String> = self
                .cookies
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect();
            request = request.header(COOKIE, cookies.join("; "));
        }
        if let Some(form) = form {
            request = request
                .header("content-type", "application/x-www-form-urlencoded")
                .body(form.to_owned());
        }
        let response: Response = request.send().await.expect("response");
        self.keep_cookies(&response);
        let status = response.status();
        let location = response
            .headers()
            .get("location")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        (status, location, response.text().await.unwrap_or_default())
    }

    pub(crate) async fn send(
        &mut self,
        method: Method,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> (StatusCode, serde_json::Value) {
        let mut request = self.client.request(method, format!("{}{path}", self.base));
        if !self.cookies.is_empty() {
            let cookies: Vec<String> = self
                .cookies
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect();
            request = request.header(COOKIE, cookies.join("; "));
        }
        if let Some(token) = &self.csrf_token {
            request = request.header("x-csrf-token", token);
        }
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response: Response = request.send().await.expect("response");
        for cookie in response.headers().get_all(SET_COOKIE) {
            let cookie = cookie.to_str().expect("ascii");
            let (name, value) = cookie
                .split(';')
                .next()
                .and_then(|pair| pair.split_once('='))
                .expect("name=value");
            if cookie.contains("Max-Age=0") {
                self.cookies.remove(name);
            } else {
                self.cookies.insert(name.to_owned(), value.to_owned());
            }
        }
        let status = response.status();
        let body: serde_json::Value = response.json().await.unwrap_or(serde_json::Value::Null);
        if let Some(token) = body["csrf_token"].as_str() {
            self.csrf_token = Some(token.to_owned());
        }
        (status, body)
    }

    pub(crate) async fn sign_in(
        &mut self,
        tenant: &str,
        identifier: &str,
        password: &str,
    ) -> (StatusCode, serde_json::Value) {
        let base = format!("/t/{tenant}/interaction/sign-in");
        self.send(Method::POST, &base, None).await;
        self.send(
            Method::POST,
            &format!("{base}/steps/identifier"),
            Some(serde_json::json!({ "identifier": identifier })),
        )
        .await;
        self.send(
            Method::POST,
            &format!("{base}/steps/password"),
            Some(serde_json::json!({ "password": password })),
        )
        .await
    }
}
