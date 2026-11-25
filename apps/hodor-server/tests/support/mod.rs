//! What the tests of the running server share: the server as a process,
//! and a browser as far as these tests need one.

#![allow(dead_code, reason = "each test file uses the parts it needs")]

use hodor_adapters_postgres::testing::TestDatabase;
use reqwest::header::{COOKIE, SET_COOKIE};
use reqwest::{Client, Method, Response, StatusCode};
use std::collections::{BTreeMap, VecDeque};
use std::io::{BufRead as _, BufReader, Read};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// Light hashing parameters, the same for the test's setup and for the
/// server, so that the test is quick. The algorithm is the real one.
pub(crate) const MEMORY_KIBIBYTES: u32 = 1024;
pub(crate) const PASSES: u32 = 1;

/// How long a server may take to become ready. A test file starts a
/// server and a database per test, all at once, and on a busy machine ten
/// seconds were not always enough.
const READY_WITHIN: Duration = Duration::from_secs(30);

/// How many of the last lines the server wrote are kept, and shown when it
/// does not become ready or a test fails.
const LINES_KEPT: usize = 200;
const LINES_SHOWN: usize = 40;

pub(crate) struct Server {
    process: Child,
    /// Where the public listener answers.
    pub(crate) base: String,
    output: Arc<Mutex<Output>>,
    readers: Vec<JoinHandle<()>>,
    /// Whether a panic already showed what the server wrote.
    shown: bool,
}

impl Drop for Server {
    #[expect(
        clippy::print_stderr,
        reason = "the test's own output, shown when the test fails"
    )]
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
        if std::thread::panicking() && !self.shown {
            eprintln!("the end of what the server wrote:\n{}", tail(&self.output));
        }
    }
}

/// What the server wrote, on its standard output and its standard error.
#[derive(Default)]
struct Output {
    lines: VecDeque<String>,
    /// The addresses of the public and the operations listeners, from the
    /// line the server writes once it listens.
    listening: Option<(String, String)>,
}

/// Reads one stream of the server on a thread of its own until the server
/// closes it, so that the server never waits on a full pipe.
fn read_into(stream: impl Read + Send + 'static, output: &Arc<Mutex<Output>>) -> JoinHandle<()> {
    let output = Arc::clone(output);
    std::thread::spawn(move || {
        let mut stream = BufReader::new(stream);
        let mut line = Vec::new();
        while stream
            .read_until(b'\n', &mut line)
            .is_ok_and(|read| read > 0)
        {
            let text = String::from_utf8_lossy(&line).trim_end().to_owned();
            line.clear();
            let mut output = output.lock().unwrap_or_else(PoisonError::into_inner);
            if output.listening.is_none() {
                output.listening = listening(&text);
            }
            if output.lines.len() == LINES_KEPT {
                output.lines.pop_front();
            }
            output.lines.push_back(text);
        }
    })
}

/// The addresses in the line `hodor-server started`, written in JSON.
fn listening(line: &str) -> Option<(String, String)> {
    let line: serde_json::Value = serde_json::from_str(line).ok()?;
    if line["message"] != "hodor-server started" {
        return None;
    }
    Some((
        line["listen"].as_str()?.to_owned(),
        line["ops"].as_str()?.to_owned(),
    ))
}

fn tail(output: &Mutex<Output>) -> String {
    let output = output.lock().unwrap_or_else(PoisonError::into_inner);
    let skipped = output.lines.len().saturating_sub(LINES_SHOWN);
    output
        .lines
        .iter()
        .skip(skipped)
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join("\n")
}

pub(crate) async fn start_server(database: &TestDatabase) -> Server {
    start_server_with(database, &[]).await
}

/// Starts the server with more settings than the tests usually need.
///
/// The server chooses its own ports and says which in the line it writes
/// once it listens. Ports chosen here and handed to it would be free when
/// chosen, not when the server binds them: on a busy machine another test,
/// another server or a connection may take one in between, and the server
/// then stops at once.
pub(crate) async fn start_server_with(
    database: &TestDatabase,
    settings: &[(&str, &str)],
) -> Server {
    let mut process = Command::new(env!("CARGO_BIN_EXE_hodor-server"))
        .envs(settings.iter().copied())
        .env("HODOR_DATABASE_URL", database.app_url())
        .env("HODOR_LISTEN_ADDR", "127.0.0.1:0")
        .env("HODOR_OPS_ADDR", "127.0.0.1:0")
        .env("HODOR_LOG_FORMAT", "json")
        .env(
            "HODOR_PASSWORD_HASH_MEMORY_KIBIBYTES",
            MEMORY_KIBIBYTES.to_string(),
        )
        .env("HODOR_PASSWORD_HASH_PASSES", PASSES.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the server should start");
    let output = Arc::new(Mutex::new(Output::default()));
    let readers = vec![
        read_into(process.stdout.take().expect("standard output"), &output),
        read_into(process.stderr.take().expect("standard error"), &output),
    ];
    let mut server = Server {
        process,
        base: String::new(),
        output,
        readers,
        shown: false,
    };

    let client = Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .expect("client");
    let deadline = Instant::now() + READY_WITHIN;
    loop {
        if let Some(status) = server.process.try_wait().expect("the server's status") {
            // Everything it wrote, up to its last line.
            for reader in server.readers.drain(..) {
                let _ = reader.join();
            }
            server.shown = true;
            panic!(
                "the server stopped before it was ready, {status}; the end of what it wrote:\n{}",
                tail(&server.output)
            );
        }
        let listening = server
            .output
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .listening
            .clone();
        if let Some((public, ops)) = listening {
            let ready = client.get(format!("http://{ops}/readyz")).send().await;
            if ready.is_ok_and(|response| response.status().is_success()) {
                server.base = format!("http://{public}");
                return server;
            }
        }
        if Instant::now() >= deadline {
            server.shown = true;
            panic!(
                "the server did not become ready within {} seconds; the end of what it wrote:\n{}",
                READY_WITHIN.as_secs(),
                tail(&server.output)
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
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

/// The bytes of a secret written in base32 without padding (RFC 4648).
pub(crate) fn base32(text: &str) -> Vec<u8> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let (mut bytes, mut buffer, mut bits) = (Vec::new(), 0_u32, 0_u32);
    for character in text.bytes() {
        let value = ALPHABET
            .iter()
            .position(|&c| c == character)
            .expect("base32");
        buffer = (buffer << 5) | u32::try_from(value).expect("small");
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            bytes.push(u8::try_from((buffer >> bits) & 0xff).expect("a byte"));
        }
    }
    bytes
}
