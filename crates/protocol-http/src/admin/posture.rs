//! The findings of a tenant's security posture, computed when they are
//! read.
//!
//! Specified in `docs/api/admin-api.md`, "The security posture", and
//! Decision 0083. The one check so far is the OAuth context's: a client
//! marked for access tokens through the browser.

use super::{Shared, authorize, failed, respond, written};
use axum::Router;
use axum::extract::State;
use axum::http::header::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Json};
use hodor_kernel::TenantContext;
use hodor_oauth::api::Client;
use serde::Serialize;
use serde_json::{Value, json};

/// The check of a marked client.
const MARKED_CLIENT_CHECK: &str = "client_marked_for_browser_access_tokens";

pub(super) fn routes() -> Router<Shared> {
    Router::new().route("/posture/findings", get(list_findings))
}

#[derive(Debug, Serialize)]
struct FindingBody {
    check: &'static str,
    severity: &'static str,
    summary: &'static str,
    object: Value,
    detail: Value,
    set_by: Value,
    since: String,
}

#[derive(Debug, Serialize)]
struct Findings {
    items: Vec<FindingBody>,
}

/// The finding of a client marked for access tokens through the browser,
/// if it is.
fn marked_client(client: &Client) -> Option<FindingBody> {
    let mark = client.browser_access_tokens()?;
    Some(FindingBody {
        check: MARKED_CLIENT_CHECK,
        severity: "medium",
        summary: "The client may receive access tokens through the browser, where they can \
                  leak through its history, its logs and the other scripts of its page",
        object: json!({
            "type": "client",
            "id": client.id().to_string(),
            "application_id": client.application_id().to_string(),
            "name": client.snapshot().settings.name,
        }),
        detail: json!({ "scopes": mark.scopes }),
        set_by: json!(mark.marked_by),
        since: written(mark.marked_at),
    })
}

async fn list_findings(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
) -> Response {
    respond(
        async {
            authorize(&state, &tenant, &headers, "GET", "/posture/findings").await?;
            let clients = state
                .applications
                .marked_clients(&tenant)
                .await
                .map_err(failed)?;
            let items = clients.iter().filter_map(marked_client).collect();
            Ok(Json(Findings { items }).into_response())
        }
        .await,
    )
}
