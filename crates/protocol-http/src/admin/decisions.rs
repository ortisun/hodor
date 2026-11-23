//! The record of decisions, as the administration and console interfaces
//! read it and set what it keeps.
//!
//! Specified in `docs/api/admin-api.md`, "The record of decisions".

use super::{PageBody, Shared, authorize, body, failed, problem, written};
use axum::Router;
use axum::body::Bytes;
use axum::extract::{RawQuery, State};
use axum::http::StatusCode;
use axum::http::header::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Json};
use hodor_authorization::api::{
    DecisionFilter, DecisionLogMode, DecisionLogSettings, DecisionRecord, Effect, MaskPath,
    SubjectKind,
};
use hodor_kernel::{Cursor, PageRequest, TenantContext};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

pub(super) fn routes() -> Router<Shared> {
    Router::new()
        .route("/decision-log", get(read_settings).put(replace_settings))
        .route("/decisions", get(list_decisions))
}

/// The modes as the interface writes them.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ModeBody {
    Full,
    Sampled,
    DenyOnly,
    Off,
}

/// The settings of the record of decisions.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SettingsBody {
    mode: ModeBody,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    allow_sample_percent: Option<u8>,
    #[serde(default)]
    masks: Vec<String>,
    retention_days: u16,
}

impl From<&DecisionLogSettings> for SettingsBody {
    fn from(settings: &DecisionLogSettings) -> Self {
        let mode = match settings.mode() {
            DecisionLogMode::Full => ModeBody::Full,
            DecisionLogMode::Sampled { .. } => ModeBody::Sampled,
            DecisionLogMode::DenyOnly => ModeBody::DenyOnly,
            DecisionLogMode::Off => ModeBody::Off,
        };
        Self {
            mode,
            allow_sample_percent: settings.mode().allow_percent(),
            masks: settings
                .masks()
                .iter()
                .map(|mask| mask.as_str().to_owned())
                .collect(),
            retention_days: settings.retention_days(),
        }
    }
}

impl SettingsBody {
    fn settings(self) -> Result<DecisionLogSettings, hodor_kernel::DomainError> {
        let name = match self.mode {
            ModeBody::Full => "full",
            ModeBody::Sampled => "sampled",
            ModeBody::DenyOnly => "deny_only",
            ModeBody::Off => "off",
        };
        let mode = DecisionLogMode::parse(name, self.allow_sample_percent)?;
        let masks = self
            .masks
            .iter()
            .map(|mask| MaskPath::parse(mask))
            .collect::<Result<Vec<_>, _>>()?;
        DecisionLogSettings::new(mode, masks, self.retention_days)
    }
}

async fn read_settings(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
) -> Response {
    super::respond(
        async {
            authorize(&state, &tenant, &headers, "GET", "/decision-log").await?;
            let settings = state.decisions.settings(&tenant).await.map_err(failed)?;
            Ok(Json(SettingsBody::from(&settings)).into_response())
        }
        .await,
    )
}

async fn replace_settings(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    super::respond(
        async {
            let caller = authorize(&state, &tenant, &headers, "PUT", "/decision-log").await?;
            let asked: SettingsBody = body(&bytes)?;
            let settings = asked.settings().map_err(failed)?;
            let now = state
                .decisions
                .replace_settings(&tenant, settings, caller)
                .await
                .map_err(failed)?;
            Ok(Json(SettingsBody::from(&now)).into_response())
        }
        .await,
    )
}

#[derive(Debug, Serialize)]
struct SubjectBody {
    kind: &'static str,
    id: String,
}

#[derive(Debug, Serialize)]
struct ResourceBody {
    #[serde(rename = "type")]
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
}

#[derive(Debug, Serialize)]
struct RecordBody {
    decision_id: String,
    namespace: String,
    subject: SubjectBody,
    action: String,
    resource: ResourceBody,
    effect: &'static str,
    reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    engine: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_version: Option<String>,
    decided_at: String,
    duration_microseconds: u64,
    input: serde_json::Value,
    masked: Vec<String>,
}

impl From<DecisionRecord> for RecordBody {
    fn from(record: DecisionRecord) -> Self {
        Self {
            decision_id: record.decision_id.to_string(),
            namespace: record.namespace,
            subject: SubjectBody {
                kind: record.subject_kind.as_str(),
                id: record.subject_id,
            },
            action: record.action,
            resource: ResourceBody {
                kind: record.resource_type,
                id: record.resource_id,
            },
            effect: match record.effect {
                Effect::Allow => "allow",
                Effect::Deny => "deny",
                Effect::Indeterminate => "indeterminate",
            },
            reason: record.reason,
            engine: record.engine,
            policy_version: record.policy_version,
            decided_at: written(record.decided_at),
            duration_microseconds: record.duration_microseconds,
            input: record.input,
            masked: record.masked,
        }
    }
}

/// Reads the filters, the limit and the cursor of a listing. Values are
/// percent-decoded: a namespace is an address.
fn listing(query: Option<&str>) -> Result<(DecisionFilter, PageRequest), Box<Response>> {
    let invalid = |detail: &'static str| {
        problem(
            StatusCode::UNPROCESSABLE_ENTITY,
            "request.query_invalid",
            detail,
        )
    };
    let time = |value: &str| {
        OffsetDateTime::parse(value, &Rfc3339)
            .map_err(|_| invalid("from and to are RFC 3339 times"))
    };
    let mut filter = DecisionFilter::default();
    let (mut limit, mut cursor) = (None, None);
    let (mut subject_kind, mut subject_id) = (None, None);
    for (name, value) in form_urlencoded::parse(query.unwrap_or_default().as_bytes()) {
        match name.as_ref() {
            "from" => filter.from = Some(time(&value)?),
            "to" => filter.to = Some(time(&value)?),
            "effect" => {
                filter.effect = Some(match value.as_ref() {
                    "allow" => Effect::Allow,
                    "deny" => Effect::Deny,
                    "indeterminate" => Effect::Indeterminate,
                    _ => return Err(invalid("effect is allow, deny or indeterminate")),
                });
            }
            "namespace" => filter.namespace = Some(value.into_owned()),
            "subject_kind" => {
                subject_kind = Some(
                    SubjectKind::parse(&value)
                        .map_err(|_| invalid("subject_kind is user or client"))?,
                );
            }
            "subject_id" => subject_id = Some(value.into_owned()),
            "limit" => {
                let asked: u32 = value
                    .parse()
                    .map_err(|_| invalid("limit must be a number from 1 to 200"))?;
                if !(1..=PageRequest::MAX_LIMIT).contains(&asked) {
                    return Err(invalid("limit must be a number from 1 to 200"));
                }
                limit = Some(asked);
            }
            "cursor" => cursor = Some(Cursor::new(value.into_owned())),
            _ => {}
        }
    }
    filter.subject = match (subject_kind, subject_id) {
        (Some(kind), Some(id)) => Some((kind, id)),
        (None, None) => None,
        _ => return Err(invalid("subject_kind and subject_id are given together")),
    };
    Ok((filter, PageRequest::new(limit, cursor)))
}

async fn list_decisions(
    State(state): State<Shared>,
    Extension(tenant): Extension<TenantContext>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    super::respond(
        async {
            authorize(&state, &tenant, &headers, "GET", "/decisions").await?;
            let (filter, page) = listing(query.as_deref())?;
            let records = state
                .decisions
                .page(&tenant, &filter, &page)
                .await
                .map_err(failed)?;
            let body: PageBody<RecordBody> = records.map(RecordBody::from).into();
            Ok(Json(body).into_response())
        }
        .await,
    )
}
