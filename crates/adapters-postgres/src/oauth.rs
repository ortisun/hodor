//! PostgreSQL storage for the OAuth context.
//!
//! See `docs/architecture/contexts/oauth.md`, "Storage".

use crate::uow::{connection, database_error};
use hodor_kernel::{DomainError, Timestamp, UnitOfWork, UserId};
use hodor_oauth::api::{
    Application, ApplicationId, ApplicationSettings, ApplicationSnapshot, ApplicationStore,
    Audience, AuthenticationMethod, Client, ClientId, ClientKey, ClientSecret, ClientSecretHash,
    ClientSecretId, ClientSettings, ClientSnapshot, ClientStore, ClientType, ExchangeRule,
    GrantType, IdTokenAlgorithm, ResourceServer, ResourceServerId, ResourceServerSettings,
    ResourceServerSnapshot, ResourceServerStore, ScopeDefinition, SpiffeId, Status, SubjectType,
    TokenPolicy,
};
use sqlx::PgConnection;
use sqlx::Row as _;
use sqlx::postgres::PgRow;
use sqlx::types::Uuid;
use time::Duration;

const CLIENT_APPLICATION_CONSTRAINT: &str = "client_application_fk";
const SERVER_APPLICATION_CONSTRAINT: &str = "resource_server_application_fk";
const AUDIENCE_CONSTRAINT: &str = "resource_server_audience_unique";
const ONE_SERVER_CONSTRAINT: &str = "resource_server_application_unique";
const SPIFFE_ID_CONSTRAINT: &str = "client_spiffe_id_unique";

fn spiffe_id_taken() -> DomainError {
    DomainError::conflict(
        "oauth.client_spiffe_id_taken",
        "another client of the tenant is bound to this SPIFFE identifier",
    )
}

fn corrupted(what: &str) -> DomainError {
    DomainError::internal(
        "oauth.stored_data_invalid",
        "stored OAuth data could not be read",
    )
    .with_detail(what.to_owned())
}

fn get(error: sqlx::Error) -> DomainError {
    database_error(&error)
}

fn version_of(version: u32) -> Result<i32, DomainError> {
    i32::try_from(version).map_err(|_| corrupted("version out of range"))
}

fn stored_version(row: &PgRow) -> Result<u32, DomainError> {
    let version: i32 = row.try_get("version").map_err(get)?;
    u32::try_from(version).map_err(|_| corrupted("negative version"))
}

fn seconds(duration: Duration) -> Result<i32, DomainError> {
    i32::try_from(duration.whole_seconds()).map_err(|_| corrupted("duration out of range"))
}

fn application_not_found() -> DomainError {
    DomainError::not_found(
        "oauth.application_not_found",
        "there is no such application",
    )
}

fn modified(code: &'static str) -> DomainError {
    DomainError::conflict(code, "it was changed by someone else; read it again")
}

/// [`ApplicationStore`] on `oauth.application`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PgApplicationStore;

fn application_from(row: &PgRow) -> Result<Application, DomainError> {
    let status: String = row.try_get("status").map_err(get)?;
    Ok(Application::from_snapshot(ApplicationSnapshot {
        id: ApplicationId::from_uuid(row.try_get("id").map_err(get)?),
        settings: ApplicationSettings {
            name: row.try_get("name").map_err(get)?,
            first_party: row.try_get("first_party").map_err(get)?,
        },
        status: Status::from_stored(&status)?,
        created_at: row.try_get("created_at").map_err(get)?,
        updated_at: row.try_get("updated_at").map_err(get)?,
        version: stored_version(row)?,
    }))
}

const APPLICATION_COLUMNS: &str = "id, name, first_party, status, created_at, updated_at, version";

#[async_trait::async_trait]
impl ApplicationStore for PgApplicationStore {
    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        application: &Application,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let state = application.snapshot();
        sqlx::query(
            "INSERT INTO oauth.application
                 (tenant_id, id, name, first_party, status, created_at, updated_at, version)
             VALUES ($1, $2, $3, $4, $5, $6, $7, 0)",
        )
        .bind(tenant.as_uuid())
        .bind(state.id.as_uuid())
        .bind(&state.settings.name)
        .bind(state.settings.first_party)
        .bind(state.status.as_str())
        .bind(state.created_at)
        .bind(state.updated_at)
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        Ok(())
    }

    async fn update(
        &self,
        uow: &mut dyn UnitOfWork,
        application: &Application,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let state = application.snapshot();
        let updated = sqlx::query(
            "UPDATE oauth.application
             SET name = $3, first_party = $4, status = $5, updated_at = $6,
                 version = version + 1
             WHERE tenant_id = $1 AND id = $2 AND version = $7",
        )
        .bind(tenant.as_uuid())
        .bind(state.id.as_uuid())
        .bind(&state.settings.name)
        .bind(state.settings.first_party)
        .bind(state.status.as_str())
        .bind(state.updated_at)
        .bind(version_of(state.version)?)
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        if updated.rows_affected() == 1 {
            Ok(())
        } else {
            Err(modified("oauth.application_modified_concurrently"))
        }
    }

    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        id: ApplicationId,
    ) -> Result<Option<Application>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {APPLICATION_COLUMNS} FROM oauth.application
             WHERE tenant_id = $1 AND id = $2"
        )))
        .bind(tenant.as_uuid())
        .bind(id.as_uuid())
        .fetch_optional(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?
        .as_ref()
        .map(application_from)
        .transpose()
    }

    async fn list(&self, uow: &mut dyn UnitOfWork) -> Result<Vec<Application>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {APPLICATION_COLUMNS} FROM oauth.application
             WHERE tenant_id = $1 ORDER BY created_at, id"
        )))
        .bind(tenant.as_uuid())
        .fetch_all(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?
        .iter()
        .map(application_from)
        .collect()
    }
}

/// A client's exchange rules as they are stored.
fn exchange_rules_of(settings: &ClientSettings) -> serde_json::Value {
    serde_json::Value::Array(
        settings
            .exchange_rules
            .iter()
            .map(|rule| {
                serde_json::json!({
                    "subject_audience": rule.subject_audience,
                    "audience": rule.audience,
                })
            })
            .collect(),
    )
}

fn exchange_rules_from(stored: &serde_json::Value) -> Result<Vec<ExchangeRule>, DomainError> {
    let invalid = || corrupted("exchange rules");
    stored
        .as_array()
        .ok_or_else(invalid)?
        .iter()
        .map(|rule| {
            let text = |name: &str| {
                rule.get(name)
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
                    .ok_or_else(invalid)
            };
            Ok(ExchangeRule {
                subject_audience: text("subject_audience")?,
                audience: text("audience")?,
            })
        })
        .collect()
}

/// [`ClientStore`] on `oauth.client`, `oauth.client_secret` and
/// `oauth.client_key`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PgClientStore;

const CLIENT_COLUMNS: &str = "id, application_id, name, client_type, authentication_method, \
     grant_types, redirect_uris, post_logout_redirect_uris, allowed_scopes, require_pkce, \
     id_token_algorithm, access_token_seconds, id_token_seconds, refresh_token_seconds, \
     refresh_idle_seconds, consent_seconds, status, created_at, updated_at, version, principal_id, \
     exchange_rules, backchannel_logout_uri, backchannel_logout_session_required, subject_type, \
     sector_identifier_uri, spiffe_id";

async fn load_client(
    connection: &mut PgConnection,
    tenant: Uuid,
    row: &PgRow,
) -> Result<Client, DomainError> {
    let id: Uuid = row.try_get("id").map_err(get)?;
    let client_type: String = row.try_get("client_type").map_err(get)?;
    let method: String = row.try_get("authentication_method").map_err(get)?;
    let grants: Vec<String> = row.try_get("grant_types").map_err(get)?;
    let status: String = row.try_get("status").map_err(get)?;
    let duration = |column: &str| -> Result<Duration, DomainError> {
        let value: i32 = row.try_get(column).map_err(get)?;
        Ok(Duration::seconds(i64::from(value)))
    };
    let secrets = sqlx::query(
        "SELECT id, secret_hash, created_at, expires_at FROM oauth.client_secret
         WHERE tenant_id = $1 AND client_id = $2 ORDER BY created_at, id",
    )
    .bind(tenant)
    .bind(id)
    .fetch_all(&mut *connection)
    .await
    .map_err(get)?
    .iter()
    .map(|secret| {
        let hash: Vec<u8> = secret.try_get("secret_hash").map_err(get)?;
        let hash: [u8; 32] = hash
            .try_into()
            .map_err(|_| corrupted("secret hash is not 32 bytes"))?;
        Ok(ClientSecret {
            id: ClientSecretId::from_uuid(secret.try_get("id").map_err(get)?),
            hash: ClientSecretHash::from_stored(hash),
            created_at: secret.try_get("created_at").map_err(get)?,
            expires_at: secret.try_get("expires_at").map_err(get)?,
        })
    })
    .collect::<Result<Vec<_>, DomainError>>()?;
    let keys = sqlx::query(
        "SELECT jwk, added_at FROM oauth.client_key
         WHERE tenant_id = $1 AND client_id = $2 ORDER BY position",
    )
    .bind(tenant)
    .bind(id)
    .fetch_all(&mut *connection)
    .await
    .map_err(get)?
    .iter()
    .map(|key| {
        let jwk: serde_json::Value = key.try_get("jwk").map_err(get)?;
        let added_at: Timestamp = key.try_get("added_at").map_err(get)?;
        // Read through the same rules it was stored under, which also
        // writes it in its one form.
        ClientKey::parse(&jwk.to_string(), added_at).map_err(|_| corrupted("client key"))
    })
    .collect::<Result<Vec<_>, DomainError>>()?;
    Ok(Client::from_snapshot(ClientSnapshot {
        id: ClientId::from_uuid(id),
        application_id: ApplicationId::from_uuid(row.try_get("application_id").map_err(get)?),
        client_type: ClientType::from_stored(&client_type)?,
        settings: ClientSettings {
            name: row.try_get("name").map_err(get)?,
            authentication_method: AuthenticationMethod::parse(&method)
                .map_err(|_| corrupted("authentication method"))?,
            grant_types: grants
                .iter()
                .map(|grant| GrantType::parse(grant).map_err(|_| corrupted("grant type")))
                .collect::<Result<_, _>>()?,
            redirect_uris: row.try_get("redirect_uris").map_err(get)?,
            post_logout_redirect_uris: row.try_get("post_logout_redirect_uris").map_err(get)?,
            allowed_scopes: row.try_get("allowed_scopes").map_err(get)?,
            require_pkce: row.try_get("require_pkce").map_err(get)?,
            id_token_algorithm: IdTokenAlgorithm::parse(
                &row.try_get::<String, _>("id_token_algorithm")
                    .map_err(get)?,
            )
            .map_err(|_| corrupted("ID token algorithm"))?,
            backchannel_logout_uri: row.try_get("backchannel_logout_uri").map_err(get)?,
            backchannel_logout_session_required: row
                .try_get("backchannel_logout_session_required")
                .map_err(get)?,
            subject_type: SubjectType::parse(
                &row.try_get::<String, _>("subject_type").map_err(get)?,
            )
            .map_err(|_| corrupted("subject type"))?,
            sector_identifier_uri: row.try_get("sector_identifier_uri").map_err(get)?,
            token_policy: TokenPolicy {
                access_token: duration("access_token_seconds")?,
                id_token: duration("id_token_seconds")?,
                refresh_token: duration("refresh_token_seconds")?,
                refresh_idle: duration("refresh_idle_seconds")?,
                consent: duration("consent_seconds")?,
            },
            principal: row
                .try_get::<Option<Uuid>, _>("principal_id")
                .map_err(get)?
                .map(UserId::from_uuid),
            exchange_rules: exchange_rules_from(
                &row.try_get::<serde_json::Value, _>("exchange_rules")
                    .map_err(get)?,
            )?,
            spiffe_id: row
                .try_get::<Option<String>, _>("spiffe_id")
                .map_err(get)?
                .map(|text| SpiffeId::parse(&text).map_err(|_| corrupted("SPIFFE identifier")))
                .transpose()?,
        },
        secrets,
        keys,
        status: Status::from_stored(&status)?,
        created_at: row.try_get("created_at").map_err(get)?,
        updated_at: row.try_get("updated_at").map_err(get)?,
        version: stored_version(row)?,
    }))
}

/// Writes the secrets and keys of a client, which has none stored.
async fn insert_parts(
    connection: &mut PgConnection,
    tenant: Uuid,
    client: &Client,
) -> Result<(), DomainError> {
    let state = client.snapshot();
    for secret in &state.secrets {
        sqlx::query(
            "INSERT INTO oauth.client_secret
                 (tenant_id, client_id, id, secret_hash, created_at, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(tenant)
        .bind(state.id.as_uuid())
        .bind(secret.id.as_uuid())
        .bind(secret.hash.as_bytes().as_slice())
        .bind(secret.created_at)
        .bind(secret.expires_at)
        .execute(&mut *connection)
        .await
        .map_err(get)?;
    }
    for (position, key) in state.keys.iter().enumerate() {
        let jwk: serde_json::Value =
            serde_json::from_str(&key.jwk).map_err(|_| corrupted("client key is not JSON"))?;
        sqlx::query(
            "INSERT INTO oauth.client_key
                 (tenant_id, client_id, key_id, jwk, position, added_at)
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(tenant)
        .bind(state.id.as_uuid())
        .bind(&key.key_id)
        .bind(sqlx::types::Json(jwk))
        .bind(i32::try_from(position).map_err(|_| corrupted("too many keys"))?)
        .bind(key.added_at)
        .execute(&mut *connection)
        .await
        .map_err(get)?;
    }
    Ok(())
}

fn grant_names(settings: &ClientSettings) -> Vec<&'static str> {
    settings
        .grant_types
        .iter()
        .map(|grant| grant.as_str())
        .collect()
}

#[async_trait::async_trait]
impl ClientStore for PgClientStore {
    async fn insert(&self, uow: &mut dyn UnitOfWork, client: &Client) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id().as_uuid();
        let state = client.snapshot();
        let settings = &state.settings;
        let policy = settings.token_policy;
        let connection = connection(uow)?;
        let inserted = sqlx::query(
            "INSERT INTO oauth.client
                 (tenant_id, id, application_id, name, client_type, authentication_method,
                  grant_types, redirect_uris, post_logout_redirect_uris, allowed_scopes,
                  require_pkce, access_token_seconds, id_token_seconds, refresh_token_seconds,
                  refresh_idle_seconds, consent_seconds, status, created_at, updated_at,
                  id_token_algorithm, principal_id, exchange_rules, backchannel_logout_uri,
                  backchannel_logout_session_required, subject_type, sector_identifier_uri,
                  spiffe_id, version)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16,
                     $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, 0)",
        )
        .bind(tenant)
        .bind(state.id.as_uuid())
        .bind(state.application_id.as_uuid())
        .bind(&settings.name)
        .bind(state.client_type.as_str())
        .bind(settings.authentication_method.as_str())
        .bind(grant_names(settings))
        .bind(&settings.redirect_uris)
        .bind(&settings.post_logout_redirect_uris)
        .bind(&settings.allowed_scopes)
        .bind(settings.require_pkce)
        .bind(seconds(policy.access_token)?)
        .bind(seconds(policy.id_token)?)
        .bind(seconds(policy.refresh_token)?)
        .bind(seconds(policy.refresh_idle)?)
        .bind(seconds(policy.consent)?)
        .bind(state.status.as_str())
        .bind(state.created_at)
        .bind(state.updated_at)
        .bind(settings.id_token_algorithm.as_str())
        .bind(settings.principal.map(|principal| principal.as_uuid()))
        .bind(exchange_rules_of(settings))
        .bind(settings.backchannel_logout_uri.as_deref())
        .bind(settings.backchannel_logout_session_required)
        .bind(settings.subject_type.as_str())
        .bind(settings.sector_identifier_uri.as_deref())
        .bind(settings.spiffe_id.as_ref().map(SpiffeId::as_str))
        .execute(&mut *connection)
        .await;
        match inserted {
            Ok(_) => {}
            Err(sqlx::Error::Database(error))
                if error.constraint() == Some(CLIENT_APPLICATION_CONSTRAINT) =>
            {
                return Err(application_not_found());
            }
            Err(sqlx::Error::Database(error))
                if error.constraint() == Some(SPIFFE_ID_CONSTRAINT) =>
            {
                return Err(spiffe_id_taken());
            }
            Err(error) => return Err(database_error(&error)),
        }
        insert_parts(connection, tenant, client).await
    }

    async fn update(&self, uow: &mut dyn UnitOfWork, client: &Client) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id().as_uuid();
        let state = client.snapshot();
        let settings = &state.settings;
        let policy = settings.token_policy;
        let connection = connection(uow)?;
        // The type and the application never change, so they are not
        // written.
        let updated = sqlx::query(
            "UPDATE oauth.client
             SET name = $3, authentication_method = $4, grant_types = $5, redirect_uris = $6,
                 post_logout_redirect_uris = $7, allowed_scopes = $8, require_pkce = $9,
                 access_token_seconds = $10, id_token_seconds = $11,
                 refresh_token_seconds = $12, refresh_idle_seconds = $13,
                 consent_seconds = $14, status = $15, updated_at = $16,
                 id_token_algorithm = $18, principal_id = $19, exchange_rules = $20,
                 backchannel_logout_uri = $21, backchannel_logout_session_required = $22,
                 subject_type = $23, sector_identifier_uri = $24, spiffe_id = $25,
                 version = version + 1
             WHERE tenant_id = $1 AND id = $2 AND version = $17",
        )
        .bind(tenant)
        .bind(state.id.as_uuid())
        .bind(&settings.name)
        .bind(settings.authentication_method.as_str())
        .bind(grant_names(settings))
        .bind(&settings.redirect_uris)
        .bind(&settings.post_logout_redirect_uris)
        .bind(&settings.allowed_scopes)
        .bind(settings.require_pkce)
        .bind(seconds(policy.access_token)?)
        .bind(seconds(policy.id_token)?)
        .bind(seconds(policy.refresh_token)?)
        .bind(seconds(policy.refresh_idle)?)
        .bind(seconds(policy.consent)?)
        .bind(state.status.as_str())
        .bind(state.updated_at)
        .bind(version_of(state.version)?)
        .bind(settings.id_token_algorithm.as_str())
        .bind(settings.principal.map(|principal| principal.as_uuid()))
        .bind(exchange_rules_of(settings))
        .bind(settings.backchannel_logout_uri.as_deref())
        .bind(settings.backchannel_logout_session_required)
        .bind(settings.subject_type.as_str())
        .bind(settings.sector_identifier_uri.as_deref())
        .bind(settings.spiffe_id.as_ref().map(SpiffeId::as_str))
        .execute(&mut *connection)
        .await
        .map_err(|error| match &error {
            sqlx::Error::Database(failure)
                if failure.constraint() == Some(SPIFFE_ID_CONSTRAINT) =>
            {
                spiffe_id_taken()
            }
            _ => get(error),
        })?;
        if updated.rows_affected() != 1 {
            return Err(modified("oauth.client_modified_concurrently"));
        }
        // The version check above holds the row, so replacing the parts
        // cannot race with another change.
        for table in ["oauth.client_secret", "oauth.client_key"] {
            sqlx::query(sqlx::AssertSqlSafe(format!(
                "DELETE FROM {table} WHERE tenant_id = $1 AND client_id = $2"
            )))
            .bind(tenant)
            .bind(state.id.as_uuid())
            .execute(&mut *connection)
            .await
            .map_err(get)?;
        }
        insert_parts(connection, tenant, client).await
    }

    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        id: ClientId,
    ) -> Result<Option<Client>, DomainError> {
        let tenant = uow.tenant().tenant_id().as_uuid();
        let connection = connection(uow)?;
        let row = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {CLIENT_COLUMNS} FROM oauth.client WHERE tenant_id = $1 AND id = $2"
        )))
        .bind(tenant)
        .bind(id.as_uuid())
        .fetch_optional(&mut *connection)
        .await
        .map_err(get)?;
        match row {
            Some(row) => Ok(Some(load_client(connection, tenant, &row).await?)),
            None => Ok(None),
        }
    }

    async fn list_for_application(
        &self,
        uow: &mut dyn UnitOfWork,
        application_id: ApplicationId,
    ) -> Result<Vec<Client>, DomainError> {
        let tenant = uow.tenant().tenant_id().as_uuid();
        let connection = connection(uow)?;
        let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {CLIENT_COLUMNS} FROM oauth.client
             WHERE tenant_id = $1 AND application_id = $2 ORDER BY created_at, id"
        )))
        .bind(tenant)
        .bind(application_id.as_uuid())
        .fetch_all(&mut *connection)
        .await
        .map_err(get)?;
        let mut clients = Vec::with_capacity(rows.len());
        for row in &rows {
            clients.push(load_client(connection, tenant, row).await?);
        }
        Ok(clients)
    }
}

/// [`ResourceServerStore`] on `oauth.resource_server` and
/// `oauth.resource_server_scope`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PgResourceServerStore;

const SERVER_COLUMNS: &str = "id, application_id, audience, name, created_at, updated_at, version";

async fn load_server(
    connection: &mut PgConnection,
    tenant: Uuid,
    row: &PgRow,
) -> Result<ResourceServer, DomainError> {
    let id: Uuid = row.try_get("id").map_err(get)?;
    let audience: String = row.try_get("audience").map_err(get)?;
    let scopes = sqlx::query(
        "SELECT name, description FROM oauth.resource_server_scope
         WHERE tenant_id = $1 AND resource_server_id = $2 ORDER BY position",
    )
    .bind(tenant)
    .bind(id)
    .fetch_all(&mut *connection)
    .await
    .map_err(get)?
    .iter()
    .map(|scope| {
        Ok(ScopeDefinition {
            name: scope.try_get("name").map_err(get)?,
            description: scope.try_get("description").map_err(get)?,
        })
    })
    .collect::<Result<Vec<_>, DomainError>>()?;
    Ok(ResourceServer::from_snapshot(ResourceServerSnapshot {
        id: ResourceServerId::from_uuid(id),
        application_id: ApplicationId::from_uuid(row.try_get("application_id").map_err(get)?),
        audience: Audience::parse(&audience).map_err(|_| corrupted("audience"))?,
        settings: ResourceServerSettings {
            name: row.try_get("name").map_err(get)?,
            scopes,
        },
        created_at: row.try_get("created_at").map_err(get)?,
        updated_at: row.try_get("updated_at").map_err(get)?,
        version: stored_version(row)?,
    }))
}

async fn insert_scopes(
    connection: &mut PgConnection,
    tenant: Uuid,
    server: &ResourceServer,
) -> Result<(), DomainError> {
    for (position, scope) in server.snapshot().settings.scopes.iter().enumerate() {
        sqlx::query(
            "INSERT INTO oauth.resource_server_scope
                 (tenant_id, resource_server_id, name, description, position)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(tenant)
        .bind(server.id().as_uuid())
        .bind(&scope.name)
        .bind(&scope.description)
        .bind(i32::try_from(position).map_err(|_| corrupted("too many scopes"))?)
        .execute(&mut *connection)
        .await
        .map_err(get)?;
    }
    Ok(())
}

#[async_trait::async_trait]
impl ResourceServerStore for PgResourceServerStore {
    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        server: &ResourceServer,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id().as_uuid();
        let state = server.snapshot();
        let connection = connection(uow)?;
        let inserted = sqlx::query(
            "INSERT INTO oauth.resource_server
                 (tenant_id, id, application_id, audience, name, created_at, updated_at,
                  version)
             VALUES ($1, $2, $3, $4, $5, $6, $7, 0)",
        )
        .bind(tenant)
        .bind(state.id.as_uuid())
        .bind(state.application_id.as_uuid())
        .bind(state.audience.as_str())
        .bind(&state.settings.name)
        .bind(state.created_at)
        .bind(state.updated_at)
        .execute(&mut *connection)
        .await;
        match inserted {
            Ok(_) => {}
            Err(sqlx::Error::Database(error)) => {
                return Err(match error.constraint() {
                    Some(AUDIENCE_CONSTRAINT) => DomainError::conflict(
                        "oauth.audience_taken",
                        "this tenant already has a resource server with this audience",
                    ),
                    Some(ONE_SERVER_CONSTRAINT) => DomainError::conflict(
                        "oauth.application_has_resource_server",
                        "this application already has a resource server",
                    ),
                    Some(SERVER_APPLICATION_CONSTRAINT) => application_not_found(),
                    _ => database_error(&sqlx::Error::Database(error)),
                });
            }
            Err(error) => return Err(database_error(&error)),
        }
        insert_scopes(connection, tenant, server).await
    }

    async fn update(
        &self,
        uow: &mut dyn UnitOfWork,
        server: &ResourceServer,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id().as_uuid();
        let state = server.snapshot();
        let connection = connection(uow)?;
        // The application and the audience never change.
        let updated = sqlx::query(
            "UPDATE oauth.resource_server
             SET name = $3, updated_at = $4, version = version + 1
             WHERE tenant_id = $1 AND id = $2 AND version = $5",
        )
        .bind(tenant)
        .bind(state.id.as_uuid())
        .bind(&state.settings.name)
        .bind(state.updated_at)
        .bind(version_of(state.version)?)
        .execute(&mut *connection)
        .await
        .map_err(get)?;
        if updated.rows_affected() != 1 {
            return Err(modified("oauth.resource_server_modified_concurrently"));
        }
        sqlx::query(
            "DELETE FROM oauth.resource_server_scope
             WHERE tenant_id = $1 AND resource_server_id = $2",
        )
        .bind(tenant)
        .bind(state.id.as_uuid())
        .execute(&mut *connection)
        .await
        .map_err(get)?;
        insert_scopes(connection, tenant, server).await
    }

    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        id: ResourceServerId,
    ) -> Result<Option<ResourceServer>, DomainError> {
        let tenant = uow.tenant().tenant_id().as_uuid();
        let connection = connection(uow)?;
        let row = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {SERVER_COLUMNS} FROM oauth.resource_server WHERE tenant_id = $1 AND id = $2"
        )))
        .bind(tenant)
        .bind(id.as_uuid())
        .fetch_optional(&mut *connection)
        .await
        .map_err(get)?;
        match row {
            Some(row) => Ok(Some(load_server(connection, tenant, &row).await?)),
            None => Ok(None),
        }
    }

    async fn find_by_audience(
        &self,
        uow: &mut dyn UnitOfWork,
        audience: &Audience,
    ) -> Result<Option<ResourceServer>, DomainError> {
        let tenant = uow.tenant().tenant_id().as_uuid();
        let connection = connection(uow)?;
        let row = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {SERVER_COLUMNS} FROM oauth.resource_server
             WHERE tenant_id = $1 AND audience = $2"
        )))
        .bind(tenant)
        .bind(audience.as_str())
        .fetch_optional(&mut *connection)
        .await
        .map_err(get)?;
        match row {
            Some(row) => Ok(Some(load_server(connection, tenant, &row).await?)),
            None => Ok(None),
        }
    }

    async fn list(&self, uow: &mut dyn UnitOfWork) -> Result<Vec<ResourceServer>, DomainError> {
        let tenant = uow.tenant().tenant_id().as_uuid();
        let connection = connection(uow)?;
        let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {SERVER_COLUMNS} FROM oauth.resource_server
             WHERE tenant_id = $1 ORDER BY created_at, id"
        )))
        .bind(tenant)
        .fetch_all(&mut *connection)
        .await
        .map_err(get)?;
        let mut servers = Vec::with_capacity(rows.len());
        for row in &rows {
            servers.push(load_server(connection, tenant, row).await?);
        }
        Ok(servers)
    }
}
