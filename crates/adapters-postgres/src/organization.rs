//! PostgreSQL storage for organizations of the identity context.
//!
//! See `docs/architecture/contexts/identity.md`, "Organizations" and
//! "Storage".

use crate::uow::{connection, database_error};
use hodor_identity::api::{
    Membership, Organization, OrganizationName, OrganizationRepository, OrganizationSnapshot, Unit,
    UnitId, UnitKind,
};
use hodor_kernel::{DomainError, OrganizationId, Timestamp, UnitOfWork, UserId};
use sqlx::types::Uuid;
use std::collections::{BTreeMap, BTreeSet};

/// [`OrganizationRepository`] on `identity.organization`,
/// `identity.organization_unit`, `identity.organization_member` and
/// `identity.organization_member_unit`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PgOrganizationRepository;

type OrganizationRow = (Uuid, String, Option<String>, Timestamp, Timestamp, i32);
type UnitRow = (
    Uuid,
    Uuid,
    Option<Uuid>,
    String,
    String,
    Timestamp,
    Timestamp,
);

fn stored(what: &str) -> DomainError {
    DomainError::internal(
        "identity.stored_data_invalid",
        "the organization could not be loaded",
    )
    .with_detail(what.to_owned())
}

fn constraint_error(error: &sqlx::Error) -> DomainError {
    if let sqlx::Error::Database(database) = error {
        match database.constraint() {
            Some("organization_name_unique") => {
                return DomainError::conflict(
                    "identity.organization_name_taken",
                    "another organization of the tenant has this name",
                );
            }
            Some("organization_unit_name_unique") => {
                return DomainError::conflict(
                    "identity.unit_name_taken",
                    "another unit with the same parent has this name",
                );
            }
            Some("organization_unit_parent_fk") => {
                return DomainError::conflict(
                    "identity.unit_not_empty",
                    "a unit with units below it cannot be deleted",
                );
            }
            _ => {}
        }
    }
    database_error(error)
}

fn organization_from(row: OrganizationRow) -> Result<Organization, DomainError> {
    let (id, name, description, created_at, updated_at, version) = row;
    Ok(Organization::from_snapshot(OrganizationSnapshot {
        id: OrganizationId::from_uuid(id),
        name: OrganizationName::parse(&name).map_err(|_| stored("a name that breaks the rules"))?,
        description,
        created_at,
        updated_at,
        version: u32::try_from(version).map_err(|_| stored("a negative version"))?,
    }))
}

fn unit_from(row: UnitRow) -> Result<Unit, DomainError> {
    let (id, organization, parent, name, kind, created_at, updated_at) = row;
    Ok(Unit {
        id: UnitId::from_uuid(id),
        organization: OrganizationId::from_uuid(organization),
        parent: parent.map(UnitId::from_uuid),
        name: OrganizationName::parse(&name)
            .map_err(|_| stored("a unit name that breaks the rules"))?,
        kind: UnitKind::parse(&kind).map_err(|_| stored("an unknown kind of unit"))?,
        created_at,
        updated_at,
    })
}

impl PgOrganizationRepository {
    /// The memberships of `(organization, user)` pairs, with their units.
    async fn memberships(
        uow: &mut dyn UnitOfWork,
        rows: Vec<(Uuid, Uuid, Timestamp)>,
    ) -> Result<Vec<Membership>, DomainError> {
        if rows.is_empty() {
            return Ok(Vec::new());
        }
        let tenant = uow.tenant().tenant_id();
        let organizations: Vec<Uuid> = rows.iter().map(|row| row.0).collect();
        let users: Vec<Uuid> = rows.iter().map(|row| row.1).collect();
        let units: Vec<(Uuid, Uuid, Uuid)> = sqlx::query_as(
            "SELECT organization_id, user_id, unit_id FROM identity.organization_member_unit
             WHERE tenant_id = $1
               AND (organization_id, user_id) IN (SELECT * FROM unnest($2::uuid[], $3::uuid[]))",
        )
        .bind(tenant.as_uuid())
        .bind(&organizations)
        .bind(&users)
        .fetch_all(connection(uow)?)
        .await
        .map_err(|error| database_error(&error))?;
        let mut by_member: BTreeMap<(Uuid, Uuid), BTreeSet<UnitId>> = BTreeMap::new();
        for (organization, user, unit) in units {
            by_member
                .entry((organization, user))
                .or_default()
                .insert(UnitId::from_uuid(unit));
        }
        Ok(rows
            .into_iter()
            .map(|(organization, user, added_at)| Membership {
                organization: OrganizationId::from_uuid(organization),
                user: UserId::from_uuid(user),
                units: by_member.remove(&(organization, user)).unwrap_or_default(),
                added_at,
            })
            .collect())
    }
}

#[async_trait::async_trait]
impl OrganizationRepository for PgOrganizationRepository {
    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        organization: &Organization,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let state = organization.snapshot();
        sqlx::query(
            "INSERT INTO identity.organization
                 (tenant_id, id, name, name_normalized, description, created_at, updated_at, version)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(tenant.as_uuid())
        .bind(state.id.as_uuid())
        .bind(state.name.as_str())
        .bind(state.name.normalized())
        .bind(state.description.as_deref())
        .bind(state.created_at)
        .bind(state.updated_at)
        .bind(i32::try_from(state.version).unwrap_or(i32::MAX))
        .execute(connection(uow)?)
        .await
        .map_err(|error| constraint_error(&error))?;
        Ok(())
    }

    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        id: OrganizationId,
    ) -> Result<Option<Organization>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let row: Option<OrganizationRow> = sqlx::query_as(
            "SELECT id, name, description, created_at, updated_at, version
             FROM identity.organization WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant.as_uuid())
        .bind(id.as_uuid())
        .fetch_optional(connection(uow)?)
        .await
        .map_err(|error| database_error(&error))?;
        row.map(organization_from).transpose()
    }

    async fn list(
        &self,
        uow: &mut dyn UnitOfWork,
        after: Option<OrganizationId>,
        limit: u32,
    ) -> Result<Vec<Organization>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let rows: Vec<OrganizationRow> = sqlx::query_as(
            "SELECT id, name, description, created_at, updated_at, version
             FROM identity.organization
             WHERE tenant_id = $1 AND ($2::uuid IS NULL OR id > $2)
             ORDER BY id LIMIT $3",
        )
        .bind(tenant.as_uuid())
        .bind(after.map(|organization| organization.as_uuid()))
        .bind(i64::from(limit))
        .fetch_all(connection(uow)?)
        .await
        .map_err(|error| database_error(&error))?;
        rows.into_iter().map(organization_from).collect()
    }

    async fn update(
        &self,
        uow: &mut dyn UnitOfWork,
        organization: &Organization,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let state = organization.snapshot();
        let changed = sqlx::query(
            "UPDATE identity.organization
             SET name = $3, name_normalized = $4, description = $5, updated_at = $6,
                 version = version + 1
             WHERE tenant_id = $1 AND id = $2 AND version = $7",
        )
        .bind(tenant.as_uuid())
        .bind(state.id.as_uuid())
        .bind(state.name.as_str())
        .bind(state.name.normalized())
        .bind(state.description.as_deref())
        .bind(state.updated_at)
        .bind(i32::try_from(state.version).unwrap_or(i32::MAX))
        .execute(connection(uow)?)
        .await
        .map_err(|error| constraint_error(&error))?
        .rows_affected();
        if changed == 1 {
            return Ok(());
        }
        let exists: Option<(i32,)> = sqlx::query_as(
            "SELECT version FROM identity.organization WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant.as_uuid())
        .bind(state.id.as_uuid())
        .fetch_optional(connection(uow)?)
        .await
        .map_err(|error| database_error(&error))?;
        Err(match exists {
            Some(_) => DomainError::conflict(
                "identity.organization_modified_concurrently",
                "the organization was changed by someone else; reload and try again",
            ),
            None => DomainError::not_found(
                "identity.organization_not_found",
                "the organization does not exist",
            ),
        })
    }

    async fn delete(
        &self,
        uow: &mut dyn UnitOfWork,
        id: OrganizationId,
    ) -> Result<Option<u64>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let (members,): (i64,) = sqlx::query_as(
            "SELECT count(*) FROM identity.organization_member
             WHERE tenant_id = $1 AND organization_id = $2",
        )
        .bind(tenant.as_uuid())
        .bind(id.as_uuid())
        .fetch_one(connection(uow)?)
        .await
        .map_err(|error| database_error(&error))?;
        let deleted =
            sqlx::query("DELETE FROM identity.organization WHERE tenant_id = $1 AND id = $2")
                .bind(tenant.as_uuid())
                .bind(id.as_uuid())
                .execute(connection(uow)?)
                .await
                .map_err(|error| constraint_error(&error))?
                .rows_affected();
        Ok((deleted == 1).then(|| u64::try_from(members).unwrap_or(0)))
    }

    async fn lock_tree(
        &self,
        uow: &mut dyn UnitOfWork,
        organization: OrganizationId,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        sqlx::query(
            "SELECT pg_advisory_xact_lock(
                 hashtextextended('identity.organization_tree:' || $1::text || ':' || $2::text, 0))",
        )
        .bind(tenant.as_uuid())
        .bind(organization.as_uuid())
        .execute(connection(uow)?)
        .await
        .map_err(|error| database_error(&error))?;
        Ok(())
    }

    async fn units(
        &self,
        uow: &mut dyn UnitOfWork,
        organization: OrganizationId,
    ) -> Result<Vec<Unit>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let rows: Vec<UnitRow> = sqlx::query_as(
            "SELECT id, organization_id, parent_id, name, kind, created_at, updated_at
             FROM identity.organization_unit
             WHERE tenant_id = $1 AND organization_id = $2 ORDER BY id",
        )
        .bind(tenant.as_uuid())
        .bind(organization.as_uuid())
        .fetch_all(connection(uow)?)
        .await
        .map_err(|error| database_error(&error))?;
        rows.into_iter().map(unit_from).collect()
    }

    async fn save_unit(&self, uow: &mut dyn UnitOfWork, unit: &Unit) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        sqlx::query(
            "INSERT INTO identity.organization_unit
                 (tenant_id, id, organization_id, parent_id, name, name_normalized, kind,
                  created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
             ON CONFLICT (tenant_id, id) DO UPDATE
             SET parent_id = EXCLUDED.parent_id, name = EXCLUDED.name,
                 name_normalized = EXCLUDED.name_normalized, kind = EXCLUDED.kind,
                 updated_at = EXCLUDED.updated_at
             WHERE identity.organization_unit.organization_id = EXCLUDED.organization_id",
        )
        .bind(tenant.as_uuid())
        .bind(unit.id.as_uuid())
        .bind(unit.organization.as_uuid())
        .bind(unit.parent.map(|parent| parent.as_uuid()))
        .bind(unit.name.as_str())
        .bind(unit.name.normalized())
        .bind(unit.kind.as_str())
        .bind(unit.created_at)
        .bind(unit.updated_at)
        .execute(connection(uow)?)
        .await
        .map_err(|error| constraint_error(&error))?;
        Ok(())
    }

    async fn delete_unit(
        &self,
        uow: &mut dyn UnitOfWork,
        organization: OrganizationId,
        unit: UnitId,
    ) -> Result<bool, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let deleted = sqlx::query(
            "DELETE FROM identity.organization_unit
             WHERE tenant_id = $1 AND organization_id = $2 AND id = $3",
        )
        .bind(tenant.as_uuid())
        .bind(organization.as_uuid())
        .bind(unit.as_uuid())
        .execute(connection(uow)?)
        .await
        .map_err(|error| constraint_error(&error))?
        .rows_affected();
        Ok(deleted == 1)
    }

    async fn membership(
        &self,
        uow: &mut dyn UnitOfWork,
        organization: OrganizationId,
        user: UserId,
    ) -> Result<Option<Membership>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let row: Option<(Uuid, Uuid, Timestamp)> = sqlx::query_as(
            "SELECT organization_id, user_id, added_at FROM identity.organization_member
             WHERE tenant_id = $1 AND organization_id = $2 AND user_id = $3",
        )
        .bind(tenant.as_uuid())
        .bind(organization.as_uuid())
        .bind(user.as_uuid())
        .fetch_optional(connection(uow)?)
        .await
        .map_err(|error| database_error(&error))?;
        Ok(Self::memberships(uow, row.into_iter().collect())
            .await?
            .pop())
    }

    async fn save_membership(
        &self,
        uow: &mut dyn UnitOfWork,
        membership: &Membership,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let (organization, user) = (membership.organization.as_uuid(), membership.user.as_uuid());
        sqlx::query(
            "INSERT INTO identity.organization_member (tenant_id, organization_id, user_id, added_at)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (tenant_id, organization_id, user_id) DO NOTHING",
        )
        .bind(tenant.as_uuid())
        .bind(organization)
        .bind(user)
        .bind(membership.added_at)
        .execute(connection(uow)?)
        .await
        .map_err(|error| database_error(&error))?;
        let units: Vec<Uuid> = membership.units.iter().map(|unit| unit.as_uuid()).collect();
        sqlx::query(
            "DELETE FROM identity.organization_member_unit
             WHERE tenant_id = $1 AND organization_id = $2 AND user_id = $3
               AND NOT (unit_id = ANY($4))",
        )
        .bind(tenant.as_uuid())
        .bind(organization)
        .bind(user)
        .bind(&units)
        .execute(connection(uow)?)
        .await
        .map_err(|error| database_error(&error))?;
        sqlx::query(
            "INSERT INTO identity.organization_member_unit (tenant_id, organization_id, user_id, unit_id)
             SELECT $1, $2, $3, unit FROM unnest($4::uuid[]) AS unit
             ON CONFLICT DO NOTHING",
        )
        .bind(tenant.as_uuid())
        .bind(organization)
        .bind(user)
        .bind(&units)
        .execute(connection(uow)?)
        .await
        .map_err(|error| database_error(&error))?;
        Ok(())
    }

    async fn remove_membership(
        &self,
        uow: &mut dyn UnitOfWork,
        organization: OrganizationId,
        user: UserId,
    ) -> Result<bool, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let removed = sqlx::query(
            "DELETE FROM identity.organization_member
             WHERE tenant_id = $1 AND organization_id = $2 AND user_id = $3",
        )
        .bind(tenant.as_uuid())
        .bind(organization.as_uuid())
        .bind(user.as_uuid())
        .execute(connection(uow)?)
        .await
        .map_err(|error| database_error(&error))?
        .rows_affected();
        Ok(removed == 1)
    }

    async fn members(
        &self,
        uow: &mut dyn UnitOfWork,
        organization: OrganizationId,
        after: Option<UserId>,
        limit: u32,
    ) -> Result<Vec<Membership>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let rows: Vec<(Uuid, Uuid, Timestamp)> = sqlx::query_as(
            "SELECT organization_id, user_id, added_at FROM identity.organization_member
             WHERE tenant_id = $1 AND organization_id = $2 AND ($3::uuid IS NULL OR user_id > $3)
             ORDER BY user_id LIMIT $4",
        )
        .bind(tenant.as_uuid())
        .bind(organization.as_uuid())
        .bind(after.map(|user| user.as_uuid()))
        .bind(i64::from(limit))
        .fetch_all(connection(uow)?)
        .await
        .map_err(|error| database_error(&error))?;
        Self::memberships(uow, rows).await
    }

    async fn memberships_of(
        &self,
        uow: &mut dyn UnitOfWork,
        user: UserId,
    ) -> Result<Vec<Membership>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let rows: Vec<(Uuid, Uuid, Timestamp)> = sqlx::query_as(
            "SELECT organization_id, user_id, added_at FROM identity.organization_member
             WHERE tenant_id = $1 AND user_id = $2 ORDER BY organization_id",
        )
        .bind(tenant.as_uuid())
        .bind(user.as_uuid())
        .fetch_all(connection(uow)?)
        .await
        .map_err(|error| database_error(&error))?;
        Self::memberships(uow, rows).await
    }
}
