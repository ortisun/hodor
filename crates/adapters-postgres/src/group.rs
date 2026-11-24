//! PostgreSQL storage for groups of the identity context.
//!
//! See `docs/architecture/contexts/identity.md`, "Groups" and "Storage".

use crate::uow::{connection, database_error};
use hodor_identity::api::{
    Group, GroupMember, GroupName, GroupPolicy, GroupRepository, GroupSnapshot,
};
use hodor_kernel::{DomainError, GroupId, Timestamp, UnitOfWork, UserId};
use sqlx::types::Uuid;

const NAME_CONSTRAINT: &str = "group_name_unique";

/// [`GroupRepository`] on `identity."group"` and `identity.group_member`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PgGroupRepository;

/// [`GroupPolicy`] read from the tenant's settings, in the same
/// transaction as the change it bounds.
#[derive(Debug, Clone, Copy, Default)]
pub struct PgGroupPolicy;

type GroupRow = (Uuid, String, Option<String>, Timestamp, Timestamp, i32);

fn name_error(error: &sqlx::Error) -> DomainError {
    match error {
        sqlx::Error::Database(database) if database.constraint() == Some(NAME_CONSTRAINT) => {
            DomainError::conflict(
                "identity.group_name_taken",
                "another group of the tenant has this name",
            )
        }
        other => database_error(other),
    }
}

fn group_from(row: GroupRow) -> Result<Group, DomainError> {
    let (id, name, description, created_at, updated_at, version) = row;
    let stored = |what: &str| {
        DomainError::internal(
            "identity.stored_data_invalid",
            "the group could not be loaded",
        )
        .with_detail(what.to_owned())
    };
    Ok(Group::from_snapshot(GroupSnapshot {
        id: GroupId::from_uuid(id),
        name: GroupName::parse(&name).map_err(|_| stored("a name that breaks the rules"))?,
        description,
        created_at,
        updated_at,
        version: u32::try_from(version).map_err(|_| stored("a negative version"))?,
    }))
}

fn member_from(user: Option<Uuid>, group: Option<Uuid>) -> Result<GroupMember, DomainError> {
    match (user, group) {
        (Some(user), None) => Ok(GroupMember::User(UserId::from_uuid(user))),
        (None, Some(group)) => Ok(GroupMember::Group(GroupId::from_uuid(group))),
        _ => Err(DomainError::internal(
            "identity.stored_data_invalid",
            "a member of a group could not be loaded",
        )),
    }
}

/// The member's two columns: the user, or the group.
fn columns(member: GroupMember) -> (Option<Uuid>, Option<Uuid>) {
    match member {
        GroupMember::User(user) => (Some(user.as_uuid()), None),
        GroupMember::Group(group) => (None, Some(group.as_uuid())),
    }
}

#[async_trait::async_trait]
impl GroupRepository for PgGroupRepository {
    async fn insert(&self, uow: &mut dyn UnitOfWork, group: &Group) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let state = group.snapshot();
        sqlx::query(
            "INSERT INTO identity.\"group\"
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
        .map_err(|error| name_error(&error))?;
        Ok(())
    }

    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        id: GroupId,
    ) -> Result<Option<Group>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let row: Option<GroupRow> = sqlx::query_as(
            "SELECT id, name, description, created_at, updated_at, version
             FROM identity.\"group\" WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant.as_uuid())
        .bind(id.as_uuid())
        .fetch_optional(connection(uow)?)
        .await
        .map_err(|error| database_error(&error))?;
        row.map(group_from).transpose()
    }

    async fn list(
        &self,
        uow: &mut dyn UnitOfWork,
        after: Option<GroupId>,
        limit: u32,
    ) -> Result<Vec<Group>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let rows: Vec<GroupRow> = sqlx::query_as(
            "SELECT id, name, description, created_at, updated_at, version
             FROM identity.\"group\"
             WHERE tenant_id = $1 AND ($2::uuid IS NULL OR id > $2)
             ORDER BY id LIMIT $3",
        )
        .bind(tenant.as_uuid())
        .bind(after.map(|group| group.as_uuid()))
        .bind(i64::from(limit))
        .fetch_all(connection(uow)?)
        .await
        .map_err(|error| database_error(&error))?;
        rows.into_iter().map(group_from).collect()
    }

    async fn update(&self, uow: &mut dyn UnitOfWork, group: &Group) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let state = group.snapshot();
        let changed = sqlx::query(
            "UPDATE identity.\"group\"
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
        .map_err(|error| name_error(&error))?
        .rows_affected();
        if changed == 1 {
            return Ok(());
        }
        let exists: Option<(i32,)> = sqlx::query_as(
            "SELECT version FROM identity.\"group\" WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant.as_uuid())
        .bind(state.id.as_uuid())
        .fetch_optional(connection(uow)?)
        .await
        .map_err(|error| database_error(&error))?;
        Err(match exists {
            Some(_) => DomainError::conflict(
                "identity.group_modified_concurrently",
                "the group was changed by someone else; reload and try again",
            ),
            None => DomainError::not_found("identity.group_not_found", "the group does not exist"),
        })
    }

    async fn delete(
        &self,
        uow: &mut dyn UnitOfWork,
        id: GroupId,
    ) -> Result<Option<u64>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let (members,): (i64,) = sqlx::query_as(
            "SELECT count(*) FROM identity.group_member WHERE tenant_id = $1 AND group_id = $2",
        )
        .bind(tenant.as_uuid())
        .bind(id.as_uuid())
        .fetch_one(connection(uow)?)
        .await
        .map_err(|error| database_error(&error))?;
        // The memberships go with the group, in both directions, by the
        // foreign keys.
        let deleted =
            sqlx::query("DELETE FROM identity.\"group\" WHERE tenant_id = $1 AND id = $2")
                .bind(tenant.as_uuid())
                .bind(id.as_uuid())
                .execute(connection(uow)?)
                .await
                .map_err(|error| database_error(&error))?
                .rows_affected();
        Ok((deleted == 1).then(|| u64::try_from(members).unwrap_or(0)))
    }

    async fn add_member(
        &self,
        uow: &mut dyn UnitOfWork,
        group: GroupId,
        member: GroupMember,
        now: Timestamp,
    ) -> Result<bool, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let (user, inner) = columns(member);
        let added = sqlx::query(
            "INSERT INTO identity.group_member (tenant_id, group_id, user_id, member_group_id, added_at)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (tenant_id, group_id, member_id) DO NOTHING",
        )
        .bind(tenant.as_uuid())
        .bind(group.as_uuid())
        .bind(user)
        .bind(inner)
        .bind(now)
        .execute(connection(uow)?)
        .await
        .map_err(|error| database_error(&error))?
        .rows_affected();
        Ok(added == 1)
    }

    async fn remove_member(
        &self,
        uow: &mut dyn UnitOfWork,
        group: GroupId,
        member: GroupMember,
    ) -> Result<bool, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let (user, inner) = columns(member);
        let removed = sqlx::query(
            "DELETE FROM identity.group_member
             WHERE tenant_id = $1 AND group_id = $2
               AND user_id IS NOT DISTINCT FROM $3 AND member_group_id IS NOT DISTINCT FROM $4",
        )
        .bind(tenant.as_uuid())
        .bind(group.as_uuid())
        .bind(user)
        .bind(inner)
        .execute(connection(uow)?)
        .await
        .map_err(|error| database_error(&error))?
        .rows_affected();
        Ok(removed == 1)
    }

    async fn members(
        &self,
        uow: &mut dyn UnitOfWork,
        group: GroupId,
        after: Option<GroupMember>,
        limit: u32,
    ) -> Result<Vec<GroupMember>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        // Users first, then groups, each by identifier: the order of
        // `GroupMember`. Kind 0 is a user, 1 a group.
        let (after_kind, after_id) = match after {
            None => (-1_i32, None),
            Some(GroupMember::User(user)) => (0, Some(user.as_uuid())),
            Some(GroupMember::Group(inner)) => (1, Some(inner.as_uuid())),
        };
        let rows: Vec<(Option<Uuid>, Option<Uuid>)> = sqlx::query_as(
            "SELECT user_id, member_group_id FROM (
                 SELECT user_id, member_group_id, member_id,
                        CASE WHEN user_id IS NOT NULL THEN 0 ELSE 1 END AS kind
                 FROM identity.group_member
                 WHERE tenant_id = $1 AND group_id = $2
             ) AS members
             WHERE $3::uuid IS NULL OR (kind, member_id) > ($4, $3)
             ORDER BY kind, member_id
             LIMIT $5",
        )
        .bind(tenant.as_uuid())
        .bind(group.as_uuid())
        .bind(after_id)
        .bind(after_kind)
        .bind(i64::from(limit))
        .fetch_all(connection(uow)?)
        .await
        .map_err(|error| database_error(&error))?;
        rows.into_iter()
            .map(|(user, inner)| member_from(user, inner))
            .collect()
    }

    async fn lock_nesting(&self, uow: &mut dyn UnitOfWork) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('identity.group_nesting:' || $1::text, 0))")
            .bind(tenant.as_uuid())
            .execute(connection(uow)?)
            .await
            .map_err(|error| database_error(&error))?;
        Ok(())
    }

    async fn nesting(
        &self,
        uow: &mut dyn UnitOfWork,
    ) -> Result<Vec<(GroupId, GroupId)>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let rows: Vec<(Uuid, Uuid)> = sqlx::query_as(
            "SELECT group_id, member_group_id FROM identity.group_member
             WHERE tenant_id = $1 AND member_group_id IS NOT NULL
             ORDER BY group_id, member_group_id",
        )
        .bind(tenant.as_uuid())
        .fetch_all(connection(uow)?)
        .await
        .map_err(|error| database_error(&error))?;
        Ok(rows
            .into_iter()
            .map(|(group, inner)| (GroupId::from_uuid(group), GroupId::from_uuid(inner)))
            .collect())
    }

    async fn groups_of(
        &self,
        uow: &mut dyn UnitOfWork,
        user: UserId,
    ) -> Result<Vec<GroupId>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let rows: Vec<(Uuid,)> = sqlx::query_as(
            "SELECT group_id FROM identity.group_member
             WHERE tenant_id = $1 AND user_id = $2 ORDER BY group_id",
        )
        .bind(tenant.as_uuid())
        .bind(user.as_uuid())
        .fetch_all(connection(uow)?)
        .await
        .map_err(|error| database_error(&error))?;
        Ok(rows
            .into_iter()
            .map(|(group,)| GroupId::from_uuid(group))
            .collect())
    }
}

#[async_trait::async_trait]
impl GroupPolicy for PgGroupPolicy {
    async fn max_depth(&self, uow: &mut dyn UnitOfWork) -> Result<u8, DomainError> {
        let tenant = uow.tenant().tenant_id();
        // The tenant's own settings: a tenant whose settings were stored
        // before the policy existed reads the default, as the tenant
        // context does.
        let stored: Option<(Option<i32>,)> = sqlx::query_as(
            "SELECT (settings -> 'groups' ->> 'max_depth')::integer
             FROM tenant.tenant WHERE tenant_id = $1",
        )
        .bind(tenant.as_uuid())
        .fetch_optional(connection(uow)?)
        .await
        .map_err(|error| database_error(&error))?;
        let default = hodor_tenant::api::GroupPolicy::default().max_depth;
        Ok(stored
            .and_then(|(depth,)| depth)
            .and_then(|depth| u8::try_from(depth).ok())
            .unwrap_or(default))
    }
}
