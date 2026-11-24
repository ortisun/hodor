//! PostgreSQL storage of the provisioning context, and finding users and
//! groups with a SCIM filter.
//!
//! See `docs/architecture/contexts/provisioning.md`, "Storage" and
//! "Finding with a filter". A filter is compiled into SQL in which every
//! value is a bound parameter and every attribute is one of the fixed
//! expressions below: no part of a filter's text is ever written into a
//! statement. The statements read the identity context's tables; they
//! never write them.

use crate::uow::{connection, database_error};
use hodor_kernel::{DomainError, GroupId, Timestamp, UnitOfWork, UserId};
use hodor_provisioning::api::{
    Attribute, AttributeType, Deprovisioning, DeprovisioningPolicy, Filter, Found, GroupAttribute,
    GroupSupplement, ListQuery, Operator, ProvisionedGroupRepository, ProvisionedUserRepository,
    SortOrder, StoredGroupSupplement, StoredUserSupplement, UserAttribute, UserSupplement, Value,
    ValueFilter,
};
use sqlx::types::{Json, Uuid};
use sqlx::{Postgres, QueryBuilder, Row};
use std::collections::BTreeMap;

/// [`ProvisionedUserRepository`] on `provisioning.user_attribute`, finding
/// users in `identity."user"` and `identity.user_identifier`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PgProvisionedUserRepository;

/// [`DeprovisioningPolicy`] read from the tenant's settings, in the same
/// transaction as the change it decides.
#[derive(Debug, Clone, Copy, Default)]
pub struct PgDeprovisioningPolicy;

#[async_trait::async_trait]
impl DeprovisioningPolicy for PgDeprovisioningPolicy {
    async fn deprovisioning(
        &self,
        uow: &mut dyn UnitOfWork,
    ) -> Result<Deprovisioning, DomainError> {
        let tenant = uow.tenant().tenant_id();
        // Settings stored before the policy existed read as the default,
        // as the tenant context reads them.
        let stored: Option<(Option<String>,)> = sqlx::query_as(
            "SELECT settings -> 'provisioning' ->> 'deprovisioning'
             FROM tenant.tenant WHERE tenant_id = $1",
        )
        .bind(tenant.as_uuid())
        .fetch_optional(connection(uow)?)
        .await
        .map_err(|error| database_error(&error))?;
        Ok(match stored.and_then(|(policy,)| policy).as_deref() {
            Some("delete") => Deprovisioning::Delete,
            _ => Deprovisioning::Deactivate,
        })
    }
}

/// [`ProvisionedGroupRepository`] on `provisioning.group_attribute`,
/// finding groups in `identity."group"` and `identity.group_member`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PgProvisionedGroupRepository;

/// How an attribute of a filter is read in SQL.
trait Column: Attribute {
    /// The expression of a single-valued attribute, over the statement's
    /// tables.
    fn expression(self) -> &'static str;
    /// For a multi-valued attribute: the start of the subquery over its
    /// values, to be followed by ` AND (condition))`, and the expression
    /// of one value.
    fn element(self) -> Option<(&'static str, &'static str)>;
}

/// The userName identifier: the primary username, or else the primary
/// email address.
const USER_NAME: &str = "(SELECT i.value_normalized FROM identity.user_identifier AS i \
     WHERE i.tenant_id = u.tenant_id AND i.user_id = u.id AND i.is_primary \
     ORDER BY (i.kind = 'username') DESC LIMIT 1)";

impl Column for UserAttribute {
    fn expression(self) -> &'static str {
        match self {
            Self::Id => "u.id::text",
            Self::ExternalId => "p.external_id",
            Self::UserName => USER_NAME,
            Self::DisplayName => "u.display_name",
            Self::GivenName => "p.given_name",
            Self::FamilyName => "p.family_name",
            Self::Active => "(u.status = 'active')",
            Self::Created => "u.created_at",
            Self::LastModified => "GREATEST(u.updated_at, p.updated_at)",
            Self::Emails => "NULL",
        }
    }

    fn element(self) -> Option<(&'static str, &'static str)> {
        (self == Self::Emails).then_some((
            "EXISTS (SELECT 1 FROM identity.user_identifier AS e \
             WHERE e.tenant_id = u.tenant_id AND e.user_id = u.id AND e.kind = 'email'",
            "e.value_normalized",
        ))
    }
}

impl Column for GroupAttribute {
    fn expression(self) -> &'static str {
        match self {
            Self::Id => "g.id::text",
            Self::ExternalId => "p.external_id",
            Self::DisplayName => "g.name",
            Self::Created => "g.created_at",
            Self::LastModified => "GREATEST(g.updated_at, p.updated_at)",
            Self::Members => "NULL",
        }
    }

    fn element(self) -> Option<(&'static str, &'static str)> {
        (self == Self::Members).then_some((
            "EXISTS (SELECT 1 FROM identity.group_member AS m \
             WHERE m.tenant_id = g.tenant_id AND m.group_id = g.id",
            "m.member_id::text",
        ))
    }
}

/// The expression as it is compared: with the letters `A` to `Z` made
/// `a` to `z` when its attribute is compared without regard to case, as
/// the domain's `fold_case` does.
fn compared(expression: &str, value_type: AttributeType) -> String {
    match value_type {
        AttributeType::Text { exact: false } => format!(
            "translate({expression}, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')"
        ),
        _ => expression.to_owned(),
    }
}

fn push_value(query: &mut QueryBuilder<Postgres>, value: &Value) {
    match value {
        Value::Text(text) => {
            query.push_bind(text.clone());
        }
        Value::Boolean(value) => {
            query.push_bind(*value);
        }
        Value::DateTime(at) => {
            query.push_bind(*at);
        }
    }
}

/// A comparison that is false, never unknown, when the expression has no
/// value: `COALESCE((…), false)`.
fn push_comparison(
    query: &mut QueryBuilder<Postgres>,
    expression: &str,
    operator: Operator,
    value: &Value,
) {
    query.push("COALESCE((");
    match (operator, value) {
        (Operator::Contains, Value::Text(text)) => {
            query
                .push("strpos(")
                .push(expression)
                .push(", ")
                .push_bind(text.clone())
                .push(") > 0");
        }
        (Operator::StartsWith, Value::Text(text)) => {
            query
                .push("starts_with(")
                .push(expression)
                .push(", ")
                .push_bind(text.clone())
                .push(")");
        }
        (Operator::EndsWith, Value::Text(text)) => {
            query
                .push("right(")
                .push(expression)
                .push(", char_length(")
                .push_bind(text.clone())
                .push(")) = ")
                .push_bind(text.clone());
        }
        (Operator::Contains | Operator::StartsWith | Operator::EndsWith, _) => {
            query.push("false");
        }
        (operator, value) => {
            let symbol = match operator {
                Operator::NotEqual => "<>",
                Operator::Greater => ">",
                Operator::GreaterOrEqual => ">=",
                Operator::Less => "<",
                Operator::LessOrEqual => "<=",
                _ => "=",
            };
            query.push(expression);
            // Text is ordered by the code points of its characters,
            // whatever the database's collation.
            if operator.orders() && matches!(value, Value::Text(_)) {
                query.push(" COLLATE \"C\"");
            }
            query.push(" ").push(symbol).push(" ");
            push_value(query, value);
        }
    }
    query.push("), false)");
}

fn push_value_filter(
    query: &mut QueryBuilder<Postgres>,
    condition: &ValueFilter,
    expression: &str,
) {
    match condition {
        ValueFilter::Compare(operator, value) => {
            push_comparison(query, expression, *operator, value);
        }
        ValueFilter::Present => {
            query.push("true");
        }
        ValueFilter::And(left, right) => {
            query.push("(");
            push_value_filter(query, left, expression);
            query.push(" AND ");
            push_value_filter(query, right, expression);
            query.push(")");
        }
        ValueFilter::Or(left, right) => {
            query.push("(");
            push_value_filter(query, left, expression);
            query.push(" OR ");
            push_value_filter(query, right, expression);
            query.push(")");
        }
        ValueFilter::Not(inner) => {
            query.push("(NOT ");
            push_value_filter(query, inner, expression);
            query.push(")");
        }
    }
}

fn push_filter<A: Column>(query: &mut QueryBuilder<Postgres>, filter: &Filter<A>) {
    match filter {
        Filter::Compare(attribute, operator, value) => {
            let expression = compared(attribute.expression(), attribute.value_type());
            push_comparison(query, &expression, *operator, value);
        }
        Filter::Present(attribute) => {
            query
                .push("(")
                .push(attribute.expression())
                .push(" IS NOT NULL)");
        }
        Filter::Any(attribute, condition) => match attribute.element() {
            Some((subquery, column)) => {
                let expression = compared(column, attribute.value_type());
                query.push(subquery).push(" AND (");
                push_value_filter(query, condition, &expression);
                query.push("))");
            }
            None => {
                query.push("false");
            }
        },
        Filter::And(left, right) => {
            query.push("(");
            push_filter(query, left);
            query.push(" AND ");
            push_filter(query, right);
            query.push(")");
        }
        Filter::Or(left, right) => {
            query.push("(");
            push_filter(query, left);
            query.push(" OR ");
            push_filter(query, right);
            query.push(")");
        }
        Filter::Not(inner) => {
            query.push("(NOT ");
            push_filter(query, inner);
            query.push(")");
        }
    }
}

/// Finds the identifiers of the resources `from` holds that match the
/// query, and how many match. `from` names the tables and the conditions
/// every resource keeps; `id` is the expression of a resource's
/// identifier.
async fn find<A: Column>(
    uow: &mut dyn UnitOfWork,
    from: &str,
    id: &str,
    query: &ListQuery<A>,
) -> Result<Found<Uuid>, DomainError> {
    let tenant = uow.tenant().tenant_id().as_uuid();
    let start = |select: &str| {
        let mut built: QueryBuilder<Postgres> = QueryBuilder::new(select);
        built.push(from).push_bind(tenant);
        if let Some(filter) = &query.filter {
            built.push(" AND ");
            push_filter(&mut built, filter);
        }
        built
    };
    let mut counting = start("SELECT count(*) ");
    let total: i64 = counting
        .build_query_scalar()
        .fetch_one(connection(uow)?)
        .await
        .map_err(|error| database_error(&error))?;
    let total = u64::try_from(total).unwrap_or(0);
    if query.count == 0 || query.offset() >= total {
        return Ok(Found {
            total,
            ids: Vec::new(),
        });
    }
    let mut paging = start(&format!("SELECT {id} "));
    paging.push(" ORDER BY ");
    if let Some((attribute, order)) = query.sort {
        paging.push(compared(attribute.expression(), attribute.value_type()));
        if matches!(attribute.value_type(), AttributeType::Text { .. }) {
            paging.push(" COLLATE \"C\"");
        }
        paging.push(match order {
            SortOrder::Ascending => " ASC NULLS LAST, ",
            SortOrder::Descending => " DESC NULLS FIRST, ",
        });
    }
    paging
        .push(id)
        .push(" ASC LIMIT ")
        .push_bind(i64::from(query.count))
        .push(" OFFSET ")
        .push_bind(i64::try_from(query.offset()).unwrap_or(i64::MAX));
    let ids: Vec<Uuid> = paging
        .build_query_scalar()
        .fetch_all(connection(uow)?)
        .await
        .map_err(|error| database_error(&error))?;
    Ok(Found { total, ids })
}

const USERS: &str = "FROM identity.\"user\" AS u \
     LEFT JOIN provisioning.user_attribute AS p ON p.tenant_id = u.tenant_id AND p.user_id = u.id \
     WHERE u.kind = 'human' AND u.status <> 'deleted' \
       AND NOT (u.status = 'deactivated' AND p.removed_at IS NOT NULL) AND u.tenant_id = ";

const GROUPS: &str = "FROM identity.\"group\" AS g \
     LEFT JOIN provisioning.group_attribute AS p ON p.tenant_id = g.tenant_id AND p.group_id = g.id \
     WHERE g.tenant_id = ";

#[async_trait::async_trait]
impl ProvisionedUserRepository for PgProvisionedUserRepository {
    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        user: UserId,
    ) -> Result<Option<StoredUserSupplement>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let row = sqlx::query(
            "SELECT external_id, name_formatted, given_name, family_name, employee_number,
                    cost_center, organization, division, department, manager_id,
                    email_types, created_at, updated_at, removed_at
             FROM provisioning.user_attribute WHERE tenant_id = $1 AND user_id = $2",
        )
        .bind(tenant.as_uuid())
        .bind(user.as_uuid())
        .fetch_optional(connection(uow)?)
        .await
        .map_err(|error| database_error(&error))?;
        row.map(|row| {
            let text = |column: &str| row.try_get::<Option<String>, _>(column);
            Ok(StoredUserSupplement {
                user_id: user,
                supplement: UserSupplement {
                    external_id: text("external_id")?,
                    formatted_name: text("name_formatted")?,
                    given_name: text("given_name")?,
                    family_name: text("family_name")?,
                    employee_number: text("employee_number")?,
                    cost_center: text("cost_center")?,
                    organization: text("organization")?,
                    division: text("division")?,
                    department: text("department")?,
                    manager: text("manager_id")?,
                    email_types: row
                        .try_get::<Json<BTreeMap<String, String>>, _>("email_types")?
                        .0,
                },
                created_at: row.try_get::<Timestamp, _>("created_at")?,
                updated_at: row.try_get::<Timestamp, _>("updated_at")?,
                removed_at: row.try_get::<Option<Timestamp>, _>("removed_at")?,
            })
        })
        .transpose()
        .map_err(|error: sqlx::Error| database_error(&error))
    }

    async fn put(
        &self,
        uow: &mut dyn UnitOfWork,
        stored: &StoredUserSupplement,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let supplement = &stored.supplement;
        sqlx::query(
            "INSERT INTO provisioning.user_attribute
                 (tenant_id, user_id, external_id, name_formatted, given_name, family_name,
                  employee_number, cost_center, organization, division, department, manager_id,
                  created_at, updated_at, email_types, removed_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
             ON CONFLICT (tenant_id, user_id) DO UPDATE SET
                 external_id = EXCLUDED.external_id,
                 name_formatted = EXCLUDED.name_formatted,
                 given_name = EXCLUDED.given_name,
                 family_name = EXCLUDED.family_name,
                 employee_number = EXCLUDED.employee_number,
                 cost_center = EXCLUDED.cost_center,
                 organization = EXCLUDED.organization,
                 division = EXCLUDED.division,
                 department = EXCLUDED.department,
                 manager_id = EXCLUDED.manager_id,
                 created_at = EXCLUDED.created_at,
                 updated_at = EXCLUDED.updated_at,
                 email_types = EXCLUDED.email_types,
                 removed_at = EXCLUDED.removed_at",
        )
        .bind(tenant.as_uuid())
        .bind(stored.user_id.as_uuid())
        .bind(supplement.external_id.as_deref())
        .bind(supplement.formatted_name.as_deref())
        .bind(supplement.given_name.as_deref())
        .bind(supplement.family_name.as_deref())
        .bind(supplement.employee_number.as_deref())
        .bind(supplement.cost_center.as_deref())
        .bind(supplement.organization.as_deref())
        .bind(supplement.division.as_deref())
        .bind(supplement.department.as_deref())
        .bind(supplement.manager.as_deref())
        .bind(stored.created_at)
        .bind(stored.updated_at)
        .bind(Json(&supplement.email_types))
        .bind(stored.removed_at)
        .execute(connection(uow)?)
        .await
        .map_err(|error| database_error(&error))?;
        Ok(())
    }

    async fn remove(&self, uow: &mut dyn UnitOfWork, user: UserId) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        sqlx::query(
            "DELETE FROM provisioning.user_attribute WHERE tenant_id = $1 AND user_id = $2",
        )
        .bind(tenant.as_uuid())
        .bind(user.as_uuid())
        .execute(connection(uow)?)
        .await
        .map_err(|error| database_error(&error))?;
        Ok(())
    }

    async fn find(
        &self,
        uow: &mut dyn UnitOfWork,
        query: &ListQuery<UserAttribute>,
    ) -> Result<Found<UserId>, DomainError> {
        let found = find(uow, USERS, "u.id", query).await?;
        Ok(Found {
            total: found.total,
            ids: found.ids.into_iter().map(UserId::from_uuid).collect(),
        })
    }
}

#[async_trait::async_trait]
impl ProvisionedGroupRepository for PgProvisionedGroupRepository {
    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        group: GroupId,
    ) -> Result<Option<StoredGroupSupplement>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let row: Option<(Option<String>, Timestamp, Timestamp)> = sqlx::query_as(
            "SELECT external_id, created_at, updated_at
             FROM provisioning.group_attribute WHERE tenant_id = $1 AND group_id = $2",
        )
        .bind(tenant.as_uuid())
        .bind(group.as_uuid())
        .fetch_optional(connection(uow)?)
        .await
        .map_err(|error| database_error(&error))?;
        Ok(row.map(
            |(external_id, created_at, updated_at)| StoredGroupSupplement {
                group_id: group,
                supplement: GroupSupplement { external_id },
                created_at,
                updated_at,
            },
        ))
    }

    async fn put(
        &self,
        uow: &mut dyn UnitOfWork,
        stored: &StoredGroupSupplement,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        sqlx::query(
            "INSERT INTO provisioning.group_attribute
                 (tenant_id, group_id, external_id, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (tenant_id, group_id) DO UPDATE SET
                 external_id = EXCLUDED.external_id,
                 created_at = EXCLUDED.created_at,
                 updated_at = EXCLUDED.updated_at",
        )
        .bind(tenant.as_uuid())
        .bind(stored.group_id.as_uuid())
        .bind(stored.supplement.external_id.as_deref())
        .bind(stored.created_at)
        .bind(stored.updated_at)
        .execute(connection(uow)?)
        .await
        .map_err(|error| database_error(&error))?;
        Ok(())
    }

    async fn remove(&self, uow: &mut dyn UnitOfWork, group: GroupId) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        sqlx::query(
            "DELETE FROM provisioning.group_attribute WHERE tenant_id = $1 AND group_id = $2",
        )
        .bind(tenant.as_uuid())
        .bind(group.as_uuid())
        .execute(connection(uow)?)
        .await
        .map_err(|error| database_error(&error))?;
        Ok(())
    }

    async fn find(
        &self,
        uow: &mut dyn UnitOfWork,
        query: &ListQuery<GroupAttribute>,
    ) -> Result<Found<GroupId>, DomainError> {
        let found = find(uow, GROUPS, "g.id", query).await?;
        Ok(Found {
            total: found.total,
            ids: found.ids.into_iter().map(GroupId::from_uuid).collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hodor_provisioning::api::parse;

    #[test]
    fn no_value_of_a_filter_reaches_the_text_of_the_statement() {
        let filter = parse::<UserAttribute>(
            r#"userName eq "x'); DROP TABLE identity.user; --" or emails[value co "o'brien"] or externalId sw "\u0000""#,
        )
        .expect("a filter");
        let mut query: QueryBuilder<Postgres> = QueryBuilder::new("SELECT 1 WHERE ");
        push_filter(&mut query, &filter);
        let sql = query.sql().as_str().to_owned();
        assert!(!sql.contains("DROP"), "{sql}");
        assert!(!sql.contains("o'brien"), "{sql}");
        assert!(
            sql.contains("$1") && sql.contains("$2") && sql.contains("$3"),
            "{sql}"
        );
    }
}
