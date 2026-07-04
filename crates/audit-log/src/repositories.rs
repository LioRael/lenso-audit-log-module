use crate::models::{
    AuditEvent, AuditEventFilter, AuditEventInput, AuditOutcome, AuditSeverity, redact_metadata,
};
use chrono::{DateTime, Utc};
use platform_core::db::DbTransaction;
use platform_core::{AppError, AppResult, DbPool, ErrorCode};
use serde_json::Value;
use sqlx::postgres::PgRow;
use sqlx::{Executor, Postgres, QueryBuilder, Row};
use uuid::Uuid;

const LIST_EVENTS_SQL: &str = r"
    select
        id,
        event_name,
        module_name,
        action,
        outcome,
        severity,
        actor_kind,
        actor_id,
        actor_display,
        scope_module,
        scope_type,
        scope_id,
        scope_display,
        resource_type,
        resource_id,
        resource_display,
        correlation_id,
        causation_id,
        request_id,
        story_id,
        reason,
        metadata,
        occurred_at,
        created_at
    from audit_log.events
    ";

const GET_EVENT_SQL: &str = r"
    select
        id,
        event_name,
        module_name,
        action,
        outcome,
        severity,
        actor_kind,
        actor_id,
        actor_display,
        scope_module,
        scope_type,
        scope_id,
        scope_display,
        resource_type,
        resource_id,
        resource_display,
        correlation_id,
        causation_id,
        request_id,
        story_id,
        reason,
        metadata,
        occurred_at,
        created_at
    from audit_log.events
    where id = $1
    ";

const INSERT_EVENT_SQL: &str = r"
    insert into audit_log.events (
        id,
        event_name,
        module_name,
        action,
        outcome,
        severity,
        actor_kind,
        actor_id,
        actor_display,
        scope_module,
        scope_type,
        scope_id,
        scope_display,
        resource_type,
        resource_id,
        resource_display,
        correlation_id,
        causation_id,
        request_id,
        story_id,
        reason,
        metadata,
        occurred_at
    )
    values (
        $1,
        $2,
        $3,
        $4,
        $5,
        $6,
        $7,
        $8,
        $9,
        $10,
        $11,
        $12,
        $13,
        $14,
        $15,
        $16,
        $17,
        $18,
        $19,
        $20,
        $21,
        $22,
        $23
    )
    returning
        id,
        event_name,
        module_name,
        action,
        outcome,
        severity,
        actor_kind,
        actor_id,
        actor_display,
        scope_module,
        scope_type,
        scope_id,
        scope_display,
        resource_type,
        resource_id,
        resource_display,
        correlation_id,
        causation_id,
        request_id,
        story_id,
        reason,
        metadata,
        occurred_at,
        created_at
    ";

#[derive(Debug, Clone)]
pub struct PostgresAuditLogRepository {
    pool: DbPool,
}

impl PostgresAuditLogRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn record_event(&self, input: AuditEventInput) -> AppResult<AuditEvent> {
        insert_event(&self.pool, NewAuditEvent::from_input(input))
            .await
            .map_err(map_audit_log_error)
    }

    pub async fn record_event_in_tx(
        &self,
        tx: &mut DbTransaction<'_>,
        input: AuditEventInput,
    ) -> AppResult<AuditEvent> {
        insert_event(&mut **tx, NewAuditEvent::from_input(input))
            .await
            .map_err(map_audit_log_error)
    }

    pub async fn list_events(&self, filter: AuditEventFilter) -> AppResult<Vec<AuditEvent>> {
        let limit = filter.limit.clamp(1, 200);
        let mut builder = QueryBuilder::<Postgres>::new(LIST_EVENTS_SQL);
        push_event_filters(&mut builder, filter);

        builder
            .push(" order by occurred_at desc, id desc limit ")
            .push_bind(limit);

        let rows = builder
            .build()
            .fetch_all(&self.pool)
            .await
            .map_err(map_audit_log_error)?;

        rows.iter()
            .map(map_event_row)
            .collect::<Result<Vec<_>, _>>()
            .map_err(map_audit_log_error)
    }

    pub async fn get_event(&self, id: &str) -> AppResult<Option<AuditEvent>> {
        let row = sqlx::query(GET_EVENT_SQL)
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_audit_log_error)?;

        row.as_ref()
            .map(map_event_row)
            .transpose()
            .map_err(map_audit_log_error)
    }
}

#[derive(Debug)]
struct NewAuditEvent {
    id: String,
    event_name: String,
    module_name: String,
    action: String,
    outcome: String,
    severity: String,
    actor_kind: String,
    actor_id: Option<String>,
    actor_display: Option<String>,
    scope_module: Option<String>,
    scope_type: Option<String>,
    scope_id: Option<String>,
    scope_display: Option<String>,
    resource_type: Option<String>,
    resource_id: Option<String>,
    resource_display: Option<String>,
    correlation_id: Option<String>,
    causation_id: Option<String>,
    request_id: Option<String>,
    story_id: Option<String>,
    reason: Option<String>,
    metadata: Value,
    occurred_at: DateTime<Utc>,
}

impl NewAuditEvent {
    fn from_input(input: AuditEventInput) -> Self {
        Self {
            id: format!("audit_evt_{}", Uuid::now_v7()),
            event_name: input.event_name,
            module_name: input.module_name,
            action: input.action,
            outcome: input.outcome.as_str().to_owned(),
            severity: input.severity.as_str().to_owned(),
            actor_kind: input.actor.kind,
            actor_id: input.actor.id,
            actor_display: input.actor.display,
            scope_module: input.scope.as_ref().and_then(|scope| scope.module.clone()),
            scope_type: input.scope.as_ref().map(|scope| scope.scope_type.clone()),
            scope_id: input.scope.as_ref().map(|scope| scope.id.clone()),
            scope_display: input.scope.as_ref().and_then(|scope| scope.display.clone()),
            resource_type: input
                .resource
                .as_ref()
                .map(|resource| resource.resource_type.clone()),
            resource_id: input.resource.as_ref().map(|resource| resource.id.clone()),
            resource_display: input
                .resource
                .as_ref()
                .and_then(|resource| resource.display.clone()),
            correlation_id: input
                .request
                .as_ref()
                .and_then(|request| request.correlation_id.clone()),
            causation_id: input
                .request
                .as_ref()
                .and_then(|request| request.causation_id.clone()),
            request_id: input
                .request
                .as_ref()
                .and_then(|request| request.request_id.clone()),
            story_id: input
                .request
                .as_ref()
                .and_then(|request| request.story_id.clone()),
            reason: input.reason,
            metadata: redact_metadata(input.metadata),
            occurred_at: input.occurred_at,
        }
    }
}

async fn insert_event<'executor, E>(
    executor: E,
    event: NewAuditEvent,
) -> Result<AuditEvent, sqlx::Error>
where
    E: Executor<'executor, Database = Postgres>,
{
    let row = sqlx::query(INSERT_EVENT_SQL)
        .bind(event.id)
        .bind(event.event_name)
        .bind(event.module_name)
        .bind(event.action)
        .bind(event.outcome)
        .bind(event.severity)
        .bind(event.actor_kind)
        .bind(event.actor_id)
        .bind(event.actor_display)
        .bind(event.scope_module)
        .bind(event.scope_type)
        .bind(event.scope_id)
        .bind(event.scope_display)
        .bind(event.resource_type)
        .bind(event.resource_id)
        .bind(event.resource_display)
        .bind(event.correlation_id)
        .bind(event.causation_id)
        .bind(event.request_id)
        .bind(event.story_id)
        .bind(event.reason)
        .bind(event.metadata)
        .bind(event.occurred_at)
        .fetch_one(executor)
        .await?;

    map_event_row(&row)
}

fn push_event_filters(builder: &mut QueryBuilder<Postgres>, filter: AuditEventFilter) {
    let mut has_where = false;

    push_text_filter(builder, &mut has_where, "event_name", filter.event_name);
    push_text_filter(builder, &mut has_where, "module_name", filter.module_name);

    if let Some(outcome) = filter.outcome {
        push_where(builder, &mut has_where);
        builder.push("outcome = ").push_bind(outcome.as_str());
    }

    if let Some(severity) = filter.severity {
        push_where(builder, &mut has_where);
        builder.push("severity = ").push_bind(severity.as_str());
    }

    push_text_filter(builder, &mut has_where, "actor_kind", filter.actor_kind);
    push_text_filter(builder, &mut has_where, "actor_id", filter.actor_id);
    push_text_filter(builder, &mut has_where, "scope_module", filter.scope_module);
    push_text_filter(builder, &mut has_where, "scope_type", filter.scope_type);
    push_text_filter(builder, &mut has_where, "scope_id", filter.scope_id);
    push_text_filter(
        builder,
        &mut has_where,
        "resource_type",
        filter.resource_type,
    );
    push_text_filter(builder, &mut has_where, "resource_id", filter.resource_id);
    push_text_filter(
        builder,
        &mut has_where,
        "correlation_id",
        filter.correlation_id,
    );

    if let Some(occurred_after) = filter.occurred_after {
        push_where(builder, &mut has_where);
        builder.push("occurred_at >= ").push_bind(occurred_after);
    }

    if let Some(occurred_before) = filter.occurred_before {
        push_where(builder, &mut has_where);
        builder.push("occurred_at <= ").push_bind(occurred_before);
    }

    if let Some(cursor) = filter.cursor {
        push_where(builder, &mut has_where);
        builder
            .push("(occurred_at < ")
            .push_bind(cursor.occurred_at)
            .push(" or (occurred_at = ")
            .push_bind(cursor.occurred_at)
            .push(" and id < ")
            .push_bind(cursor.id)
            .push("))");
    }
}

fn push_text_filter(
    builder: &mut QueryBuilder<Postgres>,
    has_where: &mut bool,
    column: &'static str,
    value: Option<String>,
) {
    if let Some(value) = value {
        push_where(builder, has_where);
        builder.push(column).push(" = ").push_bind(value);
    }
}

fn push_where(builder: &mut QueryBuilder<Postgres>, has_where: &mut bool) {
    if *has_where {
        builder.push(" and ");
    } else {
        builder.push(" where ");
        *has_where = true;
    }
}

fn map_event_row(row: &PgRow) -> Result<AuditEvent, sqlx::Error> {
    let outcome = row.try_get::<String, _>("outcome")?;
    let severity = row.try_get::<String, _>("severity")?;

    Ok(AuditEvent {
        id: row.try_get("id")?,
        event_name: row.try_get("event_name")?,
        module_name: row.try_get("module_name")?,
        action: row.try_get("action")?,
        outcome: AuditOutcome::from_str(&outcome)?,
        severity: AuditSeverity::from_str(&severity)?,
        actor_kind: row.try_get("actor_kind")?,
        actor_id: row.try_get("actor_id")?,
        actor_display: row.try_get("actor_display")?,
        scope_module: row.try_get("scope_module")?,
        scope_type: row.try_get("scope_type")?,
        scope_id: row.try_get("scope_id")?,
        scope_display: row.try_get("scope_display")?,
        resource_type: row.try_get("resource_type")?,
        resource_id: row.try_get("resource_id")?,
        resource_display: row.try_get("resource_display")?,
        correlation_id: row.try_get("correlation_id")?,
        causation_id: row.try_get("causation_id")?,
        request_id: row.try_get("request_id")?,
        story_id: row.try_get("story_id")?,
        reason: row.try_get("reason")?,
        metadata: row.try_get("metadata")?,
        occurred_at: row.try_get("occurred_at")?,
        created_at: row.try_get("created_at")?,
    })
}

fn map_audit_log_error(source: sqlx::Error) -> AppError {
    AppError::new(ErrorCode::Internal, "audit log query failed").with_source(source)
}
