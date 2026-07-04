use chrono::Utc;
use platform_core::db::DbTransaction;
use platform_core::{AppContext, AppResult, RequestContext};
use serde_json::Value;

pub use crate::models::{
    AuditActor, AuditActor as Actor, AuditEvent, AuditEvent as Event, AuditEventCursor,
    AuditEventCursor as EventCursor, AuditEventFilter, AuditEventFilter as EventFilter,
    AuditEventInput, AuditEventInput as EventInput, AuditOutcome, AuditOutcome as Outcome,
    AuditRequestContext, AuditRequestContext as Request, AuditResource, AuditResource as Resource,
    AuditScope, AuditScope as Scope, AuditSeverity, AuditSeverity as Severity, redact_metadata,
};
pub use crate::repositories::PostgresAuditLogRepository;

pub async fn record_event(ctx: &AppContext, input: AuditEventInput) -> AppResult<AuditEvent> {
    let repository = PostgresAuditLogRepository::new(ctx.db.clone());
    repository.record_event(input).await
}

pub async fn record_event_in_tx(
    repository: &PostgresAuditLogRepository,
    tx: &mut DbTransaction<'_>,
    input: AuditEventInput,
) -> AppResult<AuditEvent> {
    repository.record_event_in_tx(tx, input).await
}

pub fn success_input(
    request_ctx: &RequestContext,
    module_name: &str,
    action: &str,
    scope: Option<AuditScope>,
    resource: Option<AuditResource>,
    reason: Option<String>,
    metadata: Value,
) -> AuditEventInput {
    AuditEventInput {
        event_name: format!("{module_name}.{action}"),
        module_name: module_name.to_owned(),
        action: action.to_owned(),
        outcome: AuditOutcome::Success,
        severity: AuditSeverity::Info,
        actor: AuditActor::from_request(request_ctx),
        scope,
        resource,
        request: Some(AuditRequestContext::from_request(request_ctx)),
        reason,
        metadata,
        occurred_at: Utc::now(),
    }
}
