use crate::models::{AuditEvent, AuditEventCursor, AuditEventFilter};
use crate::repositories::PostgresAuditLogRepository;
use async_trait::async_trait;
use platform_core::{AppError, AppResult, ErrorCode};
use platform_module::{AdminDataSource, AdminListQuery, AdminPage};
use serde_json::{Value, json};

const ADMIN_EVENTS_PAGE_LIMIT: i64 = 199;

#[derive(Debug, Clone)]
pub struct AuditLogAdminData {
    repository: PostgresAuditLogRepository,
}

impl AuditLogAdminData {
    pub fn new(repository: PostgresAuditLogRepository) -> Self {
        Self { repository }
    }
}

#[async_trait]
impl AdminDataSource for AuditLogAdminData {
    async fn list(&self, entity: &str, query: &AdminListQuery) -> AppResult<AdminPage> {
        ensure_events_entity(entity)?;

        let page_limit = admin_events_page_limit(query.limit);
        if page_limit == 0 {
            return Ok(AdminPage {
                records: Vec::new(),
                next_cursor: None,
            });
        }

        let cursor = decode_admin_cursor(query.cursor.as_deref())?;
        let mut events = self
            .repository
            .list_events(AuditEventFilter {
                limit: page_limit.saturating_add(1),
                cursor,
                ..AuditEventFilter::default()
            })
            .await?;
        let page_limit = usize::try_from(page_limit).unwrap_or(usize::MAX);
        let has_next_page = events.len() > page_limit;

        if has_next_page {
            events.truncate(page_limit);
        }

        let next_cursor = if has_next_page {
            events
                .last()
                .map(|event| {
                    encode_admin_cursor(&AuditEventCursor {
                        occurred_at: event.occurred_at,
                        id: event.id.clone(),
                    })
                })
                .transpose()?
        } else {
            None
        };
        let records = events.iter().map(event_to_value).collect();

        Ok(AdminPage {
            records,
            next_cursor,
        })
    }

    async fn get(&self, entity: &str, id: &str) -> AppResult<Option<Value>> {
        ensure_events_entity(entity)?;

        self.repository
            .get_event(id)
            .await
            .map(|event| event.as_ref().map(event_to_value))
    }
}

fn ensure_events_entity(entity: &str) -> AppResult<()> {
    if entity == "events" {
        return Ok(());
    }

    Err(AppError::new(
        ErrorCode::NotFound,
        format!("unknown audit log entity: {entity}"),
    ))
}

fn admin_events_page_limit(requested_limit: i64) -> i64 {
    requested_limit.clamp(0, ADMIN_EVENTS_PAGE_LIMIT)
}

fn encode_admin_cursor(cursor: &AuditEventCursor) -> AppResult<String> {
    serde_json::to_string(cursor).map_err(|source| {
        AppError::new(
            ErrorCode::Internal,
            "failed to encode audit log admin cursor",
        )
        .with_source(source)
    })
}

fn decode_admin_cursor(cursor: Option<&str>) -> AppResult<Option<AuditEventCursor>> {
    let Some(cursor) = cursor else {
        return Ok(None);
    };

    serde_json::from_str(cursor).map(Some).map_err(|source| {
        AppError::new(ErrorCode::Validation, "invalid audit log admin cursor").with_source(source)
    })
}

fn event_to_value(event: &AuditEvent) -> Value {
    json!({
        "id": &event.id,
        "event_name": &event.event_name,
        "module_name": &event.module_name,
        "action": &event.action,
        "outcome": event.outcome,
        "severity": event.severity,
        "actor_kind": &event.actor_kind,
        "actor_id": &event.actor_id,
        "actor_display": &event.actor_display,
        "scope_module": &event.scope_module,
        "scope_type": &event.scope_type,
        "scope_id": &event.scope_id,
        "scope_display": &event.scope_display,
        "resource_type": &event.resource_type,
        "resource_id": &event.resource_id,
        "resource_display": &event.resource_display,
        "correlation_id": &event.correlation_id,
        "causation_id": &event.causation_id,
        "request_id": &event.request_id,
        "story_id": &event.story_id,
        "reason": &event.reason,
        "metadata": &event.metadata,
        "occurred_at": event.occurred_at,
        "created_at": event.created_at,
    })
}

#[cfg(test)]
mod tests {
    use super::{admin_events_page_limit, decode_admin_cursor, encode_admin_cursor};
    use crate::models::AuditEventCursor;
    use chrono::{TimeZone, Utc};
    use platform_core::ErrorCode;

    #[test]
    fn admin_cursor_round_trips_event_position() {
        let cursor = AuditEventCursor {
            occurred_at: Utc
                .with_ymd_and_hms(2026, 1, 1, 12, 30, 45)
                .single()
                .expect("valid cursor time"),
            id: "audit_evt_123".to_owned(),
        };

        let encoded = encode_admin_cursor(&cursor).expect("cursor should encode");
        assert_ne!(encoded, cursor.id);

        let decoded = decode_admin_cursor(Some(encoded.as_str())).expect("cursor should decode");
        assert_eq!(decoded, Some(cursor));
    }

    #[test]
    fn invalid_admin_cursor_returns_validation_error() {
        let error = decode_admin_cursor(Some("not-json")).expect_err("cursor should be invalid");

        assert_eq!(error.code, ErrorCode::Validation);
    }

    #[test]
    fn admin_event_page_limit_leaves_room_for_overfetch() {
        assert_eq!(admin_events_page_limit(-10), 0);
        assert_eq!(admin_events_page_limit(2), 2);
        assert_eq!(admin_events_page_limit(199), 199);
        assert_eq!(admin_events_page_limit(200), 199);
        assert_eq!(admin_events_page_limit(500), 199);
    }
}
