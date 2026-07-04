use audit_log::admin::AuditLogAdminData;
use audit_log::migrations::AUDIT_LOG_MIGRATIONS;
use audit_log::models::{
    AuditActor, AuditEventFilter, AuditEventInput, AuditOutcome, AuditRequestContext,
    AuditResource, AuditScope, AuditSeverity,
};
use audit_log::module::{AUDIT_EVENTS_READ, MODULE_NAME};
use audit_log::repositories::PostgresAuditLogRepository;
use chrono::{DateTime, Duration, TimeZone, Utc};
use platform_core::{
    ActorContext, CorrelationId, PLATFORM_MIGRATIONS, RequestContext, RequestId, apply_migrations,
};
use platform_module::{AdminDataSource, AdminListQuery, AdminSurface};
use platform_testing::TestDatabase;
use serde_json::{Value, json};
use std::sync::atomic::{AtomicBool, Ordering};

static DB_SKIP_REPORTED: AtomicBool = AtomicBool::new(false);

#[test]
fn audit_log_migration_defines_outcome_and_severity_checks() {
    let sql = AUDIT_LOG_MIGRATIONS[0].sql;

    assert!(sql.contains("outcome in ('success', 'failure', 'denied')"));
    assert!(sql.contains("severity in ('info', 'warning', 'critical')"));
}

#[test]
fn manifest_declares_audit_events_admin_schema() {
    let manifest = audit_log::module::manifest();

    assert_eq!(manifest.name, MODULE_NAME);
    assert_eq!(manifest.capabilities, vec![AUDIT_EVENTS_READ.to_owned()]);

    let Some(AdminSurface::Schema(schema)) = manifest.admin else {
        panic!("audit log manifest should expose a schema admin surface");
    };

    assert_eq!(schema.entities.len(), 1);
    let entity = &schema.entities[0];
    assert_eq!(entity.name, "events");
    assert_eq!(entity.read_capability, AUDIT_EVENTS_READ);

    let field_names = entity
        .fields
        .iter()
        .map(|field| field.name.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        field_names,
        vec![
            "id",
            "event_name",
            "module_name",
            "action",
            "outcome",
            "severity",
            "actor_kind",
            "actor_id",
            "actor_display",
            "scope_module",
            "scope_type",
            "scope_id",
            "scope_display",
            "resource_type",
            "resource_id",
            "resource_display",
            "correlation_id",
            "causation_id",
            "request_id",
            "story_id",
            "reason",
            "metadata",
            "occurred_at",
            "created_at",
        ]
    );
}

#[tokio::test]
async fn admin_data_lists_and_gets_audit_events() -> Result<(), Box<dyn std::error::Error>> {
    let Some(db) = migrated_database().await? else {
        return Ok(());
    };

    let repository = PostgresAuditLogRepository::new(db.pool.clone());
    let event = repository.record_event(sample_input()).await?;
    let admin = AuditLogAdminData::new(repository);

    let page = admin.list("events", &AdminListQuery::new(10, None)).await?;
    assert_eq!(page.records.len(), 1);
    assert_eq!(page.next_cursor, None);
    assert_eq!(
        page.records[0].get("id").and_then(Value::as_str),
        Some(event.id.as_str())
    );
    assert_eq!(
        page.records[0].get("scope_type").and_then(Value::as_str),
        Some("organization")
    );

    let fetched = admin
        .get("events", &event.id)
        .await?
        .expect("event should be available by id");
    assert_eq!(
        fetched.get("event_name").and_then(Value::as_str),
        Some("organization.member_role_changed")
    );

    assert!(
        admin
            .list("unknown", &AdminListQuery::new(10, None))
            .await
            .is_err()
    );
    assert!(admin.get("unknown", &event.id).await.is_err());

    db.cleanup().await;
    Ok(())
}

#[tokio::test]
async fn admin_data_uses_cursor_to_return_next_events_page()
-> Result<(), Box<dyn std::error::Error>> {
    let Some(db) = migrated_database().await? else {
        return Ok(());
    };

    let base = base_time();
    let repository = PostgresAuditLogRepository::new(db.pool.clone());
    let oldest = repository
        .record_event(event_named(
            "organization.page_oldest",
            base + Duration::minutes(1),
        ))
        .await?;
    let middle = repository
        .record_event(event_named(
            "organization.page_middle",
            base + Duration::minutes(2),
        ))
        .await?;
    let newest = repository
        .record_event(event_named(
            "organization.page_newest",
            base + Duration::minutes(3),
        ))
        .await?;
    let admin = AuditLogAdminData::new(repository);

    let first_page = admin.list("events", &AdminListQuery::new(2, None)).await?;
    assert_eq!(first_page.records.len(), 2);
    let first_page_ids = first_page
        .records
        .iter()
        .map(|record| record.get("id").and_then(Value::as_str).unwrap_or_default())
        .collect::<Vec<_>>();
    assert_eq!(first_page_ids, vec![newest.id.as_str(), middle.id.as_str()]);
    let cursor = first_page
        .next_cursor
        .expect("first page should include a next cursor");

    let second_page = admin
        .list("events", &AdminListQuery::new(2, Some(cursor)))
        .await?;
    assert_eq!(second_page.records.len(), 1);
    assert_eq!(second_page.next_cursor, None);
    let second_page_id = second_page.records[0]
        .get("id")
        .and_then(Value::as_str)
        .expect("second page record should include id");
    assert_eq!(second_page_id, oldest.id);
    assert!(!first_page_ids.contains(&second_page_id));

    db.cleanup().await;
    Ok(())
}

#[test]
fn success_input_builds_default_success_event_from_request_context() {
    let mut request = RequestContext::new(RequestId::new("req_2"), CorrelationId::new("corr_2"));
    request.actor = ActorContext::User {
        user_id: "usr_2".to_owned(),
        scopes: vec!["organization:write".to_owned()],
    };
    request.causation_id = Some("cause_2".to_owned());

    let scope = AuditScope {
        module: Some("organization".to_owned()),
        scope_type: "organization".to_owned(),
        id: "org_2".to_owned(),
        display: Some("Globex".to_owned()),
    };
    let resource = AuditResource {
        resource_type: "organization_member".to_owned(),
        id: "member_2".to_owned(),
        display: Some("Morgan".to_owned()),
    };
    let metadata = json!({ "role": "admin" });

    let before = Utc::now();
    let input = audit_log::public::success_input(
        &request,
        "organization",
        "member_role_changed",
        Some(scope.clone()),
        Some(resource.clone()),
        Some("role changed".to_owned()),
        metadata.clone(),
    );
    let after = Utc::now();

    assert_eq!(input.event_name, "organization.member_role_changed");
    assert_eq!(input.module_name, "organization");
    assert_eq!(input.action, "member_role_changed");
    assert_eq!(input.outcome, AuditOutcome::Success);
    assert_eq!(input.severity, AuditSeverity::Info);
    assert_eq!(
        input.actor,
        AuditActor {
            kind: "user".to_owned(),
            id: Some("usr_2".to_owned()),
            display: None,
        }
    );
    assert_eq!(
        input.request,
        Some(AuditRequestContext {
            correlation_id: Some("corr_2".to_owned()),
            causation_id: Some("cause_2".to_owned()),
            request_id: Some("req_2".to_owned()),
            story_id: Some("corr_2".to_owned()),
        })
    );
    assert_eq!(input.scope, Some(scope));
    assert_eq!(input.resource, Some(resource));
    assert_eq!(input.reason.as_deref(), Some("role changed"));
    assert_eq!(input.metadata, metadata);
    assert!(input.occurred_at >= before);
    assert!(input.occurred_at <= after);
}

#[tokio::test]
async fn record_event_inserts_append_only_row() -> Result<(), Box<dyn std::error::Error>> {
    let Some(db) = migrated_database().await? else {
        return Ok(());
    };

    let repository = PostgresAuditLogRepository::new(db.pool.clone());
    let event = repository.record_event(sample_input()).await?;

    assert!(event.id.starts_with("audit_evt_"));
    assert_eq!(event.event_name, "organization.member_role_changed");
    assert_eq!(event.module_name, "organization");
    assert_eq!(event.action, "member_role_changed");
    assert_eq!(event.outcome, AuditOutcome::Success);
    assert_eq!(event.severity, AuditSeverity::Info);
    assert_eq!(event.actor_kind, "user");
    assert_eq!(event.actor_id.as_deref(), Some("usr_owner"));
    assert_eq!(event.actor_display.as_deref(), Some("Owner"));
    assert_eq!(event.scope_module.as_deref(), Some("organization"));
    assert_eq!(event.scope_type.as_deref(), Some("organization"));
    assert_eq!(event.scope_id.as_deref(), Some("org_1"));
    assert_eq!(event.scope_display.as_deref(), Some("Acme"));
    assert_eq!(event.resource_type.as_deref(), Some("organization_member"));
    assert_eq!(event.resource_id.as_deref(), Some("member_1"));
    assert_eq!(event.resource_display.as_deref(), Some("Avery"));
    assert_eq!(event.correlation_id.as_deref(), Some("corr_1"));
    assert_eq!(event.causation_id.as_deref(), Some("httpreq_1"));
    assert_eq!(event.request_id.as_deref(), Some("req_1"));
    assert_eq!(event.story_id.as_deref(), Some("corr_1"));
    assert_eq!(
        event.reason.as_deref(),
        Some("role changed from member to admin")
    );
    assert_eq!(event.metadata, sample_metadata());

    db.cleanup().await;
    Ok(())
}

#[tokio::test]
async fn list_events_filters_by_event_scope_resource_actor_outcome_and_time()
-> Result<(), Box<dyn std::error::Error>> {
    let Some(db) = migrated_database().await? else {
        return Ok(());
    };

    let base = base_time();
    let repository = PostgresAuditLogRepository::new(db.pool.clone());
    repository
        .record_event(sample_input_at(base + Duration::minutes(1)))
        .await?;
    repository
        .record_event(non_matching_input(base + Duration::minutes(3)))
        .await?;

    let matching = repository
        .list_events(AuditEventFilter {
            event_name: Some("organization.member_role_changed".to_owned()),
            module_name: Some("organization".to_owned()),
            outcome: Some(AuditOutcome::Success),
            severity: Some(AuditSeverity::Info),
            actor_kind: Some("user".to_owned()),
            actor_id: Some("usr_owner".to_owned()),
            scope_module: Some("organization".to_owned()),
            scope_type: Some("organization".to_owned()),
            scope_id: Some("org_1".to_owned()),
            resource_type: Some("organization_member".to_owned()),
            resource_id: Some("member_1".to_owned()),
            correlation_id: Some("corr_1".to_owned()),
            occurred_after: Some(base),
            occurred_before: Some(base + Duration::minutes(2)),
            cursor: None,
            limit: 10,
        })
        .await?;

    assert_eq!(matching.len(), 1);
    assert_eq!(matching[0].event_name, "organization.member_role_changed");

    let denied = repository
        .list_events(AuditEventFilter {
            outcome: Some(AuditOutcome::Denied),
            limit: 10,
            ..AuditEventFilter::default()
        })
        .await?;

    assert!(denied.is_empty());

    db.cleanup().await;
    Ok(())
}

#[tokio::test]
async fn list_events_orders_by_occurred_at_then_id_and_clamps_limit()
-> Result<(), Box<dyn std::error::Error>> {
    let Some(db) = migrated_database().await? else {
        return Ok(());
    };

    let base = base_time();
    let repository = PostgresAuditLogRepository::new(db.pool.clone());
    repository
        .record_event(event_named("organization.older", base))
        .await?;
    let tie_a = repository
        .record_event(event_named(
            "organization.tie_a",
            base + Duration::minutes(1),
        ))
        .await?;
    let tie_b = repository
        .record_event(event_named(
            "organization.tie_b",
            base + Duration::minutes(1),
        ))
        .await?;
    repository
        .record_event(event_named(
            "organization.newer",
            base + Duration::minutes(2),
        ))
        .await?;

    let events = repository
        .list_events(AuditEventFilter {
            module_name: Some("organization".to_owned()),
            limit: 10,
            ..AuditEventFilter::default()
        })
        .await?;

    assert_eq!(events.len(), 4);
    assert_eq!(events[0].event_name, "organization.newer");
    assert_eq!(events[3].event_name, "organization.older");

    let tie_rows = events
        .iter()
        .filter(|event| event.occurred_at == base + Duration::minutes(1))
        .collect::<Vec<_>>();
    let mut expected_tie_ids = vec![tie_a.id, tie_b.id];
    expected_tie_ids.sort_by(|left, right| right.cmp(left));
    let actual_tie_ids = tie_rows
        .iter()
        .map(|event| event.id.clone())
        .collect::<Vec<_>>();
    assert_eq!(actual_tie_ids, expected_tie_ids);

    let clamped = repository
        .list_events(AuditEventFilter {
            module_name: Some("organization".to_owned()),
            limit: 0,
            ..AuditEventFilter::default()
        })
        .await?;

    assert_eq!(clamped.len(), 1);
    assert_eq!(clamped[0].event_name, "organization.newer");

    db.cleanup().await;
    Ok(())
}

#[tokio::test]
async fn record_event_in_transaction_rolls_back_with_transaction()
-> Result<(), Box<dyn std::error::Error>> {
    let Some(db) = migrated_database().await? else {
        return Ok(());
    };

    let repository = PostgresAuditLogRepository::new(db.pool.clone());
    let mut tx = db.pool.begin().await?;
    repository
        .record_event_in_tx(&mut tx, sample_input())
        .await?;
    tx.rollback().await?;

    let events = repository
        .list_events(AuditEventFilter {
            limit: 10,
            ..AuditEventFilter::default()
        })
        .await?;

    assert!(events.is_empty());

    db.cleanup().await;
    Ok(())
}

async fn migrated_database() -> Result<Option<TestDatabase>, Box<dyn std::error::Error>> {
    if std::env::var_os("DATABASE_URL").is_none() {
        report_db_skip("skipping audit-log Postgres integration tests: DATABASE_URL=unset");
        return Ok(None);
    }

    let Some(db) = TestDatabase::create().await else {
        report_db_skip(
            "skipping audit-log Postgres integration tests: DATABASE_URL=set, TestDatabase::create() returned None",
        );
        return Ok(None);
    };

    apply_migrations(&db.pool, PLATFORM_MIGRATIONS).await?;
    apply_migrations(&db.pool, AUDIT_LOG_MIGRATIONS).await?;

    Ok(Some(db))
}

fn report_db_skip(message: &str) {
    if !DB_SKIP_REPORTED.swap(true, Ordering::SeqCst) {
        eprintln!("{message}");
    }
}

fn sample_input() -> AuditEventInput {
    sample_input_at(Utc::now())
}

fn sample_input_at(occurred_at: DateTime<Utc>) -> AuditEventInput {
    AuditEventInput {
        event_name: "organization.member_role_changed".to_owned(),
        module_name: "organization".to_owned(),
        action: "member_role_changed".to_owned(),
        outcome: AuditOutcome::Success,
        severity: AuditSeverity::Info,
        actor: AuditActor {
            kind: "user".to_owned(),
            id: Some("usr_owner".to_owned()),
            display: Some("Owner".to_owned()),
        },
        scope: Some(AuditScope {
            module: Some("organization".to_owned()),
            scope_type: "organization".to_owned(),
            id: "org_1".to_owned(),
            display: Some("Acme".to_owned()),
        }),
        resource: Some(AuditResource {
            resource_type: "organization_member".to_owned(),
            id: "member_1".to_owned(),
            display: Some("Avery".to_owned()),
        }),
        request: Some(AuditRequestContext {
            correlation_id: Some("corr_1".to_owned()),
            causation_id: Some("httpreq_1".to_owned()),
            request_id: Some("req_1".to_owned()),
            story_id: Some("corr_1".to_owned()),
        }),
        reason: Some("role changed from member to admin".to_owned()),
        metadata: sample_metadata(),
        occurred_at,
    }
}

fn non_matching_input(occurred_at: DateTime<Utc>) -> AuditEventInput {
    let mut input = event_named("organization.member_removed", occurred_at);
    input.outcome = AuditOutcome::Failure;
    input.severity = AuditSeverity::Warning;
    input.actor = AuditActor {
        kind: "service".to_owned(),
        id: Some("svc_audit".to_owned()),
        display: None,
    };
    input.scope = Some(AuditScope {
        module: Some("billing".to_owned()),
        scope_type: "billing_account".to_owned(),
        id: "acct_1".to_owned(),
        display: Some("Acme Billing".to_owned()),
    });
    input.resource = Some(AuditResource {
        resource_type: "billing_member".to_owned(),
        id: "billing_member_1".to_owned(),
        display: Some("Blake".to_owned()),
    });
    input.request = Some(AuditRequestContext {
        correlation_id: Some("corr_2".to_owned()),
        causation_id: Some("httpreq_2".to_owned()),
        request_id: Some("req_2".to_owned()),
        story_id: Some("corr_2".to_owned()),
    });
    input
}

fn event_named(event_name: &str, occurred_at: DateTime<Utc>) -> AuditEventInput {
    let mut input = sample_input_at(occurred_at);
    event_name.clone_into(&mut input.event_name);
    event_name
        .rsplit_once('.')
        .map_or(event_name, |(_, action)| action)
        .clone_into(&mut input.action);
    input
}

fn sample_metadata() -> Value {
    json!({
        "old_role": "member",
        "new_role": "admin"
    })
}

fn base_time() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 1, 1, 12, 0, 0)
        .single()
        .expect("base time should be valid")
}
