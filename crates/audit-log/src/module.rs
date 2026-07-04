use crate::admin::AuditLogAdminData;
use crate::migrations::AUDIT_LOG_MIGRATIONS;
use crate::repositories::PostgresAuditLogRepository;
use platform_core::AppContext;
use platform_module::{
    AdminSchema, EntitySchema, FieldSchema, FieldType, HostLinkedModule, LinkedBinding, Module,
    ModuleManifest,
};
use std::sync::Arc;

pub const MODULE_NAME: &str = "audit-log";
pub const AUDIT_EVENTS_READ: &str = "audit_log.events.read";

pub fn capabilities() -> Vec<String> {
    vec![AUDIT_EVENTS_READ.to_owned()]
}

pub fn event_schema() -> AdminSchema {
    AdminSchema {
        entities: vec![EntitySchema {
            name: "events".to_owned(),
            label: "Audit Events".to_owned(),
            fields: vec![
                field("id", "ID", FieldType::String, false),
                field("event_name", "Event Name", FieldType::String, false),
                field("module_name", "Module", FieldType::String, false),
                field("action", "Action", FieldType::String, false),
                field("outcome", "Outcome", FieldType::String, false),
                field("severity", "Severity", FieldType::String, false),
                field("actor_kind", "Actor Kind", FieldType::String, false),
                field("actor_id", "Actor ID", FieldType::String, true),
                field("actor_display", "Actor Display", FieldType::String, true),
                field("scope_module", "Scope Module", FieldType::String, true),
                field("scope_type", "Scope Type", FieldType::String, true),
                field("scope_id", "Scope ID", FieldType::String, true),
                field("scope_display", "Scope Display", FieldType::String, true),
                field("resource_type", "Resource Type", FieldType::String, true),
                field("resource_id", "Resource ID", FieldType::String, true),
                field(
                    "resource_display",
                    "Resource Display",
                    FieldType::String,
                    true,
                ),
                field("correlation_id", "Correlation ID", FieldType::String, true),
                field("causation_id", "Causation ID", FieldType::String, true),
                field("request_id", "Request ID", FieldType::String, true),
                field("story_id", "Story ID", FieldType::String, true),
                field("reason", "Reason", FieldType::String, true),
                field("metadata", "Metadata", FieldType::Json, false),
                field("occurred_at", "Occurred At", FieldType::Timestamp, false),
                field("created_at", "Created At", FieldType::Timestamp, false),
            ],
            read_capability: AUDIT_EVENTS_READ.to_owned(),
        }],
    }
}

pub fn manifest() -> ModuleManifest {
    ModuleManifest::builder(MODULE_NAME)
        .capabilities(capabilities())
        .admin(event_schema())
        .build()
}

pub fn binding() -> LinkedBinding {
    LinkedBinding::builder().build()
}

pub fn module(ctx: &AppContext) -> Module {
    let repository = PostgresAuditLogRepository::new(ctx.db.clone());
    let admin = AuditLogAdminData::new(repository);

    Module::linked(manifest(), binding()).with_admin_data(Arc::new(admin))
}

pub fn linked_module() -> HostLinkedModule {
    HostLinkedModule::linked(MODULE_NAME, manifest, module, AUDIT_LOG_MIGRATIONS)
}

fn field(name: &str, label: &str, field_type: FieldType, nullable: bool) -> FieldSchema {
    FieldSchema {
        name: name.to_owned(),
        label: label.to_owned(),
        field_type,
        nullable,
    }
}
