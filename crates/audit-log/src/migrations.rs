use platform_core::Migration;

pub const AUDIT_LOG_MIGRATIONS: &[Migration] = &[Migration {
    name: "audit-log/0001_create_audit_log_schema",
    sql: include_str!("../migrations/0001_create_audit_log_schema.sql"),
}];
