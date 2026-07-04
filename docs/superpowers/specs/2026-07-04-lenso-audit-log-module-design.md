# Lenso Audit Log Module Design

## Goal

Build a first-party, independently versioned Lenso audit-log module that gives
business modules a shared way to record audit events.

The first version proves module collaboration through `organization` while
keeping a future remote-module write protocol visible in the design. The first
implementation starts with linked Rust modules only.

## Positioning

`audit-log` is a reusable first-party module, not a Lenso core platform crate.
It belongs in its own repository:

```text
lenso-audit-log-module
```

This matches the split used by `lenso-auth-module` and
`lenso-organization-module`. The module can be installed, tested, released, and
versioned independently. `lenso` core should not depend on it.

`audit-log` does not replace Runtime Story. Runtime Story explains how a request
or runtime flow executed. Audit Log explains the business-relevant fact:

```text
who did what to which scoped resource, with what outcome, and why
```

Audit events may carry `correlation_id` or `story_id` so Console users can move
from an audit record to runtime evidence, but audit rows are not runtime
timeline nodes.

## Scope

### First Version

- Create the independent `lenso-audit-log-module` repository.
- Add a Rust crate, later named `lenso-module-audit-log`.
- Own an `audit_log` schema and append-only `events` table.
- Provide linked Rust writer APIs for first-party linked modules.
- Provide query helpers and a schema-admin data surface.
- Integrate `lenso-organization-module` as the primary proof path.
- Design remote-module audit write support without implementing it yet.
- Optionally map a very small set of host/platform events after the module path
  is working.

### Non-Goals

- No SIEM integration.
- No webhook delivery.
- No full-text search engine.
- No cryptographic immutability or hash chain in the first version.
- No dedicated `@lenso/audit-log-console` package in the first version.
- No remote write endpoint or remote response envelope processing in the first
  version.
- No replacement for `platform.story_events`, remote call history, execution
  logs, or runtime config's current local setting audit.

## Repository Shape

Target shape:

```text
lenso-audit-log-module/
  crates/audit-log/
    migrations/
    src/
      admin.rs
      dto.rs
      lib.rs
      migrations.rs
      models.rs
      module.rs
      public.rs
      repositories.rs
  packages/audit-log-console/        # later phase
  docs/superpowers/specs/
  Cargo.toml
  README.md
```

The first implementation should create only the Rust crate and backend module
surface. The Console package is deferred until the schema-admin view proves the
model.

## Architecture

The audit module owns generic audit concepts only. It must not depend on
`organization`, `auth`, or any business module internals.

Dependency direction:

```text
organization -> audit-log public API
host/platform adapters -> audit-log public API
audit-log -> platform-core / platform-module / lenso contracts
```

`audit-log` never queries another module's tables. Modules pass scoped resource
identity into the writer API.

The module should expose:

- `ModuleManifest` and linked `ModuleBinding`.
- Migrations for `audit_log.events`.
- Public writer API.
- Public query API.
- Schema-admin surface over audit event rows.

## Data Model

Use one table in the first version:

```text
audit_log.events
```

Suggested columns:

```text
id text primary key
event_name text not null
module_name text not null
action text not null
outcome text not null
severity text not null
actor_kind text not null
actor_id text
actor_display text
scope_module text
scope_type text
scope_id text
scope_display text
resource_type text
resource_id text
resource_display text
correlation_id text
causation_id text
request_id text
story_id text
reason text
metadata jsonb not null default '{}'::jsonb
occurred_at timestamptz not null
created_at timestamptz not null default now()
```

Use generic scope fields rather than `organization_id`. For organization-owned
events, `lenso-organization-module` writes:

```text
scope_module = organization
scope_type = organization
scope_id = org_123
```

This keeps `audit-log` independent from organization tables and IDs while still
supporting organization-scoped filters.

Indexes:

- `occurred_at desc`
- `module_name, occurred_at desc`
- `actor_id, occurred_at desc`
- `scope_type, scope_id, occurred_at desc`
- `resource_type, resource_id, occurred_at desc`
- `correlation_id`

Append-only semantics:

- The public API does not expose update or delete operations.
- First version does not claim physical tamper-proof storage.
- Future phases may add hash-chain exports or retention controls.

## Event Semantics

Required concepts:

- `event_name`: stable dotted name, such as
  `organization.member_role_changed`.
- `module_name`: module that owns the business meaning.
- `action`: short action name for grouping, such as `member_role_changed`.
- `outcome`: `success`, `failure`, or `denied`.
- `severity`: `info`, `warning`, or `critical`.
- `actor`: host-resolved actor snapshot.
- `scope`: optional business scope, such as an organization, tenant, workspace,
  project, account, or custom scope.
- `resource`: optional affected resource.
- `metadata`: structured safe metadata.

Audit events should be business-relevant. Do not write one row for every HTTP
request. Avoid noisy validation failures unless the caller treats them as a
real audit concern.

## Public Writer API

Linked modules should use public APIs instead of writing SQL directly.

Design sketch:

```rust
pub async fn record_event(ctx: &AppContext, input: AuditEventInput) -> AppResult<AuditEvent>;

pub async fn record_event_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    input: AuditEventInput,
) -> AppResult<AuditEvent>;
```

The first version should provide ergonomic helpers around the full input:

```rust
pub async fn record_success(...);
pub async fn record_failure(...);
pub async fn record_denied(...);
```

Transaction rule:

- Critical business audit sites use `record_event_in_tx` so the business change
  and audit event commit together.
- Observational host/platform adapters may use `record_event` if they are not
  part of the business transaction.

For `organization`, audit write failure should fail the organization operation
at critical sites because the audit row is part of the product guarantee.

## Organization Proof Path

`lenso-organization-module` is the primary proof path.

First events:

- `organization.created`
- `organization.archived`
- `organization.invitation_created`
- `organization.invitation_revoked`
- `organization.invitation_accepted`
- `organization.member_added`
- `organization.member_removed`
- `organization.member_role_changed`

Recommended scope and resource mapping:

```text
scope_module = organization
scope_type = organization
scope_id = <organization id>
resource_type = organization | organization_invitation | organization_member
resource_id = <affected resource id>
```

The integration should be optional from the organization repository's point of
view. The preferred shape is a feature or integration boundary so
`lenso-organization-module` can still build without `audit-log`.

## Host And Platform Adapter Path

The first implementation should avoid a broad automatic capture layer. After
the organization proof works, add only the smallest useful host/platform
adapter events.

Candidate phase 1.5 events:

- `runtime_config.changed`
- `admin_action.executed`

Candidate phase 2 events:

- `module.installed`
- `module.uninstalled`
- service release or deployment audit events

Do not duplicate Runtime Story wholesale. If an admin action is already
projected to `platform.story_events`, the audit event should be a compact
business record with `correlation_id`, not a second runtime timeline.

## Query Surface

First version query capabilities:

- list recent events
- filter by `event_name`
- filter by `module_name`
- filter by `outcome`
- filter by `severity`
- filter by `actor_kind` and `actor_id`
- filter by `scope_module`, `scope_type`, and `scope_id`
- filter by `resource_type` and `resource_id`
- filter by `correlation_id`
- filter by time range
- limit and cursor/page support

The first Console-visible surface should be schema-admin. A dedicated Console
package can come later after the data model and integration points are proven.

Natural views:

- recent audit events
- resource history
- scoped activity
- actor history

## Runtime Story Linkage

Audit rows may store:

- `correlation_id`
- `causation_id`
- `request_id`
- `story_id`

The first UI may show these fields as plain data. A later dedicated Console
package can render an "Open Story" action when the story is available.

Do not merge audit events into Runtime Story timeline items in the first
version. The timeline is for execution flow. Audit Log is a business record.

## Remote Module Design Reservation

Remote modules should not write directly to `audit_log.events`.

Future design:

- The host owns audit ingestion.
- A remote service may return a bounded `audit_events` envelope from selected
  host-owned invocations, such as admin actions, event handlers, or runtime
  functions.
- The host validates the envelope against the installed module manifest,
  configured trust policy, size limits, and event-name ownership.
- The host writes accepted rows through the same audit-log writer path.

Example future response shape:

```json
{
  "output": {},
  "audit_events": [
    {
      "event_name": "crm.contact_synced",
      "action": "contact_synced",
      "outcome": "success",
      "severity": "info",
      "resource": {
        "type": "contact",
        "id": "contact_123"
      },
      "metadata": {
        "source": "salesforce"
      }
    }
  ]
}
```

First version does not implement this. The spec only preserves the direction so
linked-only APIs do not close the door on remote module audit events.

Deferred remote concerns:

- idempotency keys
- retry behavior
- event ownership checks
- replay protection
- signing or host-to-remote trust tokens
- envelope size limits
- remote module manifest declaration for audit event names

## Security And Privacy

First-version rules:

- Do not store passwords, tokens, session secrets, private keys, or full request
  bodies.
- `metadata` must be explicit and structured.
- Sensitive changes should record field names and safe summaries, not raw secret
  values.
- `actor_display`, `scope_display`, and `resource_display` are display
  snapshots only. They are not authoritative joins.
- Query access should use existing Console/admin capability checks.

First-version capability:

```text
audit_log.events.read
```

The first manifest should expose `audit_log.events.read` for schema-admin and
future Console reads.

Reserved future capabilities:

```text
audit_log.events.write
audit_log.events.export
```

`audit_log.events.write` is reserved for future host-owned remote ingestion. The
first version uses linked Rust public APIs and does not expose a general HTTP
write endpoint. `audit_log.events.export` is also reserved; export is not part
of the first implementation.

## Testing And Verification

Required tests:

- migration creates `audit_log.events`
- `record_event` inserts a safe audit row
- `record_event_in_tx` commits with the surrounding business transaction
- `record_event_in_tx` rolls back with the surrounding business transaction
- queries filter by actor, scope, resource, module, outcome, and time
- metadata redaction helper refuses or strips obvious secrets
- manifest declares capabilities and schema-admin surface
- organization integration writes expected audit rows for at least five key
  operations
- audit rows carry correlation/request/story fields when a request context is
  available

Validation commands should mirror sibling first-party module repositories:

```sh
cargo fmt --all --check
cargo test --locked -p lenso-module-audit-log
```

If a Console package is later added:

```sh
pnpm check
```

## Rollout Plan

### PR 1: Repository And Design

- Create `lenso-audit-log-module`.
- Commit this design spec.

### PR 2: Audit Log Module Core

- Add Rust workspace and `crates/audit-log`.
- Add migration, models, repository, public writer, manifest, and schema-admin
  surface.
- Add unit and integration tests.

### PR 3: Organization Integration

- Add optional integration from `lenso-organization-module` to audit-log.
- Record the main organization audit events.
- Add tests that prove transaction semantics.

### PR 4: Minimal Platform Adapter

- Add one or two host/platform adapter events only if they remain small:
  `runtime_config.changed` and/or `admin_action.executed`.
- Keep module install and service deployment audit events for later if they
  require broad CLI or receipt changes.

### Later

- Dedicated `@lenso/audit-log-console`.
- Remote module audit envelope.
- Export.
- Retention.
- Hash-chain or external archive support.

## Implementation Plan Defaults

Use these defaults unless implementation uncovers a concrete incompatibility:

- `lenso-organization-module` adds an optional `audit-log` feature that depends
  on `lenso-module-audit-log` and routes critical organization operations
  through audit writer calls.
- `record_event_in_tx` accepts the repository's existing SQLx transaction type
  in the first version. Introduce a narrower trait only if the concrete type
  makes the organization integration awkward.
- The first manifest exposes `audit_log.events.read` only. `write` and `export`
  remain reserved future capabilities.
- The first Console view is schema-admin. Backend query helpers should support
  the filters listed above, but a custom Console page is deferred.
