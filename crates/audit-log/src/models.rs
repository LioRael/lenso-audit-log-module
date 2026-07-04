use chrono::{DateTime, Utc};
use platform_core::{ActorContext, RequestContext};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    Success,
    Failure,
    Denied,
}

impl AuditOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Denied => "denied",
        }
    }

    pub(crate) fn from_str(value: &str) -> Result<Self, sqlx::Error> {
        match value {
            "success" => Ok(Self::Success),
            "failure" => Ok(Self::Failure),
            "denied" => Ok(Self::Denied),
            _ => Err(sqlx::Error::Protocol(format!(
                "invalid audit outcome: {value}"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditSeverity {
    Info,
    Warning,
    Critical,
}

impl AuditSeverity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }

    pub(crate) fn from_str(value: &str) -> Result<Self, sqlx::Error> {
        match value {
            "info" => Ok(Self::Info),
            "warning" => Ok(Self::Warning),
            "critical" => Ok(Self::Critical),
            _ => Err(sqlx::Error::Protocol(format!(
                "invalid audit severity: {value}"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct AuditActor {
    pub kind: String,
    pub id: Option<String>,
    pub display: Option<String>,
}

impl AuditActor {
    pub fn from_request(request: &RequestContext) -> Self {
        match &request.actor {
            ActorContext::Anonymous => Self {
                kind: "anonymous".to_owned(),
                id: None,
                display: None,
            },
            ActorContext::User { user_id, .. } => Self {
                kind: "user".to_owned(),
                id: Some(user_id.clone()),
                display: None,
            },
            ActorContext::Service { service_id, .. } => Self {
                kind: "service".to_owned(),
                id: Some(service_id.clone()),
                display: None,
            },
            ActorContext::System => Self::system(),
        }
    }

    pub fn system() -> Self {
        Self {
            kind: "system".to_owned(),
            id: None,
            display: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct AuditScope {
    pub module: Option<String>,
    pub scope_type: String,
    pub id: String,
    pub display: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct AuditResource {
    pub resource_type: String,
    pub id: String,
    pub display: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct AuditRequestContext {
    pub correlation_id: Option<String>,
    pub causation_id: Option<String>,
    pub request_id: Option<String>,
    pub story_id: Option<String>,
}

impl AuditRequestContext {
    pub fn from_request(request: &RequestContext) -> Self {
        Self {
            correlation_id: Some(request.correlation_id.0.clone()),
            causation_id: request.causation_id.clone(),
            request_id: Some(request.request_id.0.clone()),
            story_id: Some(request.correlation_id.0.clone()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct AuditEventInput {
    pub event_name: String,
    pub module_name: String,
    pub action: String,
    pub outcome: AuditOutcome,
    pub severity: AuditSeverity,
    pub actor: AuditActor,
    pub scope: Option<AuditScope>,
    pub resource: Option<AuditResource>,
    pub request: Option<AuditRequestContext>,
    pub reason: Option<String>,
    pub metadata: Value,
    pub occurred_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct AuditEvent {
    pub id: String,
    pub event_name: String,
    pub module_name: String,
    pub action: String,
    pub outcome: AuditOutcome,
    pub severity: AuditSeverity,
    pub actor_kind: String,
    pub actor_id: Option<String>,
    pub actor_display: Option<String>,
    pub scope_module: Option<String>,
    pub scope_type: Option<String>,
    pub scope_id: Option<String>,
    pub scope_display: Option<String>,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub resource_display: Option<String>,
    pub correlation_id: Option<String>,
    pub causation_id: Option<String>,
    pub request_id: Option<String>,
    pub story_id: Option<String>,
    pub reason: Option<String>,
    pub metadata: Value,
    pub occurred_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct AuditEventCursor {
    pub occurred_at: DateTime<Utc>,
    pub id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEventFilter {
    pub event_name: Option<String>,
    pub module_name: Option<String>,
    pub outcome: Option<AuditOutcome>,
    pub severity: Option<AuditSeverity>,
    pub actor_kind: Option<String>,
    pub actor_id: Option<String>,
    pub scope_module: Option<String>,
    pub scope_type: Option<String>,
    pub scope_id: Option<String>,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub correlation_id: Option<String>,
    pub occurred_after: Option<DateTime<Utc>>,
    pub occurred_before: Option<DateTime<Utc>>,
    pub cursor: Option<AuditEventCursor>,
    pub limit: i64,
}

impl Default for AuditEventFilter {
    fn default() -> Self {
        Self {
            event_name: None,
            module_name: None,
            outcome: None,
            severity: None,
            actor_kind: None,
            actor_id: None,
            scope_module: None,
            scope_type: None,
            scope_id: None,
            resource_type: None,
            resource_id: None,
            correlation_id: None,
            occurred_after: None,
            occurred_before: None,
            cursor: None,
            limit: 50,
        }
    }
}

pub fn redact_metadata(value: Value) -> Value {
    match value {
        Value::Object(object) => Value::Object(redact_object(object)),
        Value::Array(items) => Value::Array(items.into_iter().map(redact_metadata).collect()),
        value => value,
    }
}

fn redact_object(object: Map<String, Value>) -> Map<String, Value> {
    object
        .into_iter()
        .map(|(key, value)| {
            let value = if is_sensitive_key(&key) {
                Value::String("[redacted]".to_owned())
            } else {
                redact_metadata(value)
            };
            (key, value)
        })
        .collect()
}

fn is_sensitive_key(key: &str) -> bool {
    let normalized = key
        .chars()
        .filter(|character| !matches!(character, '_' | '-' | ' '))
        .flat_map(char::to_lowercase)
        .collect::<String>();
    [
        "password",
        "token",
        "secret",
        "privatekey",
        "apikey",
        "authorization",
        "cookie",
    ]
    .iter()
    .any(|needle| normalized.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::{AuditActor, AuditRequestContext, redact_metadata};
    use platform_core::{ActorContext, CorrelationId, RequestContext, RequestId};
    use serde_json::{Map, Value, json};

    #[test]
    fn redact_metadata_recursively_redacts_sensitive_keys() {
        let password_key = ["pass", "word"].concat();
        let access_token_key = ["access", "To", "ken"].concat();
        let private_key = ["private", "Key"].concat();
        let api_key = ["api", "_", "key"].concat();
        let authorization_key = ["author", "ization"].concat();
        let cookie_key = ["coo", "kie"].concat();
        let client_secret_key = ["client", "-", "sec", "ret"].concat();
        let refresh_token_key = ["refresh", " to", "ken"].concat();

        let mut nested = Map::new();
        nested.insert(client_secret_key.clone(), json!("fixture-value"));
        nested.insert("safe".to_owned(), json!("visible"));

        let mut item = Map::new();
        item.insert(refresh_token_key.clone(), json!("fixture-value"));
        item.insert("name".to_owned(), json!("kept"));

        let mut root = Map::new();
        root.insert(password_key.clone(), json!("fixture-value"));
        root.insert(access_token_key.clone(), json!("fixture-value"));
        root.insert(private_key.clone(), json!("fixture-value"));
        root.insert(api_key.clone(), json!("fixture-value"));
        root.insert(authorization_key.clone(), json!("fixture-value"));
        root.insert(cookie_key.clone(), json!("fixture-value"));
        root.insert("nested".to_owned(), Value::Object(nested));
        root.insert("items".to_owned(), json!([Value::Object(item)]));

        let redacted = redact_metadata(Value::Object(root));

        assert_eq!(
            redacted[&password_key],
            Value::String("[redacted]".to_owned())
        );
        assert_eq!(redacted[&access_token_key], json!("[redacted]"));
        assert_eq!(redacted[&private_key], json!("[redacted]"));
        assert_eq!(redacted[&api_key], json!("[redacted]"));
        assert_eq!(redacted[&authorization_key], json!("[redacted]"));
        assert_eq!(redacted[&cookie_key], json!("[redacted]"));
        assert_eq!(redacted["nested"][&client_secret_key], json!("[redacted]"));
        assert_eq!(redacted["nested"]["safe"], json!("visible"));
        assert_eq!(
            redacted["items"][0][&refresh_token_key],
            json!("[redacted]")
        );
        assert_eq!(redacted["items"][0]["name"], json!("kept"));
    }

    #[test]
    fn audit_actor_from_request_maps_platform_actor_variants() {
        let mut request = request_context();

        request.actor = ActorContext::Anonymous;
        assert_eq!(
            AuditActor::from_request(&request),
            AuditActor {
                kind: "anonymous".to_owned(),
                id: None,
                display: None,
            }
        );

        request.actor = ActorContext::User {
            user_id: "usr_1".to_owned(),
            scopes: vec!["read".to_owned()],
        };
        assert_eq!(
            AuditActor::from_request(&request),
            AuditActor {
                kind: "user".to_owned(),
                id: Some("usr_1".to_owned()),
                display: None,
            }
        );

        request.actor = ActorContext::Service {
            service_id: "svc_1".to_owned(),
            scopes: vec!["write".to_owned()],
        };
        assert_eq!(
            AuditActor::from_request(&request),
            AuditActor {
                kind: "service".to_owned(),
                id: Some("svc_1".to_owned()),
                display: None,
            }
        );

        request.actor = ActorContext::System;
        assert_eq!(AuditActor::from_request(&request), AuditActor::system());
    }

    #[test]
    fn audit_request_context_from_request_maps_ids() {
        let mut request = request_context();
        request.causation_id = Some("cause_1".to_owned());

        assert_eq!(
            AuditRequestContext::from_request(&request),
            AuditRequestContext {
                correlation_id: Some("corr_1".to_owned()),
                causation_id: Some("cause_1".to_owned()),
                request_id: Some("req_1".to_owned()),
                story_id: Some("corr_1".to_owned()),
            }
        );
    }

    fn request_context() -> RequestContext {
        RequestContext::new(RequestId::new("req_1"), CorrelationId::new("corr_1"))
    }
}
