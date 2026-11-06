use serde::{Deserialize, Serialize};

/// Where a message came from, one shape for every sender (A12): an instance's `id` or a
/// service's name, the `node` that attests it, and the sender's own `label`. An anonymous
/// sender has neither `id` nor `service`; its `label` is its unattested `from`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Origin {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    pub node: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

impl Origin {
    pub fn instance(id: &str, node: &str, label: Option<&str>) -> Origin {
        Origin {
            id: Some(id.to_string()),
            service: None,
            node: node.to_string(),
            label: label.map(str::to_string),
        }
    }

    pub fn service(name: &str, node: &str) -> Origin {
        Origin {
            id: None,
            service: Some(name.to_string()),
            node: node.to_string(),
            label: None,
        }
    }

    pub fn anonymous(from: &str, node: &str) -> Origin {
        Origin {
            id: None,
            service: None,
            node: node.to_string(),
            label: Some(from.to_string()),
        }
    }

    /// A12's one render, with `node` shown as `shown_node` (a reader's nickname for it):
    /// `name@node` for a service, `label · id@node` for an instance, and
    /// `<from> · anon@node` for an anonymous sender.
    #[cfg(feature = "daemon")]
    pub fn render(&self, shown_node: &str) -> String {
        match (&self.service, &self.id) {
            (Some(name), _) => crate::inbox::sender_label(shown_node, "svc", name, None),
            (None, Some(id)) => {
                crate::inbox::sender_label(shown_node, "", id, self.label.as_deref())
            }
            (None, None) => {
                let from = self
                    .label
                    .as_deref()
                    .and_then(crate::inbox::clean_label)
                    .unwrap_or_default();
                format!("{from} · anon@{shown_node}")
            }
        }
    }

    /// The sender's attested key: its instance ID or service name, `None` when anonymous.
    pub fn key(&self) -> Option<&str> {
        self.service.as_deref().or(self.id.as_deref())
    }

    /// The literal machine address `id@node` or `service@node`, built only from the
    /// attested identifier and node, never from the label (XU1 Gate 2).
    pub fn machine_ref(&self) -> Option<String> {
        self.key().map(|k| format!("{k}@{}", self.node))
    }
}
