use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub hub_enabled: bool,
    #[serde(default)]
    pub leaf_enabled: bool,
    #[serde(default)]
    pub routes: Vec<Route>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Route {
    pub hub: String,
    pub leaf: String,
    pub collector: String,
}

pub(crate) fn identity_node(value: &str) -> Option<String> {
    if value.len() > 512
        || value.contains('*')
        || value
            .bytes()
            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
    {
        return None;
    }
    if value.starts_with("spiffe://") {
        crate::fed::validate_spiffe_pattern(value).ok()?;
        crate::node::node_name_from_uri(value).ok()
    } else {
        let pin = value.strip_prefix("sha256:")?;
        if pin.len() != 64
            || !pin
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return None;
        }
        crate::node::node_name_from_pin(pin).ok()
    }
}

impl Config {
    pub(crate) fn validate(&self) -> Result<(), String> {
        for (index, route) in self.routes.iter().enumerate() {
            if [&route.hub, &route.leaf, &route.collector]
                .iter()
                .any(|v| identity_node(v).is_none())
                || self.routes[..index].contains(route)
                || route.hub == route.leaf
                || route.collector == route.leaf
                || route.collector == route.hub
            {
                return Err("invalid or duplicate reverse observation route".into());
            }
        }
        Ok(())
    }
}
