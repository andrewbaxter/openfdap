use {
    schemars::JsonSchema,
    serde::{
        Deserialize,
        Serialize,
    },
    std::{
        cmp::Ordering,
        collections::HashMap,
        path::PathBuf,
    },
};

#[derive(Serialize, Deserialize, Clone, Copy, JsonSchema, Debug)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct AccessAction {
    pub read: bool,
    pub write: bool,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Hash, JsonSchema, Debug)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum AccessPathSeg {
    Wildcard,
    String(String),
}

impl PartialOrd for AccessPathSeg {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        return Some(self.cmp(other));
    }
}

impl Ord for AccessPathSeg {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (AccessPathSeg::Wildcard, AccessPathSeg::Wildcard) => Ordering::Equal,
            (AccessPathSeg::Wildcard, AccessPathSeg::String(_)) => Ordering::Less,
            (AccessPathSeg::String(_), AccessPathSeg::Wildcard) => Ordering::Greater,
            (AccessPathSeg::String(a), AccessPathSeg::String(b)) => a.cmp(b),
        }
    }
}

pub type AccessPath = Vec<AccessPathSeg>;

#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct AccessPair {
    pub path: AccessPath,
    pub action: AccessAction,
}

#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct Config {
    /// Address to serve on, like `0.0.0.0:64116`
    pub bind_addr: String,
    /// Directory in which to store database, will be created if it doesn't exist
    pub data_dir: PathBuf,
    /// Mapping of application IDs to pairs of
    pub users: HashMap<String, Vec<AccessPair>>,
}
