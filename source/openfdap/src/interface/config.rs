use {
    schemars::JsonSchema,
    serde::{
        Deserialize,
        Serialize,
    },
    std::{
        cmp::Ordering,
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

pub const DEFAULT_MAX_WRITE_BYTES: usize = 1024 * 1024;

fn default_max_write_bytes() -> usize {
    return DEFAULT_MAX_WRITE_BYTES;
}

/// How an application token is stored in the config. Only hashes are accepted,
/// so that the config file, the database and their backups never contain
/// usable tokens.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, JsonSchema, Debug)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Token {
    /// Hex-encoded SHA-256 hash of the token. Generate with `openfdap hash-token`.
    Sha256(String),
}

#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct User {
    pub token: Token,
    pub access: Vec<AccessPair>,
}

pub type Users = Vec<User>;

#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct Config {
    /// Address to serve on, like `0.0.0.0:64116`.
    pub bind_addr: String,
    /// Directory in which to store database, will be created if it doesn't exist
    pub data_dir: PathBuf,
    /// Application tokens and their access - for setting up tokens for
    /// applications to access FDAP. This can also be done (identically) via the
    /// `fdap_user` root key in the FDAP tree.
    pub users: Users,
    /// Maximum size in bytes of a `POST` request body. Defaults to 1 MiB.
    #[serde(default = "default_max_write_bytes")]
    pub max_write_bytes: usize,
}
