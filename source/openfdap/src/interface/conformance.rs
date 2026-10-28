//! Format of the language-neutral FDAP conformance test cases in `/spec` (and the
//! `openfdap`-specific cases in `tests/cases`).
use {
    super::config::AccessPair,
    schemars::JsonSchema,
    serde::{
        Deserialize,
        Deserializer,
        Serialize,
    },
    std::collections::BTreeMap,
};

/// Distinguish an explicit JSON `null` (`Some(Null)`) from an absent field
/// (`None`).
fn some<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Option<T>, D::Error> {
    return T::deserialize(d).map(Some);
}

/// A file of test cases.
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct CaseFile {
    #[serde(rename = "$schema", default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    pub cases: Vec<Case>,
}

/// A single test case. Each case starts a fresh server with `setup`, then runs
/// `steps` in order against it.
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct Case {
    pub description: String,
    #[serde(default)]
    pub setup: Setup,
    pub steps: Vec<Step>,
}

#[derive(Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct Setup {
    /// Tokens with read and write access to the whole tree.
    #[serde(default)]
    pub tokens: Vec<String>,
    /// Initial contents of the database. Defaults to `null` (empty).
    #[serde(default)]
    pub db: serde_json::Value,
    /// Settings for cases testing `openfdap`-specific behavior, not part of the
    /// FDAP spec.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub openfdap: Option<OpenfdapSetup>,
}

#[derive(Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct OpenfdapSetup {
    /// Additional applications in the config, with access rules.
    #[serde(default)]
    pub users: Vec<SetupUser>,
    /// Maximum `POST` body size.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_write_bytes: Option<usize>,
}

/// Like a config `users` entry, but with the plain token rather than its hash.
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct SetupUser {
    pub token: String,
    pub access: Vec<AccessPair>,
}

#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct Step {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub request: Request,
    pub expect: Expect,
}

#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum RequestPath {
    /// Data path segments. Each segment is percent-encoded by the runner (every
    /// byte other than ASCII alphanumerics and `-._~`, plus `.` and `..` as whole
    /// segments) and joined with `/`.
    Segments(Vec<String>),
    /// The literal path of the request URL, sent as-is.
    Raw(String),
}

#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct Request {
    pub method: String,
    pub path: RequestPath,
    /// Sent as `Authorization: Bearer TOKEN`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// Extra headers. Values may reference captured variables as `{{name}}`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
    /// JSON request body (`null` is sent as the JSON text `null`).
    #[serde(default, deserialize_with = "some", skip_serializing_if = "Option::is_none")]
    pub body: Option<serde_json::Value>,
    /// Request body sent verbatim, for bodies that aren't valid JSON.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_body: Option<String>,
}

#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct HeaderNotEquals {
    pub not_equals: String,
}

#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct HeaderPresent {
    pub present: bool,
}

#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum HeaderExpect {
    /// The header must have exactly this value. May reference captured variables
    /// as `{{name}}`.
    Equals(String),
    /// The header must be absent or have a different value. May reference captured
    /// variables as `{{name}}`.
    NotEquals(HeaderNotEquals),
    /// The header must be present (`true`) or absent (`false`).
    Present(HeaderPresent),
}

/// Expected response. Only the fields present are checked.
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct Expect {
    pub status: u16,
    /// The response body parsed as JSON must equal this.
    #[serde(default, deserialize_with = "some", skip_serializing_if = "Option::is_none")]
    pub body: Option<serde_json::Value>,
    /// The response body must be exactly this text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_body: Option<String>,
    /// Header names are case-insensitive.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, HeaderExpect>,
    /// Save response header values into variables: `{"VARIABLE": "HEADER"}`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub capture: BTreeMap<String, String>,
    /// The full database contents after the request.
    #[serde(default, deserialize_with = "some", skip_serializing_if = "Option::is_none")]
    pub db: Option<serde_json::Value>,
}
