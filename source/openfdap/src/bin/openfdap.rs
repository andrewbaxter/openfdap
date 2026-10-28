use {
    crate::dball::DbVersion,
    aargvark::{
        traits_impls::AargvarkJson,
        Aargvark,
    },
    flowcontrol::{
        shed,
        ta_return,
    },
    http::{
        header::{
            CONTENT_TYPE,
            ETAG,
            IF_NONE_MATCH,
        },
        Response,
    },
    http_body_util::{
        BodyExt,
        LengthLimitError,
        Limited,
    },
    htwrap::htserve::{
        self,
        auth::get_auth_token,
        handler::async_trait::async_trait,
        responses::{
            body_empty,
            body_full,
            body_json,
            response_200_json,
            response_400,
            response_401,
            response_403,
            response_404,
            response_503,
            Body,
        },
    },
    hyper::Method,
    loga::{
        ea,
        DebugDisplay,
        ErrContext,
        Log,
        ResultContext,
    },
    openfdap::interface::config::{
        AccessAction,
        AccessPath,
        AccessPathSeg,
        Config,
        Token,
        Users,
    },
    serde::{
        Deserialize,
        Serialize,
    },
    sha2::Digest,
    std::{
        borrow::Cow,
        collections::{
            BTreeMap,
            HashMap,
            HashSet,
        },
        io::{
            ErrorKind,
            Read,
            Write,
        },
        ops::Bound,
        path::{
            Path,
            PathBuf,
        },
        sync::{
            Arc,
            RwLock,
        },
    },
    taskmanager::TaskManager,
    tempfile::NamedTempFile,
    tokio::{
        fs::create_dir_all,
        net::TcpListener,
    },
    tokio_stream::wrappers::TcpListenerStream,
};

#[derive(Aargvark)]
struct ServeArgs {
    /// Configuration JSON file. If not specified, the config is read from the
    /// `OPENFDAP_CONFIG` environment variable.
    config: Option<AargvarkJson<Config>>,
    /// Check the config then exit
    validate: Option<()>,
    /// Enable debug logging
    debug: Option<()>,
}

#[derive(Aargvark)]
#[vark(break_help)]
enum Args {
    /// Run the server
    Serve(ServeArgs),
    /// Read a token from stdin and print a hashed `token` entry for use in the
    /// config
    HashToken,
}

pub mod dball {
    pub type DbVersion = usize;
}

pub mod dbv1 {
    use {
        serde::{
            Deserialize,
            Serialize,
        },
        crate::dball::DbVersion,
    };

    #[derive(Clone, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case", deny_unknown_fields)]
    pub struct Database {
        pub version: DbVersion,
        pub data: serde_json::Value,
    }
}

/// Root key in the database holding dynamically-configured users.
const DB_USERS_KEY: &str = "fdap_user";

fn format_etag(ver: DbVersion) -> String {
    return format!("\"{}\"", ver);
}

fn response_200_json_etag(v: impl Serialize, etag: String) -> Response<Body> {
    return Response::builder()
        .status(200)
        .header(CONTENT_TYPE, "application/json")
        .header(ETAG, etag)
        .body(body_json(v))
        .unwrap();
}

fn response_405() -> Response<Body> {
    return Response::builder().status(405).body(body_empty()).unwrap();
}

fn response_413(max: usize) -> Response<Body> {
    return Response::builder()
        .status(413)
        .body(body_full(format!("Request body exceeds the configured maximum of {} bytes", max).into_bytes()))
        .unwrap();
}

pub use dbv1 as latest;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum Database<'a> {
    V1(Cow<'a, dbv1::Database>),
}

pub type Access = BTreeMap<AccessPath, AccessAction>;

/// Token lookup key: the SHA-256 hash of the token. Tokens are never stored in
/// memory in plaintext after startup.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct TokenHash([u8; 32]);

impl TokenHash {
    fn of(token: &str) -> Self {
        return Self(sha2::Sha256::digest(token.as_bytes()).into());
    }

    fn to_hex(&self) -> String {
        let mut out = String::with_capacity(64);
        for b in self.0 {
            out.push_str(&format!("{:02x}", b));
        }
        return out;
    }

    fn from_hex(hex: &str) -> Result<Self, loga::Error> {
        let hex = hex.trim();
        if hex.len() != 64 {
            return Err(loga::err_with("SHA-256 hex must be exactly 64 characters", ea!(len = hex.len())));
        }
        let mut out = [0u8; 32];
        for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
            out[i] =
                u8::from_str_radix(
                    std::str::from_utf8(chunk).context("Invalid utf-8 in hex")?,
                    16,
                ).context_with("Invalid hex digit in SHA-256", ea!(offset = i * 2))?;
        }
        return Ok(Self(out));
    }
}

impl TryFrom<&Token> for TokenHash {
    type Error = loga::Error;

    fn try_from(t: &Token) -> Result<Self, loga::Error> {
        match t {
            Token::Sha256(hex) => return Self::from_hex(hex),
        }
    }
}

fn build_users(users: Users) -> Result<HashMap<TokenHash, Access>, loga::Error> {
    let mut out = HashMap::new();
    for (i, u) in users.into_iter().enumerate() {
        let hash =
            TokenHash::try_from(&u.token).context_with("Invalid token in users entry", ea!(index = i))?;
        if out.insert(hash, u.access.into_iter().map(|p| (p.path, p.action)).collect()).is_some() {
            return Err(loga::err_with("Duplicate token in users", ea!(index = i)));
        }
    }
    return Ok(out);
}

/// Like `build_users` but for the `fdap_user` tree, which can't be rejected up
/// front: invalid entries are logged and skipped, and a token appearing in
/// multiple entries is ambiguous so all of its entries are skipped.
fn build_db_users(log: &Log, users: Users) -> HashMap<TokenHash, Access> {
    let mut out = HashMap::new();
    let mut duplicates = HashSet::new();
    for (i, u) in users.into_iter().enumerate() {
        let hash = match TokenHash::try_from(&u.token) {
            Ok(h) => h,
            Err(e) => {
                log.log_err(
                    loga::WARN,
                    e.context_with(&format!("Ignoring `{}` entry with invalid token", DB_USERS_KEY), ea!(index = i)),
                );
                continue;
            },
        };
        if duplicates.contains(&hash) ||
            out.insert(hash, u.access.into_iter().map(|p| (p.path, p.action)).collect::<Access>()).is_some() {
            log.log_with(
                loga::WARN,
                format!("Ignoring all `{}` entries with a token used by multiple entries", DB_USERS_KEY),
                ea!(index = i),
            );
            out.remove(&hash);
            duplicates.insert(hash);
        }
    }
    return out;
}

/// Find the most specific grant matching `path`.
fn find_grant(grants: &Access, path: &AccessPath) -> Option<AccessAction> {
    return grants
        .iter()
        .filter(|(rule, _)| {
            rule.len() <= path.len() && Iterator::zip(rule.iter(), path.iter()).all(|(want, have)| match want {
                AccessPathSeg::Wildcard => true,
                AccessPathSeg::String(want) => {
                    let AccessPathSeg::String(have) = have else {
                        // Request paths are built from concrete segments only
                        unreachable!("request paths never contain wildcards");
                    };
                    want == have
                },
            })
        })
        .max_by(|(a, _), (b, _)| (a.len(), *a).cmp(&(b.len(), *b)))
        .map(|(_, actions)| *actions);
}

pub type DataPath = Vec<String>;

struct State {
    log: Log,
    db_path: PathBuf,
    database: tokio::sync::RwLock<latest::Database>,
    users: HashMap<TokenHash, Access>,
    max_write_bytes: usize,
    etags: RwLock<BTreeMap<DataPath, DbVersion>>,
}

#[async_trait]
impl htserve::handler::Handler<Body> for State {
    async fn handle(&self, args: htserve::handler::HandlerArgs<'_>) -> http::Response<Body> {
        let log = self.log.fork(ea!(path = args.url, peer = args.peer_addr));
        match async {
            ta_return!(http:: Response < Body >, loga::Error);
            let token = match get_auth_token(&args.head.headers) {
                Ok(t) => t,
                Err(_) => {
                    log.log(loga::DEBUG, "No auth token in request");
                    return Ok(response_401());
                },
            };
            let token_hash = TokenHash::of(&token);
            drop(token);
            let grants = shed!{
                'grants _;
                if let Some(grants) = self.users.get(&token_hash) {
                    break 'grants Cow::Borrowed(grants);
                };
                shed!{
                    let db = self.database.read().await;
                    let Some(fdap_users) = get(&*db, &self.etags, &vec![DB_USERS_KEY.to_string()]) else {
                        break;
                    };
                    let fdap_users = match serde_json::from_value::<Users>(fdap_users.0.clone()) {
                        Ok(f) => f,
                        Err(e) => {
                            log.log_err(
                                loga::WARN,
                                e.context(&format!("`{}` key in database has invalid format", DB_USERS_KEY)),
                            );
                            break;
                        },
                    };
                    let mut fdap_users = build_db_users(&log, fdap_users);
                    if let Some(grants) = fdap_users.remove(&token_hash) {
                        break 'grants Cow::Owned(grants);
                    }
                }
                log.log(loga::DEBUG, "No user in config for token");
                return Ok(response_401());
            };
            let mut path: DataPath = vec![];
            let mut access_path: AccessPath = vec![];
            let subpath = args.subpath.trim_matches('/');
            if subpath == "" {
                // nop
            } else {
                for seg in subpath.split("/") {
                    let seg = match urlencoding::decode(&seg) {
                        Ok(s) => s,
                        Err(e) => {
                            return Ok(response_400(format!("Path segment {:?} can't be urldecoded: {}", seg, e)));
                        },
                    };
                    path.push(seg.to_string());
                    access_path.push(AccessPathSeg::String(seg.to_string()));
                }
            }
            log.log_with(
                loga::DEBUG,
                "Checking path against grants",
                ea!(path = path.dbg_str(), grants = grants.dbg_str()),
            );
            let Some(grants_actions) = find_grant(&grants, &access_path) else {
                log.log_with(loga::DEBUG, "Found no actions granted at path", ea!(path = path.dbg_str()));
                return Ok(response_403());
            };
            log.log_with(
                loga::DEBUG,
                "User granted actions at path",
                ea!(path = path.dbg_str(), actions = grants_actions.dbg_str()),
            );
            match args.head.method {
                Method::HEAD | Method::GET => {
                    if !grants_actions.read {
                        return Ok(response_403());
                    }
                    shed!{
                        let Some(if_ver) = args.head.headers.get(IF_NONE_MATCH) else {
                            break;
                        };
                        let etags = self.etags.read().unwrap();
                        let Some(&stored_ver) = etags.get(&path) else {
                            break;
                        };
                        let etag = format_etag(stored_ver);
                        if if_ver != etag.as_bytes() {
                            break;
                        }
                        return Ok(Response::builder().status(304).body(body_full(vec![])).unwrap());
                    }
                    let db = self.database.read().await;
                    if let Some((data, ver)) = get(&db, &self.etags, &path) {
                        let etag = format_etag(ver);
                        if args.head.method == Method::HEAD {
                            return Ok(response_200_json_etag((), etag));
                        } else {
                            return Ok(response_200_json_etag(data, etag));
                        }
                    } else {
                        return Ok(response_404());
                    }
                },
                Method::POST => {
                    if !grants_actions.write {
                        return Ok(response_403());
                    }
                    let body = match Limited::new(args.body, self.max_write_bytes).collect().await {
                        Ok(b) => b.to_bytes(),
                        Err(e) => {
                            if e.downcast_ref::<LengthLimitError>().is_some() {
                                return Ok(response_413(self.max_write_bytes));
                            }
                            return Err(loga::err(format!("Error reading request body: {}", e)));
                        },
                    };
                    let data = match serde_json::from_slice::<serde_json::Value>(body.as_ref()) {
                        Ok(d) => d,
                        Err(e) => {
                            return Ok(response_400(format!("Invalid JSON in request body: {}", e)));
                        },
                    };
                    let mut db_ref = self.database.write().await;
                    let mut db = db_ref.clone();
                    db.version += 1;
                    let mut at = &mut db.data;
                    if !path.is_empty() {
                        for (i, seg) in path.iter().enumerate() {
                            match at {
                                serde_json::Value::Null => {
                                    *at = serde_json::Value::Object(serde_json::Map::new());
                                    let serde_json::Value::Object(map) = at else {
                                        unreachable!();
                                    };
                                    at = map.entry(seg).or_insert_with(|| serde_json::Value::Null);
                                },
                                serde_json::Value::Object(map) => {
                                    at = map.entry(seg).or_insert_with(|| serde_json::Value::Null);
                                },
                                _ => {
                                    return Ok(
                                        response_400(
                                            format!(
                                                "Data at path segment {:?} is a {}, not null or an object",
                                                &path[..=i],
                                                json_type(at)
                                            ),
                                        ),
                                    );
                                },
                            }
                        }
                    }
                    *at = data;
                    let db = write_db(&self.db_path, db).await.context("Failed to write database changes")?;
                    wipe_etags(self, &path, Some(db.version));
                    *db_ref = db;
                    return Ok(response_200_json(()));
                },
                Method::DELETE => {
                    if !grants_actions.write {
                        return Ok(response_403());
                    }
                    let mut db_ref = self.database.write().await;
                    let mut db = db_ref.clone();
                    db.version += 1;
                    let mut parent_path = path.clone();
                    match parent_path.pop() {
                        Some(last_seg) => {
                            let mut at = &mut db.data;
                            for (i, seg) in parent_path.iter().enumerate() {
                                match at {
                                    serde_json::Value::Null => {
                                        // Nothing to delete; idempotent success without a write
                                        return Ok(response_200_json(()));
                                    },
                                    serde_json::Value::Object(map) => {
                                        at = match map.get_mut(seg) {
                                            Some(e) => e,
                                            None => {
                                                // Nothing to delete; idempotent success without a write
                                                return Ok(response_200_json(()));
                                            },
                                        };
                                    },
                                    _ => {
                                        return Ok(
                                            response_400(
                                                format!(
                                                    "Data at path segment {:?} is a {}, not an object",
                                                    &parent_path[..=i],
                                                    json_type(at)
                                                ),
                                            ),
                                        );
                                    },
                                }
                            }
                            match at {
                                serde_json::Value::Null => {
                                    // Nothing to delete; idempotent success without a write
                                    return Ok(response_200_json(()));
                                },
                                serde_json::Value::Object(map) => {
                                    if map.remove(&last_seg).is_none() {
                                        // Nothing to delete; idempotent success without a write
                                        return Ok(response_200_json(()));
                                    }
                                },
                                _ => {
                                    return Ok(
                                        response_400(
                                            format!(
                                                "Data at path segment {:?} is a {}, not an object",
                                                parent_path,
                                                json_type(at)
                                            ),
                                        ),
                                    );
                                },
                            }
                        },
                        None => {
                            db.data = serde_json::Value::Null;
                        },
                    }
                    let db = write_db(&self.db_path, db).await.context("Failed to write database changes")?;
                    wipe_etags(self, &path, None);
                    *db_ref = db;
                    return Ok(response_200_json(()));
                },
                _ => {
                    return Ok(response_405());
                },
            }
        }.await {
            Ok(r) => return r,
            Err(e) => {
                log.log_err(loga::WARN, e.context("Error handling response"));
                return response_503();
            },
        }
    }
}

const ENV_CONFIG: &str = "OPENFDAP_CONFIG";

fn wipe_etags(self0: &State, at: &DataPath, replace: Option<DbVersion>) {
    let mut etags = self0.etags.write().unwrap();
    for prefix in 0 .. at.len() {
        etags.remove(&at[0 .. prefix]);
    }
    let mut suffixes = vec![];
    for (k, _v) in etags.range((Bound::Included(at.clone()), Bound::Unbounded)) {
        if !k.starts_with(&at) {
            break;
        }
        suffixes.push(k.clone());
    }
    for k in suffixes {
        etags.remove(&k);
    }
    if let Some(v) = replace {
        etags.insert(at.clone(), v);
    }
}

fn get<
    'a,
>(
    db: &'a latest::Database,
    etags: &RwLock<BTreeMap<DataPath, DbVersion>>,
    path: &DataPath,
) -> Option<(&'a serde_json::Value, DbVersion)> {
    let mut at = &db.data;
    for seg in path {
        match at {
            serde_json::Value::Object(m) => {
                let Some(v) = m.get(seg) else {
                    return None;
                };
                at = v;
            },
            _ => {
                return None;
            },
        }
    }
    {
        let etags = etags.read().unwrap();
        for prefix in (0 ..= path.len()).rev() {
            if let Some(&ver) = etags.get(&path[0 .. prefix]) {
                return Some((at, ver));
            }
        }
    }
    etags.write().unwrap().insert(path.clone(), db.version);
    return Some((at, db.version));
}

fn json_type(v: &serde_json::Value) -> &str {
    return match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "bool",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    };
}

/// Write the file via a temp file + rename, with fsync so a completed request
/// survives power loss. Blocking; call via `write_db`.
fn atomic_write(path: &Path, data: &[u8]) -> Result<(), loga::Error> {
    let dir = path.parent().unwrap();
    let mut temp = NamedTempFile::new_in(dir).context("Error creating temp file for atomic write")?;
    temp.write_all(data).context_with("Error writing temp file", ea!(path = temp.path().display()))?;
    temp.as_file().sync_all().context_with("Error syncing temp file", ea!(path = temp.path().display()))?;
    temp.persist(path).context_with("Error atomically replacing file", ea!(path = path.display()))?;
    std::fs::File::open(dir)
        .and_then(|d| d.sync_all())
        .context_with("Error syncing data dir after rename", ea!(path = dir.display()))?;
    return Ok(());
}

/// Serialize and write the database on a blocking thread so disk I/O doesn't
/// stall the async workers. Returns the database so the caller can install it.
async fn write_db(path: &Path, db: latest::Database) -> Result<latest::Database, loga::Error> {
    let path = path.to_path_buf();
    return tokio::task::spawn_blocking(move || {
        let bytes = serde_json::to_vec(&Database::V1(Cow::Borrowed(&db))).unwrap();
        atomic_write(&path, &bytes)?;
        return Ok(db) as Result<_, loga::Error>;
    }).await.context("Database write task panicked")?;
}

async fn inner(log: &Log, tm: &TaskManager, args: ServeArgs) -> Result<(), loga::Error> {
    // Get config (fallback to env, for use in ex: docker)
    let config = if let Some(p) = args.config {
        p.value
    } else if let Some(c) = match std::env::var(ENV_CONFIG) {
        Ok(c) => Some(c),
        Err(e) => match e {
            std::env::VarError::NotPresent => None,
            std::env::VarError::NotUnicode(_) => {
                return Err(loga::err_with("Error parsing env var as unicode", ea!(env = ENV_CONFIG)))
            },
        },
    } {
        serde_json::from_str::<Config>(&c).context("Parsing config")?
    } else {
        return Err(
            loga::err_with("No config passed on command line, and no config set in env var", ea!(env = ENV_CONFIG)),
        );
    };

    // Setup state
    create_dir_all(&config.data_dir).await.context("Error creating data dir")?;
    let db_path = config.data_dir.join("db.json");
    let state = Arc::new(State {
        log: log.clone(),
        database: tokio::sync::RwLock::new(match std::fs::read(&db_path) {
            Ok(db) => {
                match serde_json::from_slice::<Database>(&db).context("Error parsing database")? {
                    Database::V1(db) => db.into_owned(),
                }
            },
            Err(e) => {
                if e.kind() != ErrorKind::NotFound {
                    return Err(e.context_with("Error opening existing database", ea!(path = db_path.display())));
                }
                latest::Database {
                    version: 0,
                    data: serde_json::Value::Null,
                }
            },
        }),
        db_path: db_path,
        users: build_users(config.users).context("Invalid `users` in config")?,
        max_write_bytes: config.max_write_bytes,
        etags: Default::default(),
    });

    // Start server
    tm.critical_stream(
        format!("Http server - {}", config.bind_addr),
        TcpListenerStream::new(
            TcpListener::bind(&config.bind_addr)
                .await
                .context_with("Error binding to address", ea!(addr = config.bind_addr))?,
        ),
        {
            let state = state.clone();
            let log = log.clone();
            move |stream| {
                let state = state.clone();
                let log = log.clone();
                async move {
                    let stream = match stream {
                        Ok(s) => s,
                        Err(e) => {
                            log.log(loga::DEBUG, e.context("Error opening peer stream"));
                            return Ok(());
                        },
                    };
                    htserve::handler::root_handle_http(&log, Default::default(), state, stream);
                    return Ok(());
                }
            }
        },
    );
    return Ok(());
}

#[tokio::main]
async fn main() {
    let args = match aargvark::vark::<Args>() {
        Args::HashToken => {
            let mut token = String::new();
            if let Err(e) = std::io::stdin().read_to_string(&mut token) {
                loga::fatal(loga::err(format!("Error reading token from stdin: {}", e)));
            }
            let token = token.trim_end_matches(['\r', '\n']);
            if token.is_empty() {
                loga::fatal(loga::err("Token read from stdin is empty"));
            }
            println!("{}", serde_json::to_string(&Token::Sha256(TokenHash::of(token).to_hex())).unwrap());
            return;
        },
        Args::Serve(args) => args,
    };
    if args.validate.is_some() {
        return;
    }
    let log = Log::new_root(match args.debug.is_some() {
        true => loga::DEBUG,
        false => loga::INFO,
    });
    let tm = taskmanager::TaskManager::new();
    match inner(&log, &tm, args).await.map_err(|e| {
        tm.terminate();
        return e;
    }).also({
        tm.join(&log).await.context("Critical services failed")
    }) {
        Ok(_) => { },
        Err(e) => {
            loga::fatal(e);
        },
    }
}

#[cfg(test)]
mod tests {
    use {
        super::{
            build_users,
            find_grant,
            Access,
            TokenHash,
        },
        openfdap::interface::config::{
            AccessAction,
            AccessPair,
            AccessPathSeg,
            Token,
            User,
            Users,
        },
    };

    fn path(segs: &[&str]) -> Vec<AccessPathSeg> {
        return segs.iter().map(|s| match *s {
            "*" => AccessPathSeg::Wildcard,
            s => AccessPathSeg::String(s.to_string()),
        }).collect();
    }

    const READ: AccessAction = AccessAction {
        read: true,
        write: false,
    };
    const WRITE: AccessAction = AccessAction {
        read: true,
        write: true,
    };

    fn grants(rules: &[(&[&str], AccessAction)]) -> Access {
        return rules.iter().map(|(p, a)| (path(p), *a)).collect();
    }

    fn found(g: &Access, p: &[&str]) -> Option<(bool, bool)> {
        return find_grant(g, &path(p)).map(|a| (a.read, a.write));
    }

    #[test]
    fn rule_longer_than_request_does_not_match() {
        let g = grants(&[(&["user", "*", "kwa"], READ)]);
        assert_eq!(found(&g, &["user", "a"]), None);
        assert_eq!(found(&g, &["user"]), None);
        assert_eq!(found(&g, &[]), None);
        assert_eq!(found(&g, &["user", "a", "kwa"]), Some((true, false)));
        assert_eq!(found(&g, &["user", "a", "kwa", "x"]), Some((true, false)));
        assert_eq!(found(&g, &["user", "a", "fdap-login"]), None);
    }

    #[test]
    fn sibling_wildcard_rules_all_considered() {
        let g = grants(&[(&["user", "*", "fdap-login"], READ), (&["user", "*", "kwa"], READ)]);
        assert_eq!(found(&g, &["user", "test", "fdap-login"]), Some((true, false)));
        assert_eq!(found(&g, &["user", "test", "kwa"]), Some((true, false)));
        assert_eq!(found(&g, &["user", "test", "other"]), None);
    }

    #[test]
    fn most_specific_rule_wins() {
        let g = grants(&[(&[], READ), (&["user", "*", "app"], WRITE), (&["user", "admin", "app"], READ)]);
        assert_eq!(found(&g, &["anything"]), Some((true, false)));
        assert_eq!(found(&g, &["user", "a", "app"]), Some((true, true)));
        assert_eq!(found(&g, &["user", "admin", "app"]), Some((true, false)));
    }

    #[test]
    fn hashed_and_raw_tokens_match() {
        let raw = "secret-token";
        let hash = TokenHash::of(raw);
        assert_eq!(TokenHash::from_hex(&hash.to_hex()).unwrap(), hash);
        assert_eq!(TokenHash::from_hex(&hash.to_hex().to_uppercase()).unwrap(), hash);
        assert_eq!(TokenHash::try_from(&Token::Sha256(hash.to_hex())).unwrap(), hash);
        assert!(TokenHash::from_hex("abc").is_err());
        assert!(TokenHash::from_hex(&"zz".repeat(32)).is_err());
    }

    #[test]
    fn build_users_rejects_bad_and_duplicate_tokens() {
        let user = |t: Token| User {
            token: t,
            access: vec![AccessPair {
                path: vec![],
                action: READ,
            }],
        };
        assert!(build_users(vec![user(Token::Sha256("nothex".to_string()))]).is_err());
        let hex = TokenHash::of("tok").to_hex();
        assert!(build_users(vec![user(Token::Sha256(hex.clone())), user(Token::Sha256(hex.to_uppercase()))]).is_err());
        assert!(build_users(vec![user(Token::Sha256(hex))]).is_ok());
    }

    #[test]
    fn db_users_json_shape_matches_config() {
        // The `fdap_user` tree must round-trip through JSON in the same shape as the
        // config `users` field.
        let json = serde_json::json!([
            {
                "token": {"sha256": TokenHash::of("TOKEN").to_hex()},
                "access": [{"path": [{"string": "user"}, "wildcard"], "action": {"read": true, "write": false}}],
            },
        ]);
        let users: Users = serde_json::from_value(json).unwrap();
        let built = build_users(users).unwrap();
        let g = built.get(&TokenHash::of("TOKEN")).unwrap();
        assert_eq!(find_grant(g, &path(&["user", "a"])).map(|a| a.read), Some(true));
    }
}
