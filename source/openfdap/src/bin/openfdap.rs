use {
    aargvark::{
        traits_impls::AargvarkJson,
        Aargvark,
    },
    flowcontrol::{
        shed,
        ta_return,
    },
    http_body_util::BodyExt,
    htwrap::htserve::{
        self,
        auth::get_auth_token,
        handler::async_trait::async_trait,
        responses::{
            response_200_json,
            response_400,
            response_401,
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
    },
    serde::{
        Deserialize,
        Serialize,
    },
    std::{
        borrow::Cow,
        collections::{
            BTreeMap,
            HashMap,
        },
        io::{
            ErrorKind,
            Write,
        },
        ops::Bound,
        path::{
            Path,
            PathBuf,
        },
        sync::Arc,
    },
    taskmanager::TaskManager,
    tempfile::NamedTempFile,
    tokio::{
        fs::create_dir_all,
        net::TcpListener,
        sync::RwLock,
    },
    tokio_stream::wrappers::TcpListenerStream,
};

#[derive(Aargvark)]
struct Args {
    /// Configuration JSON file
    config: Option<AargvarkJson<Config>>,
    /// Check the config then exit
    validate: Option<()>,
    /// Enable debug logging
    debug: Option<()>,
}

pub mod dbv1 {
    use serde::{
        Deserialize,
        Serialize,
    };

    #[derive(Clone, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case", deny_unknown_fields)]
    pub struct Database {
        pub version: usize,
        pub data: serde_json::Value,
    }
}

pub use dbv1 as latest;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum Database<'a> {
    V1(Cow<'a, dbv1::Database>),
}

pub type Access = BTreeMap<AccessPath, AccessAction>;

struct State {
    log: Log,
    db_path: PathBuf,
    database: RwLock<latest::Database>,
    users: HashMap<String, Access>,
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
            let Some(grants) = self.users.get(&token) else {
                log.log(loga::DEBUG, "No user in config for token");
                return Ok(response_401());
            };
            let mut path = vec![];
            let mut access_path = vec![];
            let subpath = args.subpath.trim_matches('/');
            if subpath == "" {
                // nop
            } else {
                for seg in subpath.split("/") {
                    let seg =
                        urlencoding::decode(&seg).context_with("Path segment can't be urldecoded", ea!(seg = seg))?;
                    path.push(seg.clone());
                    access_path.push(AccessPathSeg::String(seg.to_string()));
                }
            }
            log.log_with(
                loga::DEBUG,
                "Checking path against grants",
                ea!(path = path.dbg_str(), grants = grants.dbg_str()),
            );
            let grants_actions;
            shed!{
                'found _;
                for(prefix, grants) in grants.range::< AccessPath,
                (
                    Bound <& AccessPath >,
                    Bound <& AccessPath >
                ) >((Bound::Unbounded, Bound::Included(&access_path))).rev() {
                    if !Iterator::zip(
                        prefix.iter(),
                        access_path.iter(),
                    ).all(|(want_seg, have_seg)| match want_seg {
                        AccessPathSeg::Wildcard => {
                            return true;
                        },
                        AccessPathSeg::String(want_seg) => {
                            let AccessPathSeg::String(have_seg) = have_seg else {
                                panic!();
                            };
                            return want_seg == have_seg;
                        },
                    }) {
                        break;
                    };
                    grants_actions = *grants;
                    break 'found;
                }
                log.log_with(loga::DEBUG, "Found no actions granted at path", ea!(path = path.dbg_str()));
                return Ok(response_401());
            };
            log.log_with(
                loga::DEBUG,
                "User granted actions at path",
                ea!(path = path.dbg_str(), actions = grants_actions.dbg_str()),
            );
            match args.head.method {
                Method::HEAD => {
                    if !grants_actions.read {
                        return Ok(response_401());
                    }
                    let db = self.database.read().await;
                    if db_get(&db, path.iter().map(|x| x.as_ref())).is_some() {
                        return Ok(response_200_json(()));
                    } else {
                        return Ok(response_404());
                    }
                },
                Method::GET => {
                    if !grants_actions.read {
                        return Ok(response_401());
                    }
                    let db = self.database.read().await;
                    let Some(data) = db_get(&db, path.iter().map(|x| x.as_ref())) else {
                        return Ok(response_404());
                    };
                    return Ok(response_200_json(data));
                },
                Method::POST => {
                    if !grants_actions.write {
                        return Ok(response_401());
                    }
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
                                        panic!();
                                    };
                                    at = map.entry(seg.as_ref()).or_insert_with(|| serde_json::Value::Null);
                                },
                                serde_json::Value::Object(map) => {
                                    at = map.entry(seg.as_ref()).or_insert_with(|| serde_json::Value::Null);
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
                    *at =
                        serde_json::from_slice::<serde_json::Value>(
                            args.body.collect().await.context("Error reading request body")?.to_bytes().as_ref(),
                        ).context("Got invalid json in POST")?;
                    atomic_write(&self.db_path, Database::V1(Cow::Borrowed(&db)))
                        .await
                        .context("Failed to write database changes")?;
                    *db_ref = db;
                    return Ok(response_200_json(()));
                },
                Method::DELETE => {
                    if !grants_actions.write {
                        return Ok(response_401());
                    }
                    let mut db_ref = self.database.write().await;
                    let mut db = db_ref.clone();
                    db.version += 1;
                    match path.pop() {
                        Some(last_seg) => {
                            let mut at = &mut db.data;
                            for (i, seg) in path.iter().enumerate() {
                                match at {
                                    serde_json::Value::Object(map) => {
                                        at = match map.get_mut(seg.as_ref()) {
                                            Some(e) => e,
                                            None => {
                                                return Ok(
                                                    response_400(
                                                        format!("Data at path segment {:?} is missing", &path[..=i]),
                                                    ),
                                                );
                                            },
                                        };
                                    },
                                    _ => {
                                        return Ok(
                                            response_400(
                                                format!(
                                                    "Data at path segment {:?} is a {}, not an object",
                                                    &path[..=i],
                                                    json_type(at)
                                                ),
                                            ),
                                        );
                                    },
                                }
                            }
                            match at {
                                serde_json::Value::Object(map) => {
                                    map.remove(last_seg.as_ref());
                                },
                                _ => {
                                    return Ok(
                                        response_400(
                                            format!(
                                                "Data at path segment {:?} is a {}, not an object",
                                                path,
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
                    atomic_write(&self.db_path, Database::V1(Cow::Borrowed(&db)))
                        .await
                        .context("Failed to write database changes")?;
                    *db_ref = db;
                    return Ok(response_200_json(()));
                },
                _ => {
                    return Ok(response_401());
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

fn db_get<'a, 'x>(db: &'a latest::Database, path: impl Iterator<Item = &'x str>) -> Option<&'a serde_json::Value> {
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
    return Some(at);
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

async fn atomic_write(path: &Path, data: impl Serialize) -> Result<(), loga::Error> {
    let mut temp =
        NamedTempFile::new_in(path.parent().unwrap()).context("Error creating temp file for atomic write")?;
    temp
        .write_all(serde_json::to_string(&data).unwrap().as_bytes())
        .context_with("Error writing temp file", ea!(path = temp.path().display()))?;
    temp.persist(path).context_with("Error atomically replacing file", ea!(path = path.display()))?;
    return Ok(());
}

async fn inner(log: &Log, tm: &TaskManager, args: Args) -> Result<(), loga::Error> {
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
        database: RwLock::new(match std::fs::read(&db_path) {
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
        users: config
            .users
            .into_iter()
            .map(|(k, v)| (k, v.into_iter().map(|p| (p.path, p.action)).collect()))
            .collect(),
    });

    // Start server
    tm.critical_stream(
        format!("Http server - {}", config.bind_addr),
        TcpListenerStream::new(TcpListener::bind(&config.bind_addr).await.context("Error binding to address")?),
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
                    tokio::task::spawn({
                        async move {
                            match htserve::handler::root_handle_http(&log, state, stream).await {
                                Ok(_) => (),
                                Err(e) => {
                                    log.log_err(loga::DEBUG, e.context("Error serving connection"));
                                },
                            }
                        }
                    });
                    return Ok(());
                }
            }
        },
    );
    return Ok(());
}

#[tokio::main]
async fn main() {
    let args = aargvark::vark::<Args>();
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
