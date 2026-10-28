//! Runs the language-neutral FDAP conformance cases in `/spec`, plus the
//! `openfdap`-specific cases in `tests/cases`, against the `openfdap` binary. This
//! is the openfdap-specific part: starting a server for a case's `setup` and
//! reading back the database.
use {
    http::{
        header::AUTHORIZATION,
        HeaderName,
        HeaderValue,
        Method,
        Request,
        Uri,
    },
    http_body_util::Full,
    hyper::body::Bytes,
    htwrap::htreq,
    loga::Log,
    openfdap::interface::conformance::{
        Case,
        CaseFile,
        Expect,
        HeaderExpect,
        RequestPath,
        Setup,
        Step,
    },
    sha2::Digest,
    std::{
        collections::BTreeMap,
        fs,
        net::TcpListener,
        path::{
            Path,
            PathBuf,
        },
        process::{
            Child,
            Command,
            Stdio,
        },
        time::{
            Duration,
            Instant,
        },
    },
    tempfile::TempDir,
};

struct Server {
    child: Child,
    port: u16,
    dir: TempDir,
}

impl Drop for Server {
    fn drop(&mut self) {
        _ = self.child.kill();
        _ = self.child.wait();
    }
}

impl Server {
    fn data_dir(&self) -> PathBuf {
        return self.dir.path().join("data");
    }

    fn log(&self) -> String {
        return fs::read_to_string(self.dir.path().join("log")).unwrap_or_default();
    }

    fn read_db(&self) -> Result<serde_json::Value, String> {
        let path = self.data_dir().join("db.json");
        let raw = fs::read(&path).map_err(|e| format!("Error reading database {}: {}", path.display(), e))?;
        let db =
            serde_json::from_slice::<serde_json::Value>(
                &raw,
            ).map_err(|e| format!("Database {} isn't valid JSON: {}", path.display(), e))?;
        return Ok(db["v1"]["data"].clone());
    }
}

fn start_server(setup: &Setup) -> Result<Server, String> {
    let dir = tempfile::tempdir().unwrap();
    let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let data_dir = dir.path().join("data");
    fs::create_dir_all(&data_dir).unwrap();
    fs::write(data_dir.join("db.json"), serde_json::to_vec(&serde_json::json!({
        "v1": {
            "version": 0,
            "data": setup.db
        }
    })).unwrap()).unwrap();
    let mut config = serde_json::json!({
        "bind_addr": format!("127.0.0.1:{}", port),
        "data_dir": data_dir,
        "users": [],
    });
    let users = config["users"].as_array_mut().unwrap();
    for token in &setup.tokens {
        users.push(serde_json::json!({
            "token": {
                "sha256": hex(&sha2::Sha256::digest(token.as_bytes()))
            },
            "access": [{
                "path": [],
                "action": {
                    "read": true,
                    "write": true
                }
            }],
        }));
    }
    if let Some(o) = &setup.openfdap {
        for u in &o.users {
            users.push(serde_json::json!({
                "token": {
                    "sha256": hex(&sha2::Sha256::digest(u.token.as_bytes()))
                },
                "access": u.access,
            }));
        }
        if let Some(max) = o.max_write_bytes {
            config["max_write_bytes"] = max.into();
        }
    }
    let config_path = dir.path().join("config.json");
    fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
    let log = fs::File::create(dir.path().join("log")).unwrap();
    let child =
        Command::new(env!("CARGO_BIN_EXE_openfdap"))
            .arg("serve")
            .arg("--config")
            .arg(&config_path)
            .arg("--debug")
            .stdin(Stdio::null())
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .map_err(|e| format!("Error starting openfdap: {}", e))?;
    let mut server = Server {
        child: child,
        port: port,
        dir: dir,
    };
    let start = Instant::now();
    loop {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return Ok(server);
        }
        if let Some(status) = server.child.try_wait().unwrap() {
            return Err(format!("openfdap exited during startup ({}):\n{}", status, server.log()));
        }
        if start.elapsed() > Duration::from_secs(10) {
            return Err(format!("openfdap didn't start listening in time:\n{}", server.log()));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn hex(bytes: &[u8]) -> String {
    return bytes.iter().map(|b| format!("{:02x}", b)).collect();
}

/// Percent-encode a data path segment as described in `/spec/readme.md`.
fn encode_segment(seg: &str) -> String {
    match seg {
        "." => return "%2E".to_string(),
        ".." => return "%2E%2E".to_string(),
        _ => return urlencoding::encode(seg).into_owned(),
    }
}

fn substitute(vars: &BTreeMap<String, String>, s: &str) -> Result<String, String> {
    let mut out = s.to_string();
    for (k, v) in vars {
        out = out.replace(&format!("{{{{{}}}}}", k), v);
    }
    if out.contains("{{") {
        return Err(format!("Unknown variable reference in {:?}", s));
    }
    return Ok(out);
}

async fn run_step(server: &Server, vars: &mut BTreeMap<String, String>, step: &Step) -> Result<(), String> {
    let req = &step.request;
    let path = match &req.path {
        RequestPath::Segments(segs) => format!(
            "/{}",
            segs.iter().map(|s| encode_segment(s)).collect::<Vec<_>>().join("/")
        ),
        RequestPath::Raw(p) => p.clone(),
    };
    let url =
        Uri::try_from(
            format!("http://127.0.0.1:{}{}", server.port, path),
        ).map_err(|e| format!("Invalid request url for path {:?}: {}", path, e))?;
    let body = match (&req.body, &req.raw_body) {
        (Some(_), Some(_)) => return Err("Request has both `body` and `raw_body`".to_string()),
        (Some(b), None) => serde_json::to_vec(b).unwrap(),
        (None, Some(b)) => b.as_bytes().to_vec(),
        (None, None) => vec![],
    };
    let mut http_req =
        Request::builder()
            .method(
                Method::from_bytes(
                    req.method.as_bytes(),
                ).map_err(|e| format!("Invalid method {:?}: {}", req.method, e))?,
            )
            .uri(url.clone())
            .body(Full::new(Bytes::from(body)))
            .unwrap();
    if let Some(token) = &req.token {
        http_req.headers_mut().insert(AUTHORIZATION, HeaderValue::from_str(&format!("Bearer {}", token)).unwrap());
    }
    for (k, v) in &req.headers {
        http_req
            .headers_mut()
            .insert(
                HeaderName::try_from(k).map_err(|e| format!("Invalid header name {:?}: {}", k, e))?,
                HeaderValue::try_from(
                    substitute(vars, v)?,
                ).map_err(|e| format!("Invalid header value {:?}: {}", v, e))?,
            );
    }
    let log = Log::new_root(loga::WARN);
    let limits = htreq::Limits::default();
    let mut conn = htreq::connect(limits, &url).await.map_err(|e| format!("Error connecting: {}", e))?;
    let (status, headers, cont) =
        htreq::send(&log, limits, &mut conn, http_req).await.map_err(|e| format!("Error sending request: {}", e))?;
    let resp_body = htreq::receive(limits, cont).await.map_err(|e| format!("Error reading response body: {}", e))?;
    let Expect { status: want_status, body: want_body, raw_body: want_raw_body, headers: want_headers, capture, db } =
        &step.expect;
    let mut errors = vec![];
    if status.as_u16() != *want_status {
        errors.push(format!("Status: expected {}, got {}", want_status, status.as_u16()));
    }
    if let Some(want) = want_body {
        match serde_json::from_slice::<serde_json::Value>(&resp_body) {
            Ok(got) => if got != *want {
                errors.push(format!("Body: expected {}, got {}", want, got));
            },
            Err(e) => errors.push(
                format!("Body: expected JSON {}, got {:?} ({})", want, String::from_utf8_lossy(&resp_body), e),
            ),
        }
    }
    if let Some(want) = want_raw_body {
        if resp_body != want.as_bytes() {
            errors.push(format!("Body: expected {:?}, got {:?}", want, String::from_utf8_lossy(&resp_body)));
        }
    }
    for (name, want) in want_headers {
        let got = headers.get(name).map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned());
        match want {
            HeaderExpect::Equals(want) => {
                let want = substitute(vars, want)?;
                if got.as_deref() != Some(&want) {
                    errors.push(format!("Header {}: expected {:?}, got {:?}", name, want, got));
                }
            },
            HeaderExpect::NotEquals(want) => {
                let want = substitute(vars, &want.not_equals)?;
                if got.as_deref() == Some(&want) {
                    errors.push(format!("Header {}: expected anything but {:?}", name, want));
                }
            },
            HeaderExpect::Present(want) => {
                if got.is_some() != want.present {
                    errors.push(format!("Header {}: expected present={}, got {:?}", name, want.present, got));
                }
            },
        }
    }
    for (var, name) in capture {
        match headers.get(name) {
            Some(v) => {
                vars.insert(var.clone(), String::from_utf8_lossy(v.as_bytes()).into_owned());
            },
            None => errors.push(format!("Capture {}: response has no {} header", var, name)),
        }
    }
    if let Some(want) = db {
        let got = server.read_db()?;
        if got != *want {
            errors.push(format!("Database: expected {}, got {}", want, got));
        }
    }
    if !errors.is_empty() {
        return Err(
            format!(
                "{} {} ->\n{}\n  Response body: {}",
                req.method,
                path,
                errors.iter().map(|e| format!("  {}", e)).collect::<Vec<_>>().join("\n"),
                String::from_utf8_lossy(&resp_body)
            ),
        );
    }
    return Ok(());
}

async fn run_case(case: &Case) -> Result<(), String> {
    let server = start_server(&case.setup)?;
    let mut vars = BTreeMap::new();
    for (i, step) in case.steps.iter().enumerate() {
        if let Err(e) = run_step(&server, &mut vars, step).await {
            return Err(
                format!(
                    "Step {}{}: {}\n  Server log:\n{}",
                    i,
                    step.description.as_ref().map(|d| format!(" ({})", d)).unwrap_or_default(),
                    e,
                    server.log()
                ),
            );
        }
    }
    return Ok(());
}

fn case_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            case_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "json") {
            out.push(path);
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn conformance() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut files = vec![];
    for root in [manifest_dir.join("../../spec"), manifest_dir.join("tests/cases")] {
        let mut root_files = vec![];
        case_files(&root, &mut root_files);
        assert!(!root_files.is_empty(), "No case files found in {}", root.display());
        files.extend(root_files);
    }
    files.sort();
    let mut count = 0;
    let mut failures = vec![];
    for file in files {
        let rel = file.canonicalize().unwrap();
        let rel = rel.strip_prefix(manifest_dir.join("../..").canonicalize().unwrap()).unwrap().display().to_string();
        let cases = match serde_json::from_slice::<CaseFile>(&fs::read(&file).unwrap()) {
            Ok(c) => c.cases,
            Err(e) => {
                failures.push(format!("{}: invalid case file: {}", rel, e));
                continue;
            },
        };
        for case in cases {
            count += 1;
            if let Err(e) = run_case(&case).await {
                failures.push(format!("{} / {}:\n{}", rel, case.description, e));
            }
        }
    }
    if !failures.is_empty() {
        panic!("{} of {} conformance cases failed:\n\n{}", failures.len(), count, failures.join("\n\n"));
    }
    eprintln!("{} conformance cases passed", count);
}
