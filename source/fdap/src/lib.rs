use {
    http::{
        header::AUTHORIZATION,
        Uri,
    },
    htwrap::{
        htreq,
        UriJoin,
    },
    loga::Log,
    std::{
        collections::HashMap,
        env,
        sync::Arc,
    },
};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Error(pub String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        return self.0.fmt(f);
    }
}

impl std::error::Error for Error { }

impl From<loga::Error> for Error {
    fn from(value: loga::Error) -> Self {
        return Self(value.to_string());
    }
}

struct Client_ {
    log: Log,
    base_url: Uri,
    headers: HashMap<String, String>,
}

pub struct Client(Arc<Client_>);

impl Client {
    pub fn builder() -> ClientBuilder {
        return ClientBuilder::default();
    }

    fn build_path<'a>(&self, path: impl Iterator<Item = &'a dyn AsRef<str>>) -> Uri {
        let mut subpath = String::new();
        for (i, seg) in path.enumerate() {
            if i > 0 {
                subpath.push_str("/");
            }
            subpath.push_str(seg.as_ref());
        }
        return self.0.base_url.join(subpath);
    }

    /// Replace all data under `path`.
    pub async fn get<
        T: AsRef<str>,
        I: AsRef<[T]>,
    >(&self, path: I, max_size: usize) -> Result<Option<serde_json::Value>, Error> {
        let url = self.build_path(path.as_ref().iter().map(|x| x as &dyn AsRef<str>));
        let mut conn = htreq::connect(&url).await?;
        return Ok(htreq::get_json(&self.0.log, &mut conn, &url, &self.0.headers, max_size).await?);
    }

    /// Replace all data under `path`.
    pub async fn set<T: AsRef<str>, I: AsRef<[T]>>(&self, path: I, data: serde_json::Value) -> Result<(), Error> {
        let url = self.build_path(path.as_ref().iter().map(|x| x as &dyn AsRef<str>));
        let mut conn = htreq::connect(&url).await?;
        htreq::post_json::<()>(&self.0.log, &mut conn, &url, &self.0.headers, data, 100).await?;
        return Ok(());
    }

    /// Delete all data under `path`.
    pub async fn delete<T: AsRef<str>, I: AsRef<[T]>>(&self, path: I) -> Result<(), Error> {
        let url = self.build_path(path.as_ref().iter().map(|x| x as &dyn AsRef<str>));
        let mut conn = htreq::connect(&url).await?;
        htreq::delete(&self.0.log, &mut conn, &url, &self.0.headers, 100).await?;
        return Ok(());
    }

    /// Helper for getting under a user path.
    pub async fn user_get<
        T: AsRef<str>,
        I: AsRef<[T]>,
    >(&self, user: impl AsRef<str>, path: I, max_size: usize) -> Result<Option<serde_json::Value>, Error> {
        let url =
            self.build_path(
                Iterator::chain(
                    [&"user" as &dyn AsRef<str>, &user].into_iter(),
                    path.as_ref().iter().map(|x| x as &dyn AsRef<str>),
                ),
            );
        let mut conn = htreq::connect(&url).await?;
        return Ok(htreq::get_json(&self.0.log, &mut conn, &url, &self.0.headers, max_size).await?);
    }

    /// Helper for setting under a user path.
    pub async fn user_set<
        T: AsRef<str>,
        I: AsRef<[T]>,
    >(&self, user: impl AsRef<str>, path: I, data: serde_json::Value) -> Result<(), Error> {
        let url =
            self.build_path(
                Iterator::chain(
                    [&"user" as &dyn AsRef<str>, &user].into_iter(),
                    path.as_ref().iter().map(|x| x as &dyn AsRef<str>),
                ),
            );
        let mut conn = htreq::connect(&url).await?;
        htreq::post_json::<()>(&self.0.log, &mut conn, &url, &self.0.headers, data, 100).await?;
        return Ok(());
    }

    /// Helper for deleting under a user path.
    pub async fn user_delete<
        T: AsRef<str>,
        I: AsRef<[T]>,
    >(&self, user: impl AsRef<str>, path: I) -> Result<(), Error> {
        let url =
            self.build_path(
                Iterator::chain(
                    [&"user" as &dyn AsRef<str>, &user].into_iter(),
                    path.as_ref().iter().map(|x| x as &dyn AsRef<str>),
                ),
            );
        let mut conn = htreq::connect(&url).await?;
        htreq::delete(&self.0.log, &mut conn, &url, &self.0.headers, 100).await?;
        return Ok(());
    }
}

pub const ENV_BASE_URL: &str = "FDAP_BASE_URL";
pub const ENV_TOKEN: &str = "FDAP_TOKEN";

#[derive(Default)]
pub struct ClientBuilder {
    log: Option<Log>,
    base_url: Option<Uri>,
    token: Option<String>,
}

impl ClientBuilder {
    /// Explicitly set a base url for the fdap server. Otherwise, the default url be
    /// read from an environment variable.
    pub fn with_base_url(mut self, base_url: Uri) -> Self {
        self.base_url = Some(base_url);
        return self;
    }

    /// Explicitly set a token. Otherwise, the token will be read from an environment
    /// variable.
    pub fn with_token(mut self, token: String) -> Self {
        self.token = Some(token);
        return self;
    }

    /// Override the default logger. Logging only occurs at DEBUG level and the default
    /// logger won't log anything.
    pub fn with_log(mut self, log: Log) -> Self {
        self.log = Some(log);
        return self;
    }

    pub fn build(self) -> Result<Client, Error> {
        let base_url;
        match self.base_url {
            Some(b) => {
                base_url = b;
            },
            None => {
                base_url =
                    Uri::try_from(
                        env::var(
                            ENV_BASE_URL,
                        ).map_err(
                            |e| Error(
                                format!(
                                    "No base URL explicitly set and unable to resolve env var {}: {}",
                                    ENV_BASE_URL,
                                    e
                                ),
                            ),
                        )?,
                    ).map_err(
                        |e| Error(
                            format!("Found base url in environment variable, but it is not a valid URL: {}", e),
                        ),
                    )?;
            },
        }
        let token;
        match self.token {
            Some(t) => {
                token = t;
            },
            None => {
                token =
                    env::var(
                        ENV_TOKEN,
                    ).map_err(
                        |e| Error(
                            format!("No token explicitly set and unable to resolve env var {}: {}", ENV_TOKEN, e),
                        ),
                    )?;
            },
        }
        let log = self.log.unwrap_or_else(|| Log::new_root(loga::WARN));
        return Ok(Client(Arc::new(Client_ {
            log: log,
            base_url: base_url,
            headers: [(AUTHORIZATION.to_string(), format!("{}{}", htwrap::HEADER_BEARER_PREFIX, token))]
                .into_iter()
                .collect(),
        })));
    }
}
