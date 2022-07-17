use crate::auth_keys::{maybe_load_keys_v3, AuthCache, AuthKeySet, AuthKeySetV3, LoadAuthActor};
use actix::prelude::*;
use actix_web::{error::ErrorUnauthorized, HttpRequest};
use jwks_client::jwt::Jwt;
use nbroutes_util::{jwks::Jwks, timestamp};
use serde::{Deserialize, Serialize};
use serde_yaml;
use simple_error::SimpleError;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Clone)]
pub struct Share {
    pub(crate) config: Config,
    pub(crate) auth: Arc<Jwks>,
    pub(crate) auth_keys: Arc<RwLock<AuthKeySet>>,
    pub(crate) auth_keys_v3: Arc<RwLock<AuthKeySetV3>>,
    pub(crate) metrics: Arc<RwLock<HashMap<String, f64>>>,
    pub(crate) load_auth_addr: Option<Addr<LoadAuthActor>>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Config {
    pub aud_cluster_map: HashMap<String, Vec<String>>,
    pub db_host: String,
    pub apikey_db_ca: Option<String>,
}

#[derive(Debug)]
pub(crate) struct APIErr {
    pub msg: &'static str,
}
impl std::error::Error for APIErr {}
impl std::fmt::Display for APIErr {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "(msg: {})", self.msg)
    }
}

fn header<'a>(req: &'a HttpRequest, name: &str) -> Option<&'a str> {
    match req.headers().get(name)?.to_str() {
        Ok(v) => Some(v),
        Err(_) => None,
    }
}

impl Share {
    pub(crate) fn verify_jwt(
        &self,
        jwt: Jwt,
    ) -> std::result::Result<(Vec<String>, Vec<String>, String, bool), actix_web::error::Error>
    {
        debug!("jwt is {:?}", jwt);

        let auds = jwt.payload().get_array("aud").ok_or_else(|| {
            debug!("auds not in jwt token");
            ErrorUnauthorized(APIErr {
                msg: "jwt token has no valid auth",
            })
        })?;

        let mut clusters = vec![];
        let mut valid_auds = vec![];
        for aud in auds {
            debug!("auds  in jwt token are: {}", aud.as_str().unwrap_or(""));
            let aud_string = aud.as_str().unwrap_or("");
            if aud_string == "" {
                continue;
            }

            match self.config.aud_cluster_map.get(aud_string) {
                Some(aud_clusters) => {
                    for cluster in aud_clusters {
                        clusters.push(cluster.clone());
                    }
                }
                None => clusters.push(aud_string.to_string()),
            };
            valid_auds.push(aud_string.to_string());
        }

        if clusters.len() == 0 {
            return Err(ErrorUnauthorized(APIErr {
                msg: "jwt token has no valid auth",
            }));
        }

        if clusters.len() == 1 && &clusters[0] == "starter" {
            let maybe_org_id = jwt.payload().get_u64("org");
            if maybe_org_id.is_some() {
                return Ok((
                    valid_auds,
                    clusters,
                    maybe_org_id.unwrap().to_string(),
                    true,
                ));
            }
        }

        let cid = jwt.payload().get_str("cid").unwrap_or("");
        Ok((valid_auds, clusters, cid.to_string(), false))
    }

    pub(crate) fn auth(
        &self,
        req: &HttpRequest,
    ) -> std::result::Result<(Vec<String>, Vec<String>, String, bool), actix_web::error::Error>
    {
        let hauth = header(req, "authorization");
        if hauth.is_none() {
            return Err(ErrorUnauthorized(APIErr {
                msg: "authorization header not found",
            }));
        }
        let hauth = hauth.unwrap();
        let items: Vec<&str> = hauth.split(" ").collect();
        if !(items.len() == 2 && items[0] == "Bearer") {
            return Err(ErrorUnauthorized(APIErr {
                msg: "invalid authorization header",
            }));
        }

        match self.auth.verify_without_auds(items[1]) {
            Ok(jwt) => self.verify_jwt(jwt),
            Err(e) => Err(ErrorUnauthorized(e)),
        }
    }
    pub(crate) fn get_metrics(&self) -> Result<String> {
        let mut m = self
            .metrics
            .write()
            .map_err(|_b| SimpleError::new("unable to get write lock of metrics"))?;
        let mut s = String::new();
        use std::fmt::Write;
        for (key, value) in &(*m) {
            write!(s, "\n{} {}", key, value)?;
        }
        m.clear();
        debug!("{}", &s);
        return Ok(s);
    }
    pub(crate) fn update_metrics(&self, input: &str) -> Result<()> {
        debug!("{}", input);
        let lines = input.lines();
        for line in lines {
            if line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.rsplitn(2, ' ').collect();
            if parts.len() != 2 {
                bail!("invalid metrics line: {}", line);
            }
            debug!("key:{} , value: {} ", parts[1], parts[0]);
            self.metrics
                .write()
                .map_err(|_b| SimpleError::new("unable to get write lock of metrics"))?
                .insert(parts[1].to_string(), parts[0].parse::<f64>()?);
        }
        Ok(())
    }
}

pub async fn init() -> Result<Share> {
    let config = load_config()?;
    let auth_keys = Arc::new(RwLock::new(AuthKeySet {
        keys: HashMap::<String, AuthCache>::new(),
    }));
    let auth_keys_v3 = Arc::new(RwLock::new(maybe_load_keys_v3().await));
    let metrics = Arc::new(RwLock::new(HashMap::new()));

    let res = Share {
        config,
        auth: init_jwt(),
        auth_keys,
        auth_keys_v3,
        metrics,
        load_auth_addr: None,
    };

    Ok(res)
}

fn init_jwt() -> Arc<Jwks> {
    let jwks_url = std::env::var("JWKS_URL").unwrap_or(
        format!(
            "https://static.nextbillion.io/jwks/nb.ai.key_server.pub?{}",
            timestamp()
        )
        .to_string(),
    );

    Arc::new(Jwks::load_from_url(&jwks_url))
}

fn load_config() -> Result<Config> {
    let path = std::env::var("CONFIG_PATH").unwrap_or("/etc/config/config.yaml".to_string());
    let contents = std::fs::read_to_string(&path)?;
    Ok(serde_yaml::from_str(&contents)?)
}
