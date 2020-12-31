use crate::auth_keys::{load_auth_keys, AuthKeySet};
use actix_web::{error::ErrorUnauthorized, HttpRequest};
use nbroutes_util::{jwks::Jwks, timestamp};
use serde::{Deserialize, Serialize};
use serde_yaml;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Clone)]
pub struct Share {
    pub(crate) config: Config,
    pub(crate) auth: Arc<Jwks>,
    pub(crate) auth_keys: Arc<RwLock<AuthKeySet>>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Config {
    pub aud_cluster_map: HashMap<String, Vec<String>>,
    pub apikey_db_ca: Option<String>,
}

#[derive(Debug)]
pub(crate) struct AuthErr {
    pub msg: &'static str,
}
impl std::error::Error for AuthErr {}
impl std::fmt::Display for AuthErr {
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
    pub(crate) fn auth(
        &self,
        req: &HttpRequest,
    ) -> std::result::Result<(Vec<String>, Vec<String>), actix_web::error::Error> {
        let hauth = header(req, "authorization");
        if hauth.is_none() {
            return Err(ErrorUnauthorized(AuthErr {
                msg: "authorization header not found",
            }));
        }
        let hauth = hauth.unwrap();
        let items: Vec<&str> = hauth.split(" ").collect();
        if !(items.len() == 2 && items[0] == "Bearer") {
            return Err(ErrorUnauthorized(AuthErr {
                msg: "invalid authorization header",
            }));
        }

        match self.auth.verify_without_auds(items[1]) {
            Ok(jwt) => {
                debug!("jwt is {:?}", jwt);

                let mut clusters = vec![];

                let auds = jwt.payload().get_array("aud");
                if auds.is_none() {
                    debug!("auds not in jwt token");
                    return Err(ErrorUnauthorized(AuthErr {
                        msg: "jwt token has no valid auth",
                    }));
                }
                let mut valid_auds = vec![];
                for aud in auds.unwrap() {
                    debug!("auds  in jwt token are: {}", aud.as_str().unwrap_or(""));
                    let aud_string = aud.as_str().unwrap_or("");
                    if aud_string == "" {
                        continue;
                    }

                    let aud_clusters = match self.config.aud_cluster_map.get(aud_string) {
                        Some(aud_clusters) => aud_clusters.clone(),
                        None => vec![aud_string.to_string()],
                    };
                    for cluster in aud_clusters {
                        clusters.push(cluster.clone());
                    }
                    valid_auds.push(aud_string.to_string());
                }

                if clusters.len() == 0 {
                    return Err(ErrorUnauthorized(AuthErr {
                        msg: "jwt token has no valid auth",
                    }));
                }
                Ok((valid_auds, clusters))
            }
            Err(e) => Err(ErrorUnauthorized(e)),
        }
    }
}

pub async fn init() -> Result<Share> {
    let config = load_config()?;
    let auth_keys = Arc::new(RwLock::new(AuthKeySet {
        keys: load_auth_keys(&config).await?,
    }));
    Ok(Share {
        config,
        auth: init_jwt(),
        auth_keys,
    })
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
