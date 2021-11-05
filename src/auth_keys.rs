use crate::share::{Config, Share};
use actix::prelude::*;
use actix_rt::time::interval;
use core::time::Duration;
use nbroutes_util::Result as nbResult;
use nbroutes_util::{
    def::{KeyServerAuthKey, KeyServerAuthKeyDecodedSource},
    util::gsutil,
};
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use postgres::{Client, NoTls, Row};
use postgres_openssl::MakeTlsConnector;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) fn timestamp() -> i32 {
    let now = SystemTime::now();
    now.duration_since(UNIX_EPOCH).unwrap().as_secs() as i32
}

#[derive(Message, Debug)]
#[rtype(result = "AuthCache")]
pub struct LoadAuthMsg {
    pub cluster: String,
    pub cid: String,
}

pub struct LoadAuthActor {
    conn_str: String,
    connector: Option<MakeTlsConnector>,
    client: Option<Client>,
    ttl: i32,
}

impl LoadAuthActor {
    pub fn new(cfg: &Config) -> LoadAuthActor {
        let conn_str = format!(
            "host={} user=gateway password=nextbillion1234$ dbname=apikey sslmode=prefer",
            cfg.db_host,
        );
        let mut connector: Option<MakeTlsConnector> = None;
        if cfg.apikey_db_ca.is_some() {
            let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
            builder
                .set_ca_file(&cfg.apikey_db_ca.as_ref().unwrap())
                .unwrap();
            builder.set_verify(SslVerifyMode::NONE);
            connector = Some(MakeTlsConnector::new(builder.build()));
        }
        let ttl = std::env::var("TTL")
            .unwrap_or("60".to_string())
            .parse::<i32>()
            .unwrap();
        return LoadAuthActor {
            conn_str,
            connector,
            client: None,
            ttl,
        };
    }
    pub fn connect(&mut self) {
        if self.connector.is_some() {
            let _client = Client::connect(
                self.conn_str.as_str(),
                self.connector.as_ref().unwrap().clone(),
            );
            if _client.is_ok() {
                self.client = Some(_client.unwrap());
            }
        } else {
            let _client = Client::connect(self.conn_str.as_str(), NoTls);
            if _client.is_ok() {
                self.client = Some(_client.unwrap());
            }
        }
    }
}

impl Actor for LoadAuthActor {
    type Context = SyncContext<Self>;
}

impl Handler<LoadAuthMsg> for LoadAuthActor {
    type Result = MessageResult<LoadAuthMsg>;

    fn handle(&mut self, msg: LoadAuthMsg, _ctx: &mut SyncContext<Self>) -> Self::Result {
        debug!("process Load Auth: {:?}", &msg);
        if self.client.is_none() {
            self.connect();
        }
        let mut result = AuthCache {
            ttl: timestamp() + self.ttl,
            map: HashMap::<String, AuthKeyV2>::new(),
        };
        if self.client.is_some() {
            let rows = self.client.as_mut().unwrap().query("select * from apikey where status='active' and cluster=$1 and cid=$2 and (expiration = 0 or expiration > $3)",&[&(msg.cluster),&(msg.cid), &timestamp()]);
            if rows.is_ok() {
                let rows = rows.unwrap();
                for row in rows {
                    match parse_auth_key_row(&row) {
                        Ok((_cluster, kid, _cid, key)) => {
                            debug!("key loaded for cluster:{:?}: {:?}", &msg.cluster, &kid);
                            result.map.insert(kid, key);
                        }
                        Err(_) => {
                            warn!("fail to parse row: {:?}", row);
                        }
                    }
                }
            } else {
                warn!("fail to query: {:?}", &rows);
                self.client = None;
            }
        }
        MessageResult(result)
    }
}

pub struct AuthCache {
    pub ttl: i32,
    pub map: HashMap<String, AuthKeyV2>,
}

pub struct AuthKeySet {
    // map from cluster to {map from key id to key}
    pub keys: HashMap<String, AuthCache>,
}

#[derive(Debug)]
pub struct AuthKeySetV3 {
    // map from ord_id to {map from key id to key}
    pub org_keys_map: HashMap<String, HashMap<String, KeyServerAuthKey>>,
}

impl AuthKeySetV3 {
    fn new(keys: HashMap<String, KeyServerAuthKey>) -> AuthKeySetV3 {
        let mut org_keys_map = HashMap::new();

        for (key_id, key) in keys {
            if key.labels.is_none() {
                warn!(
                    "AuthKeySetV3 skip key_id {} since lables are none",
                    key_id.as_str()
                );
                continue;
            }

            let labels = key.labels.as_ref().unwrap();
            let maybe_org_id = labels.get("org_id");
            if maybe_org_id.is_none() {
                warn!(
                    "AuthKeySetV3 skip key_id {} since org_id is missing",
                    key_id.as_str()
                );
                continue;
            }

            let org_id = maybe_org_id.unwrap().to_string();

            org_keys_map
                .entry(org_id)
                .or_insert(HashMap::new())
                .insert(key_id, key);
        }

        AuthKeySetV3 { org_keys_map }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthKeyV2 {
    pub source: Option<KeyServerAuthKeyDecodedSource>,
    pub expiration: i32,
}

impl AuthKeyV2 {
    pub fn to_auth_key_general(&self) -> KeyServerAuthKey {
        KeyServerAuthKey {
            source: self.source.clone(),
            sku_map: None,
            labels: None,
            qps_limit: None,
        }
    }
}

#[derive(Deserialize, Clone, Debug, Serialize)]
pub struct AuthKeyV2Payload {
    pub source: Option<KeyServerAuthKeyDecodedSource>,
}

fn parse_auth_key_row(row: &Row) -> nbResult<(String, String, String, AuthKeyV2)> {
    let maybe_cluster: Result<&str, _> = row.try_get("cluster");
    let maybe_kid: Result<&str, _> = row.try_get("kid");
    let maybe_cid: Result<&str, _> = row.try_get("cid");
    let maybe_payload: Result<&str, _> = row.try_get("payload");

    let maybe_expiration: Result<i32, _> = row.try_get("expiration");
    if let (Ok(cluster), Ok(kid), Ok(cid), Ok(payload), Ok(expiration)) = (
        maybe_cluster,
        maybe_kid,
        maybe_cid,
        maybe_payload,
        maybe_expiration,
    ) {
        let payload: AuthKeyV2Payload = serde_yaml::from_str(payload)?;
        let decoded = AuthKeyV2 {
            source: payload.source,
            expiration,
        };
        return Ok((cluster.to_owned(), kid.to_owned(), cid.to_owned(), decoded));
    }

    bail!("failed to parse row")
}

pub async fn start_key_refresher(share_conf: Arc<Share>) {
    let mut intev = interval(Duration::from_secs(60));
    intev.tick().await;
    loop {
        intev.tick().await;
        reload_keys_v3(Arc::clone(&share_conf)).await;
    }
}

pub async fn reload_keys_v3(share_conf: Arc<Share>) {
    let maybe_keys_v3 = load_keys_v3_from_gcs().await;
    if maybe_keys_v3.is_err() {
        warn!("load auth key failed due to {:?}", maybe_keys_v3.err());
        return;
    }

    let keys_v3 = maybe_keys_v3.unwrap();
    info!(
        "successfully loaded new keys. number of keys: {}",
        keys_v3.len()
    );

    let key_set_v3 = AuthKeySetV3::new(keys_v3);
    let mut share_auth_keys_v3 = share_conf.auth_keys_v3.write().unwrap();
    share_auth_keys_v3.org_keys_map = key_set_v3.org_keys_map;
}

// maybe_load_keys_v3 returns empty key set when gcs fails
//  this is to allow key server to start without GCS dependency.
//  after all only the docker version might relies on key server to have api key v3
pub async fn maybe_load_keys_v3() -> AuthKeySetV3 {
    let maybe_keys_v3 = load_keys_v3_from_gcs().await;
    if maybe_keys_v3.is_err() {
        warn!("load auth key failed due to {:?}", maybe_keys_v3.err());
        return AuthKeySetV3::new(HashMap::new());
    }

    let keys_v3 = maybe_keys_v3.unwrap();
    info!(
        "successfully loaded new keys. number of keys: {}",
        keys_v3.len()
    );

    AuthKeySetV3::new(keys_v3)
}

async fn load_keys_v3_from_gcs() -> nbResult<HashMap<String, KeyServerAuthKey>> {
    let output = gsutil("gs://maaas/apikeys/global.json").await?;

    debug!("loaded result from maaas, they are {}", &output);
    let keys: HashMap<String, KeyServerAuthKey> = serde_json::from_str(&output)?;

    return Ok(keys);
}
