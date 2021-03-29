use crate::share::{Config, Result as nbResult};
use actix::prelude::*;
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use postgres::{Client, NoTls, Row};
use postgres_openssl::MakeTlsConnector;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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
            conn_str: conn_str,
            connector: connector,
            client: None,
            ttl: ttl,
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
        let mut result = AuthCache{
            ttl: timestamp() + self.ttl,
            map: HashMap::<String, AuthKey>::new(),
        };
        if self.client.is_some() {
            let rows = self.client.as_mut().unwrap().query("select * from apikey where status='active' and cluster=$1 and cid=$2 and (expiration = 0 or expiration > $3)",&[&(msg.cluster),&(msg.cid), &timestamp()]);
            if rows.is_ok() {
                let rows = rows.unwrap();
                for row in rows {
                    match parse_auth_key_row(&row) {
                        Ok((_cluster, kid, _cid, key)) => {
                            debug!("key loaded for cluster:{:?}: {:?}",&msg.cluster,&kid);
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

pub struct AuthCache{
    pub ttl: i32,
    pub map: HashMap<String,AuthKey>
}

pub struct AuthKeySet {
    // map from cluster to {map from key id to key}
    pub keys: HashMap<String, AuthCache>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthKey {
    pub payload: Payload,
    pub expiration: i32,
}

#[derive(Deserialize, Clone, Debug, Serialize)]
pub struct Payload {
    pub referers: Option<Vec<String>>,
}

fn parse_auth_key_row(row: &Row) -> nbResult<(String, String, String, AuthKey)> {
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
        let payload: Payload = serde_yaml::from_str(payload)?;
        let decoded = AuthKey {
            payload: payload,
            expiration: expiration,
        };
        return Ok((cluster.to_owned(), kid.to_owned(), cid.to_owned(), decoded));
    }

    bail!("failed to parse row")
}
