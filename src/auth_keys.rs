use crate::share::{Config, Result as nbResult};
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use postgres_openssl::MakeTlsConnector;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio_postgres::{Client, NoTls, Row};

fn timestamp() -> i32 {
    let now = SystemTime::now();
    now.duration_since(UNIX_EPOCH).unwrap().as_secs() as i32
}

pub struct AuthKeySet {
    // map from cluster to {map from key id to key}
    pub keys: HashMap<String, HashMap<String, AuthKey>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthKey {
    pub source: Option<AuthKeyDecodedSource>,
}

#[derive(Deserialize, Clone, Debug, Serialize)]
pub struct AuthKeyDecodedSource {
    pub referers: Option<Vec<String>>,
}

pub async fn load_auth_keys(conf: &Config) -> nbResult<HashMap<String, HashMap<String, AuthKey>>> {
    let client: Client;
    let conn_str = format!(
        "host={} user=gateway password=nextbillion1234$ dbname=apikey sslmode=prefer",
        conf.db_host
    );

    match &conf.apikey_db_ca {
        Some(v) => {
            let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
            builder.set_ca_file(&v).unwrap();
            builder.set_verify(SslVerifyMode::NONE);
            let connector = MakeTlsConnector::new(builder.build());
            let (_client, connection) = tokio_postgres::connect(conn_str.as_str(), connector)
                .await
                .unwrap();
            client = _client;
            actix_rt::spawn(async move {
                if let Err(e) = connection.await {
                    eprintln!("connection error: {}", e);
                }
            });
        }
        None => {
            let (_client, connection) = tokio_postgres::connect(conn_str.as_str(), NoTls)
                .await
                .unwrap();
            client = _client;
            actix_rt::spawn(async move {
                if let Err(e) = connection.await {
                    eprintln!("connection error: {}", e);
                }
            });
        }
    }

    let rows = &client
        .query(
            "select * from apikey where status='active' and (expiration = 0 or expiration > $1)",
            &[&timestamp()],
        )
        .await?;

    let mut keys: HashMap<String, HashMap<String, AuthKey>> = HashMap::new();
    for row in rows {
        match parse_auth_key_row(&row) {
            Ok((cluster, kid, cid, key)) => {
                let ckey = cluster + "|" + &cid;
                let cluster_map = keys.get_mut(&ckey);
                match cluster_map {
                    Some(c_map) => {
                        c_map.insert(kid, key);
                    }
                    None => {
                        let mut c_map: HashMap<String, AuthKey> = HashMap::new();
                        c_map.insert(kid, key);
                        keys.insert(ckey.clone(), c_map);
                    }
                };
            }
            Err(_) => {
                warn!("fail to parse row: {:?}", row);
            }
        }
    }

    info!("auth keys loaded/reloaded");
    debug!("keys are {:?}", &keys);

    Ok(keys)
}

fn parse_auth_key_row(row: &Row) -> nbResult<(String, String, String, AuthKey)> {
    let maybe_cluster: Result<&str, _> = row.try_get("cluster");
    let maybe_kid: Result<&str, _> = row.try_get("kid");
    let maybe_cid: Result<&str, _> = row.try_get("cid");
    let maybe_payload: Result<&str, _> = row.try_get("payload");
    if let (Ok(cluster), Ok(kid), Ok(cid), Ok(payload)) =
        (maybe_cluster, maybe_kid, maybe_cid, maybe_payload)
    {
        let decoded: AuthKey = serde_yaml::from_str(payload)?;
        return Ok((cluster.to_owned(), kid.to_owned(), cid.to_owned(), decoded));
    }

    bail!("failed to parse row")
}
