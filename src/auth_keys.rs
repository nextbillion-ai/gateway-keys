use crate::share::{Config, Result as nbResult};
use nbroutes_util::timestamp;
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use postgres_openssl::MakeTlsConnector;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio_postgres::{Client, NoTls, Row};

pub struct AuthKeySet {
    // map from cluster to {map from key id to key}
    pub keys: HashMap<String, HashMap<String, AuthKey>>,
    pub tokens: HashMap<String, String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct AuthKey {
    pub decoded: AuthKeyDecoded,
    pub refresh_ts: i64,
}

#[derive(Deserialize, Clone, Debug, Serialize)]
pub struct AuthKeyDecoded {
    pub source: Option<AuthKeyDecodedSource>,
}

#[derive(Deserialize, Clone, Debug, Serialize)]
pub struct AuthKeyDecodedSource {
    pub referers: Option<Vec<String>>,
}

pub async fn load_auth_keys(conf: &Config) -> nbResult<HashMap<String, HashMap<String, AuthKey>>> {
    let client: Client;
    let conn_str =
        "host=35.198.230.110 user=gateway password=nextbillion1234$ dbname=apikey sslmode=prefer";

    match &conf.apikey_db_ca {
        Some(v) => {
            let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
            builder.set_ca_file(&v).unwrap();
            builder.set_verify(SslVerifyMode::NONE);
            let connector = MakeTlsConnector::new(builder.build());
            let (_client, connection) = tokio_postgres::connect(conn_str, connector).await.unwrap();
            client = _client;
            actix_rt::spawn(async move {
                if let Err(e) = connection.await {
                    eprintln!("connection error: {}", e);
                }
            });
        }
        None => {
            let (_client, connection) = tokio_postgres::connect(conn_str, NoTls).await.unwrap();
            client = _client;
            actix_rt::spawn(async move {
                if let Err(e) = connection.await {
                    eprintln!("connection error: {}", e);
                }
            });
        }
    }

    let rows = &client
        .query("select * from apikey where status='active'", &[])
        .await?;

    let mut keys: HashMap<String, HashMap<String, AuthKey>> = HashMap::new();
    for row in rows {
        match parse_auth_key_row(&row) {
            Ok((cluster, kid, key)) => {
                let cluster_map = keys.get_mut(cluster.as_str());
                match cluster_map {
                    Some(c_map) => {
                        c_map.insert(kid, key);
                    }
                    None => {
                        let mut c_map: HashMap<String, AuthKey> = HashMap::new();
                        c_map.insert(kid, key);
                        keys.insert(cluster.clone(), c_map);
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

fn parse_auth_key_row(row: &Row) -> nbResult<(String, String, AuthKey)> {
    let maybe_cluster: Result<&str, _> = row.try_get("cluster");
    let maybe_kid: Result<&str, _> = row.try_get("kid");
    let maybe_payload: Result<&str, _> = row.try_get("payload");
    if let (Ok(cluster), Ok(kid), Ok(payload)) = (maybe_cluster, maybe_kid, maybe_payload) {
        let decoded: AuthKeyDecoded = serde_yaml::from_str(payload)?;
        return Ok((
            cluster.to_owned(),
            kid.to_owned(),
            AuthKey {
                decoded,
                refresh_ts: timestamp(),
            },
        ));
    }

    bail!("failed to parse row")
}