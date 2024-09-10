use crate::share::Share;
use actix_rt::time::interval;
use core::time::Duration;
use nbroutes_util::Result as nbResult;
use nbroutes_util::{
    def::{KeyServerAuthKey, KeyServerAuthKeyDecodedSource},
    util::gsutil,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

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

#[derive(Deserialize, Clone, Debug, Serialize)]
pub struct AuthKeyV2Payload {
    pub source: Option<KeyServerAuthKeyDecodedSource>,
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

    let mut keys_v3 = maybe_keys_v3.unwrap();
    info!(
        "successfully loaded new keys. number of keys: {}",
        keys_v3.len()
    );

    for (_kid, key) in keys_v3.iter_mut() {
        if key.sku_map.is_none() {
            key.sku_map = Some(HashMap::new());
        }
    }

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
