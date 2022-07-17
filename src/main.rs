mod auth_keys;
mod share;
mod tokens;

use crate::auth_keys::{start_key_refresher, timestamp, LoadAuthActor, LoadAuthMsg};
use crate::share::{init, APIErr, Share};
use crate::tokens::sign_jwt;
use actix::prelude::*;
use actix_web::error::ErrorBadRequest;
use actix_web::error::ErrorInternalServerError;
use actix_web::{
    get, middleware::Logger, post, web, web::Bytes, App, HttpRequest, HttpResponse, HttpServer,
};
use nbroutes_util::def::KeyServerAuthKey;
use nbroutes_util::Result as nbResult;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;

#[macro_use]
extern crate log;
#[macro_use]
extern crate simple_error;
extern crate openssl;
extern crate serde;
extern crate serde_derive;
extern crate smpl_jwt;

#[get("/health")]
async fn health() -> HttpResponse {
    HttpResponse::Ok().body("healthy")
}

#[get("/metrics")]
async fn metrics(share: web::Data<Arc<Share>>) -> actix_web::Result<web::HttpResponse> {
    Ok(HttpResponse::Ok().body(
        share
            .get_metrics()
            .map_err(|b| ErrorBadRequest((*b).to_string()))?,
    ))
}

#[derive(Serialize)]
pub struct KeysOutput {
    pub keys: HashMap<String, KeyServerAuthKey>,
    pub token: String,
}

fn get_keys_v3(org_id: String, share: Arc<Share>) -> HashMap<String, KeyServerAuthKey> {
    let all_keys_v3 = share.auth_keys_v3.read().unwrap();
    let org_keys = all_keys_v3.org_keys_map.get(org_id.as_str());
    if org_keys.is_none() {
        return HashMap::new();
    }

    org_keys.unwrap().clone()
}

async fn get_keys_v2(
    clusters: Vec<String>,
    cid: String,
    share: Arc<Share>,
) -> nbResult<HashMap<String, KeyServerAuthKey>> {
    let mut res_keys: HashMap<String, KeyServerAuthKey> = HashMap::new();

    for cluster in clusters {
        let _cluster = cluster.clone();
        let _cid = cid.clone();
        let _clusterkey = cluster + "|" + &cid;
        let mut load = true;
        {
            let all_keys = share.auth_keys.read().unwrap();
            if let Some(cache) = all_keys.keys.get(&_clusterkey) {
                if cache.ttl > timestamp() {
                    if cache.map.len() > 0 {
                        let ts = timestamp();
                        let mut cnt = 0;
                        for (kid, auth_key) in &cache.map {
                            if auth_key.expiration > ts || auth_key.expiration == 0 {
                                res_keys.insert(kid.clone(), auth_key.to_auth_key_general());
                                cnt = cnt + 1;
                            }
                        }
                        //if no valid keys found, reload from db
                        load = cnt == 0;
                    } else {
                        //skip examine for reloading when cache has empty map
                        load = false;
                    }
                }
            }
        }
        if load {
            let cache = share
                .load_auth_addr
                .clone()
                .unwrap()
                .send(LoadAuthMsg {
                    cluster: _cluster,
                    cid: _cid,
                })
                .await;
            if cache.is_err() {
                bail!("sending load auth message failed")
            }

            let cache = cache.unwrap();
            if !cache.load_success {
                bail!("load auth message failed")
            }

            let mut all_keys = share.auth_keys.write().unwrap();

            for (kid, auth_key) in &cache.map {
                res_keys.insert(kid.clone(), auth_key.to_auth_key_general());
            }
            all_keys.keys.insert(_clusterkey.clone(), cache);
        }
    }

    Ok(res_keys)
}

async fn parse_auth(
    share: &web::Data<Arc<Share>>,
    req: &HttpRequest,
) -> Result<(HashMap<String, KeyServerAuthKey>, String), actix_web::error::Error> {
    let (auds, clusters, cid, is_v3) = share.auth(req)?;
    info!(
        "receive keys request. auds are {:?}, clusters are: {:?}, cid: {:?}",
        auds, clusters, cid
    );

    let res_keys: HashMap<String, KeyServerAuthKey>;
    if is_v3 {
        res_keys = get_keys_v3(cid, Arc::clone(&share));
    } else {
        let maybe_key_res = get_keys_v2(clusters, cid, Arc::clone(&share)).await;
        if maybe_key_res.is_err() {
            return Err(ErrorInternalServerError(APIErr {
                msg: "failed to load apikeys",
            }));
        }
        res_keys = maybe_key_res.unwrap();
    }

    let token: String;
    if res_keys.len() > 0 {
        token = sign_jwt(auds);
    } else {
        token = "".to_string();
    }

    Ok((res_keys, token))
}

#[post("/keys")]
async fn postkeys(
    req: HttpRequest,
    bytes: Bytes,
    share: web::Data<Arc<Share>>,
) -> actix_web::Result<web::Json<KeysOutput>> {
    let (res_keys, token) = parse_auth(&share, &req).await?;
    share
        .update_metrics(std::str::from_utf8(&bytes.to_vec())?)
        .map_err(|b| ErrorBadRequest((*b).to_string()))?;

    Ok(web::Json(KeysOutput {
        keys: res_keys,
        token,
    }))
}

#[get("/keys")]
async fn keys(
    req: HttpRequest,
    share: web::Data<Arc<Share>>,
) -> actix_web::Result<web::Json<KeysOutput>> {
    let (res_keys, token) = parse_auth(&share, &req).await?;

    Ok(web::Json(KeysOutput {
        keys: res_keys,
        token,
    }))
}

#[actix_web::main]
async fn main() {
    env_logger::init();
    let mut share = init().await.unwrap();

    let config_clone = share.config.clone();
    let authloader_cnt = std::env::var("POOLSIZE")
        .unwrap_or("5".to_string())
        .parse::<usize>()
        .unwrap();

    let load_auth_addr = SyncArbiter::start(authloader_cnt, move || {
        LoadAuthActor::new(&config_clone.clone())
    });
    share.load_auth_addr = Some(load_auth_addr);

    let share_arc = Arc::new(share);
    actix_rt::spawn(start_key_refresher(Arc::clone(&share_arc)));

    let _ = HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .data(Arc::clone(&share_arc))
            .service(keys)
            .service(metrics)
            .service(postkeys)
            .service(health)
    })
    .bind("0.0.0.0:8888")
    .unwrap()
    .run()
    .await;
}
