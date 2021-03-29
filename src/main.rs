mod auth_keys;
mod share;
mod tokens;

use crate::auth_keys::{timestamp, AuthKey, LoadAuthActor, LoadAuthMsg};
use crate::share::{init, Share};
use crate::tokens::sign_jwt;
use actix::prelude::*;
use actix_web::error::ErrorBadRequest;
use actix_web::{
    get, middleware::Logger, post, web, web::Bytes, App, HttpRequest, HttpResponse, HttpServer,
};
use serde::Serialize;
use std::collections::HashMap;

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
async fn metrics(share: web::Data<Share>) -> actix_web::Result<web::HttpResponse> {
    Ok(HttpResponse::Ok().body(
        share
            .get_metrics()
            .map_err(|b| ErrorBadRequest((*b).to_string()))?,
    ))
}

#[derive(Serialize)]
pub struct KeysOutput {
    pub keys: HashMap<String, AuthKey>,
    pub token: String,
}

async fn parse_auth(
    share: &web::Data<Share>,
    req: &HttpRequest,
) -> Result<(HashMap<String, AuthKey>, String), actix_web::error::Error> {
    let (auds, clusters, cid) = share.auth(req)?;
    info!(
        "receive keys request. auds are {:?}, clusters are: {:?}, cid: {:?}",
        auds, clusters, cid
    );

    let mut res_keys: HashMap<String, AuthKey> = HashMap::new();

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
                                res_keys.insert(kid.clone(), auth_key.clone());
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
            if let Ok(cache) = share
                .load_auth_addr
                .clone()
                .unwrap()
                .send(LoadAuthMsg {
                    cluster: _cluster,
                    cid: _cid,
                })
                .await
            {
                let mut all_keys = share.auth_keys.write().unwrap();

                for (kid, auth_key) in &cache.map {
                    res_keys.insert(kid.clone(), auth_key.clone());
                }
                all_keys.keys.insert(_clusterkey.clone(), cache);
            }
        }
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
    share: web::Data<Share>,
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
    share: web::Data<Share>,
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

    let _ = HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .data(share.clone())
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
