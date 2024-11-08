mod auth_keys;
mod share;
mod tokens;

use crate::auth_keys::start_key_refresher;
use crate::share::{init, Share};
use crate::tokens::sign_jwt;
use actix_web::error::ErrorBadRequest;
use actix_web::{
    get, middleware::Logger, post, web, web::Bytes, App, HttpRequest, HttpResponse, HttpServer,
};
use nbroutes_util::def::KeyServerAuthKey;
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

async fn parse_auth(
    share: &web::Data<Arc<Share>>,
    req: &HttpRequest,
) -> Result<(HashMap<String, KeyServerAuthKey>, String), actix_web::error::Error> {
    let (auds, clusters, cid, is_v3) = share.auth(req)?;
    info!(
        "receive keys request. auds are {:?}, clusters are: {:?}, cid: {:?}",
        auds, clusters, cid
    );

    let mut res_keys: HashMap<String, KeyServerAuthKey> = HashMap::new();
    if is_v3 {
        res_keys = get_keys_v3(cid, Arc::clone(&share));
    } 

    let token = sign_jwt(auds);
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
    let share = init().await.unwrap();

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
