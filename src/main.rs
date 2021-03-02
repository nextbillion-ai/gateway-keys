mod auth_keys;
mod share;
mod tokens;

use crate::auth_keys::{load_auth_keys, AuthKey};
use crate::share::{init, AuthErr, Share};
use crate::tokens::sign_jwt;
use actix_web::error::{ErrorBadRequest, ErrorUnauthorized};
use actix_web::{
    get, middleware::Logger, post, web, web::Bytes, App, HttpRequest, HttpResponse, HttpServer,
};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::time::{interval, Duration};

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
async fn metrics(share: web::Data<Share>) -> actix_web::Result<web::HttpResponse>{
    Ok(HttpResponse::Ok().body(share.get_metrics()
        .map_err(|b| ErrorBadRequest((*b).to_string()))?))
}

#[derive(Serialize)]
pub struct KeysOutput {
    pub keys: HashMap<String, AuthKey>,
    pub token: String,
}

#[post("/keys")]
async fn postkeys(
    req: HttpRequest,
    bytes: Bytes,
    share: web::Data<Share>,
) -> actix_web::Result<web::Json<KeysOutput>> {
    let (auds, clusters) = share.auth(&req)?;
    info!(
        "receive keys post request. auds are {:?}, clusters are: {:?}",
        auds, clusters
    );
    share
        .update_metrics(std::str::from_utf8(&bytes.to_vec())?)
        .map_err(|b| ErrorBadRequest((*b).to_string()))?;

    let mut res_keys: HashMap<String, AuthKey> = HashMap::new();

    let all_keys = share.auth_keys.read().unwrap();
    for cluster in clusters {
        if let Some(cluster_keys) = all_keys.keys.get(cluster.as_str()) {
            for (key_name, key_value) in cluster_keys {
                res_keys.insert(key_name.clone(), key_value.clone());
            }
        }
    }

    if res_keys.len() == 0 {
        return Err(ErrorUnauthorized(AuthErr {
            msg: "cluster have not valid keys",
        }));
    }

    let token = sign_jwt(auds);
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
    let (auds, clusters) = share.auth(&req)?;
    info!(
        "receive keys request. auds are {:?}, clusters are: {:?}",
        auds, clusters
    );

    let mut res_keys: HashMap<String, AuthKey> = HashMap::new();

    let all_keys = share.auth_keys.read().unwrap();
    for cluster in clusters {
        if let Some(cluster_keys) = all_keys.keys.get(cluster.as_str()) {
            for (key_name, key_value) in cluster_keys {
                res_keys.insert(key_name.clone(), key_value.clone());
            }
        }
    }

    if res_keys.len() == 0 {
        return Err(ErrorUnauthorized(AuthErr {
            msg: "cluster have not valid keys",
        }));
    }

    let token = sign_jwt(auds);
    Ok(web::Json(KeysOutput {
        keys: res_keys,
        token,
    }))
}

fn main() {
    // TODO: note that currently these tokio runtime and tasks are messy, I will properly change it after studying the tokio doc
    let mut tok_tuntime = tokio::runtime::Runtime::new().unwrap();
    let local_tasks = tokio::task::LocalSet::new();

    let system_fut = actix_rt::System::run_in_tokio("main", &local_tasks);

    local_tasks.block_on(&mut tok_tuntime, async {
        tokio::task::spawn_local(system_fut);

        env_logger::init();
        let share = init().await.unwrap();

        // start a timer to periodically query db to update key cache
        let key_set = Arc::clone(&share.auth_keys);
        let config_clone = share.config.clone();
        tokio::task::spawn_local(async move {
            let mut intev = interval(Duration::from_secs(60));
            loop {
                intev.tick().await;
                let mut key_set_mut = key_set.write().unwrap();

                let maybe_new_auth_keys = load_auth_keys(&config_clone).await;
                match maybe_new_auth_keys {
                    Ok(new_keys) => {
                        info!(
                            "successfully loaded new keys. available clusters: {:?}",
                            new_keys.keys()
                        );

                        key_set_mut.keys = new_keys;
                        info!("successfully updated new keys in cache");
                    }
                    Err(e) => warn!("load auth key failed due to {:?}", e),
                }
            }
        });

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
    });
}
