mod auth_keys;
mod share;
mod tokens;

use crate::auth_keys::{load_auth_keys, AuthKey};
use crate::share::{init, Share};
use crate::tokens::sign_jwts;
use actix_web::{get, middleware::Logger, web, App, HttpRequest, HttpResponse, HttpServer};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::time;
use tokio::time::{interval, Duration};

#[macro_use]
extern crate log;
#[macro_use]
extern crate simple_error;
#[macro_use]
extern crate serde_derive;
extern crate openssl;
extern crate serde;
extern crate smpl_jwt;

#[get("/health")]
async fn health() -> HttpResponse {
    HttpResponse::Ok().body("healthy")
}

#[derive(Serialize)]
pub struct KeysOutput {
    pub keys: HashMap<String, KeyOutput>,
}

#[derive(Serialize)]
pub struct KeyOutput {
    pub keys: HashMap<String, AuthKey>,
    pub token: String,
}

#[get("/keys")]
async fn keys(
    req: HttpRequest,
    share: web::Data<Share>,
) -> actix_web::Result<web::Json<KeysOutput>> {
    let clusters = share.auth(&req)?;

    let mut res_keys: HashMap<String, KeyOutput> = HashMap::new();

    let all_keys = share.auth_keys.read().unwrap();
    for cluster in clusters {
        if let (Some(cluster_keys), Some(cluster_token)) = (
            all_keys.keys.get(cluster.as_str()),
            all_keys.tokens.get(cluster.as_str()),
        ) {
            let cluster_key_output = KeyOutput {
                keys: cluster_keys.clone(),
                token: cluster_token.clone(),
            };
            res_keys.insert(cluster.clone(), cluster_key_output);
        }
    }

    Ok(web::Json(KeysOutput { keys: res_keys }))
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
                key_set_mut.tokens = sign_jwts(&config_clone);

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
                    Err(e) => {}
                }
            }
        });

        let _ = HttpServer::new(move || {
            App::new()
                .wrap(Logger::default())
                .data(share.clone())
                .service(keys)
                .service(health)
        })
        .bind("0.0.0.0:8888")
        .unwrap()
        .run()
        .await;
    });
}
