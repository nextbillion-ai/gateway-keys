mod auth_keys;
mod share;

use crate::auth_keys::{load_auth_keys, AuthKey, AuthKeyDecoded};
use crate::share::{init, Share};
use actix_web::{get, middleware::Logger, web, App, HttpRequest, HttpResponse, HttpServer};
// use futures::future::lazy;
// use futures::stream::Stream;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::{thread, time};
use tokio::time::{interval, Duration};
// use tokio_timer::Interval;
use std::sync::Arc;

#[macro_use]
extern crate log;
#[macro_use]
extern crate simple_error;

#[get("/health")]
async fn health() -> HttpResponse {
    HttpResponse::Ok().body("healthy")
}

#[derive(Serialize)]
pub struct KeysOutput {
    pub keys: HashMap<String, HashMap<String, AuthKey>>,
}

#[get("/keys")]
async fn keys(
    req: HttpRequest,
    share: web::Data<Share>,
) -> actix_web::Result<web::Json<KeysOutput>> {
    let clusters = share.auth(&req)?;

    let mut res_keys: HashMap<String, HashMap<String, AuthKey>> = HashMap::new();

    let all_keys = share.auth_keys.read().unwrap();
    for cluster in clusters {
        if let Some(cluster_keys) = all_keys.keys.get(cluster.as_str()) {
            res_keys.insert(cluster.clone(), cluster_keys.clone());
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
                match load_auth_keys(&config_clone).await {
                    Ok(new_keys) => {
                        info!(
                            "successfully loaded new keys. available clusters: {:?}",
                            new_keys.keys()
                        );
                        let mut key_set_mut = key_set.write().unwrap();
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
