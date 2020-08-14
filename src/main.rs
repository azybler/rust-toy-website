#[macro_use]
extern crate actix_web;

use r2d2_sqlite::SqliteConnectionManager;

mod api_handlers;
mod config;

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    std::env::set_var("RUST_LOG", "actix_web=info");

    let manager = SqliteConnectionManager::file("db/data.sqlite");
    let pool = r2d2::Pool::new(manager).unwrap();

    actix_web::HttpServer::new(move || {
        actix_web::App::new()
            .data(pool.clone())
            // APIs
            .service(api_handlers::login::handler)
            .service(api_handlers::signup::handler)
    })
    .bind(config::BIND_HOST_PORT)?
    .run()
    .await
}
