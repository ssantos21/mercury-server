mod endpoints;

#[macro_use] extern crate rocket;

use rocket::serde::json::{Value, json};
use sqlx::postgres::PgPoolOptions;

#[get("/")]
fn hello() -> &'static str {
    "Hello, world!\n"
}

#[catch(404)]
fn not_found() -> Value {
    json!("Not found!")
}


#[rocket::main]
async fn main() {

    let pool = 
        PgPoolOptions::new()
        // .max_connections(5)
        .connect("postgresql://postgres:postgres@localhost/mercury")
        .await
        .unwrap();

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .unwrap();

    let _ = rocket::build()
        .mount("/", routes![
            hello,
            endpoints::deposit::post_deposit,
            endpoints::sign::post_public_nonce,
        ])
        .register("/", catchers![
            not_found
        ])
        .manage(pool)
        // .attach(MercuryPgDatabase::fairing())
        .launch()
        .await;
}