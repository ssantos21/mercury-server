use std::str::FromStr;

use bitcoin::hashes::sha256;
use rocket::{State, serde::json::Json, response::status, http::Status};
use secp256k1_zkp::{XOnlyPublicKey, Secp256k1, Message, schnorr::Signature};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::Row;

#[derive(Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct SignFirstRequestPayload {
    statechain_id: String,
    r2_commitment: String,
    blind_commitment: String,
    signed_statechain_id: String,
}


async fn get_auth_key_by_statechain_id(pool: &State<sqlx::PgPool>, statechain_id: &str) -> Result<XOnlyPublicKey, sqlx::Error> {

    let row = sqlx::query(
        "SELECT auth_xonly_public_key \
        FROM public.key_data \
        WHERE statechain_id = $1")
        .bind(&statechain_id)
        .fetch_one(pool.clone().inner())
        .await;

    match row {
        Ok(row) => {
            let public_key_bytes = row.get::<Option<Vec<u8>>, _>("auth_xonly_public_key");
            let pk = XOnlyPublicKey::from_slice(&public_key_bytes.unwrap()).unwrap();
            return Ok(pk);
        },
        Err(err) => {
            return Err(err);
        }
    };

}


pub async fn update_commitments(pool: &State<sqlx::PgPool>, r2_commitment: &str, blind_commitment: &str, statechain_id: &str)  {

    let query = "\
        UPDATE key_data \
        SET r2_commitment= $1, blind_commitment = $2 \
        WHERE statechain_id = $3";

    let _ = sqlx::query(query)
        .bind(r2_commitment)
        .bind(blind_commitment)
        .bind(statechain_id)
        .execute(pool.inner())
        .await
        .unwrap();
}

#[post("/sign/first", format = "json", data = "<sign_first_request_payload>")]
pub async fn sign_first(pool: &State<sqlx::PgPool>, sign_first_request_payload: Json<SignFirstRequestPayload>) -> status::Custom<Json<Value>>  {

    let lockbox_endpoint = "http://0.0.0.0:18080";
    let path = "get_public_nonce";

    let client: reqwest::Client = reqwest::Client::new();
    let request = client.post(&format!("{}/{}", lockbox_endpoint, path));

    let statechain_id = sign_first_request_payload.0.statechain_id.clone();
    let r2_commitment = sign_first_request_payload.0.r2_commitment.clone();
    let blind_commitment = sign_first_request_payload.0.blind_commitment.clone();
    let signed_statechain_id = Signature::from_str(&sign_first_request_payload.0.signed_statechain_id).unwrap();

    let msg = Message::from_hashed_data::<sha256::Hash>(statechain_id.to_string().as_bytes());

    let auth_key = get_auth_key_by_statechain_id(pool, &statechain_id).await.unwrap();

    let secp = Secp256k1::new();
    if !secp.verify_schnorr(&signed_statechain_id, &msg, &auth_key).is_ok() {

        let response_body = json!({
            "error": "Internal Server Error",
            "message": "Signature does not match authentication key."
        });
    
        return status::Custom(Status::InternalServerError, Json(response_body));
    }

    update_commitments(pool, &r2_commitment, &blind_commitment, &statechain_id).await;

    let value = match request.json(&sign_first_request_payload.0).send().await {
        Ok(response) => {
            let text = response.text().await.unwrap();
            text
        },
        Err(err) => {
            let response_body = json!({
                "error": "Internal Server Error",
                "message": err.to_string()
            });
        
            return status::Custom(Status::InternalServerError, Json(response_body));
        },
    };

    println!("value: {}", value);

    #[derive(Serialize, Deserialize, Debug, Clone)]
    pub struct ServerPublicNonceResponsePayload {
        server_pubnonce: String,
    }

    let response: ServerPublicNonceResponsePayload = serde_json::from_str(value.as_str()).expect(&format!("failed to parse: {}", value.as_str()));


    let response_body = json!(response);

/*     let response_body = json!({
        "server_pubnonce": hex::encode(server_pub_nonce.serialize()),
    }); */

    return status::Custom(Status::Ok, Json(response_body));
}

#[derive(Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct PartialSignatureRequestPayload<'r> {
    statechain_id: &'r str,
    keyaggcoef: &'r str,
    negate_seckey: u8,
    session: &'r str,
}

#[post("/sign/second", format = "json", data = "<partial_signature_request_payload>")]
pub async fn sign_second (pool: &State<sqlx::PgPool>, partial_signature_request_payload: Json<PartialSignatureRequestPayload<'_>>) -> status::Custom<Json<Value>>  {
    
    let lockbox_endpoint = "http://0.0.0.0:18080";
    let path = "get_partial_signature";

    let client: reqwest::Client = reqwest::Client::new();
    let request = client.post(&format!("{}/{}", lockbox_endpoint, path));

    let value = match request.json(&partial_signature_request_payload.0).send().await {
        Ok(response) => {
            let text = response.text().await.unwrap();
            text
        },
        Err(err) => {
            println!("ERROR sig: {}", err);

            let response_body = json!({
                "error": "Internal Server Error",
                "message": err.to_string()
            });
        
            return status::Custom(Status::InternalServerError, Json(response_body));
        },
    };

    #[derive(Serialize, Deserialize, Debug, Clone)]
    pub struct PartialSignatureResponsePayload<'r> {
        partial_sig: &'r str,
    }

    let response: PartialSignatureResponsePayload = serde_json::from_str(value.as_str()).expect(&format!("failed to parse: {}", value.as_str()));

    let response_body = json!(response);

    return status::Custom(Status::Ok, Json(response_body));
}
   