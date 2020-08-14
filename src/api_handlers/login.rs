use actix_web::web::Form;
use actix_web::{web, HttpRequest};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use regex::Regex;

#[path = "../common/structs.rs"]
mod structs;

#[path = "../common/password.rs"]
mod password_helper;

#[path = "../models/mod.rs"]
mod models;

const PARAM__VERSION: usize = 0;

#[post("/api/login")]
pub async fn handler(
    _req: HttpRequest,
    params: Form<structs::GenericParams>,
    pool: web::Data<Pool<SqliteConnectionManager>>,
) -> String {
    let values: Vec<&str> = params.p.split("�").collect();
    return match values[PARAM__VERSION] {
        "v1" => v1(values, pool.get_ref()),
        _ => "".to_string(),
    };
}

const PARAM_V1__USERNAME: usize = 1;
const PARAM_V1__PASSWORD: usize = 2;

fn v1(values: Vec<&str>, pool: &Pool<SqliteConnectionManager>) -> String {
    // TODO: add rate limiting.

    let username = values[PARAM_V1__USERNAME];
    let password = values[PARAM_V1__PASSWORD];

    // validate username.
    let re = Regex::new(r"^[a-zA-Z0-9@._-]+$").unwrap();
    if !re.is_match(username) {
        return "v1�1".to_string();
    }

    // validate password.
    let re = Regex::new(r"^.{8,}$").unwrap();
    if !re.is_match(password) {
        return "v1�2".to_string();
    }

    let user_result: Option<models::user::UserWithID> = models::user::get(username, pool);
    match user_result {
        // DB has such record with the username.
        Some(user) => {
            let password_verified = verify_password(
                user.left_salt.to_string(),
                password.to_string(),
                user.right_salt.to_string(),
                user.encoded_password.to_string(),
                user.scrypt_n,
                user.scrypt_r,
                user.scrypt_p,
            );
            if password_verified {
                let session_token_result: Option<String> =
                    models::user::insert_session(user.id.clone(), pool);
                return match session_token_result {
                    Some(session_token) => format!("v1�0�{}�{}", user.id.clone(), session_token),
                    None => "v1�3".to_string(),
                };
            } else {
                "v1�3".to_string()
            }
        }
        // DB has no such user.
        None => "v1�3".to_string(),
    }
}

fn verify_password(
    left_salt: String,
    password: String,
    right_salt: String,
    encoded_password: String,
    scrypt_n: u64,
    scrypt_r: u32,
    scrypt_p: u32,
) -> bool {
    let password_to_encode = format!("{}{}{}", left_salt, password, right_salt);
    let encoded_input_password =
        password_helper::encode_password(password_to_encode, scrypt_n, scrypt_r, scrypt_p);
    encoded_input_password == encoded_password
}
