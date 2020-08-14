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

#[path = "../config.rs"]
mod config;

const PARAM__VERSION: usize = 0;

#[post("/api/signup")]
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

    // ensure username is not taken.
    let exist = models::user::exist(username, pool);
    if exist {
        return "v1�3".to_string();
    }

    let user = {
        let left_salt = password_helper::generate_salt();
        let right_salt = password_helper::generate_salt();
        let encoded_input_password = {
            let password_to_encode = format!("{}{}{}", left_salt, password, right_salt);
            password_helper::encode_password(
                password_to_encode,
                config::SCRYPT_ITERATION,
                config::SCRYPT_BLOCK_SIZE,
                config::SCRYPT_PARALLELIZATION_FACTOR,
            )
        };
        models::user::User {
            username: username.to_string(),
            encoded_password: encoded_input_password,
            left_salt: left_salt,
            right_salt: right_salt,
            scrypt_n: config::SCRYPT_ITERATION,
            scrypt_r: config::SCRYPT_BLOCK_SIZE,
            scrypt_p: config::SCRYPT_PARALLELIZATION_FACTOR,
        }
    };
    models::user::put(user, pool);

    "v1�0".to_string()
}
