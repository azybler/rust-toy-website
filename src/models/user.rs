use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::params;
use serde::{Deserialize, Serialize};

#[path = "../common/string.rs"]
mod string;

pub struct User {
    pub username: String,
    pub encoded_password: String,
    pub left_salt: String,
    pub right_salt: String,
}

pub struct UserWithID {
    pub id: String,
    pub username: String,
    pub encoded_password: String,
    pub left_salt: String,
    pub right_salt: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct UserInternal {
    pub id: String,
    pub username: String,
    pub encoded_password: String,
    pub left_salt: String,
    pub right_salt: String,
    pub scrypt_n: u64,
    pub scrypt_r: u32,
    pub scrypt_p: u32,
}

#[allow(dead_code)]
pub fn insert_session(
    user_id: String,
    pool: &Pool<SqliteConnectionManager>,
) -> Option<String> {
    let conn = pool.clone().get().unwrap();
    let session_token = string::get_random_base64_str();
    let res = conn.execute(
        "INSERT INTO user_session (user_id, session_token, created_time) values (?1, ?2, strftime('%s','now'))
        ON CONFLICT(user_id) DO UPDATE SET created_time=strftime('%s','now'), session_token=?3;",
        params![user_id, session_token.clone(), session_token.clone()],
    );
    return match res {
        Ok(_v) => Some(session_token.clone()),
        Err(e) => {
            //TODO: log the errors properly.
            println!("e={}", e);
            None
        }
    };
}

#[allow(dead_code)]
pub fn put(user: User, pool: &Pool<SqliteConnectionManager>) {
    let conn = pool.clone().get().unwrap();
    let mut i = 0;
    while i < 5 {
        let uniq_id = string::get_random_base64_str();
        let res = conn.execute(
            "INSERT INTO user (id, username, encoded_password, left_salt, right_salt, scrypt_n, scrypt_r, scrypt_p) values (?1, ?2, ?3, ?4, ?5, 2, 8, 1);",
            params![uniq_id, user.username, user.encoded_password, user.left_salt, user.right_salt],
        );
        match res {
            Ok(v) => {
                println!("v={}", v);
                break;
            }
            Err(e) => {
                if format!("{}", e) == "UNIQUE constraint failed: user.id" {
                    // retry
                    i += 1;
                    continue;
                } else {
                    println!("e={}", e);
                    break;
                }
            }
        }
    }
}

#[allow(dead_code)]
pub fn get(username: &str, pool: &Pool<SqliteConnectionManager>) -> Option<UserWithID> {
    let conn = pool.clone().get().unwrap();
    let res = conn.query_row(
        "SELECT id, username, encoded_password, left_salt, right_salt FROM user WHERE username=? LIMIT 1;",
        params![username],
        |r| {
            Ok(UserWithID {
                id: r.get::<_, String>(0)?,
                username: r.get::<_, String>(1)?,
                encoded_password: r.get::<_, String>(2)?,
                left_salt: r.get::<_, String>(3)?,
                right_salt: r.get::<_, String>(4)?,
            })
        },
    );
    return match res {
        Ok(v) => Some(v),
        Err(e) => {
            println!("e={}", e);
            None
        }
    };
}

#[allow(dead_code)]
pub fn exist(username: &str, pool: &Pool<SqliteConnectionManager>) -> bool {
    let conn = pool.clone().get().unwrap();
    let res = conn.query_row(
        "SELECT count(id) FROM user WHERE username=? LIMIT 1;",
        params![username],
        |r| r.get::<_, u8>(0),
    );
    return match res {
        Ok(v) => {
            println!("v={}", v);
            v == 1
        }
        Err(e) => {
            println!("e={}", e);
            false
        }
    };
}
