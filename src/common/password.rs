use hex::{decode, encode};
use rust_scrypt::{scrypt, ScryptParams};

#[path = "./string.rs"]
mod string_helper;

#[path = "../config.rs"]
mod config;

#[allow(dead_code)]
pub fn encode_password(password: String, scrypt_n: u64, scrypt_r: u32, scrypt_p: u32) -> String {
    fn to_bytes<A, T>(slice: &[T]) -> A
    where
        A: AsMut<[T]> + Default,
        T: Clone,
    {
        let mut arr = Default::default();
        <A as AsMut<[T]>>::as_mut(&mut arr).clone_from_slice(slice);
        arr
    }
    let salt: [u8; 32] = to_bytes(&decode(config::SALT).unwrap());
    let params = ScryptParams {
        n: scrypt_n,
        r: scrypt_r,
        p: scrypt_p,
    };
    let mut buf = [0u8; 32];
    scrypt(password.as_bytes(), &salt, &params, &mut buf);
    return String::from(encode(buf.as_ref()));
}

#[allow(dead_code)]
pub fn generate_salt() -> String {
    return string_helper::get_random_base64_str();
}
