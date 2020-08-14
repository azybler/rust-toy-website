use random_b64_str;

#[allow(dead_code)]
pub fn get_random_base64_str() -> String {
    random_b64_str::get_u128()
}
