use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct GenericParams {
    pub p: String,
}
