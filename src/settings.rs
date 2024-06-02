use std::{path::PathBuf, str::FromStr};

use config::{Config, ConfigError, Environment};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[allow(unused)]
pub struct Settings {
    pub connection_string: String,

    pub liveness_path: PathBuf,
}

impl Settings {
    pub fn new() -> Result<Self, ConfigError> {
        let s = Config::builder()
            .set_default("liveness_path", "/tmp/liveness")?
            .add_source(Environment::with_prefix("certhoover"))
            .build()?;

        s.try_deserialize()
    }
}
