use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub(crate) struct Config {
    pub(crate) bind_address: String,
    pub(crate) port: u16,
}