use crate::config::Config;
use once_cell::sync::Lazy;
use std::{fs::read_to_string, path::Path, };

pub(crate) const CONFIG: Lazy<Config> = Lazy::new(|| {
    serde_json::from_str::<Config>(
        &read_to_string("config.json").expect("Failed to read config file"),
    )
    .expect("Failed to construct config from config file.")
});
pub(crate) const TOKEN: Lazy<String> = Lazy::new(|| {
    read_to_string(Path::new(".token")).expect("Do you have a '.token' file, containing your Discogs token?")
});

