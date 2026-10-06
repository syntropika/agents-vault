//! User-local proxy routing preferences for brokered host commands.
//!
//! This file contains only a fixed endpoint. Task capabilities and temporary
//! trust roots are obtained from the broker for each approved execution.

use std::fs;
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use directories::ProjectDirs;
use serde_json::{Value, json};

const ENDPOINT: &str = "http://127.0.0.1:14322";
const MAX_SETTINGS_BYTES: u64 = 512;

pub struct ProxySettings {
    endpoint: String,
}

impl ProxySettings {
    pub fn load_or_initialize() -> Result<Self> {
        let dirs = ProjectDirs::from("", "AgentsVault", "av")
            .context("user configuration directory unavailable")?;
        Self::load_or_initialize_at(&dirs.config_dir().join("proxy.json"))
    }

    fn load_or_initialize_at(path: &Path) -> Result<Self> {
        let parent = path
            .parent()
            .context("proxy settings have no parent directory")?;
        fs::create_dir_all(parent).context("cannot create user proxy configuration directory")?;
        let directory = fs::symlink_metadata(parent)?;
        ensure!(
            directory.is_dir(),
            "proxy configuration directory is not a directory"
        );

        match fs::symlink_metadata(path) {
            Ok(_) => (),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let mut temporary = tempfile::NamedTempFile::new_in(parent)
                    .context("cannot stage user proxy settings")?;
                serde_json::to_writer_pretty(&mut temporary, &expected_settings())?;
                temporary.write_all(b"\n")?;
                temporary.as_file().sync_all()?;
                match temporary.persist_noclobber(path) {
                    Ok(file) => file.sync_all()?,
                    Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => (),
                    Err(error) => {
                        return Err(error.error).context("cannot save user proxy settings");
                    }
                }
            }
            Err(error) => return Err(error).context("cannot inspect user proxy settings"),
        }

        let metadata = fs::symlink_metadata(path).context("cannot inspect user proxy settings")?;
        ensure!(
            metadata.is_file() && metadata.len() <= MAX_SETTINGS_BYTES,
            "proxy settings must be a small regular file"
        );
        let source = fs::read(path).context("cannot read user proxy settings")?;
        let settings: Value =
            serde_json::from_slice(&source).context("invalid user proxy settings")?;
        ensure!(
            settings == expected_settings(),
            "proxy settings differ from the broker's fixed local endpoint"
        );
        Ok(Self {
            endpoint: settings["proxy_url"]
                .as_str()
                .expect("validated proxy settings")
                .to_owned(),
        })
    }

    pub fn authorized_url(&self, broker_url: &str) -> Result<String> {
        let endpoint = self
            .endpoint
            .strip_prefix("http://")
            .expect("validated local endpoint");
        let (capability, address) = broker_url
            .strip_prefix("http://av:")
            .and_then(|url| url.split_once('@'))
            .context("broker returned an invalid proxy URL")?;
        ensure!(
            capability.len() == 64 && capability.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "broker returned an invalid proxy capability"
        );
        ensure!(
            address == endpoint,
            "broker proxy address differs from the saved local endpoint"
        );
        Ok(format!("http://av:{capability}@{endpoint}"))
    }
}

fn expected_settings() -> Value {
    json!({"version": 1, "proxy_url": ENDPOINT})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_reuses_and_rejects_redirected_proxy_settings() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("av").join("proxy.json");
        let initial = ProxySettings::load_or_initialize_at(&path).unwrap();
        let original = fs::read(&path).unwrap();
        let token = "a".repeat(64);
        assert_eq!(
            initial
                .authorized_url(&format!("http://av:{token}@127.0.0.1:14322"))
                .unwrap(),
            format!("http://av:{token}@127.0.0.1:14322")
        );
        assert!(
            initial
                .authorized_url(&format!("http://av:{token}@127.0.0.1:14323"))
                .is_err()
        );
        ProxySettings::load_or_initialize_at(&path).unwrap();
        assert_eq!(fs::read(&path).unwrap(), original);
        assert!(!String::from_utf8(original).unwrap().contains(&token));

        fs::write(
            &path,
            b"{\"version\":1,\"proxy_url\":\"http://127.0.0.1:14323\"}",
        )
        .unwrap();
        assert!(ProxySettings::load_or_initialize_at(&path).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn refuses_a_symlink_as_proxy_settings() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target.json");
        fs::write(&target, serde_json::to_vec(&expected_settings()).unwrap()).unwrap();
        let path = directory.path().join("proxy.json");
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(ProxySettings::load_or_initialize_at(&path).is_err());
    }
}
