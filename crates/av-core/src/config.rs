use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;
use zeroize::Zeroize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub schema: u32,
    pub project: Project,
    #[serde(default)]
    pub values: BTreeMap<String, ValueDecl>,
    #[serde(default)]
    pub environments: BTreeMap<String, Environment>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Project {
    pub id: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Environment {
    #[serde(default)]
    pub values: BTreeMap<String, ValueDecl>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValueDecl {
    #[serde(rename = "type")]
    pub kind: ValueType,
    pub value: Option<toml::Value>,
    pub secret: Option<String>,
    pub connection: Option<ConnectionRef>,
    pub delivery: Option<ConnectionDelivery>,
    #[serde(default)]
    pub required: bool,
}

/// Public connection identity only. This declaration requests delivery; it
/// neither contains a credential nor authorizes its release.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionRef {
    pub id: String,
    pub version: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConnectionDelivery {
    Proxy,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ValueType {
    String,
    Integer,
    Boolean,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretRef {
    pub project: String,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct Resolved {
    pub values: BTreeMap<String, String>,
    pub secret_names: BTreeSet<String>,
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let source = fs::read_to_string(path.as_ref())
            .with_context(|| format!("cannot read {}", path.as_ref().display()))?;
        Self::parse(&source)
    }

    pub fn parse(source: &str) -> Result<Self> {
        let config: Config = toml::from_str(source).context("invalid av.toml")?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == 2,
            "unsupported av.toml schema {}",
            self.schema
        );
        ensure!(valid_slug(&self.project.id), "invalid project id");
        ensure!(
            self.project.id != "av-connections",
            "project id av-connections is reserved for connection records"
        );
        for (name, decl) in &self.values {
            validate_decl(name, decl, &self.project.id)?;
        }
        for (environment, content) in &self.environments {
            ensure!(valid_slug(environment), "invalid environment name");
            for (name, decl) in &content.values {
                ensure!(
                    self.values.contains_key(name),
                    "environment override has unknown value {name}"
                );
                validate_decl(name, decl, &self.project.id)?;
            }
        }
        Ok(())
    }

    pub fn selected<'a>(
        &'a self,
        environment: Option<&str>,
    ) -> Result<BTreeMap<&'a str, &'a ValueDecl>> {
        let mut selected = self
            .values
            .iter()
            .map(|(k, v)| (k.as_str(), v))
            .collect::<BTreeMap<_, _>>();
        if let Some(name) = environment {
            let overrides = self
                .environments
                .get(name)
                .with_context(|| format!("unknown environment {name}"))?;
            for (key, value) in &overrides.values {
                selected.insert(key, value);
            }
        }
        Ok(selected)
    }

    /// Returns selected public references for a caller to inspect or submit to
    /// a broker. Existence, current version, and authorization require that
    /// broker's independent checks.
    pub fn connection_refs(
        &self,
        environment: Option<&str>,
    ) -> Result<BTreeMap<&str, &ConnectionRef>> {
        self.validate()?;
        Ok(self
            .selected(environment)?
            .into_iter()
            .filter_map(|(name, declaration)| {
                declaration
                    .connection
                    .as_ref()
                    .map(|reference| (name, reference))
            })
            .collect())
    }
}

impl ConnectionRef {
    fn validate(&self) -> Result<()> {
        validate_connection_id(&self.id)?;
        ensure!(self.version > 0, "connection version must be positive");
        Ok(())
    }
}

pub fn validate_connection_id(id: &str) -> Result<(&str, &str)> {
    let (provider, name) = id
        .split_once('/')
        .context("connection ID must be provider/name")?;
    ensure!(
        !provider.is_empty()
            && provider.len() <= 32
            && provider
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            && !provider.starts_with('-')
            && !provider.ends_with('-')
            && !name.is_empty()
            && name.len() <= 64
            && name.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
            }),
        "invalid connection ID"
    );
    Ok((provider, name))
}

impl SecretRef {
    pub fn parse(raw: &str, expected_project: &str) -> Result<Self> {
        let path = raw
            .strip_prefix("secret://")
            .context("secret reference must begin with secret://")?;
        let (project, name) = path
            .split_once('/')
            .context("secret reference must include project and name")?;
        ensure!(
            project == expected_project,
            "secret reference is outside this project"
        );
        ensure!(
            valid_slug(project) && valid_slug(name),
            "invalid secret reference"
        );
        Ok(Self {
            project: project.to_owned(),
            name: name.to_owned(),
        })
    }

    pub fn storage_key(&self) -> String {
        format!("{}/{}", self.project, self.name)
    }
}

/// Validates declarations and generic secret values. Connection references are
/// checked structurally without fetching credentials or checking broker grants.
pub fn check(
    config: &Config,
    environment: Option<&str>,
    mut get_secret: impl FnMut(&SecretRef) -> Result<Option<String>>,
) -> Result<BTreeSet<String>> {
    config.validate()?;
    let mut names = BTreeSet::new();
    for (name, decl) in config.selected(environment)? {
        if let Some(reference) = &decl.secret {
            let parsed = SecretRef::parse(reference, &config.project.id)?;
            let mut value =
                get_secret(&parsed)?.with_context(|| format!("missing secret for {name}"))?;
            let result = validate_runtime_type(name, &value, decl.kind);
            value.zeroize();
            result?;
            names.insert(parsed.storage_key());
        } else if decl.value.is_none() && decl.connection.is_none() && decl.required {
            bail!("required value {name} has no source");
        }
    }
    Ok(names)
}

pub fn resolve(
    config: &Config,
    environment: Option<&str>,
    mut get_secret: impl FnMut(&SecretRef) -> Result<Option<String>>,
) -> Result<Resolved> {
    config.validate()?;
    let selected = config.selected(environment)?;
    // Reject the whole direct resolution before reading any generic secrets.
    for (name, declaration) in &selected {
        ensure!(
            declaration.connection.is_none(),
            "connection value {name} requires protected proxy execution; direct resolution is not permitted"
        );
    }
    let mut values = BTreeMap::new();
    let mut secret_names = BTreeSet::new();
    for (name, decl) in selected {
        let value = if let Some(reference) = &decl.secret {
            let parsed = SecretRef::parse(reference, &config.project.id)?;
            let value =
                get_secret(&parsed)?.with_context(|| format!("missing secret for {name}"))?;
            secret_names.insert(parsed.storage_key());
            Some(value)
        } else {
            decl.value.as_ref().map(literal_string).transpose()?
        };
        if let Some(value) = value {
            validate_runtime_type(name, &value, decl.kind)?;
            values.insert(name.to_owned(), value);
        } else if decl.required {
            bail!("required value {name} has no source");
        }
    }
    Ok(Resolved {
        values,
        secret_names,
    })
}

fn validate_decl(name: &str, decl: &ValueDecl, project: &str) -> Result<()> {
    ensure!(
        valid_env_key(name),
        "invalid environment variable name {name}"
    );
    ensure!(
        [
            decl.value.is_some(),
            decl.secret.is_some(),
            decl.connection.is_some()
        ]
        .into_iter()
        .filter(|present| *present)
        .count()
            <= 1,
        "value {name} has multiple sources"
    );
    if let Some(reference) = &decl.connection {
        ensure!(
            matches!(decl.kind, ValueType::String),
            "connection sources require a string value"
        );
        ensure!(
            decl.delivery == Some(ConnectionDelivery::Proxy),
            "connection sources require delivery = \"proxy\""
        );
        reference.validate()?;
    } else {
        ensure!(
            decl.delivery.is_none(),
            "delivery requires a connection source"
        );
    }
    if let Some(reference) = &decl.secret {
        SecretRef::parse(reference, project)?;
    }
    if let Some(value) = &decl.value {
        let plain = literal_string(value)?;
        validate_runtime_type(name, &plain, decl.kind)?;
    }
    Ok(())
}

fn literal_string(value: &toml::Value) -> Result<String> {
    match value {
        toml::Value::String(s) => {
            ensure!(!s.contains("${"), "interpolation is not supported");
            Ok(s.clone())
        }
        toml::Value::Integer(i) => Ok(i.to_string()),
        toml::Value::Boolean(b) => Ok(b.to_string()),
        _ => bail!("only scalar string, integer, and boolean literals are supported"),
    }
}

fn validate_runtime_type(name: &str, value: &str, kind: ValueType) -> Result<()> {
    ensure!(!value.contains('\0'), "value {name} contains NUL");
    match kind {
        ValueType::String => {}
        ValueType::Integer => {
            value
                .parse::<i64>()
                .with_context(|| format!("value {name} is not an integer"))?;
        }
        ValueType::Boolean => {
            ensure!(
                value == "true" || value == "false",
                "value {name} is not a boolean"
            );
        }
    }
    Ok(())
}

fn valid_slug(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

pub(crate) fn valid_env_key(s: &str) -> bool {
    let mut bytes = s.bytes();
    matches!(bytes.next(), Some(b'A'..=b'Z' | b'_'))
        && s.len() <= 128
        && bytes.all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = r#"
schema = 2
[project]
id = "demo"
[values.MODE]
type = "string"
value = "dev"
[values.COUNT]
type = "integer"
value = 3
[values.API_TOKEN]
type = "string"
secret = "secret://demo/token"
[environments.prod.values.MODE]
type = "string"
value = "prod"
"#;

    const CONNECTION_FIXTURE: &str = r#"
schema = 2
[project]
id = "demo"
[values.APP_ENV]
type = "string"
value = "development"
[values.SERVICE_TOKEN]
type = "string"
connection = { id = "service/work", version = 1 }
delivery = "proxy"
required = true
[environments.prod.values.SERVICE_TOKEN]
type = "string"
connection = { id = "service/work", version = 2 }
delivery = "proxy"
required = true
"#;

    #[test]
    fn validates_and_resolves_environment() {
        let config = Config::parse(FIXTURE).unwrap();
        let resolved = resolve(&config, Some("prod"), |reference| {
            assert_eq!(reference.storage_key(), "demo/token");
            Ok(Some("private".into()))
        })
        .unwrap();
        assert_eq!(resolved.values["MODE"], "prod");
        assert_eq!(resolved.values["COUNT"], "3");
        assert_eq!(resolved.values["API_TOKEN"], "private");
    }

    #[test]
    fn rejects_ambiguous_and_untrusted_declarations() {
        let bad = FIXTURE.replace(
            "secret = \"secret://demo/token\"",
            "secret = \"secret://demo/token\"\nvalue = \"leak\"",
        );
        assert!(Config::parse(&bad).is_err());
        let bad = FIXTURE.replace("secret://demo/token", "secret://other/token");
        assert!(Config::parse(&bad).is_err());
        let bad = FIXTURE.replace("schema = 2", "schema = 999");
        assert!(Config::parse(&bad).is_err());
        let bad = format!("{FIXTURE}\n[values.BAD]\ntype = \"string\"\nresolver = \"cat /x\"\n");
        assert!(Config::parse(&bad).is_err());
    }

    #[test]
    fn missing_secret_fails_before_resolution() {
        let config = Config::parse(FIXTURE).unwrap();
        assert!(
            check(&config, None, |_| Ok(None))
                .unwrap_err()
                .to_string()
                .contains("missing secret")
        );
    }

    #[test]
    fn connection_check_exposes_only_selected_public_references() {
        let config = Config::parse(CONNECTION_FIXTURE).unwrap();
        let names = check(&config, Some("prod"), |_| {
            panic!("checking a connection must not fetch a generic secret")
        })
        .unwrap();
        assert!(names.is_empty());
        let references = config.connection_refs(Some("prod")).unwrap();
        assert_eq!(references.len(), 1);
        assert_eq!(
            references["SERVICE_TOKEN"],
            &ConnectionRef {
                id: "service/work".into(),
                version: 2
            }
        );
        assert_eq!(
            config.connection_refs(None).unwrap()["SERVICE_TOKEN"].version,
            1
        );
        assert!(config.connection_refs(Some("missing")).is_err());
    }

    #[test]
    fn nonstandard_connection_reference_is_public_metadata_only() {
        let source = "schema = 2\n[project]\nid = 'demo'\n[values.SERVICE_TOKEN]\ntype = 'string'\nconnection = { id = 'service/work', version = 1 }\ndelivery = 'proxy'\nrequired = true\n";
        let config = Config::parse(source).unwrap();
        assert_eq!(
            config.connection_refs(None).unwrap()["SERVICE_TOKEN"],
            &ConnectionRef {
                id: "service/work".into(),
                version: 1,
            }
        );
        assert!(
            check(&config, None, |_| panic!("must not read a credential"))
                .unwrap()
                .is_empty()
        );
        assert!(resolve(&config, None, |_| panic!("must not read a credential")).is_err());
    }

    #[test]
    fn rejects_connection_source_collisions_and_unsupported_delivery() {
        for insertion in [
            "value = 'literal'\n",
            "secret = 'secret://demo/token'\n",
            "value = 'literal'\nsecret = 'secret://demo/token'\n",
        ] {
            let source = CONNECTION_FIXTURE
                .replace("required = true", &format!("required = true\n{insertion}"));
            assert!(
                Config::parse(&source)
                    .unwrap_err()
                    .to_string()
                    .contains("multiple sources")
            );
        }
        for replacement in ["", "delivery = 'direct'", "delivery = 'proxy-preview'"] {
            let source = CONNECTION_FIXTURE.replace("delivery = \"proxy\"", replacement);
            assert!(
                Config::parse(&source).is_err(),
                "accepted delivery: {replacement}"
            );
        }
        for source in ["value = 'literal'", "secret = 'secret://demo/token'", ""] {
            let source = format!(
                "schema = 2\n[project]\nid = 'demo'\n[values.SERVICE_TOKEN]\ntype = 'string'\n{source}\ndelivery = 'proxy'\n"
            );
            assert!(
                Config::parse(&source)
                    .unwrap_err()
                    .to_string()
                    .contains("delivery requires a connection")
            );
        }
    }

    #[test]
    fn rejects_invalid_connection_identity_version_and_fields() {
        for id in [
            "service",
            "/work",
            "Service/work",
            "-service/work",
            "service-/work",
            "service/",
            "service/Work",
            "service/work/extra",
            "service/../work",
            "service/work name",
            "service/work?host=other",
            "service/w\u{00f6}rk",
        ]
        .into_iter()
        .map(str::to_owned)
        .chain([format!("service/{}", "a".repeat(65))])
        {
            let source = CONNECTION_FIXTURE.replace("service/work", &id);
            assert!(
                Config::parse(&source).is_err(),
                "accepted connection ID: {id}"
            );
        }
        let longest =
            CONNECTION_FIXTURE.replace("service/work", &format!("service/{}", "a".repeat(64)));
        assert!(Config::parse(&longest).is_ok());
        for source in [
            CONNECTION_FIXTURE.replace("version = 1", "version = 0"),
            CONNECTION_FIXTURE.replace("version = 1", "version = -1"),
            CONNECTION_FIXTURE.replace("version = 1", "version = '1'"),
            CONNECTION_FIXTURE.replace(", version = 1", ""),
            CONNECTION_FIXTURE.replace("id = \"service/work\", ", ""),
            CONNECTION_FIXTURE.replace("version = 1", "version = 1, host = 'other.example'"),
        ] {
            assert!(
                Config::parse(&source).is_err(),
                "accepted invalid connection source: {source}"
            );
        }
    }

    #[test]
    fn connection_source_accepts_any_valid_string_environment_name() {
        let other_name = CONNECTION_FIXTURE.replace("SERVICE_TOKEN", "OTHER_TOKEN");
        assert!(Config::parse(&other_name).is_ok());
        for kind in ["integer", "boolean"] {
            let source = CONNECTION_FIXTURE.replace(
                "SERVICE_TOKEN]\ntype = \"string\"",
                &format!("SERVICE_TOKEN]\ntype = \"{kind}\""),
            );
            assert!(
                Config::parse(&source).is_err(),
                "accepted connection type: {kind}"
            );
        }
    }

    #[test]
    fn direct_resolution_refuses_connections_before_fetching_any_secret() {
        let source = format!(
            "{CONNECTION_FIXTURE}\n[values.A_SECRET]\ntype = 'string'\nsecret = 'secret://demo/token'\n"
        );
        for required in [true, false] {
            let config = Config::parse(
                &source.replace("required = true", &format!("required = {required}")),
            )
            .unwrap();
            for environment in [None, Some("prod")] {
                let error = resolve(&config, environment, |_| {
                    panic!("direct connection refusal must happen before any secret fetch")
                })
                .unwrap_err();
                assert!(
                    error
                        .to_string()
                        .contains("direct resolution is not permitted")
                );
            }
        }
    }

    #[test]
    fn public_and_generic_secret_resolution() {
        let config = Config::parse(FIXTURE).unwrap();
        assert!(config.connection_refs(None).unwrap().is_empty());
        assert_eq!(
            check(&config, Some("prod"), |_| Ok(Some("private".into()))).unwrap(),
            BTreeSet::from(["demo/token".into()])
        );
        let resolved = resolve(&config, Some("prod"), |_| Ok(Some("private".into()))).unwrap();
        assert_eq!(resolved.values["MODE"], "prod");
        assert_eq!(resolved.values["API_TOKEN"], "private");
    }
}
