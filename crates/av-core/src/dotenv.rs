//! Deliberately limited .env parsing: no expansion, execution, or multiline values.
use std::collections::BTreeMap;

use anyhow::{Context, Result, ensure};
use zeroize::Zeroizing;

pub fn parse(source: &str) -> Result<BTreeMap<String, Zeroizing<String>>> {
    let mut values = BTreeMap::new();
    for (index, line) in source.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let (name, raw) = line
            .split_once('=')
            .with_context(|| format!("invalid .env assignment at line {}", index + 1))?;
        let name = name.trim();
        ensure!(
            super::config::valid_env_key(name),
            "invalid .env variable name at line {}",
            index + 1
        );
        ensure!(!values.contains_key(name), "duplicate .env variable {name}");
        let raw = raw.trim();
        let value = if let Some(quote @ ('\'' | '"')) = raw.chars().next() {
            ensure!(
                raw.len() >= 2 && raw.ends_with(quote),
                "unclosed .env quote at line {}",
                index + 1
            );
            let inner = &raw[1..raw.len() - 1];
            ensure!(
                !inner.contains(quote),
                "embedded .env quotes are unsupported at line {}",
                index + 1
            );
            inner
        } else {
            raw.split_once(" #")
                .map(|(v, _)| v.trim_end())
                .unwrap_or(raw)
        };
        ensure!(
            !value.contains(['$', '`', '\\', '\0']),
            ".env expansion and escapes are unsupported at line {}",
            index + 1
        );
        values.insert(name.to_owned(), Zeroizing::new(value.to_owned()));
    }
    ensure!(!values.is_empty(), ".env file has no assignments");
    Ok(values)
}

pub fn reference_config(project: &str, names: impl Iterator<Item = String>) -> Result<String> {
    reference_config_with_public(project, names, std::iter::empty())
}

pub fn reference_config_with_public(
    project: &str,
    secret_names: impl Iterator<Item = String>,
    public_values: impl Iterator<Item = (String, String)>,
) -> Result<String> {
    let mut source = format!("schema = 2\n\n[project]\nid = {project:?}\n");
    for name in secret_names {
        ensure!(super::config::valid_env_key(&name), "invalid variable name");
        source.push_str(&format!("\n[values.{name}]\ntype = \"string\"\nsecret = \"secret://{project}/{name}\"\nrequired = true\n"));
    }
    for (name, value) in public_values {
        ensure!(super::config::valid_env_key(&name), "invalid variable name");
        source.push_str(&format!(
            "\n[values.{name}]\ntype = \"string\"\nvalue = {}\nrequired = true\n",
            toml::Value::String(value)
        ));
    }
    super::Config::parse(&source)?;
    Ok(source)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imports_without_expansion_or_disclosing_values() {
        let values = parse(
            "# Header\nexport TOKEN='secret value'\nURL=https://example.test/#path\nEMPTY=\n",
        )
        .unwrap();
        assert_eq!(values["TOKEN"].as_str(), "secret value");
        assert_eq!(values["URL"].as_str(), "https://example.test/#path");
        let config = reference_config("demo", values.keys().cloned()).unwrap();
        assert!(config.contains("secret://demo/TOKEN"));
        assert!(!config.contains("secret value"));
        assert!(parse("A=$TOKEN").is_err());
        assert!(parse("A=x\nA=y").is_err());
        assert!(parse("A=\"unclosed").is_err());
        assert!(parse("A=`id`").is_err());
    }

    #[test]
    fn public_import_requires_explicit_selection_and_escapes_literal_values() {
        let source = reference_config_with_public(
            "demo",
            ["TOKEN".to_owned()].into_iter(),
            [("MODE".to_owned(), "development #1".to_owned())].into_iter(),
        )
        .unwrap();
        assert!(source.contains("secret://demo/TOKEN"));
        assert!(source.contains("development #1"));
        let config = super::super::Config::parse(&source).unwrap();
        let resolved =
            super::super::resolve(&config, None, |_| Ok(Some("synthetic".into()))).unwrap();
        assert_eq!(resolved.values["MODE"], "development #1");
        assert_eq!(resolved.values["TOKEN"], "synthetic");

        assert!(
            reference_config_with_public(
                "demo",
                ["TOKEN".to_owned()].into_iter(),
                [("TOKEN".to_owned(), "visible".to_owned())].into_iter(),
            )
            .is_err()
        );
    }
}
