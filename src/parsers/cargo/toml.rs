use anyhow::anyhow;
use cargo_toml::Manifest;
use std::collections::HashMap;

use tracing::{error, trace};

use crate::{
    common::{
        purl::Purl,
        range::{Position, Range},
        MetadataDependencies,
    },
    VulnLspError,
};

pub(crate) fn parse_cargo_toml(document: &str) -> anyhow::Result<MetadataDependencies> {
    let ranges = parse_cargo_doc_for_ranges(document)?;
    let parsed = match Manifest::from_str(document) {
        Ok(manifest) => {
            let mut result = HashMap::new();

            manifest.dependencies.into_iter().for_each(|(name, dep)| {
                let purl = parse_purl(&dep, &name);
                let range = ranges.get(&purl.artifact_id).unwrap().clone();
                result.insert(purl, range);
            });
            Ok(result)
        }
        Err(err) => Err(anyhow!("Failed to parse Cargo.toml: {}", err)),
    };

    parsed
}

fn parse_purl(dep: &cargo_toml::Dependency, name: &String) -> Purl {
    match dep {
        cargo_toml::Dependency::Simple(simple) => Purl {
            package: "cargo".to_string(),
            group_id: None,
            artifact_id: name.to_owned(),
            version: simple.to_owned().replace(&['=', '>', '<', '~', ' '], ""),
            purl_type: None,
        },
        cargo_toml::Dependency::Detailed(detail) => Purl {
            package: "cargo".to_string(),
            group_id: None,
            artifact_id: name.to_owned(),
            version: detail
                .version
                .to_owned()
                .unwrap()
                .replace(&['=', '>', '<', '~', ' '], ""),
            purl_type: None,
        },
        cargo_toml::Dependency::Inherited(_) => Purl {
            package: "cargo".to_string(),
            group_id: None,
            artifact_id: name.to_owned(),
            version: "0".to_string(),
            purl_type: None,
        },
    }
}

fn parse_cargo_doc_for_ranges(document: &str) -> anyhow::Result<HashMap<String, Range>> {
    match toml::from_str::<toml::Value>(document) {
        Ok(value) => {
            let mut ranges: HashMap<String, Range> = HashMap::new();
            trace!("Parsed Cargo.toml");

            let deps = value.get("dependencies").unwrap().as_table().unwrap();
            let lines = document.lines().collect::<Vec<&str>>();

            deps.iter().for_each(|(name, _dep)| {
                let mut dep_start = Position::default();
                let mut dep_end = Position::default();

                let look_for = format!("{} = ", name);

                for (index, line) in lines.iter().enumerate() {
                    if let Some(start) = line.find(look_for.as_str()) {
                        dep_start.row = index;
                        dep_start.col = start;

                        if !line.contains('{') {
                            dep_end.row = index;
                            dep_end.col += line.len();
                            ranges.insert(
                                name.to_owned(),
                                Range {
                                    start: dep_start,
                                    end: dep_end,
                                },
                            );
                            break;
                        }
                    }
                    if dep_start.row != 0 && line.contains('}') {
                        dep_end.row = index;
                        dep_end.col = line.len();

                        ranges.insert(
                            name.to_owned(),
                            Range {
                                start: dep_start,
                                end: dep_end,
                            },
                        );
                        break;
                    }
                }
            });

            Ok(ranges)
        }
        Err(err) => {
            error!("Failed to parse Cargo.toml: {}", err);
            Err(anyhow!(VulnLspError::ManifestParse(
                "Failed to parse Cargo.toml".to_string(),
            )))
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn can_parse_ranges() {
        let source = r#"
            [package]
            name = "vuln-lsp"
            version = "0.1.0"
            edition = "2021"

            [dependencies]

            tokio = { version = "1.34.0", features = [
            "rt-multi-thread",
            "macros",
            "io-std",
            ] }
            tower-lsp = { version = "0.20.0", features = ["proposed"] }
            log = "0.4.20"
            serde = { version = "1.0.193", features = ["derive"] }
            serde-xml-rs = "0.6.0"
            serde_json = "1.0.108"
            anyhow = { version = "1.0.75", features = ["default"] }
            tracing = "0.1.40"
            tracing-subscriber = { version = "0.3.18", features = ["env-filter"] }
            futures = "0.3.29"
            async-trait = "0.1.74"
            reqwest = { version = "0.11.22", features = ["json"] }
            rand = "0.8.5"
            clap = { version = "4.4.11", features = ["derive", "cargo"] }
            thiserror = "1.0.50"
            toml = "0.8.8"
        "#;

        let ranges = parse_cargo_doc_for_ranges(source).unwrap();
        assert_eq!(ranges.len(), 16);
        assert_eq!(ranges.get("tokio").unwrap().start.row, 8);
        assert_eq!(ranges.get("tokio").unwrap().start.col, 12);
        assert_eq!(ranges.get("tokio").unwrap().end.row, 12);
        assert_eq!(ranges.get("tokio").unwrap().end.col, 15);

        assert_eq!(ranges.get("anyhow").unwrap().start.row, 18);
        assert_eq!(ranges.get("anyhow").unwrap().start.col, 12);
        assert_eq!(ranges.get("anyhow").unwrap().end.row, 18);
        assert_eq!(ranges.get("anyhow").unwrap().end.col, 67);

        assert_eq!(ranges.get("rand").unwrap().start.row, 24);
        assert_eq!(ranges.get("rand").unwrap().start.col, 12);
        assert_eq!(ranges.get("rand").unwrap().end.row, 24);
        assert_eq!(ranges.get("rand").unwrap().end.col, 26);
    }
}
