use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, PartialEq)]
struct Project {
    #[serde(rename = "groupId")]
    pub group_id: String,
    #[serde(rename = "artifactId")]
    pub artifact_id: String,
    pub version: String,

    pub name: String,

    pub dependencies: Dependencies,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
struct Dependencies {
    pub dependency: Vec<Dependency>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
struct Dependency {
    #[serde(rename = "groupId")]
    pub group_id: String,
    #[serde(rename = "artifactId")]
    pub artifact_id: String,
    pub version: String,
}

fn to_pom(content: &str) -> anyhow::Result<Project> {
    let project: Project = serde_xml_rs::from_str(content)?;
    Ok(project)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    pub fn parse_pom_file() {
        let content = r#"
            <project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">

                <modelVersion>4.0.0</modelVersion>

                <groupId>com.example</groupId>
                <artifactId>demo</artifactId>
                <version>1.0</version>
                <packaging>jar</packaging>

                <name>Maven Quick Start Archetype</name>
                <url>http://maven.apache.org</url>

                <dependencies>
                    <dependency>
                        <groupId>junit</groupId>
                        <artifactId>junit</artifactId>
                        <version>4.8.2</version>
                        <scope>test</scope>
                    </dependency>
                    <dependency>
                        <groupId>test</groupId>
                        <artifactId>foo</artifactId>
                        <version>1.0.0</version>
                    </dependency>
                </dependencies>

            </project>
            "#;
        let project = to_pom(content).unwrap();

        assert_eq!(project.group_id, "com.example");
        assert_eq!(project.artifact_id, "demo");
        assert_eq!(project.version, "1.0");
        assert_eq!(project.name, "Maven Quick Start Archetype");

        assert_eq!(project.dependencies.dependency.len(), 2);
        assert_eq!(project.dependencies.dependency[0].group_id, "junit");
        assert_eq!(project.dependencies.dependency[0].artifact_id, "junit");
        assert_eq!(project.dependencies.dependency[0].version, "4.8.2");

        assert_eq!(project.dependencies.dependency[1].group_id, "test");
        assert_eq!(project.dependencies.dependency[1].artifact_id, "foo");
        assert_eq!(project.dependencies.dependency[1].version, "1.0.0");
    }
}
