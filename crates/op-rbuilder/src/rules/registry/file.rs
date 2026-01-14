use crate::rules::{registry::RuleRegistry, types::RuleSet};
use std::path::PathBuf;

/// Registry that loads rules from a YAML file
pub struct FileRuleRegistry {
    path: PathBuf,
    name: String,
}

impl FileRuleRegistry {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let name = format!("file:{}", path.display());
        Self { path, name }
    }
}

#[async_trait::async_trait]
impl RuleRegistry for FileRuleRegistry {
    async fn get_rules(&self) -> anyhow::Result<RuleSet> {
        let content = tokio::fs::read_to_string(&self.path).await?;
        let ruleset: RuleSet = serde_yaml::from_str(&content)?;
        Ok(ruleset)
    }

    fn name(&self) -> &str {
        &self.name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_registry_name_format() {
        let registry = FileRuleRegistry::new("/path/to/rules.yaml");
        assert_eq!(registry.name(), "file:/path/to/rules.yaml");
    }

    #[test]
    fn test_file_registry_name_with_relative_path() {
        let registry = FileRuleRegistry::new("./config/rules.yaml");
        assert_eq!(registry.name(), "file:./config/rules.yaml");
    }

    #[test]
    fn test_file_registry_from_pathbuf() {
        let path = PathBuf::from("/etc/rules/base.yaml");
        let registry = FileRuleRegistry::new(path);
        assert_eq!(registry.name(), "file:/etc/rules/base.yaml");
    }

    #[tokio::test]
    async fn test_get_rules_nonexistent_file() {
        let registry = FileRuleRegistry::new("/nonexistent/path/rules.yaml");
        let result = registry.get_rules().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_get_rules_valid_file() {
        use std::io::Write;
        let temp_dir = std::env::temp_dir();
        let rules_path = temp_dir.join("test_file_registry_rules.yaml");

        let yaml_content = r#"
version: 1
rules:
  deny:
    - name: "test deny"
      addresses:
        - "0x1234567890123456789012345678901234567890"
  boost:
    - name: "test boost"
      type: from
      target:
        - "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"
      weight: 100
"#;

        {
            let mut file = std::fs::File::create(&rules_path).unwrap();
            file.write_all(yaml_content.as_bytes()).unwrap();
        }

        let registry = FileRuleRegistry::new(&rules_path);
        let ruleset = registry.get_rules().await.unwrap();

        assert_eq!(ruleset.version, 1);
        assert_eq!(ruleset.rules.deny.len(), 1);
        assert_eq!(ruleset.rules.boost.len(), 1);
        assert_eq!(ruleset.rules.boost[0].weight, 100);

        // Cleanup
        std::fs::remove_file(&rules_path).ok();
    }

    #[tokio::test]
    async fn test_get_rules_invalid_yaml() {
        use std::io::Write;
        let temp_dir = std::env::temp_dir();
        let rules_path = temp_dir.join("test_invalid_rules.yaml");

        let invalid_yaml = "version: [not a number]\nrules: {invalid";

        {
            let mut file = std::fs::File::create(&rules_path).unwrap();
            file.write_all(invalid_yaml.as_bytes()).unwrap();
        }

        let registry = FileRuleRegistry::new(&rules_path);
        let result = registry.get_rules().await;
        assert!(result.is_err());

        // Cleanup
        std::fs::remove_file(&rules_path).ok();
    }

    #[tokio::test]
    async fn test_get_rules_empty_file() {
        use std::io::Write;
        let temp_dir = std::env::temp_dir();
        let rules_path = temp_dir.join("test_empty_rules.yaml");

        {
            let mut file = std::fs::File::create(&rules_path).unwrap();
            file.write_all(b"").unwrap();
        }

        let registry = FileRuleRegistry::new(&rules_path);
        let ruleset = registry.get_rules().await.unwrap();

        // Empty YAML should result in default ruleset
        assert_eq!(ruleset.version, 0);
        assert!(ruleset.rules.deny.is_empty());
        assert!(ruleset.rules.boost.is_empty());

        // Cleanup
        std::fs::remove_file(&rules_path).ok();
    }

    #[tokio::test]
    async fn test_get_rules_with_aliases() {
        use std::io::Write;
        let temp_dir = std::env::temp_dir();
        let rules_path = temp_dir.join("test_rules_with_aliases.yaml");

        let yaml_content = r#"
version: 2
aliases:
  vip_users:
    - "0x1111111111111111111111111111111111111111"
    - "0x2222222222222222222222222222222222222222"
rules:
  boost:
    - name: "vip boost"
      type: from
      aliases:
        - vip_users
      weight: 500
"#;

        {
            let mut file = std::fs::File::create(&rules_path).unwrap();
            file.write_all(yaml_content.as_bytes()).unwrap();
        }

        let registry = FileRuleRegistry::new(&rules_path);
        let ruleset = registry.get_rules().await.unwrap();

        assert_eq!(ruleset.version, 2);
        assert!(ruleset.aliases.groups.contains_key("vip_users"));
        assert_eq!(ruleset.aliases.groups.get("vip_users").unwrap().len(), 2);
        assert_eq!(ruleset.rules.boost.len(), 1);
        assert_eq!(ruleset.rules.boost[0].aliases, vec!["vip_users"]);

        // Cleanup
        std::fs::remove_file(&rules_path).ok();
    }
}
