use tokio::process::Command;

use super::types::AstGrepMatch;
use log::{debug, error, warn};
pub struct AstGrepClient {
    pub config_path: String,
}

impl AstGrepClient {
    pub async fn get_file_symbols(
        &self,
        file_name: &str,
    ) -> Result<Vec<AstGrepMatch>, Box<dyn std::error::Error>> {
        let command_result = Command::new("sg")
            .arg("scan")
            .arg("--config")
            .arg(&self.config_path)
            .arg("--json")
            .arg(file_name)
            .output()
            .await?;

        if !command_result.status.success() {
            let error = String::from_utf8_lossy(&command_result.stderr);
            return Err(format!("sg command failed: {}", error).into());
        }

        let output = String::from_utf8(command_result.stdout)?;

        let mut symbols: Vec<AstGrepMatch> = serde_json::from_str(&output)
            .map_err(|e| format!("Failed to parse JSON: {}\nJSON: {}", e, output))?;
        symbols.sort_by_key(|s| s.range.start.line);
        Ok(symbols)
    }

    pub async fn global_search(
        &self,
        target: &str,
        file_path: &str,
    ) -> Result<Vec<AstGrepMatch>, Box<dyn std::error::Error>> {
        let rule = Self::create_dynamic_rule(target);
        let command_result = Command::new("sh")
            .arg("-c")
            .arg(format!(
                "sg scan --inline-rules '{}' --json {}",
                rule,
                file_path
            ))
            .output()
            .await?;

        if !command_result.status.success() {
            let error = String::from_utf8_lossy(&command_result.stderr);
            return Err(format!("sg command failed: {}", error).into());
        }

        let output = String::from_utf8(command_result.stdout)?;

        let mut symbols: Vec<AstGrepMatch> = serde_json::from_str(&output)
            .map_err(|e| format!("Failed to parse JSON: {}\nJSON: {}", e, output))?;
        symbols.sort_by_key(|s| s.range.start.line);
        Ok(symbols)
    }

    pub fn create_dynamic_rule(target: &str) -> String{
        return format!("
id: variable
language: java
rule:
  kind: identifier
  pattern: $NAME
  inside:
    kind: variable_declarator
    pattern: $CONTEXT
    regex: {}

---

id: method
language: java
rule:
  kind: identifier
  pattern: $NAME
  inside:
    kind: method_declaration
    pattern: $CONTEXT
    regex: {}
---

id: enum
language: java
rule:
  kind: identifier
  pattern: $NAME
  inside:
    kind: enum_constant
    pattern: $CONTEXT
    regex: {}
        ",target,target,target);

    }
}
