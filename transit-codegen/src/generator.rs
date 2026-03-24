//! Generator trait and output types.

use crate::spec::ProtocolSpec;
use heck::{ToLowerCamelCase, ToPascalCase, ToSnakeCase};
use std::path::Path;

/// A named output file produced by a generator.
pub struct GeneratedFile {
    /// Relative path within the output directory.
    pub path: String,
    /// File contents.
    pub content: String,
}

/// Trait implemented by each language generator.
pub trait Generator {
    /// Human-readable name of the target language (e.g. "Python", "TypeScript").
    fn language(&self) -> &'static str;

    /// Generate all output files from the protocol spec.
    fn generate(&self, spec: &ProtocolSpec) -> Vec<GeneratedFile>;
}

/// Naming conventions derived from the protocol spec.
/// Generators use this instead of hardcoding "keyva".
pub struct Naming {
    /// Raw protocol name (e.g., "keyva" or "keyva-transit")
    pub raw: String,
    /// Snake case (e.g., "keyva" or "keyva_transit")
    pub snake: String,
    /// PascalCase (e.g., "Keyva" or "KeyvaTransit")
    pub pascal: String,
    /// camelCase (e.g., "keyva" or "keyvaTransit")
    pub camel: String,
    /// Hyphenated (e.g., "keyva" or "keyva-transit") — for package names
    pub kebab: String,
    /// npm package name (e.g., "keyva-client" or "keyva-transit-client")
    pub npm_name: String,
    /// Go module path
    pub go_module: String,
    /// Description from protocol spec
    pub description: String,
    /// Default port
    pub default_port: u16,
    /// URI schemes
    pub uri_schemes: Vec<String>,
}

impl Naming {
    pub fn from_spec(spec: &ProtocolSpec) -> Self {
        let raw = spec.protocol.name.clone();
        let snake = raw.to_snake_case();
        let pascal = raw.to_pascal_case();
        let camel = raw.to_lower_camel_case();
        let kebab = raw.clone();
        let npm_name = format!("{kebab}-client");
        let go_module = format!("github.com/keyva-io/{kebab}-go");

        Self {
            raw,
            snake,
            pascal,
            camel,
            kebab,
            npm_name,
            go_module,
            description: spec.protocol.description.clone(),
            default_port: spec.protocol.default_port,
            uri_schemes: spec.protocol.uri_schemes.clone(),
        }
    }
}

/// Write all generated files to the output directory.
pub fn write_output(files: &[GeneratedFile], output_dir: &Path) -> std::io::Result<()> {
    for file in files {
        let path = output_dir.join(&file.path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, &file.content)?;
    }
    Ok(())
}
