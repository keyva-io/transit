//! transit-codegen — client SDK generator for the Keyva Transit protocol.
//!
//! Reads protocol.toml and produces ready-to-publish client packages.
//!
//! Usage:
//!   transit-codegen --spec protocol.toml --lang python --output generated/python
//!   transit-codegen --spec protocol.toml --lang all --output generated/

use clap::Parser;
use std::path::PathBuf;
use transit_codegen::generator::{Generator, write_output};
use transit_codegen::generators::go::GoGenerator;
use transit_codegen::generators::python::PythonGenerator;
use transit_codegen::generators::ruby::RubyGenerator;
use transit_codegen::generators::typescript::TypeScriptGenerator;
use transit_codegen::spec::ProtocolSpec;

#[derive(Parser)]
#[command(
    name = "transit-codegen",
    about = "Generate typed client libraries from the Keyva Transit protocol spec"
)]
struct Cli {
    /// Path to the protocol spec file (protocol.toml)
    #[arg(short, long, default_value = "protocol.toml")]
    spec: PathBuf,

    /// Target language: python, typescript, go, ruby, or all
    #[arg(short, long)]
    lang: String,

    /// Output directory for generated code
    #[arg(short, long, default_value = "generated")]
    output: PathBuf,

    /// Print what would be generated without writing files
    #[arg(long)]
    dry_run: bool,
}

fn main() {
    let cli = Cli::parse();

    let spec_text = std::fs::read_to_string(&cli.spec).unwrap_or_else(|e| {
        eprintln!("Error reading spec file {:?}: {e}", cli.spec);
        std::process::exit(1);
    });

    let spec = ProtocolSpec::from_toml(&spec_text).unwrap_or_else(|e| {
        eprintln!("Error parsing spec: {e}");
        std::process::exit(1);
    });

    let generators: Vec<Box<dyn Generator>> = match cli.lang.as_str() {
        "python" | "py" => vec![Box::new(PythonGenerator)],
        "typescript" | "ts" => vec![Box::new(TypeScriptGenerator)],
        "go" | "golang" => vec![Box::new(GoGenerator)],
        "ruby" | "rb" => vec![Box::new(RubyGenerator)],
        "all" => vec![
            Box::new(PythonGenerator),
            Box::new(TypeScriptGenerator),
            Box::new(GoGenerator),
            Box::new(RubyGenerator),
        ],
        other => {
            eprintln!("Unknown language: {other}\nSupported: python, typescript, go, ruby, all");
            std::process::exit(1);
        }
    };

    for generator in &generators {
        let files = generator.generate(&spec);
        let lang_dir = if generators.len() > 1 {
            cli.output.join(generator.language().to_lowercase())
        } else {
            cli.output.clone()
        };

        if cli.dry_run {
            println!("\n=== {} ({} files) ===", generator.language(), files.len());
            for f in &files {
                println!("  {}", lang_dir.join(&f.path).display());
            }
        } else {
            write_output(&files, &lang_dir).unwrap_or_else(|e| {
                eprintln!("Error writing {} output: {e}", generator.language());
                std::process::exit(1);
            });
            println!(
                "Generated {} {} files in {}",
                files.len(),
                generator.language(),
                lang_dir.display()
            );
        }
    }
}
