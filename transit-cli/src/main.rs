//! keyva-transit-cli — interactive command-line client for Keyva Transit.

use clap::Parser;
use rustyline::error::ReadlineError;
use rustyline::hint::HistoryHinter;
use transit_client::Response;
use transit_client::connection::Connection;

/// Known command names for tab completion.
const COMMANDS: &[&str] = &[
    "ENCRYPT",
    "DECRYPT",
    "REWRAP",
    "GENERATE_DATA_KEY",
    "SIGN",
    "VERIFY_SIGNATURE",
    "HASH",
    "ROTATE",
    "KEY_INFO",
    "HEALTH",
    "AUTH",
    "help",
    "quit",
    "exit",
];

// ---------------------------------------------------------------------------
// Tab-completion helper
// ---------------------------------------------------------------------------

struct TransitHelper {
    hinter: HistoryHinter,
}

impl rustyline::completion::Completer for TransitHelper {
    type Candidate = String;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &rustyline::Context<'_>,
    ) -> rustyline::Result<(usize, Vec<String>)> {
        let word_start = line[..pos].rfind(' ').map(|i| i + 1).unwrap_or(0);
        let prefix = &line[word_start..pos];
        let matches: Vec<String> = COMMANDS
            .iter()
            .filter(|c| c.to_uppercase().starts_with(&prefix.to_uppercase()))
            .map(|c| c.to_string())
            .collect();
        Ok((word_start, matches))
    }
}

impl rustyline::hint::Hinter for TransitHelper {
    type Hint = String;

    fn hint(&self, line: &str, pos: usize, ctx: &rustyline::Context<'_>) -> Option<String> {
        self.hinter.hint(line, pos, ctx)
    }
}

impl rustyline::highlight::Highlighter for TransitHelper {}
impl rustyline::validate::Validator for TransitHelper {}
impl rustyline::Helper for TransitHelper {}

// ---------------------------------------------------------------------------
// CLI args
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(
    name = "keyva-transit-cli",
    about = "Interactive client for Keyva Transit",
    version
)]
struct Cli {
    /// Connection URI (e.g., kvt://localhost:6499, kvt+tls://token@host:6499).
    #[arg(long)]
    uri: Option<String>,

    /// Server host.
    #[arg(long, default_value = "127.0.0.1")]
    host: String,

    /// Server port.
    #[arg(short, long, default_value_t = 6499)]
    port: u16,

    /// Output responses as JSON.
    #[arg(long)]
    json: bool,

    /// Output raw RESP3 wire format instead of parsed responses.
    #[arg(long)]
    raw: bool,

    /// Connect with TLS.
    #[arg(long)]
    tls: bool,

    /// Execute a single command and exit (non-interactive).
    #[arg(trailing_var_arg = true)]
    command: Vec<String>,
}

/// Output mode derived from CLI flags.
#[derive(Clone, Copy)]
enum OutputMode {
    Human,
    Json,
    Raw,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let output_mode = if cli.raw {
        OutputMode::Raw
    } else if cli.json {
        OutputMode::Json
    } else {
        OutputMode::Human
    };

    let (addr, mut conn) = if let Some(ref uri) = cli.uri {
        let config = transit_client::parse_uri(uri)?;
        let addr = format!("{}:{}", config.host, config.port);
        let mut conn = if config.tls {
            Connection::connect_tls(&addr).await?
        } else {
            Connection::connect(&addr).await?
        };
        if let Some(token) = &config.auth_token {
            let auth_args = vec!["AUTH".to_string(), token.clone()];
            conn.send_command(&auth_args).await?;
        }
        (addr, conn)
    } else {
        let addr = format!("{}:{}", cli.host, cli.port);
        let conn = if cli.tls {
            Connection::connect_tls(&addr).await?
        } else {
            Connection::connect(&addr).await?
        };
        (addr, conn)
    };

    // Non-interactive: execute single command and exit.
    if !cli.command.is_empty() {
        let response = conn.send_command(&cli.command).await?;
        print_output(&response, output_mode);
        return Ok(());
    }

    // Interactive REPL.
    println!("Connected to keyva-transit at {addr}");
    println!("Type 'help' for command list, 'help <command>' for details, Ctrl-C to exit.\n");

    let config = rustyline::Config::builder().auto_add_history(true).build();
    let helper = TransitHelper {
        hinter: HistoryHinter::new(),
    };
    let mut rl = rustyline::Editor::with_config(config)?;
    rl.set_helper(Some(helper));

    let history_path = dirs_home().join(".transit_history");
    let _ = rl.load_history(&history_path);

    loop {
        match rl.readline("transit> ") {
            Ok(line) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }

                if let Some(cmd) = line
                    .strip_prefix("help ")
                    .or_else(|| line.strip_prefix("HELP "))
                {
                    print_command_help(cmd.trim());
                    continue;
                }

                if line.eq_ignore_ascii_case("help") {
                    print_help();
                    continue;
                }
                if line.eq_ignore_ascii_case("quit") || line.eq_ignore_ascii_case("exit") {
                    break;
                }

                let args = shell_words(line);
                match conn.send_command(&args).await {
                    Ok(response) => print_output(&response, output_mode),
                    Err(e) => eprintln!("error: {e}"),
                }
            }
            Err(ReadlineError::Interrupted) => break,
            Err(ReadlineError::Eof) => break,
            Err(e) => {
                eprintln!("readline error: {e}");
                break;
            }
        }
    }

    let _ = rl.save_history(&history_path);
    Ok(())
}

/// Print a response in the requested output mode.
fn print_output(resp: &Response, mode: OutputMode) {
    match mode {
        OutputMode::Human => resp.print(0),
        OutputMode::Json => {
            let json_val = resp.to_json();
            println!("{}", serde_json::to_string_pretty(&json_val).unwrap());
        }
        OutputMode::Raw => {
            let raw = resp.to_raw();
            print!("{raw}");
        }
    }
}

fn dirs_home() -> std::path::PathBuf {
    std::env::var("HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
}

/// Split a line into words, respecting double-quoted strings.
fn shell_words(input: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;

    for ch in input.chars() {
        match ch {
            '"' => in_quotes = !in_quotes,
            ' ' | '\t' if !in_quotes => {
                if !current.is_empty() {
                    words.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(ch),
        }
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

fn print_help() {
    println!(
        r#"
Commands:

  Encryption / Decryption
    ENCRYPT <keyring> <plaintext> [CONTEXT <aad>] [KEY_VERSION <version>]
    DECRYPT <keyring> <ciphertext> [CONTEXT <aad>]
    REWRAP <keyring> <ciphertext> [CONTEXT <aad>]
    GENERATE_DATA_KEY <keyring> [BITS <256|512>]

  Signing / Hashing
    SIGN <keyring> <data> [ALGORITHM <algo>]
    VERIFY_SIGNATURE <keyring> <data> <signature>
    HASH <algorithm> <data>

  Key Management
    ROTATE <keyring> [FORCE] [DRYRUN]
    KEY_INFO <keyring>

  Operational
    HEALTH [<keyring>]
    AUTH <token>

  Other
    help [<command>]   Show help (optionally for a specific command)
    quit/exit          Disconnect
"#
    );
}

fn print_command_help(cmd: &str) {
    match cmd.to_uppercase().as_str() {
        "ENCRYPT" => println!(
            r#"ENCRYPT <keyring> <plaintext> [CONTEXT <aad>] [KEY_VERSION <version>]

  Encrypt base64-encoded plaintext with the active key version.
  Returns ciphertext that embeds the key version used.

  CONTEXT      Additional authenticated data (AAD). Must match on decrypt.
  KEY_VERSION  Encrypt with a specific version instead of active.

  Example:
    ENCRYPT payments aGVsbG8 CONTEXT user:42
"#
        ),
        "DECRYPT" => println!(
            r#"DECRYPT <keyring> <ciphertext> [CONTEXT <aad>]

  Decrypt ciphertext. Extracts the key version from the ciphertext prefix.

  CONTEXT  Must match the context used during encryption.

  Example:
    DECRYPT payments v3:abc123 CONTEXT user:42
"#
        ),
        "REWRAP" => println!(
            r#"REWRAP <keyring> <ciphertext> [CONTEXT <aad>]

  Decrypt with the old key, re-encrypt with the current active key.
  Plaintext never leaves the server.

  Example:
    REWRAP payments v2:olddata
"#
        ),
        "GENERATE_DATA_KEY" => println!(
            r#"GENERATE_DATA_KEY <keyring> [BITS <256|512>]

  Generate a data encryption key (DEK) for envelope encryption.
  Returns both the plaintext key and a wrapped (encrypted) copy.

  Example:
    GENERATE_DATA_KEY payments BITS 256
"#
        ),
        "SIGN" => println!(
            r#"SIGN <keyring> <data> [ALGORITHM <algo>]

  Create a detached signature over base64-encoded data.

  Example:
    SIGN signing dGVzdA
"#
        ),
        "VERIFY_SIGNATURE" => println!(
            r#"VERIFY_SIGNATURE <keyring> <data> <signature>

  Verify a detached signature.

  Example:
    VERIFY_SIGNATURE signing dGVzdA sig123
"#
        ),
        "HASH" => println!(
            r#"HASH <algorithm> <data>

  Compute a one-way hash. Algorithms: sha256, sha384, sha512.

  Example:
    HASH sha256 dGVzdA
"#
        ),
        "ROTATE" => println!(
            r#"ROTATE <keyring> [FORCE] [DRYRUN]

  Trigger key rotation. The old key enters draining state.

  FORCE    Rotate even if not due.
  DRYRUN   Preview without making changes.

  Example:
    ROTATE payments FORCE
"#
        ),
        "KEY_INFO" => println!(
            r#"KEY_INFO <keyring>

  Show all key versions with state, creation time, and algorithm.

  Example:
    KEY_INFO payments
"#
        ),
        "HEALTH" => println!(
            r#"HEALTH [<keyring>]

  Check server health, optionally for a specific keyring.

  Example:
    HEALTH
    HEALTH payments
"#
        ),
        "AUTH" => println!(
            r#"AUTH <token>

  Authenticate the current connection with a bearer token.

  Example:
    AUTH my-secret-token
"#
        ),
        _ => println!("Unknown command: {cmd}. Type 'help' for all commands."),
    }
}
