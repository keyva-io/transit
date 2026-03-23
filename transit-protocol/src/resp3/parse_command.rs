use crate::command::Command;
use crate::error::CommandError;

use super::Resp3Frame;

/// Convert a RESP3 frame (an array of bulk strings) into a Transit `Command`.
pub fn parse_command(frame: Resp3Frame) -> Result<Command, CommandError> {
    let parts = match frame {
        Resp3Frame::Array(parts) => parts,
        _ => {
            return Err(CommandError::BadArg {
                message: "expected array frame".into(),
            });
        }
    };

    let strings: Vec<String> = parts
        .into_iter()
        .map(frame_to_string)
        .collect::<Result<_, _>>()?;

    if strings.is_empty() {
        return Err(CommandError::BadArg {
            message: "empty command".into(),
        });
    }

    let verb = strings[0].to_ascii_uppercase();
    let args = &strings[1..];

    match verb.as_str() {
        "ENCRYPT" => parse_encrypt(args),
        "DECRYPT" => parse_decrypt(args),
        "REWRAP" => parse_rewrap(args),
        "GENERATE_DATA_KEY" => parse_generate_data_key(args),
        "SIGN" => parse_sign(args),
        "VERIFY_SIGNATURE" => parse_verify_signature(args),
        "HASH" => parse_hash(args),
        "ROTATE" => parse_rotate(args),
        "KEY_INFO" => parse_key_info(args),
        "HEALTH" => parse_health(args),
        "AUTH" => parse_auth(args),
        "PIPELINE" => parse_pipeline(&strings),
        _ => Err(CommandError::BadArg {
            message: format!("unknown command: {verb}"),
        }),
    }
}

fn frame_to_string(frame: Resp3Frame) -> Result<String, CommandError> {
    match frame {
        Resp3Frame::BulkString(data) => String::from_utf8(data).map_err(|_| CommandError::BadArg {
            message: "non-UTF-8 bulk string".into(),
        }),
        _ => Err(CommandError::BadArg {
            message: "expected bulk string element".into(),
        }),
    }
}

fn require_arg<'a>(args: &'a [String], index: usize, name: &str) -> Result<&'a str, CommandError> {
    args.get(index)
        .map(|s| s.as_str())
        .ok_or_else(|| CommandError::BadArg {
            message: format!("missing required argument: {name}"),
        })
}

/// Find a keyword in the args and return the value after it.
fn find_opt<'a>(args: &'a [String], keyword: &str) -> Option<&'a str> {
    args.windows(2).find_map(|w| {
        if w[0].eq_ignore_ascii_case(keyword) {
            Some(w[1].as_str())
        } else {
            None
        }
    })
}

/// Check if a keyword flag is present.
fn has_flag(args: &[String], keyword: &str) -> bool {
    args.iter().any(|a| a.eq_ignore_ascii_case(keyword))
}

// ENCRYPT <keyring> <plaintext> [CONTEXT <aad>] [KEY_VERSION <version>]
fn parse_encrypt(args: &[String]) -> Result<Command, CommandError> {
    let keyring = require_arg(args, 0, "keyring")?.to_owned();
    let plaintext = require_arg(args, 1, "plaintext")?.to_owned();
    let rest = &args[2..];

    let context = find_opt(rest, "CONTEXT").map(|s| s.to_owned());
    let key_version = find_opt(rest, "KEY_VERSION")
        .map(|s| {
            s.parse::<u32>().map_err(|e| CommandError::BadArg {
                message: format!("invalid KEY_VERSION: {e}"),
            })
        })
        .transpose()?;

    Ok(Command::Encrypt {
        keyring,
        plaintext,
        context,
        key_version,
    })
}

// DECRYPT <keyring> <ciphertext> [CONTEXT <aad>]
fn parse_decrypt(args: &[String]) -> Result<Command, CommandError> {
    let keyring = require_arg(args, 0, "keyring")?.to_owned();
    let ciphertext = require_arg(args, 1, "ciphertext")?.to_owned();
    let rest = &args[2..];

    let context = find_opt(rest, "CONTEXT").map(|s| s.to_owned());

    Ok(Command::Decrypt {
        keyring,
        ciphertext,
        context,
    })
}

// REWRAP <keyring> <ciphertext> [CONTEXT <aad>]
fn parse_rewrap(args: &[String]) -> Result<Command, CommandError> {
    let keyring = require_arg(args, 0, "keyring")?.to_owned();
    let ciphertext = require_arg(args, 1, "ciphertext")?.to_owned();
    let rest = &args[2..];

    let context = find_opt(rest, "CONTEXT").map(|s| s.to_owned());

    Ok(Command::Rewrap {
        keyring,
        ciphertext,
        context,
    })
}

// GENERATE_DATA_KEY <keyring> [BITS <256|512>]
fn parse_generate_data_key(args: &[String]) -> Result<Command, CommandError> {
    let keyring = require_arg(args, 0, "keyring")?.to_owned();
    let rest = &args[1..];

    let bits = find_opt(rest, "BITS")
        .map(|s| {
            s.parse::<u32>().map_err(|e| CommandError::BadArg {
                message: format!("invalid BITS: {e}"),
            })
        })
        .transpose()?;

    Ok(Command::GenerateDataKey { keyring, bits })
}

// SIGN <keyring> <data> [ALGORITHM <algo>]
fn parse_sign(args: &[String]) -> Result<Command, CommandError> {
    let keyring = require_arg(args, 0, "keyring")?.to_owned();
    let data = require_arg(args, 1, "data")?.to_owned();
    let rest = &args[2..];

    let algorithm = find_opt(rest, "ALGORITHM").map(|s| s.to_owned());

    Ok(Command::Sign {
        keyring,
        data,
        algorithm,
    })
}

// VERIFY_SIGNATURE <keyring> <data> <signature>
fn parse_verify_signature(args: &[String]) -> Result<Command, CommandError> {
    let keyring = require_arg(args, 0, "keyring")?.to_owned();
    let data = require_arg(args, 1, "data")?.to_owned();
    let signature = require_arg(args, 2, "signature")?.to_owned();

    Ok(Command::VerifySignature {
        keyring,
        data,
        signature,
    })
}

// HASH <algorithm> <data>
fn parse_hash(args: &[String]) -> Result<Command, CommandError> {
    let algorithm = require_arg(args, 0, "algorithm")?.to_owned();
    let data = require_arg(args, 1, "data")?.to_owned();

    Ok(Command::Hash { algorithm, data })
}

// ROTATE <keyring> [FORCE] [DRYRUN]
fn parse_rotate(args: &[String]) -> Result<Command, CommandError> {
    let keyring = require_arg(args, 0, "keyring")?.to_owned();
    let rest = &args[1..];

    Ok(Command::Rotate {
        keyring,
        force: has_flag(rest, "FORCE"),
        dryrun: has_flag(rest, "DRYRUN"),
    })
}

// KEY_INFO <keyring>
fn parse_key_info(args: &[String]) -> Result<Command, CommandError> {
    let keyring = require_arg(args, 0, "keyring")?.to_owned();
    Ok(Command::KeyInfo { keyring })
}

// HEALTH [<keyring>]
fn parse_health(args: &[String]) -> Result<Command, CommandError> {
    let keyring = args.first().map(|s| s.to_owned());
    Ok(Command::Health { keyring })
}

// AUTH <token>
fn parse_auth(args: &[String]) -> Result<Command, CommandError> {
    let token = require_arg(args, 0, "token")?.to_owned();
    Ok(Command::Auth { token })
}

// PIPELINE ... END
fn parse_pipeline(all_strings: &[String]) -> Result<Command, CommandError> {
    let end_idx = all_strings
        .iter()
        .position(|s| s.eq_ignore_ascii_case("END"))
        .ok_or_else(|| CommandError::BadArg {
            message: "PIPELINE without END".into(),
        })?;

    let inner = &all_strings[1..end_idx];
    if inner.is_empty() {
        return Ok(Command::Pipeline(vec![]));
    }

    let verbs = [
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
    ];

    let mut commands = Vec::new();
    let mut start = 0;

    for i in 1..=inner.len() {
        let is_boundary =
            i == inner.len() || verbs.contains(&inner[i].to_ascii_uppercase().as_str());
        if is_boundary {
            let slice = &inner[start..i];
            if !slice.is_empty() {
                let frame = Resp3Frame::Array(
                    slice
                        .iter()
                        .map(|s| Resp3Frame::BulkString(s.as_bytes().to_vec()))
                        .collect(),
                );
                commands.push(parse_command(frame)?);
            }
            start = i;
        }
    }

    Ok(Command::Pipeline(commands))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bs(s: &str) -> Resp3Frame {
        Resp3Frame::BulkString(s.as_bytes().to_vec())
    }

    fn cmd_array(parts: &[&str]) -> Resp3Frame {
        Resp3Frame::Array(parts.iter().map(|s| bs(s)).collect())
    }

    #[test]
    fn parse_health_no_keyring() {
        let frame = cmd_array(&["HEALTH"]);
        let cmd = parse_command(frame).unwrap();
        assert!(matches!(cmd, Command::Health { keyring: None }));
    }

    #[test]
    fn parse_health_with_keyring() {
        let frame = cmd_array(&["HEALTH", "payments"]);
        let cmd = parse_command(frame).unwrap();
        match cmd {
            Command::Health { keyring } => assert_eq!(keyring.as_deref(), Some("payments")),
            _ => panic!("expected Health"),
        }
    }

    #[test]
    fn parse_encrypt() {
        let frame = cmd_array(&["ENCRYPT", "payments", "aGVsbG8", "CONTEXT", "user:42"]);
        let cmd = parse_command(frame).unwrap();
        match cmd {
            Command::Encrypt {
                keyring,
                plaintext,
                context,
                key_version,
            } => {
                assert_eq!(keyring, "payments");
                assert_eq!(plaintext, "aGVsbG8");
                assert_eq!(context.as_deref(), Some("user:42"));
                assert!(key_version.is_none());
            }
            _ => panic!("expected Encrypt"),
        }
    }

    #[test]
    fn parse_decrypt() {
        let frame = cmd_array(&["DECRYPT", "payments", "v3:abc123"]);
        let cmd = parse_command(frame).unwrap();
        match cmd {
            Command::Decrypt {
                keyring,
                ciphertext,
                context,
            } => {
                assert_eq!(keyring, "payments");
                assert_eq!(ciphertext, "v3:abc123");
                assert!(context.is_none());
            }
            _ => panic!("expected Decrypt"),
        }
    }

    #[test]
    fn parse_hash() {
        let frame = cmd_array(&["HASH", "sha256", "dGVzdA"]);
        let cmd = parse_command(frame).unwrap();
        match cmd {
            Command::Hash { algorithm, data } => {
                assert_eq!(algorithm, "sha256");
                assert_eq!(data, "dGVzdA");
            }
            _ => panic!("expected Hash"),
        }
    }

    #[test]
    fn parse_rotate_with_flags() {
        let frame = cmd_array(&["ROTATE", "payments", "FORCE", "DRYRUN"]);
        let cmd = parse_command(frame).unwrap();
        match cmd {
            Command::Rotate {
                keyring,
                force,
                dryrun,
            } => {
                assert_eq!(keyring, "payments");
                assert!(force);
                assert!(dryrun);
            }
            _ => panic!("expected Rotate"),
        }
    }

    #[test]
    fn parse_unknown_command() {
        let frame = cmd_array(&["BOGUS", "arg"]);
        let err = parse_command(frame).unwrap_err();
        assert!(matches!(err, CommandError::BadArg { .. }));
    }

    #[test]
    fn parse_verify_signature() {
        let frame = cmd_array(&["VERIFY_SIGNATURE", "signing", "data123", "sig456"]);
        let cmd = parse_command(frame).unwrap();
        match cmd {
            Command::VerifySignature {
                keyring,
                data,
                signature,
            } => {
                assert_eq!(keyring, "signing");
                assert_eq!(data, "data123");
                assert_eq!(signature, "sig456");
            }
            _ => panic!("expected VerifySignature"),
        }
    }

    #[test]
    fn parse_generate_data_key() {
        let frame = cmd_array(&["GENERATE_DATA_KEY", "payments", "BITS", "512"]);
        let cmd = parse_command(frame).unwrap();
        match cmd {
            Command::GenerateDataKey { keyring, bits } => {
                assert_eq!(keyring, "payments");
                assert_eq!(bits, Some(512));
            }
            _ => panic!("expected GenerateDataKey"),
        }
    }
}
