//! Local administration client; run under the broker service identity.
use anyhow::{Context, Result, bail, ensure};
use avd::{
    RequestState, Review,
    management::{
        MAX_SECRET_BYTES, ManagementOperation, installed_runtime, validate_operator_identity,
    },
    session::{AdminRequest, admin_call},
};
use std::{
    fs,
    io::{self, IsTerminal, Read, Write},
    os::{
        fd::{AsFd, AsRawFd},
        unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
};
use uuid::Uuid;
use zeroize::Zeroizing;

const USAGE: &str = "usage: av-operator init --recovery-file ABSOLUTE_ROOT_PRIVATE_PATH\n       av-operator status|unlock|lock [runtime-directory]\n       av-operator review|approve|deny REQUEST_ID\n       av-operator add|rotate|policy|revoke PROJECT/NAME\n       av-operator grant PROJECT/NAME [--preapprove]\n       av-operator connect-add ID HOST | connect-list | connect-show ID\n       av-operator connect-replace|connect-disconnect|connect-revoke|connect-grant ID VERSION\n\nInit requires sudo and a new recovery file in an existing private root-owned directory; its passphrase is entered twice after dropping to the broker identity. Approval displays the broker-owned frozen request and requires the vault passphrase. Management requires a locked installed service vault. Generic secret grant pins the installed platform proxy recipe. Passphrases and credential values are read with terminal echo disabled, or as newline-delimited input from a private pipe/socket. Regular-file input is rejected. For add/rotate and connect-add/connect-replace, supply the passphrase first and the value second.";

#[derive(Debug, PartialEq, Eq)]
struct Arguments {
    action: String,
    name: Option<String>,
    runtime: PathBuf,
    preapprove: bool,
    recovery_file: Option<PathBuf>,
    expected_version: Option<u64>,
    host: Option<String>,
    request_id: Option<Uuid>,
}

impl Arguments {
    fn parse(mut args: impl Iterator<Item = String>) -> Result<Self> {
        let action = args.next().context(USAGE)?;
        let mut parsed = Self {
            action,
            name: None,
            runtime: installed_runtime(),
            preapprove: false,
            recovery_file: None,
            expected_version: None,
            host: None,
            request_id: None,
        };
        match parsed.action.as_str() {
            "init" => {
                ensure!(
                    args.next().as_deref() == Some("--recovery-file"),
                    "init requires --recovery-file ABSOLUTE_ROOT_PRIVATE_PATH"
                );
                parsed.recovery_file = Some(PathBuf::from(
                    args.next().context("recovery output path is required")?,
                ));
            }
            "status" | "unlock" | "lock" => {
                if let Some(path) = args.next() {
                    parsed.runtime = PathBuf::from(path);
                }
            }
            "review" | "approve" | "deny" => {
                parsed.request_id = Some(
                    args.next()
                        .context("request ID is required")?
                        .parse()
                        .context("invalid request ID")?,
                );
            }
            "add" | "rotate" | "grant" | "policy" | "revoke" => {
                parsed.name = Some(
                    args.next()
                        .context("a PROJECT/NAME secret key is required")?,
                );
                if parsed.action == "grant"
                    && let Some(option) = args.next()
                {
                    ensure!(
                        option == "--preapprove",
                        "grant accepts only --preapprove after the secret name"
                    );
                    parsed.preapprove = true;
                }
            }
            "connect-list" => (),
            "connect-add" => {
                parsed.name = Some(args.next().context("connection ID is required")?);
                parsed.host = Some(args.next().context("connection host is required")?);
            }
            "connect-show" => {
                parsed.name = Some(args.next().context("connection ID is required")?);
            }
            "connect-replace" | "connect-disconnect" | "connect-revoke" | "connect-grant" => {
                parsed.name = Some(args.next().context("connection ID is required")?);
                parsed.expected_version = Some(parse_version(
                    &args.next().context("connection version is required")?,
                )?);
            }
            _ => bail!(USAGE),
        }
        ensure!(
            args.next().is_none(),
            "unexpected argument; values and passphrases must use private input"
        );
        Ok(parsed)
    }
}

fn parse_version(value: &str) -> Result<u64> {
    let version = value.parse::<u64>().context("invalid connection version")?;
    ensure!(version > 0, "connection version must be positive");
    Ok(version)
}

fn main() -> Result<()> {
    if std::env::args().nth(1).as_deref() == Some("--help") {
        println!("{USAGE}");
        return Ok(());
    }
    let args = Arguments::parse(std::env::args().skip(1))?;
    if args.action == "init" {
        let recovery_path = args
            .recovery_file
            .as_deref()
            .context("recovery output path is required")?;
        let result = initialize(recovery_path).with_context(|| format!(
            "initialization failed; a root-owned recovery output may remain at {}; inspect it and any pending vault state before retrying; existing outputs are never overwritten",
            recovery_path.display()
        ))?;
        println!("{}", serde_json::to_string_pretty(&result)?);
        return Ok(());
    }
    ensure!(
        unsafe { libc::getuid() } != 0 && unsafe { libc::geteuid() } != 0,
        "only init may run as root; use the broker identity for administration"
    );
    administration(args)
}

fn initialize(recovery_path: &Path) -> Result<serde_json::Value> {
    let bootstrap = avd::management::bootstrap::Bootstrap::prepare(recovery_path)?;
    let mut input = fs::File::from(io::stdin().as_fd().try_clone_to_owned()?);
    let passphrase = read_private_line(&mut input, "New vault passphrase: ", 4096)?;
    let confirmation = read_private_line(&mut input, "Confirm vault passphrase: ", 4096)?;
    ensure!(
        *passphrase == *confirmation,
        "passphrases do not match; no vault was created"
    );
    bootstrap.finish(&passphrase)
}

#[tokio::main]
async fn administration(args: Arguments) -> Result<()> {
    if args.runtime == installed_runtime() {
        validate_operator_identity()?;
        #[cfg(target_os = "macos")]
        av_vmm::service::validate_broker_path(&args.runtime, true)?;
        #[cfg(not(target_os = "macos"))]
        avd::service::validate_trusted_path(&args.runtime, false)?;
    }
    let mut token = read_admin_token(&args.runtime)?;
    let mut input = fs::File::from(io::stdin().as_fd().try_clone_to_owned()?);
    if matches!(args.action.as_str(), "review" | "approve" | "deny") {
        let request_id = args.request_id.context("request ID is required")?;
        let review_reply = admin_call(
            &args.runtime.join("admin.sock"),
            &AdminRequest::Review {
                token: token.to_string(),
                request_id,
            },
        )
        .await?;
        ensure!(
            review_reply.ok,
            "{}",
            review_reply.error.unwrap_or_else(|| "review failed".into())
        );
        let review: Review = serde_json::from_value(review_reply.data.context("empty review")?)?;
        ensure!(review.id == request_id, "review ID mismatch");
        let display = visible_json(&review)?;
        if args.action == "review" {
            println!("{display}");
            return Ok(());
        }
        ensure!(
            review.state == RequestState::Pending,
            "request is not pending"
        );
        eprintln!("{display}");
        let passphrase = read_private_line(&mut input, "Vault passphrase: ", 4096)?;
        let request = AdminRequest::Decide {
            token: take_secret(&mut token),
            passphrase: passphrase.to_string(),
            request_id,
            approve: args.action == "approve",
            ttl_seconds: if args.action == "approve" { 60 } else { 0 },
        };
        let reply = admin_call(&args.runtime.join("admin.sock"), &request).await?;
        ensure!(
            reply.ok,
            "{}",
            reply.error.unwrap_or_else(|| "decision failed".into())
        );
        println!(
            "{}",
            if args.action == "approve" {
                "APPROVED"
            } else {
                "DENIED"
            }
        );
        return Ok(());
    }
    let request = match args.action.as_str() {
        "status" => AdminRequest::Status {
            token: take_secret(&mut token),
        },
        "lock" => AdminRequest::Lock {
            token: take_secret(&mut token),
        },
        "unlock" => AdminRequest::Unlock {
            token: take_secret(&mut token),
            passphrase: take_secret(&mut read_private_line(
                &mut input,
                "Vault passphrase: ",
                4096,
            )?),
        },
        "review" | "approve" | "deny" => unreachable!(),
        action => {
            let mut passphrase = read_private_line(&mut input, "Vault passphrase: ", 4096)?;
            let operation = match action {
                "add" => ManagementOperation::Add {
                    name: args.name.context("secret name is required")?,
                    value: take_secret(&mut read_private_line(
                        &mut input,
                        "Secret value: ",
                        MAX_SECRET_BYTES,
                    )?),
                },
                "rotate" => ManagementOperation::Rotate {
                    name: args.name.context("secret name is required")?,
                    value: take_secret(&mut read_private_line(
                        &mut input,
                        "Replacement secret value: ",
                        MAX_SECRET_BYTES,
                    )?),
                },
                "grant" => ManagementOperation::Grant {
                    name: args.name.context("secret name is required")?,
                    preapprove: args.preapprove,
                },
                "revoke" => ManagementOperation::Revoke {
                    name: args.name.context("secret name is required")?,
                },
                "policy" => ManagementOperation::Policy {
                    name: args.name.context("secret name is required")?,
                },
                "connect-add" => ManagementOperation::ConnectAdd {
                    id: args.name.context("connection ID is required")?,
                    host: args.host.context("connection host is required")?,
                    value: take_secret(&mut read_private_line(
                        &mut input,
                        "Connection credential: ",
                        MAX_SECRET_BYTES,
                    )?),
                },
                "connect-list" => ManagementOperation::ConnectList,
                "connect-show" => ManagementOperation::ConnectShow {
                    id: args.name.context("connection ID is required")?,
                },
                "connect-replace" => ManagementOperation::ConnectReplace {
                    id: args.name.context("connection ID is required")?,
                    expected_version: args.expected_version.context("version is required")?,
                    value: take_secret(&mut read_private_line(
                        &mut input,
                        "Replacement connection credential: ",
                        MAX_SECRET_BYTES,
                    )?),
                },
                "connect-disconnect" => ManagementOperation::ConnectDisconnect {
                    id: args.name.context("connection ID is required")?,
                    expected_version: args.expected_version.context("version is required")?,
                },
                "connect-revoke" => ManagementOperation::ConnectRevoke {
                    id: args.name.context("connection ID is required")?,
                    expected_version: args.expected_version.context("version is required")?,
                },
                "connect-grant" => ManagementOperation::ConnectGrant {
                    id: args.name.context("connection ID is required")?,
                    expected_version: args.expected_version.context("version is required")?,
                },
                _ => unreachable!(),
            };
            AdminRequest::Manage {
                token: take_secret(&mut token),
                passphrase: take_secret(&mut passphrase),
                operation,
            }
        }
    };
    let reply = admin_call(&args.runtime.join("admin.sock"), &request).await?;
    if !reply.ok {
        bail!(
            "{}",
            reply
                .error
                .unwrap_or_else(|| "administration failed".into())
        );
    }
    println!("{}", serde_json::to_string_pretty(&reply.data)?);
    Ok(())
}

fn visible_json<T: serde::Serialize>(value: &T) -> Result<String> {
    use std::fmt::Write as _;

    let serialized = serde_json::to_string_pretty(value)?;
    let mut visible = String::with_capacity(serialized.len());
    for character in serialized.chars() {
        if character.is_ascii() {
            visible.push(character);
        } else {
            for unit in character.encode_utf16(&mut [0_u16; 2]) {
                write!(&mut visible, "\\u{unit:04X}")?;
            }
        }
    }
    Ok(visible)
}

fn take_secret(value: &mut Zeroizing<String>) -> String {
    std::mem::take(&mut **value)
}

fn read_admin_token(base: &Path) -> Result<Zeroizing<String>> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(base.join("admin.token"))?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.nlink() == 1
            && metadata.mode() & 0o077 == 0
            && metadata.len() == 64,
        "invalid private administration capability"
    );
    let mut token = Zeroizing::new(String::new());
    file.take(65).read_to_string(&mut token)?;
    ensure!(
        token.len() == 64 && token.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid administration capability"
    );
    Ok(token)
}

/// File input is deliberately unsupported. Anonymous pipes and private Unix
/// sockets are useful for an operator's credential manager or a test harness.
fn validate_private_input() -> Result<bool> {
    if io::stdin().is_terminal() {
        return Ok(true);
    }
    let metadata = fs::File::from(io::stdin().as_fd().try_clone_to_owned()?).metadata()?;
    ensure!(
        metadata.file_type().is_fifo() || metadata.file_type().is_socket(),
        "sensitive input requires a terminal or private pipe/socket; files are not accepted"
    );
    ensure!(
        metadata.mode() & 0o077 == 0,
        "input pipe/socket must not be accessible by other identities"
    );
    Ok(false)
}

fn read_private_line(
    input: &mut impl Read,
    prompt: &str,
    max_bytes: usize,
) -> Result<Zeroizing<String>> {
    struct RestoreEcho(Option<libc::termios>);
    impl Drop for RestoreEcho {
        fn drop(&mut self) {
            if let Some(previous) = self.0 {
                unsafe {
                    libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &previous);
                }
                eprintln!();
            }
        }
    }
    let mut restore = RestoreEcho(None);
    if validate_private_input()? {
        let mut previous = std::mem::MaybeUninit::<libc::termios>::uninit();
        if unsafe { libc::tcgetattr(io::stdin().as_raw_fd(), previous.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        let previous = unsafe { previous.assume_init() };
        let mut hidden = previous;
        hidden.c_lflag &= !(libc::ECHO | libc::ECHONL);
        if unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &hidden) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        restore.0 = Some(previous);
        eprint!("{prompt}");
        io::stderr().flush()?;
    }
    bounded_line(input, max_bytes)
}

fn bounded_line(input: &mut impl Read, max_bytes: usize) -> Result<Zeroizing<String>> {
    // Read directly from the descriptor so a standard stdin/BufReader buffer
    // cannot retain another copy of the passphrase or the following value.
    let mut bytes = Zeroizing::new(Vec::with_capacity(max_bytes + 2));
    let mut byte = Zeroizing::new([0_u8; 1]);
    while bytes.len() < max_bytes + 2 {
        match input.read(byte.as_mut()) {
            Ok(0) => break,
            Ok(_) => {
                bytes.push(byte[0]);
                if byte[0] == b'\n' {
                    break;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        }
    }
    ensure!(
        bytes.last() == Some(&b'\n'),
        "sensitive input must end with a newline"
    );
    bytes.pop();
    if bytes.last() == Some(&b'\r') {
        bytes.pop();
    }
    ensure!(
        !bytes.is_empty() && bytes.len() <= max_bytes && !bytes.contains(&0),
        "invalid sensitive input length or content"
    );
    let value = std::str::from_utf8(&bytes).context("sensitive input must be UTF-8")?;
    Ok(Zeroizing::new(value.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_line_accepts_generic_connection_lifecycle_without_secrets() {
        let parsed = Arguments::parse(
            ["connect-add", "service/work", "api.example.test"]
                .into_iter()
                .map(str::to_owned),
        )
        .unwrap();
        assert_eq!(parsed.name.as_deref(), Some("service/work"));
        assert_eq!(parsed.host.as_deref(), Some("api.example.test"));
        let granted = Arguments::parse(
            ["connect-grant", "service/work", "1"]
                .into_iter()
                .map(str::to_owned),
        )
        .unwrap();
        assert_eq!(granted.expected_version, Some(1));
        for args in [
            vec!["connect-add", "service/work"],
            vec!["connect-add", "service/work", "api.example.test", "secret"],
            vec!["connect-replace", "service/work", "0"],
            vec!["connect-replace", "service/work", "1", "secret"],
            vec!["connect-grant-action", "service/work", "1"],
        ] {
            assert!(Arguments::parse(args.into_iter().map(str::to_owned)).is_err());
        }
    }

    #[test]
    fn approval_commands_require_one_request_id() {
        let id = Uuid::new_v4();
        for action in ["review", "approve", "deny"] {
            let parsed = Arguments::parse([action.to_owned(), id.to_string()].into_iter()).unwrap();
            assert_eq!(parsed.request_id, Some(id));
            assert!(Arguments::parse([action.to_owned()].into_iter()).is_err());
            assert!(
                Arguments::parse([action.to_owned(), id.to_string(), "extra".into()].into_iter())
                    .is_err()
            );
        }
        assert!(Arguments::parse(["approve".into(), "not-a-uuid".into()].into_iter()).is_err());
    }

    #[test]
    fn operator_review_display_escapes_layout_controls() {
        let displayed =
            visible_json(&serde_json::json!({"target":"host\u{202E}reversed"})).unwrap();
        assert!(displayed.contains("\\u202E"));
        assert!(!displayed.contains('\u{202E}'));
    }

    #[test]
    fn bounded_input_preserves_separate_passphrase_and_value_lines() {
        let mut input = io::Cursor::new(b"passphrase\nav-synthetic-value\n");
        assert_eq!(
            bounded_line(&mut input, 4096).unwrap().as_str(),
            "passphrase"
        );
        assert_eq!(
            bounded_line(&mut input, 4096).unwrap().as_str(),
            "av-synthetic-value"
        );
        for bytes in [
            b"".as_slice(),
            b"\n",
            b"unterminated",
            b"nul\0\n",
            b"12345\n",
        ] {
            assert!(bounded_line(&mut io::Cursor::new(bytes), 4).is_err());
        }
        assert_eq!(
            bounded_line(&mut io::Cursor::new(b"1234\r\n"), 4)
                .unwrap()
                .as_str(),
            "1234"
        );
    }
}
