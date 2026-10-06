#![cfg(target_os = "linux")]

use av_runner::{RunSpec, prepare_command};
use std::fs;
use std::io::{self, Read, Write};
use std::net::TcpListener;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::Stdio;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[test]
fn network_namespace_blocks_egress_but_allows_local_proxy() -> Result<(), Box<dyn std::error::Error>>
{
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let temp = std::env::temp_dir().join(format!("av-runner-test-{}-{nonce}", std::process::id()));
    fs::create_dir(&temp)?;
    let result = run_test(&temp);
    fs::remove_dir_all(&temp)?;
    result
}

fn run_test(temp: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let socket = temp.join("proxy.sock");
    let host_proxy = UnixListener::bind(&socket)?;
    host_proxy.set_nonblocking(true)?;
    let secret_path = temp.join("broker-secret");
    fs::write(&secret_path, "synthetic-host-secret")?;
    let other_socket = temp.join("forbidden.sock");
    let _operator = UnixListener::bind(&other_socket)?;
    let host_loopback = TcpListener::bind("127.0.0.1:0")?;
    let host_port = host_loopback.local_addr()?.port();

    let relay = thread::spawn(move || -> io::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match host_proxy.accept() {
                Ok((mut stream, _)) => {
                    let mut request = [0; 4];
                    stream.read_exact(&mut request)?;
                    if &request != b"PING" {
                        return Err(io::Error::other("wrong synthetic proxy request"));
                    }
                    stream.write_all(b"PONG")?;
                    return Ok(());
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "proxy was not reached",
                        ));
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(error),
            }
        }
    });

    let mut spec = RunSpec::new(PathBuf::from(env!("CARGO_BIN_EXE_av-runner-canary")));
    spec.env.extend([
        ("HOST_TEST_PORT".into(), host_port.to_string().into()),
        ("HOST_SECRET_PATH".into(), secret_path.into_os_string()),
        ("HOST_SOCKET_PATH".into(), other_socket.into_os_string()),
        (
            "BROKER_HOST_PID".into(),
            std::process::id().to_string().into(),
        ),
    ]);
    spec.expected_sha256 = Some(av_runner::executable_sha256(&spec.program)?);
    let mut command = prepare_command(
        std::path::Path::new(env!("CARGO_BIN_EXE_av-runner-helper")),
        &socket,
        &spec,
    )?;
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn()?;
    let deadline = Instant::now() + Duration::from_secs(5);
    while child.try_wait()?.is_none() {
        if Instant::now() >= deadline {
            child.kill()?;
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output()?;
    let relay_result = relay.join().map_err(|_| "relay thread panicked")?;
    if !output.status.success() {
        return Err(format!(
            "runner failed: status={} stdout={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    relay_result?;
    assert!(String::from_utf8_lossy(&output.stdout).contains("proxy: PONG"));
    Ok(())
}

#[test]
fn killing_outer_helper_terminates_cli_and_descendant() -> Result<(), Box<dyn std::error::Error>> {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let temp = std::env::temp_dir().join(format!("av-runner-kill-{}-{nonce}", std::process::id()));
    fs::create_dir(&temp)?;
    let result = run_termination_test(&temp);
    fs::remove_dir_all(&temp)?;
    result
}

fn run_termination_test(temp: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let mut spec = RunSpec::new(PathBuf::from(env!("CARGO_BIN_EXE_av-runner-canary")));
    spec.args.push("long-parent".into());
    let _proxy = UnixListener::bind(temp.join("unused.sock"))?;
    let mut command = prepare_command(
        std::path::Path::new(env!("CARGO_BIN_EXE_av-runner-helper")),
        &temp.join("unused.sock"),
        &spec,
    )?;
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut helper = command.spawn()?;
    let test_result = (|| -> Result<(), Box<dyn std::error::Error>> {
        let init_pid = wait_for_child(helper.id(), Duration::from_secs(5))?;
        let parent_pid = wait_for_child(init_pid, Duration::from_secs(5))?;
        let child_pid = wait_for_child(parent_pid, Duration::from_secs(5))?;
        assert!(process_is_running(parent_pid)?);
        assert!(process_is_running(child_pid)?);
        helper.kill()?;
        helper.wait()?;
        let deadline = Instant::now() + Duration::from_secs(3);
        while process_is_running(parent_pid)? || process_is_running(child_pid)? {
            if Instant::now() >= deadline {
                return Err(format!(
                    "CLI process tree survived helper termination: parent={parent_pid}, child={child_pid}"
                )
                .into());
            }
            thread::sleep(Duration::from_millis(10));
        }
        Ok(())
    })();
    if helper.try_wait()?.is_none() {
        helper.kill()?;
        helper.wait()?;
    }
    test_result
}

fn wait_for_child(parent: u32, timeout: Duration) -> io::Result<u32> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(contents) = fs::read_to_string(format!("/proc/{parent}/task/{parent}/children"))
            && let Some(pid) = contents
                .split_whitespace()
                .next()
                .and_then(|value| value.parse().ok())
        {
            return Ok(pid);
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "child process did not start",
            ));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn process_is_running(pid: u32) -> io::Result<bool> {
    let path = format!("/proc/{pid}/status");
    match fs::read_to_string(path) {
        Ok(contents) => Ok(!contents
            .lines()
            .any(|line| line.starts_with("State:") && line.contains("Z (zombie)"))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

#[test]
fn rejects_changed_executable_digest() {
    let mut spec = RunSpec::new(env!("CARGO_BIN_EXE_av-runner-canary"));
    spec.expected_sha256 = Some([0; 32]);
    let error = prepare_command(
        std::path::Path::new(env!("CARGO_BIN_EXE_av-runner-helper")),
        std::path::Path::new("/tmp/unused.sock"),
        &spec,
    )
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
}

#[test]
fn prepared_command_uses_sealed_snapshot_after_path_replacement()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = std::env::temp_dir().join(format!("av-runner-snapshot-{}", std::process::id()));
    fs::create_dir(&temp)?;
    let program = temp.join("command");
    fs::copy("/usr/bin/true", &program)?;
    let socket = temp.join("proxy.sock");
    let _listener = UnixListener::bind(&socket)?;
    let mut spec = RunSpec::new(&program);
    spec.expected_sha256 = Some(av_runner::executable_sha256(&program)?);
    let helper = temp.join("helper");
    fs::copy(env!("CARGO_BIN_EXE_av-runner-helper"), &helper)?;
    let helper_hash = av_runner::executable_sha256(&helper)?;
    let mut command =
        av_runner::prepare_verified_command(&helper, &socket, &spec, Some(helper_hash))?;
    fs::copy("/usr/bin/false", &program)?;
    fs::copy("/usr/bin/false", &helper)?;
    assert!(command.status()?.success());
    fs::remove_dir_all(temp)?;
    Ok(())
}
