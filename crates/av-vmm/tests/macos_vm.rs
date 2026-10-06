#![cfg(target_os = "macos")]

use av_vmm::{TaskSpec, prepare_command, write_task};
use std::{
    fs,
    io::Read,
    os::unix::net::UnixStream,
    path::PathBuf,
    process::{Child, Stdio},
    time::{Duration, Instant},
};

fn inputs() -> (PathBuf, PathBuf) {
    (
        std::env::var_os("AVD_TEST_VMM")
            .expect("set AVD_TEST_VMM")
            .into(),
        std::env::var_os("AVD_TEST_GUEST_BUNDLE")
            .expect("set AVD_TEST_GUEST_BUNDLE")
            .into(),
    )
}

fn launch(bundle: &std::path::Path, timeout_secs: u32) -> (Child, UnixStream) {
    let (vmm, _) = inputs();
    let ca = rcgen::generate_simple_self_signed(vec!["api.example.test".into()]).unwrap();
    let (mut command, mut stream) = prepare_command(&vmm, bundle).unwrap();
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let child = command.spawn().unwrap();
    drop(command);
    write_task(
        &mut stream,
        &TaskSpec {
            args: [
                "request",
                "--host",
                "api.example.test",
                "--method",
                "get",
                "--path",
                "/probe",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
            ca_pem: ca.cert.pem(),
            timeout_secs,
        },
    )
    .unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    (child, stream)
}

fn expect_connect(child: &mut Child, stream: &mut UnixStream) {
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        let mut byte = [0_u8];
        if let Err(error) = stream.read_exact(&mut byte) {
            let _ = child.kill();
            let status = child.wait().unwrap();
            let mut stderr = String::new();
            child
                .stderr
                .take()
                .unwrap()
                .read_to_string(&mut stderr)
                .unwrap();
            panic!(
                "guest proxy did not open: {error}; status={}; stderr={}",
                status, stderr
            );
        }
        header.push(byte[0]);
        assert!(header.len() < 16 * 1024);
    }
    let header = std::str::from_utf8(&header).unwrap();
    assert!(header.starts_with("CONNECT api.example.test:443 HTTP/1.1\r\n"));
    assert!(!header.to_ascii_lowercase().contains("proxy-authorization"));
    // The observed CONNECT proves the guest fixture reached its proxy after
    // passing its mandatory direct TCP ENETUNREACH assertion.
}

#[test]
#[ignore = "requires a signed native VMM and packaged guest on Apple silicon"]
fn cancellation_closes_the_private_guest_transport() {
    let (_, bundle) = inputs();
    let (mut child, mut stream) = launch(&bundle, 20);
    expect_connect(&mut child, &mut stream);
    child.kill().unwrap();
    let status = child.wait().unwrap();
    assert!(!status.success());
    assert_eq!(stream.read(&mut [0_u8]).unwrap(), 0);
}

#[test]
#[ignore = "requires a signed native VMM and packaged guest on Apple silicon"]
fn disconnected_broker_stops_the_guest_before_its_deadline() {
    let (_, bundle) = inputs();
    let (mut child, mut stream) = launch(&bundle, 30);
    expect_connect(&mut child, &mut stream);
    let disconnected = Instant::now();
    drop(stream);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(!status.success());
            break;
        }
        if disconnected.elapsed() >= Duration::from_secs(5) {
            child.kill().unwrap();
            let output = child.wait_with_output().unwrap();
            panic!(
                "guest survived broker disconnection; stderr={}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

#[test]
#[ignore = "requires a signed native VMM and packaged guest on Apple silicon"]
fn fresh_guests_boot_after_repeated_vmm_process_death() {
    let (_, bundle) = inputs();
    for _ in 0..3 {
        let (mut child, mut stream) = launch(&bundle, 20);
        expect_connect(&mut child, &mut stream);
        child.kill().unwrap();
        assert!(!child.wait().unwrap().success());
        assert_eq!(stream.read(&mut [0_u8]).unwrap(), 0);
    }
}

#[test]
#[ignore = "requires a signed native VMM and packaged guest on Apple silicon"]
fn unanswered_proxy_expires_with_the_vm_deadline() {
    let (_, bundle) = inputs();
    let started = Instant::now();
    let (child, _stream) = launch(&bundle, 3);
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert!(started.elapsed() < Duration::from_secs(8));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("deadline"),
        "status={}; stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore = "requires a signed native VMM and packaged guest on Apple silicon"]
fn changed_guest_image_is_rejected_before_boot() {
    let (_, bundle) = inputs();
    let modified = tempfile::tempdir().unwrap();
    fs::copy(
        bundle.join("guest.json"),
        modified.path().join("guest.json"),
    )
    .unwrap();
    fs::write(modified.path().join("Image"), b"modified image").unwrap();
    fs::write(modified.path().join("initramfs.gz"), b"modified guest").unwrap();
    let (child, _stream) = launch(modified.path(), 10);
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("integrity failure"));
}
