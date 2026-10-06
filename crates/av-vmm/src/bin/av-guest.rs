#[cfg(target_os = "linux")]
fn main() -> std::io::Result<()> {
    use av_vmm::{CONTROL_PORT, PROXY_PORT, TaskOutcome, TaskSpec, read_frame, write_frame};
    use std::{
        fs, io,
        net::{Shutdown, TcpListener},
        os::{
            fd::{AsRawFd, FromRawFd, OwnedFd},
            unix::{fs::PermissionsExt, net::UnixStream, process::CommandExt},
        },
        process::{Command, Stdio},
        time::{Duration, Instant},
    };

    fn listener(port: u32) -> io::Result<OwnedFd> {
        let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut address: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
        address.svm_family = libc::AF_VSOCK as _;
        address.svm_port = port;
        address.svm_cid = libc::VMADDR_CID_ANY;
        if unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&address as *const libc::sockaddr_vm).cast(),
                std::mem::size_of_val(&address) as _,
            )
        } != 0
            || unsafe { libc::listen(fd.as_raw_fd(), 1) } != 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(fd)
    }
    fn accept(listener: &OwnedFd) -> io::Result<UnixStream> {
        let fd = unsafe {
            libc::accept4(
                listener.as_raw_fd(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                libc::SOCK_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { UnixStream::from_raw_fd(fd) })
    }

    let control_listener = listener(CONTROL_PORT)?;
    let proxy_listener = listener(PROXY_PORT)?;
    let mut control = accept(&control_listener)?;
    control.set_read_timeout(Some(Duration::from_secs(5)))?;
    control.set_write_timeout(Some(Duration::from_secs(5)))?;
    let task: TaskSpec = read_frame(&mut control)?;
    task.validate()?;
    let mut proxy = accept(&proxy_listener)?;
    drop(control_listener);
    drop(proxy_listener);
    let timeout = Some(Duration::from_secs(task.timeout_secs.into()));
    proxy.set_read_timeout(timeout)?;
    proxy.set_write_timeout(timeout)?;
    fs::create_dir_all("/run/av")?;
    fs::write("/run/av/ca.pem", &task.ca_pem)?;
    fs::set_permissions("/run/av/ca.pem", fs::Permissions::from_mode(0o444))?;
    let localhost = TcpListener::bind("127.0.0.1:0")?;
    let proxy_url = format!("http://{}", localhost.local_addr()?);
    let proxy_shutdown = proxy.try_clone()?;
    std::thread::spawn(move || -> io::Result<()> {
        let (mut child, _) = localhost.accept()?;
        child.set_read_timeout(timeout)?;
        child.set_write_timeout(timeout)?;
        let mut child_write = child.try_clone()?;
        let mut proxy_read = proxy.try_clone()?;
        std::thread::spawn(move || {
            let _ = io::copy(&mut proxy_read, &mut child_write);
            let _ = child_write.shutdown(Shutdown::Write);
        });
        let _ = io::copy(&mut child, &mut proxy);
        let _ = proxy.shutdown(Shutdown::Write);
        Ok(())
    });
    let mut command = Command::new("/usr/bin/av-fixture");
    command.args(&task.args);
    if !task
        .args
        .iter()
        .any(|arg| arg == "--assert-direct-tcp-blocked")
    {
        command.arg("--assert-direct-tcp-blocked");
    }
    let command = command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", "/run/av")
        .env("HTTPS_PROXY", proxy_url)
        .env("SSL_CERT_FILE", "/run/av/ca.pem")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .uid(65534)
        .gid(65534)
        .process_group(0);
    command.env("AV_FIXTURE_TOKEN", "av-placeholder");
    let mut child = command.spawn()?;
    let deadline = Instant::now() + Duration::from_secs(task.timeout_secs.into());
    let exit_code = loop {
        if let Some(status) = child.try_wait()? {
            break status.code().unwrap_or(1);
        }
        if Instant::now() >= deadline {
            unsafe {
                libc::kill(-(child.id() as i32), libc::SIGKILL);
            }
            let _ = child.kill();
            let _ = child.wait();
            break 124;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let _ = proxy_shutdown.shutdown(Shutdown::Both);
    write_frame(&mut control, &TaskOutcome { exit_code })?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("av-guest runs only inside the packaged Linux guest");
    std::process::exit(1);
}
