//! Synthetic command used by the Linux runner integration test.

#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    linux::run()
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("av-runner-canary is only available on Linux");
    std::process::exit(125);
}

#[cfg(target_os = "linux")]
mod linux {
    use std::fs;
    use std::io::{self, Read, Write};
    use std::net::{Shutdown, SocketAddr, TcpStream};
    use std::os::unix::process::CommandExt;
    use std::process::Command;
    use std::thread;
    use std::time::Duration;

    pub fn run() -> Result<(), Box<dyn std::error::Error>> {
        let isolation_only = match std::env::args().nth(1).as_deref() {
            Some("long-parent") => return long_running(true),
            Some("long-child") => return long_running(false),
            Some("isolation-only") => true,
            None => false,
            _ => return Err("unknown canary action".into()),
        };
        let status = thread::spawn(|| fs::read_to_string("/proc/self/status"))
            .join()
            .map_err(|_| "sandbox worker thread panicked")??;
        if !status
            .lines()
            .any(|line| line == "CapEff:\t0000000000000000")
            || !status.lines().any(|line| line == "NoNewPrivs:\t1")
            || !status.lines().any(|line| line == "Seccomp:\t2")
        {
            return Err("child capability or syscall restrictions are absent".into());
        }
        if let Ok(path) = std::env::var("HOST_SECRET_PATH")
            && fs::read(&path).is_ok()
        {
            return Err("host secret was readable".into());
        }
        if let Ok(path) = std::env::var("HOST_SOCKET_PATH")
            && std::os::unix::net::UnixStream::connect(&path).is_ok()
        {
            return Err("host Unix socket was reachable".into());
        }
        if let Ok(pid) = std::env::var("BROKER_HOST_PID")
            && fs::read(format!("/proc/{pid}/environ")).is_ok()
        {
            return Err("broker process environment was visible".into());
        }
        if fs::read_link("/proc/1/root").is_ok() {
            return Err("supervisor root descriptor was accessible".into());
        }
        if unsafe { libc::unshare(libc::CLONE_NEWUSER) } == 0 {
            return Err("child could create another user namespace".into());
        }
        let external: SocketAddr = "1.1.1.1:443".parse()?;
        match TcpStream::connect_timeout(&external, Duration::from_secs(1)) {
            Err(error) if error.raw_os_error() == Some(libc::ENETUNREACH) => {}
            result => {
                return Err(format!("unexpected direct external TCP result: {result:?}").into());
            }
        }

        if isolation_only {
            for path in [
                "/var/lib/agents-vault/vault.db",
                "/run/agents-vault/admin.token",
                "/proc/kmsg",
            ] {
                if fs::read(path).is_ok() {
                    return Err(format!("host-only path was readable: {path}").into());
                }
            }
            if std::os::unix::net::UnixStream::connect("/run/agents-vault/admin.sock").is_ok() {
                return Err("host admin socket was reachable".into());
            }
            if fs::OpenOptions::new()
                .write(true)
                .open("/proc/sys/kernel/hostname")
                .is_ok()
            {
                return Err("host kernel hostname was writable".into());
            }
            println!(
                "isolation: capabilities dropped; namespace creation, host state and direct egress denied"
            );
            return Ok(());
        }

        let host_port: u16 = std::env::var("HOST_TEST_PORT")?.parse()?;
        let host_loopback: SocketAddr = format!("127.0.0.1:{host_port}").parse()?;
        if TcpStream::connect_timeout(&host_loopback, Duration::from_millis(300)).is_ok() {
            return Err("host loopback unexpectedly reachable".into());
        }

        let proxy = std::env::var("HTTPS_PROXY")?;
        let address = proxy.strip_prefix("http://").ok_or("invalid proxy URL")?;
        let mut stream = TcpStream::connect(address)?;
        stream.set_read_timeout(Some(Duration::from_secs(3)))?;
        stream.write_all(b"PING")?;
        stream.shutdown(Shutdown::Write)?;
        let mut response = [0; 4];
        stream.read_exact(&mut response)?;
        if &response != b"PONG" {
            return Err(io::Error::other("wrong synthetic proxy response").into());
        }
        println!("direct TCP: ENETUNREACH; host loopback: blocked; proxy: PONG");
        Ok(())
    }

    fn long_running(parent: bool) -> Result<(), Box<dyn std::error::Error>> {
        if !parent && unsafe { libc::getsid(0) != libc::getpid() } {
            return Err("descendant is not in its detached session".into());
        }
        if parent {
            let mut child = Command::new("/proc/self/exe");
            child.arg("long-child");
            // SAFETY: setsid is async-signal-safe in the post-fork child.
            unsafe {
                child.pre_exec(|| {
                    if libc::setsid() < 0 {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            child.spawn()?;
        }
        loop {
            thread::sleep(Duration::from_secs(1));
        }
    }
}
