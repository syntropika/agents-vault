//! Bundled Linux namespace helper for `av-runner`.

#[cfg(target_os = "linux")]
mod linux {
    use std::env;
    use std::ffi::{CString, OsString};
    use std::fs;
    use std::io;
    use std::net::{TcpListener, TcpStream};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::{CommandExt, ExitStatusExt};
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::thread;
    use std::time::Duration;

    const MAX_CONNECTIONS: usize = 32;

    pub fn main() -> Result<i32, Box<dyn std::error::Error>> {
        let mut args = env::args_os().skip(1);
        let action = args.next().ok_or("missing helper action")?;
        let remaining: Vec<OsString> = args.collect();
        let launch = parse_launch(&remaining)?;
        match action.to_str() {
            Some("run") => outer(remaining, &launch),
            Some("inner") => inner(launch),
            _ => Err("expected `run` or `inner`".into()),
        }
    }

    struct Launch {
        socket: PathBuf,
        child_env: Vec<(OsString, OsString)>,
        program: PathBuf,
        arguments: Vec<OsString>,
        helper_fd: i32,
        program_fd: i32,
        ca: Option<PathBuf>,
        root: Option<PathBuf>,
    }

    fn parse_launch(args: &[OsString]) -> Result<Launch, Box<dyn std::error::Error>> {
        let mut args = args.iter().cloned();
        let socket = PathBuf::from(args.next().ok_or("missing host proxy socket")?);
        let mut child_env = Vec::new();
        let mut helper_fd = None;
        let mut program_fd = None;
        let mut ca = None;
        let mut root = None;
        loop {
            match args.next() {
                Some(token) if token == "--helper-fd" => {
                    helper_fd = Some(
                        args.next()
                            .ok_or("missing helper fd")?
                            .to_str()
                            .ok_or("invalid fd")?
                            .parse::<i32>()?,
                    );
                }
                Some(token) if token == "--program-fd" => {
                    program_fd = Some(
                        args.next()
                            .ok_or("missing program fd")?
                            .to_str()
                            .ok_or("invalid fd")?
                            .parse::<i32>()?,
                    );
                }
                Some(token) if token == "--root" => {
                    root = Some(PathBuf::from(args.next().ok_or("missing sandbox root")?));
                }
                Some(token) if token == "--ca" => {
                    ca = Some(PathBuf::from(args.next().ok_or("missing CA file")?));
                }
                Some(token) if token == "--env" => {
                    let key = args.next().ok_or("missing environment name")?;
                    let value = args.next().ok_or("missing environment value")?;
                    child_env.push((key, value));
                }
                Some(token) if token == "--" => break,
                _ => return Err("expected `--env NAME VALUE` or `--`".into()),
            }
        }
        let program = PathBuf::from(args.next().ok_or("missing command")?);
        let arguments: Vec<OsString> = args.collect();
        if !socket.is_absolute() || !program.is_absolute() {
            return Err("socket and command paths must be absolute".into());
        }
        Ok(Launch {
            socket,
            child_env,
            program,
            arguments,
            helper_fd: helper_fd.ok_or("missing sealed helper fd")?,
            program_fd: program_fd.ok_or("missing sealed program fd")?,
            ca,
            root,
        })
    }

    fn outer(
        mut remaining: Vec<OsString>,
        launch: &Launch,
    ) -> Result<i32, Box<dyn std::error::Error>> {
        verify_sealed_fd(launch.helper_fd)?;
        verify_sealed_fd(launch.program_fd)?;
        close_inherited_descriptors(&[launch.helper_fd, launch.program_fd])?;
        let root = std::env::temp_dir().join(format!(
            "av-runner-root-{}-{}",
            unsafe { libc::getpid() },
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        fs::create_dir(&root)?;
        struct RootCleanup(PathBuf);
        impl Drop for RootCleanup {
            fn drop(&mut self) {
                let _ = fs::remove_dir(&self.0);
            }
        }
        let _cleanup = RootCleanup(root.clone());
        remaining.splice(1..1, [OsString::from("--root"), root.into_os_string()]);
        enter_namespaces()
            .map_err(|error| io::Error::new(error.kind(), format!("namespace setup: {error}")))?;
        if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        let parent_pid = unsafe { libc::getpid() };
        let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, parent_pid, 0) };
        if pidfd < 0 {
            return Err(io::Error::last_os_error().into());
        }
        let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd as libc::c_int) };
        let parent_fd = pidfd.as_raw_fd();
        let mut command = Command::new(format!("/proc/self/fd/{}", launch.helper_fd));
        command.arg("inner").args(remaining).env_clear();
        // SAFETY: the closure calls only libc functions between fork and exec.
        // PDEATHSIG and the parent's pidfd close the race where the broker
        // kills this outer helper while namespace PID 1 is starting.
        unsafe {
            command.pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                    return Err(io::Error::last_os_error());
                }
                let mut pollfd = libc::pollfd {
                    fd: parent_fd,
                    events: libc::POLLIN,
                    revents: 0,
                };
                let polled = libc::poll(&mut pollfd, 1, 0);
                if polled < 0 {
                    return Err(io::Error::last_os_error());
                }
                if polled != 0 {
                    libc::_exit(125);
                }
                Ok(())
            });
        }
        let status = command.status().map_err(|error| {
            io::Error::new(error.kind(), format!("namespace supervisor: {error}"))
        })?;
        Ok(exit_code(status))
    }

    fn inner(mut launch: Launch) -> Result<i32, Box<dyn std::error::Error>> {
        if unsafe { libc::getpid() } != 1 {
            return Err("inner helper is not PID 1 in a private namespace".into());
        }
        if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        prepare_filesystem(&launch)
            .map_err(|error| io::Error::new(error.kind(), format!("filesystem setup: {error}")))?;
        launch.socket = PathBuf::from("/run/proxy.sock");
        unsafe {
            libc::close(launch.helper_fd);
        }
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let proxy_url = format!("http://{}", listener.local_addr()?);
        let stop = Arc::new(AtomicBool::new(false));
        let relay = thread::spawn({
            let stop = Arc::clone(&stop);
            move || serve_local_proxy(listener, launch.socket, stop)
        });

        let mut child = Command::new(format!("/proc/self/fd/{}", launch.program_fd));
        child
            .arg0(launch.program)
            .args(launch.arguments)
            .env_clear()
            .envs(launch.child_env)
            .env("HTTP_PROXY", &proxy_url)
            .env("HTTPS_PROXY", &proxy_url)
            .env("http_proxy", &proxy_url)
            .env("https_proxy", &proxy_url)
            .current_dir("/tmp");
        let program_fd = launch.program_fd;
        // SAFETY: confinement uses only syscalls and stack data after fork.
        unsafe {
            child.pre_exec(move || {
                if libc::fcntl(program_fd, libc::F_SETFD, libc::FD_CLOEXEC) < 0 {
                    return Err(io::Error::last_os_error());
                }
                confine_child()
            });
        }
        let status = child.status();
        stop.store(true, Ordering::Release);
        relay.join().map_err(|_| "proxy relay thread panicked")??;
        let status = status?;
        Ok(exit_code(status))
    }

    fn exit_code(status: std::process::ExitStatus) -> i32 {
        status
            .code()
            .unwrap_or_else(|| 128 + status.signal().unwrap_or(1))
    }

    fn enter_namespaces() -> io::Result<()> {
        let host_uid = unsafe { libc::geteuid() };
        let host_gid = unsafe { libc::getegid() };
        if unsafe {
            libc::unshare(
                libc::CLONE_NEWUSER | libc::CLONE_NEWNET | libc::CLONE_NEWPID | libc::CLONE_NEWNS,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        fs::write("/proc/self/setgroups", "deny")
            .map_err(|error| io::Error::new(error.kind(), format!("setgroups map: {error}")))?;
        fs::write("/proc/self/uid_map", format!("0 {host_uid} 1\n"))
            .map_err(|error| io::Error::new(error.kind(), format!("UID map: {error}")))?;
        fs::write("/proc/self/gid_map", format!("0 {host_gid} 1\n"))
            .map_err(|error| io::Error::new(error.kind(), format!("GID map: {error}")))?;
        bring_loopback_up()
    }

    fn verify_sealed_fd(fd: i32) -> io::Result<()> {
        let required =
            libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
        if fd <= 2 || unsafe { libc::fcntl(fd, libc::F_GET_SEALS) } & required != required {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "executable fd is not sealed",
            ));
        }
        Ok(())
    }

    fn close_inherited_descriptors(keep: &[i32]) -> io::Result<()> {
        for fd in 0..=2 {
            let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
            if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } == 0
                && unsafe { stat.assume_init() }.st_mode & libc::S_IFMT == libc::S_IFSOCK
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "network sockets are forbidden in stdio",
                ));
            }
        }
        let descriptors: Vec<i32> = fs::read_dir("/proc/self/fd")?
            .filter_map(|entry| entry.ok()?.file_name().to_str()?.parse().ok())
            .collect();
        for fd in descriptors {
            if fd > 2 && !keep.contains(&fd) {
                unsafe {
                    libc::close(fd);
                }
            }
        }
        Ok(())
    }

    fn path_string(path: &Path) -> io::Result<CString> {
        CString::new(path.as_os_str().as_bytes()).map_err(|_| io::Error::other("NUL in mount path"))
    }

    fn mount(
        source: Option<&Path>,
        target: &Path,
        kind: Option<&str>,
        flags: libc::c_ulong,
        data: Option<&str>,
    ) -> io::Result<()> {
        let source = source.map(path_string).transpose()?;
        let target = path_string(target)?;
        let kind = kind
            .map(CString::new)
            .transpose()
            .map_err(io::Error::other)?;
        let data = data
            .map(CString::new)
            .transpose()
            .map_err(io::Error::other)?;
        if unsafe {
            libc::mount(
                source.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()),
                target.as_ptr(),
                kind.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()),
                flags,
                data.as_ref()
                    .map_or(std::ptr::null(), |s| s.as_ptr().cast()),
            )
        } != 0
        {
            let error = io::Error::last_os_error();
            return Err(io::Error::new(
                error.kind(),
                format!("mount target {target:?}: {error}"),
            ));
        }
        Ok(())
    }

    fn bind(source: &Path, target: &Path, readonly: bool) -> io::Result<()> {
        if source.is_dir() {
            fs::create_dir_all(target)?;
        } else {
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(target, [])?;
        }
        mount(
            Some(source),
            target,
            None,
            libc::MS_BIND | libc::MS_REC,
            None,
        )?;
        if readonly {
            // Apply read-only recursively, including any nested source mounts.
            #[repr(C)]
            struct MountAttr {
                set: u64,
                clear: u64,
                propagation: u64,
                userns: u64,
            }
            let attr = MountAttr {
                set: 1 | 2 | 4,
                clear: 0,
                propagation: 0,
                userns: 0,
            };
            let target = path_string(target)?;
            if unsafe {
                libc::syscall(
                    libc::SYS_mount_setattr,
                    libc::AT_FDCWD,
                    target.as_ptr(),
                    0x8000u32,
                    &attr,
                    std::mem::size_of::<MountAttr>(),
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    fn prepare_filesystem(launch: &Launch) -> io::Result<()> {
        if unsafe { libc::unshare(libc::CLONE_NEWNS) } != 0 {
            let error = io::Error::last_os_error();
            return Err(io::Error::new(
                error.kind(),
                format!("filesystem mount namespace: {error}"),
            ));
        }
        mount(
            None,
            Path::new("/"),
            None,
            libc::MS_REC | libc::MS_PRIVATE,
            None,
        )?;
        let root = launch
            .root
            .as_ref()
            .ok_or_else(|| io::Error::other("missing private mount root"))?;
        mount(
            None,
            root,
            Some("tmpfs"),
            libc::MS_NOSUID | libc::MS_NODEV,
            Some("size=16m,mode=0755"),
        )?;
        for path in ["usr", "bin", "lib", "lib64"] {
            let source = Path::new("/").join(path);
            if source.exists() {
                bind(&fs::canonicalize(&source)?, &root.join(path), true)?;
            }
        }
        for device in ["null", "zero", "random", "urandom"] {
            bind(
                &Path::new("/dev").join(device),
                &root.join("dev").join(device),
                false,
            )?;
        }
        fs::create_dir_all(root.join("proc"))?;
        mount(
            Some(Path::new("proc")),
            &root.join("proc"),
            Some("proc"),
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            None,
        )?;
        fs::create_dir_all(root.join("tmp"))?;
        mount(
            None,
            &root.join("tmp"),
            Some("tmpfs"),
            libc::MS_NOSUID | libc::MS_NODEV,
            Some("size=64m,mode=1777"),
        )?;
        bind(&launch.socket, &root.join("run/proxy.sock"), true)?;
        if let Some(ca) = &launch.ca {
            bind(ca, &root.join("run/ca.pem"), true)?;
        }
        fs::create_dir(root.join("old-root"))?;
        std::env::set_current_dir(root)?;
        if unsafe { libc::syscall(libc::SYS_pivot_root, c".".as_ptr(), c"old-root".as_ptr()) } != 0
        {
            return Err(io::Error::last_os_error());
        }
        std::env::set_current_dir("/")?;
        if unsafe { libc::umount2(c"/old-root".as_ptr(), libc::MNT_DETACH) } != 0 {
            return Err(io::Error::last_os_error());
        }
        fs::remove_dir("/old-root")?;
        mount(
            None,
            Path::new("/"),
            None,
            libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV,
            None,
        )?;
        Ok(())
    }

    fn confine_child() -> io::Result<()> {
        #[repr(C)]
        struct CapHeader {
            version: u32,
            pid: i32,
        }
        #[repr(C)]
        struct CapData {
            effective: u32,
            permitted: u32,
            inheritable: u32,
        }
        for capability in 0..=40 {
            if unsafe { libc::prctl(libc::PR_CAPBSET_DROP, capability, 0, 0, 0) } != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        let header = CapHeader {
            version: 0x20080522,
            pid: 0,
        };
        let data = [
            CapData {
                effective: 0,
                permitted: 0,
                inheritable: 0,
            },
            CapData {
                effective: 0,
                permitted: 0,
                inheritable: 0,
            },
        ];
        if unsafe { libc::syscall(libc::SYS_capset, &header, &data) } != 0
            || unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0
        {
            return Err(io::Error::last_os_error());
        }
        // Deny new namespace/mount and process-memory access even if a child
        // creates another user namespace through clone. Native ELF only.
        let blocked = [
            libc::SYS_unshare,
            libc::SYS_setns,
            libc::SYS_mount,
            libc::SYS_umount2,
            libc::SYS_pivot_root,
            libc::SYS_chroot,
            libc::SYS_ptrace,
            libc::SYS_process_vm_readv,
            libc::SYS_process_vm_writev,
            libc::SYS_open_tree,
            libc::SYS_move_mount,
            libc::SYS_fsopen,
            libc::SYS_fsmount,
            libc::SYS_fspick,
            libc::SYS_mount_setattr,
            libc::SYS_clone3,
        ];
        let mut filters = [libc::sock_filter {
            code: 0,
            jt: 0,
            jf: 0,
            k: 0,
        }; 40];
        #[cfg(target_arch = "x86_64")]
        let arch = 0xc000003e;
        #[cfg(target_arch = "aarch64")]
        let arch = 0xc00000b7;
        filters[0] = libc::sock_filter {
            code: 0x20,
            jt: 0,
            jf: 0,
            k: 4,
        };
        filters[1] = libc::sock_filter {
            code: 0x15,
            jt: 1,
            jf: 0,
            k: arch,
        };
        filters[2] = libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x80000000,
        };
        filters[3] = libc::sock_filter {
            code: 0x20,
            jt: 0,
            jf: 0,
            k: 0,
        };
        let mut index = 4;
        // x32 uses the x86_64 arch marker but a distinct syscall number range.
        filters[index] = libc::sock_filter {
            code: 0x45,
            jt: 0,
            jf: 1,
            k: 0x40000000,
        };
        index += 1;
        filters[index] = libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x80000000,
        };
        index += 1;
        for syscall in blocked {
            filters[index] = libc::sock_filter {
                code: 0x15,
                jt: 0,
                jf: 1,
                k: syscall as u32,
            };
            filters[index + 1] = libc::sock_filter {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: 0x00050000
                    | if syscall == libc::SYS_clone3 {
                        libc::ENOSYS
                    } else {
                        libc::EPERM
                    } as u32,
            };
            index += 2;
        }
        filters[index] = libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x7fff0000,
        };
        let program = libc::sock_fprog {
            len: (index + 1) as u16,
            filter: filters.as_mut_ptr(),
        };
        if unsafe { libc::prctl(libc::PR_SET_SECCOMP, 2, &program) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn serve_local_proxy(
        listener: TcpListener,
        socket: PathBuf,
        stop: Arc<AtomicBool>,
    ) -> io::Result<()> {
        let active = Arc::new(AtomicUsize::new(0));
        while !stop.load(Ordering::Acquire) {
            match listener.accept() {
                Ok((client, _)) => {
                    if active.fetch_add(1, Ordering::AcqRel) >= MAX_CONNECTIONS {
                        active.fetch_sub(1, Ordering::AcqRel);
                        drop(client);
                        continue;
                    }
                    let socket = socket.clone();
                    let active = Arc::clone(&active);
                    thread::spawn(move || {
                        let _ = bridge(client, &socket);
                        active.fetch_sub(1, Ordering::AcqRel);
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    fn bridge(mut tcp: TcpStream, socket: &Path) -> io::Result<()> {
        let mut unix = UnixStream::connect(socket)?;
        let mut request_source = tcp.try_clone()?;
        let mut request_destination = unix.try_clone()?;
        let requests = thread::spawn(move || -> io::Result<()> {
            io::copy(&mut request_source, &mut request_destination)?;
            request_destination.shutdown(std::net::Shutdown::Write)
        });
        let response = io::copy(&mut unix, &mut tcp);
        let _ = tcp.shutdown(std::net::Shutdown::Write);
        requests
            .join()
            .map_err(|_| io::Error::other("request relay panicked"))??;
        response.map(|_| ())
    }

    #[repr(C)]
    struct IfReq {
        name: [libc::c_char; libc::IFNAMSIZ],
        data: [u8; 24],
    }

    fn bring_loopback_up() -> io::Result<()> {
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let result = (|| {
            let mut req = IfReq {
                name: [0; libc::IFNAMSIZ],
                data: [0; 24],
            };
            req.name[0] = b'l' as libc::c_char;
            req.name[1] = b'o' as libc::c_char;
            if unsafe { libc::ioctl(fd, libc::SIOCGIFFLAGS, &mut req) } < 0 {
                return Err(io::Error::last_os_error());
            }
            let flags = i16::from_ne_bytes([req.data[0], req.data[1]]) | libc::IFF_UP as i16;
            req.data[..2].copy_from_slice(&flags.to_ne_bytes());
            if unsafe { libc::ioctl(fd, libc::SIOCSIFFLAGS, &req) } < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        })();
        unsafe { libc::close(fd) };
        result
    }
}

#[cfg(target_os = "linux")]
fn main() {
    match linux::main() {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("av-runner-helper: {error}");
            std::process::exit(125);
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("av-runner-helper is only available on Linux");
    std::process::exit(125);
}
