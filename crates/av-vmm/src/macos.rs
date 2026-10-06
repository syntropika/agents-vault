use av_vmm::{
    CONTROL_PORT, PROXY_PORT, TaskOutcome, TaskSpec, read_frame, verify_bundle, write_task,
};
use block2::RcBlock;
use objc2::{AnyThread, rc::Retained};
use objc2_foundation::{NSArray, NSDate, NSRunLoop, NSString, NSURL};
use objc2_virtualization::{
    VZEntropyDeviceConfiguration, VZGenericPlatformConfiguration, VZLinuxBootLoader,
    VZSocketDeviceConfiguration, VZVirtioEntropyDeviceConfiguration, VZVirtioSocketConnection,
    VZVirtioSocketDevice, VZVirtioSocketDeviceConfiguration, VZVirtualMachine,
    VZVirtualMachineConfiguration,
};
use std::{
    io,
    net::Shutdown,
    os::{fd::FromRawFd, unix::net::UnixStream},
    path::Path,
    sync::mpsc,
    time::{Duration, Instant},
};

fn file_url(path: &Path) -> io::Result<Retained<NSURL>> {
    let path = path
        .to_str()
        .ok_or_else(|| io::Error::other("guest path must be UTF-8"))?;
    Ok(NSURL::fileURLWithPath(&NSString::from_str(path)))
}

pub fn run() -> io::Result<i32> {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 3 {
        return Err(io::Error::other(
            "usage: av-vmm run <fixed-bundle> (private broker socket on fd 3)",
        ));
    }
    // Refuse a missing or non-socket descriptor instead of opening a public
    // fallback transport. The service launcher owns descriptor provenance.
    unsafe {
        let mut kind: libc::c_int = 0;
        let mut size = std::mem::size_of_val(&kind) as libc::socklen_t;
        if libc::getsockopt(
            3,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut kind as *mut libc::c_int).cast(),
            &mut size,
        ) != 0
            || kind != libc::SOCK_STREAM
        {
            return Err(io::Error::other("private broker stream missing"));
        }
        let mut peer: libc::sockaddr_storage = std::mem::zeroed();
        let mut peer_size = std::mem::size_of_val(&peer) as libc::socklen_t;
        if libc::getpeername(
            3,
            (&mut peer as *mut libc::sockaddr_storage).cast(),
            &mut peer_size,
        ) != 0
            || i32::from(peer.ss_family) != libc::AF_UNIX
        {
            return Err(io::Error::other(
                "broker stream must be a connected Unix socket",
            ));
        }
        libc::fcntl(3, libc::F_SETFD, libc::FD_CLOEXEC);
    }
    let mut broker = unsafe { UnixStream::from_raw_fd(3) };
    if args[1] != "run" {
        return Err(io::Error::other("unsupported av-vmm mode"));
    }
    broker.set_read_timeout(Some(Duration::from_secs(5)))?;
    let task: TaskSpec = read_frame(&mut broker)?;
    task.validate()?;
    let lifetime = Duration::from_secs(task.timeout_secs.into());
    broker.set_read_timeout(Some(lifetime))?;
    broker.set_write_timeout(Some(lifetime))?;
    let (kernel, initramfs) = verify_bundle(Path::new(&args[2]))?;
    let deadline = Instant::now() + lifetime;
    unsafe {
        if !VZVirtualMachine::isSupported() {
            return Err(io::Error::other("Virtualization.framework is unavailable"));
        }
        let config = VZVirtualMachineConfiguration::new();
        config.setCPUCount(2);
        config.setMemorySize(512 * 1024 * 1024);
        config.setPlatform(&VZGenericPlatformConfiguration::new());
        let entropy = VZVirtioEntropyDeviceConfiguration::new();
        let entropy_devices: Retained<NSArray<VZEntropyDeviceConfiguration>> =
            NSArray::from_retained_slice(&[entropy.into_super()]);
        config.setEntropyDevices(&entropy_devices);
        let kernel_url = file_url(&kernel)?;
        let initramfs_url = file_url(&initramfs)?;
        let boot = VZLinuxBootLoader::initWithKernelURL(VZLinuxBootLoader::alloc(), &kernel_url);
        boot.setInitialRamdiskURL(Some(&initramfs_url));
        boot.setCommandLine(&NSString::from_str("console=hvc0 loglevel=3 panic=-1"));
        config.setBootLoader(Some(&boot));
        let socket = VZVirtioSocketDeviceConfiguration::new();
        let sockets: Retained<NSArray<VZSocketDeviceConfiguration>> =
            NSArray::from_retained_slice(&[socket.into_super()]);
        config.setSocketDevices(&sockets);
        if config.networkDevices().count() != 0
            || config.directorySharingDevices().count() != 0
            || config.storageDevices().count() != 0
            || config.socketDevices().count() != 1
        {
            return Err(io::Error::other("unsafe virtual machine configuration"));
        }
        config
            .validateWithError()
            .map_err(|error| io::Error::other(format!("guest configuration: {error:?}")))?;
        let vm = VZVirtualMachine::initWithConfiguration(VZVirtualMachine::alloc(), &config);
        let (started_tx, started_rx) = mpsc::channel();
        let started = RcBlock::new(move |error: *mut objc2_foundation::NSError| {
            let result = if error.is_null() {
                Ok(())
            } else {
                Err(format!("guest start: {:?}", &*error))
            };
            let _ = started_tx.send(result);
        });
        vm.startWithCompletionHandler(&started);
        let run_loop = NSRunLoop::mainRunLoop();
        loop {
            pump(&run_loop, deadline)?;
            match started_rx.try_recv() {
                Ok(result) => {
                    result.map_err(io::Error::other)?;
                    break;
                }
                Err(mpsc::TryRecvError::Empty) => (),
                Err(error) => return Err(io::Error::other(error)),
            }
        }
        let devices = vm.socketDevices();
        let device = devices.objectAtIndex(0);
        let socket = device
            .downcast_ref::<VZVirtioSocketDevice>()
            .ok_or_else(|| io::Error::other("missing virtio socket"))?;
        let (control, _control_connection) = connect(socket, CONTROL_PORT, &run_loop, deadline)?;
        let (proxy, _proxy_connection) = connect(socket, PROXY_PORT, &run_loop, deadline)?;
        let (result_tx, result_rx) = mpsc::channel();
        std::thread::spawn(move || {
            let result = exchange(control, proxy, broker, task);
            let _ = result_tx.send(result);
        });
        let outcome = loop {
            pump(&run_loop, deadline)?;
            match result_rx.try_recv() {
                Ok(result) => break result?,
                Err(mpsc::TryRecvError::Empty) => (),
                Err(error) => return Err(io::Error::other(error)),
            }
        };
        while vm.state().0 != 0 {
            pump(&run_loop, deadline)?;
        }
        Ok(outcome.exit_code.clamp(0, 255))
    }
}

fn pump(run_loop: &NSRunLoop, deadline: Instant) -> io::Result<()> {
    if Instant::now() >= deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "guest deadline exceeded",
        ));
    }
    run_loop.runUntilDate(&NSDate::dateWithTimeIntervalSinceNow(0.05));
    Ok(())
}

unsafe fn connect(
    device: &VZVirtioSocketDevice,
    port: u32,
    run_loop: &NSRunLoop,
    deadline: Instant,
) -> io::Result<(UnixStream, Retained<VZVirtioSocketConnection>)> {
    // A running VM may still be loading initramfs modules. Retry connection
    // refusal until the same broker task deadline; never fall back to IP.
    loop {
        let (tx, rx) = mpsc::channel();
        let callback = RcBlock::new(
            move |connection: *mut VZVirtioSocketConnection,
                  error: *mut objc2_foundation::NSError| {
                let result = if !error.is_null() || connection.is_null() {
                    None
                } else {
                    let fd = unsafe { libc::dup((&*connection).fileDescriptor()) };
                    if fd < 0 {
                        None
                    } else {
                        Some(unsafe {
                            (
                                UnixStream::from_raw_fd(fd),
                                Retained::retain(connection).unwrap(),
                            )
                        })
                    }
                };
                let _ = tx.send(result);
            },
        );
        unsafe {
            device.connectToPort_completionHandler(port, &callback);
        }
        loop {
            pump(run_loop, deadline)?;
            match rx.try_recv() {
                Ok(Some(stream)) => return Ok(stream),
                Ok(None) => break,
                Err(mpsc::TryRecvError::Empty) => (),
                Err(error) => return Err(io::Error::other(error)),
            }
        }
        pump(run_loop, deadline)?;
    }
}

fn exchange(
    mut control: UnixStream,
    proxy: UnixStream,
    mut broker: UnixStream,
    task: TaskSpec,
) -> io::Result<TaskOutcome> {
    let timeout = Some(Duration::from_secs(task.timeout_secs.into()));
    control.set_read_timeout(timeout)?;
    control.set_write_timeout(timeout)?;
    proxy.set_read_timeout(timeout)?;
    proxy.set_write_timeout(timeout)?;
    write_task(&mut control, &task)?;
    let mut broker_read = broker.try_clone()?;
    let mut proxy_write = proxy.try_clone()?;
    let mut proxy_read = proxy.try_clone()?;
    std::thread::spawn(move || {
        let _ = io::copy(&mut broker_read, &mut proxy_write);
        let _ = proxy_write.shutdown(Shutdown::Write);
    });
    std::thread::spawn(move || {
        let _ = io::copy(&mut proxy_read, &mut broker);
        let _ = broker.shutdown(Shutdown::Write);
    });
    let outcome = read_frame(&mut control);
    let _ = proxy.shutdown(Shutdown::Both);
    outcome
}
