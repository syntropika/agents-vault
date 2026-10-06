//! The installed root service has no configurable executable, identity, or path.
fn main() {
    #[cfg(target_os = "macos")]
    let result = av_vmm::service::run_supervisor();
    #[cfg(not(target_os = "macos"))]
    let result: std::io::Result<()> = Err(std::io::Error::other("macOS is required"));
    if let Err(error) = result {
        eprintln!("av-supervisor: {error}");
        std::process::exit(1);
    }
}
