#[cfg(target_os = "linux")]
fn main() {
    match av_runner::service::server_main() {
        Ok(()) => {}
        Err(error) => {
            eprintln!("av-runner-service: {error}");
            std::process::exit(125);
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("av-runner-service requires Linux");
    std::process::exit(125);
}
