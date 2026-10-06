#[cfg(target_os = "linux")]
fn main() {
    match av_runner::service::client_main() {
        Ok(status) => std::process::exit(status),
        Err(error) => {
            eprintln!("av-runner-client: {error}");
            std::process::exit(125);
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("av-runner-client requires Linux");
    std::process::exit(125);
}
