#[cfg(target_os = "macos")]
mod macos;

fn main() {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    let result = macos::run();
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    let result: std::io::Result<i32> = Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "av-vmm currently requires Apple silicon macOS",
    ));
    match result {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("av-vmm: {error}");
            std::process::exit(1);
        }
    }
}
