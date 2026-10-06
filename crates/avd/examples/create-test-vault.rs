//! Create a deliberately synthetic vault for disposable service tests.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .ok_or("expected a new test vault path")?;
    let created = av_core::create_vault(
        std::path::Path::new(&path),
        "synthetic-service-test-passphrase",
    )?;
    created
        .vault
        .set("demo/provider-token", "av-synthetic-systemd-fixture")?;
    Ok(())
}
