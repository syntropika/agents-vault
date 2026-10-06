use std::{env, fs, path::Path};
fn main() {
    let path = Path::new("../../web/dist-mcp/mcp-app.html");
    println!("cargo:rerun-if-changed=../../web/dist-mcp/mcp-app.html");
    let content = if path.is_file() && !path.is_symlink() {
        format!(
            "pub const APP_HTML: &str = include_str!({:?});",
            fs::canonicalize(path).unwrap()
        )
    } else {
        "pub const APP_HTML: &str = \"\";".into()
    };
    fs::write(
        Path::new(&env::var("OUT_DIR").unwrap()).join("mcp_app.rs"),
        content,
    )
    .unwrap();
}
