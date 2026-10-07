use std::{env, fs, path::Path};

fn main() {
    let packaged = Path::new("assets");
    let root = if packaged.is_dir() {
        packaged
    } else {
        Path::new("../../web/dist")
    };
    println!("cargo:rerun-if-changed=assets");
    println!("cargo:rerun-if-changed=../../web/dist");
    let mut entries = Vec::new();
    fn collect(root: &Path, directory: &Path, entries: &mut Vec<(String, String)>) {
        if let Ok(files) = fs::read_dir(directory) {
            for file in files.flatten() {
                let path = file.path();
                if path.is_symlink() {
                    continue;
                }
                if path.is_dir() {
                    collect(root, &path, entries);
                } else if path.is_file() && !path.is_symlink() {
                    let name = path
                        .strip_prefix(root)
                        .unwrap()
                        .to_string_lossy()
                        .replace('\\', "/");
                    entries.push((
                        name,
                        fs::canonicalize(path)
                            .unwrap()
                            .to_string_lossy()
                            .into_owned(),
                    ));
                }
            }
        }
    }
    collect(root, root, &mut entries);
    entries.sort();
    if entries.is_empty() {
        fs::write(
            Path::new(&env::var("OUT_DIR").unwrap()).join("web_assets.rs"),
            "pub fn asset(_path: &str) -> Option<(&'static [u8], &'static str)> { None }\n",
        )
        .unwrap();
        return;
    }
    let mut output = String::from(
        "pub fn asset(path: &str) -> Option<(&'static [u8], &'static str)> { match path {\n",
    );
    for (name, path) in entries {
        let mime = if name.ends_with(".js") {
            "text/javascript; charset=utf-8"
        } else if name.ends_with(".css") {
            "text/css; charset=utf-8"
        } else if name.ends_with(".html") {
            "text/html; charset=utf-8"
        } else {
            continue;
        };
        output.push_str(&format!(
            "{:?} => Some((include_bytes!({:?}), {:?})),\n",
            format!("/{name}"),
            path,
            mime
        ));
    }
    output.push_str("_ => None } }\n");
    fs::write(
        Path::new(&env::var("OUT_DIR").unwrap()).join("web_assets.rs"),
        output,
    )
    .unwrap();
}
