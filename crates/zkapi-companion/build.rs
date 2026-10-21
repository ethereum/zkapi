mod build_support;

use std::fs;
use std::path::PathBuf;

fn main() {
    let manifest = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let output_dir = PathBuf::from(std::env::var_os("OUT_DIR").expect("out dir"));
    println!("cargo:rerun-if-env-changed=ZKAPI_FRONTEND_DIST");
    println!("cargo:rerun-if-changed=build_support.rs");
    let supplied = std::env::var_os("ZKAPI_FRONTEND_DIST");
    let root = match supplied.as_ref() {
        Some(path) if path.is_empty() => {
            panic!("ZKAPI_FRONTEND_DIST must name a prebuilt static directory, or be unset")
        }
        Some(path) => manifest.join(path),
        None => manifest.join("static/funding"),
    };
    // Cargo's directory tracking includes additions/removals; no Node, network,
    // proof generation or frontend source checkout is needed to compile Rust.
    println!("cargo:rerun-if-changed={}", root.display());
    let files = build_support::frontend_assets(&root)
        .unwrap_or_else(|error| panic!("Cannot embed frontend {}: {error}", root.display()));
    let mut generated = format!(
        "#[cfg(test)]\npub(crate) const EMBEDDED_FUNDING_IS_DEFAULT: bool = {};\n\
         pub(crate) fn embedded_funding_asset(path: &str) -> Option<(&'static [u8], &'static str)> {{\n    match path {{\n",
        supplied.is_none()
    );
    for (relative, absolute) in files {
        generated.push_str(&format!(
            "        {:?} => Some((include_bytes!({:?}), {:?})),\n",
            relative,
            absolute.to_str().expect("validated UTF-8 asset path"),
            build_support::content_type(&absolute)
        ));
    }
    generated.push_str("        _ => None,\n    }\n}\n");
    fs::write(output_dir.join("embedded_funding_assets.rs"), generated)
        .expect("write embedded frontend asset map");
}
