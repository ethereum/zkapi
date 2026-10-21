#[path = "../build_support.rs"]
mod build_support;

use std::fs;
use std::path::Path;

#[test]
fn default_frontend_is_a_standalone_help_page() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("static/funding");
    let files = build_support::frontend_assets(&root).unwrap();
    assert_eq!(
        files
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>(),
        ["index.html", "styles.css"]
    );
    let index = fs::read_to_string(root.join("index.html")).unwrap();
    assert!(index.contains("OA Chat is a separate app"));
    assert!(!index.contains("<script"));
}

#[test]
fn caller_supplied_static_assets_preserve_nested_paths_and_mime_types() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("index.html"),
        "<!doctype html><title>Host app</title>",
    )
    .unwrap();
    fs::create_dir(dir.path().join("assets")).unwrap();
    fs::write(
        dir.path().join("assets/app.js"),
        "export const host = true;",
    )
    .unwrap();
    fs::write(dir.path().join("assets/proof.wasm"), [0, 97, 115, 109]).unwrap();
    let files = build_support::frontend_assets(dir.path()).unwrap();
    assert_eq!(
        files
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>(),
        ["assets/app.js", "assets/proof.wasm", "index.html"]
    );
    assert_eq!(
        build_support::content_type(&files[0].1),
        "application/javascript; charset=utf-8"
    );
    assert_eq!(build_support::content_type(&files[1].1), "application/wasm");
    assert_eq!(
        build_support::content_type(&files[2].1),
        "text/html; charset=utf-8"
    );
    assert!(files.iter().all(|(_, path)| path.is_absolute()));
}

#[test]
fn supplied_frontend_requires_a_nonempty_utf8_root_index() {
    let dir = tempfile::tempdir().unwrap();
    assert!(build_support::frontend_assets(&dir.path().join("absent")).is_err());
    assert!(build_support::frontend_assets(dir.path()).is_err());
    let index = dir.path().join("index.html");
    fs::write(&index, "   ").unwrap();
    assert!(build_support::frontend_assets(dir.path()).is_err());
    fs::write(&index, [255]).unwrap();
    assert!(build_support::frontend_assets(dir.path()).is_err());
    fs::write(&index, "<title>Ready</title>").unwrap();
    assert!(build_support::frontend_assets(dir.path()).is_ok());
}

#[test]
fn frontend_rejects_hidden_secrets_and_source_dependency_directories() {
    for name in [".env", ".env.production", ".git", "node_modules"] {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("index.html"), "<title>Ready</title>").unwrap();
        fs::write(dir.path().join(name), "must not be published").unwrap();
        let error = build_support::frontend_assets(dir.path()).unwrap_err();
        assert!(error.to_string().contains("non-public entry"));
    }
}

#[cfg(unix)]
#[test]
fn frontend_rejects_symlinks_including_external_index() {
    use std::os::unix::fs::symlink;
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("private.txt"), "must not be published").unwrap();
    let dir = tempfile::tempdir().unwrap();
    symlink(
        outside.path().join("private.txt"),
        dir.path().join("index.html"),
    )
    .unwrap();
    assert!(build_support::frontend_assets(dir.path())
        .unwrap_err()
        .to_string()
        .contains("symlinks"));
    fs::remove_file(dir.path().join("index.html")).unwrap();
    fs::write(dir.path().join("index.html"), "<title>Ready</title>").unwrap();
    symlink(outside.path(), dir.path().join("assets")).unwrap();
    assert!(build_support::frontend_assets(dir.path())
        .unwrap_err()
        .to_string()
        .contains("symlinks"));
}
