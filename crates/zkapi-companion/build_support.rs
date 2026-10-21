use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub fn content_type(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or_default()
    {
        "html" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" | "cjs" => "application/javascript; charset=utf-8",
        "json" => "application/json; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        "wasm" => "application/wasm",
        "txt" | "md" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

/// Accept only an explicit static output directory, never a source checkout or
/// symlinks into one. The caller controls every byte published by this build.
pub fn frontend_assets(root: &Path) -> io::Result<Vec<(String, PathBuf)>> {
    if !root.is_dir() || fs::symlink_metadata(root)?.file_type().is_symlink() {
        return Err(invalid("frontend dist must be a real directory"));
    }
    let root = root.canonicalize()?;
    let mut files = Vec::new();
    collect_files(&root, &root, &mut files)?;
    if !files.iter().any(|(relative, _)| relative == "index.html") {
        return Err(invalid("frontend dist must contain index.html at its root"));
    }
    let index = fs::read_to_string(root.join("index.html"))?;
    if index.trim().is_empty() {
        return Err(invalid("frontend index.html must not be empty"));
    }
    Ok(files)
}

fn collect_files(root: &Path, dir: &Path, files: &mut Vec<(String, PathBuf)>) -> io::Result<()> {
    let mut entries = fs::read_dir(dir)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.path());
    for entry in entries {
        let path = entry.path();
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| invalid("frontend paths must be UTF-8"))?;
        if name.starts_with('.') || name == "node_modules" || name.contains('\\') {
            return Err(invalid(format!(
                "frontend dist contains a non-public entry: {name}"
            )));
        }
        let kind = entry.file_type()?;
        if kind.is_symlink() {
            return Err(invalid(format!(
                "frontend dist must not contain symlinks: {name}"
            )));
        }
        if kind.is_dir() {
            collect_files(root, &path, files)?;
        } else if kind.is_file() {
            let relative = path
                .strip_prefix(root)
                .expect("asset under root")
                .to_str()
                .ok_or_else(|| invalid("frontend paths must be UTF-8"))?
                .replace('\\', "/");
            files.push((relative, path));
        } else {
            return Err(invalid(format!(
                "frontend dist contains a non-file entry: {name}"
            )));
        }
    }
    Ok(())
}
