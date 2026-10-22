//! `zkapi serverd` refuses to start with a setting removed in vault revision
//! 4, given as a flag or through the environment, before it opens anything.

use std::process::Command;

const MESSAGE: &str =
    "removed in vault revision 4: clearance checks the note leaf; delete this setting";

fn serverd(extra: &[&str], env: Option<(&str, &str)>) -> std::process::Output {
    let directory = tempfile_dir();
    let mut command = Command::new(env!("CARGO_BIN_EXE_zkapi"));
    command
        .args([
            "serverd",
            "--native-billing-rpc-url",
            "http://127.0.0.1:1",
            "--native-price-feed-address",
            "0x694AA1769357215DE4FAC081bf1f309aDC325306",
            "--db-path",
        ])
        .arg(directory.join("must-not-exist.db"))
        .args(extra)
        .env_remove("ZKAPI_CLEARANCE_ROOT_WINDOW_SECONDS")
        .env_remove("ZKAPI_REQUEST_ROOT_GRACE_SECONDS");
    if let Some((name, value)) = env {
        command.env(name, value);
    }
    let output = command.output().unwrap();
    assert!(!directory.join("must-not-exist.db").exists());
    let _ = std::fs::remove_dir_all(&directory);
    output
}

/// A fresh directory under the target's temporary directory.
fn tempfile_dir() -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU32, Ordering};
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let directory = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "removed-settings-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&directory).unwrap();
    directory
}

#[test]
fn the_clearance_root_window_flag_fails_startup() {
    for value in ["3600", "60"] {
        let output = serverd(&["--clearance-root-window-seconds", value], None);
        assert_eq!(output.status.code(), Some(1), "{value}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(MESSAGE), "{value}: {stderr}");
    }
}

#[test]
fn the_clearance_root_window_environment_fails_startup() {
    let output = serverd(&[], Some(("ZKAPI_CLEARANCE_ROOT_WINDOW_SECONDS", "3600")));
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(MESSAGE), "{stderr}");
}
