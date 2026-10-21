//! A release `zkapi` binary rejects `--adversary` (§5.5): the adversary modes
//! exist only in drill builds (`--features adversary`).
#![cfg(not(feature = "adversary"))]

use std::process::Command;

#[test]
fn the_release_binary_rejects_the_adversary_flag() {
    for args in [
        ["--adversary", "hang", "serverd"],
        ["serverd", "--adversary", "hang"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_zkapi"))
            .args(args)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("unexpected argument '--adversary'"),
            "{args:?}: {stderr}"
        );
    }
}
