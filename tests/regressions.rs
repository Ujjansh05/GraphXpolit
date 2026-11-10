use graphxploit::{scan_project, store::Store, ScanOptions};
use std::{
    fs,
    process::Command,
    time::{Duration, Instant},
};

#[test]
fn lexical_scope_and_explicit_aliases_preserve_precision() {
    let d = tempfile::tempdir().unwrap();
    fs::write(d.path().join("lib.py"), "def target(): pass\n").unwrap();
    fs::write(d.path().join("app.py"), "from lib import target as alias\nimport lib as module\ndef a(): alias()\ndef b(): module.target()\ndef wrong(): unknown.target()\ndef outer():\n    def private(): pass\n    private()\ndef outside(): private()\n").unwrap();
    scan_project(d.path(), ScanOptions::default()).unwrap();
    let impacted = graphxploit::impact(d.path(), "lib.py::target", 3).unwrap();
    assert!(impacted.results.iter().any(|n| n.name == "a"));
    assert!(impacted.results.iter().any(|n| n.name == "b"));
    assert!(!impacted.results.iter().any(|n| n.name == "wrong"));
    assert!(!graphxploit::dependencies(d.path(), "outside", 3)
        .unwrap()
        .results
        .iter()
        .any(|n| n.name == "private"));
    fs::write(d.path().join("lib.py"), "def target():\n    return 123\n").unwrap();
    scan_project(d.path(), ScanOptions::default()).unwrap();
    assert!(graphxploit::impact(d.path(), "lib.py::target", 3)
        .unwrap()
        .results
        .iter()
        .any(|n| n.name == "a"));
}

#[test]
fn javascript_relative_import_alias_resolves() {
    let d = tempfile::tempdir().unwrap();
    fs::create_dir(d.path().join("src")).unwrap();
    fs::write(d.path().join("lib.js"), "export function target() {}\n").unwrap();
    fs::write(
        d.path().join("src/app.js"),
        "import { target as alias } from '../lib.js';\nfunction caller() { alias(); }\n",
    )
    .unwrap();
    scan_project(d.path(), ScanOptions::default()).unwrap();
    assert!(graphxploit::impact(d.path(), "target", 3)
        .unwrap()
        .results
        .iter()
        .any(|n| n.name == "caller"));
}

#[test]
fn deleted_symbols_keep_before_change_callers_and_renames_get_both_sides() {
    let d = tempfile::tempdir().unwrap();
    let git = graphxploit::process::trusted_program("git", d.path()).unwrap();
    let run = |args: &[&str]| {
        let result = Command::new(&git)
            .current_dir(d.path())
            .args(args)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    };
    run(&["init"]);
    fs::write(d.path().join("lib.py"), "def target(): pass\n").unwrap();
    fs::write(
        d.path().join("app.py"),
        "from lib import target\ndef caller(): target()\n",
    )
    .unwrap();
    run(&["add", "."]);
    run(&[
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
        "commit",
        "-m",
        "fixture",
        "--no-gpg-sign",
    ]);
    fs::remove_file(d.path().join("lib.py")).unwrap();
    let deleted = graphxploit::working_changes(d.path()).unwrap();
    assert!(deleted.changes.iter().any(|c| c.basis == "before"
        && c.qualified_name == "lib.py::target"
        && c.affected.iter().any(|a| a.name == "caller")));
    fs::write(d.path().join("lib.py"), "def target(): pass\n").unwrap();
    run(&["mv", "lib.py", "renamed.py"]);
    let renamed = graphxploit::working_changes(d.path()).unwrap();
    assert!(renamed
        .changes
        .iter()
        .any(|c| c.status == "renamed" && c.basis == "before"));
    assert!(renamed
        .changes
        .iter()
        .any(|c| c.status == "renamed" && c.basis == "after"));
}

#[test]
fn incremental_edges_match_fresh_rebuild_after_changes() {
    let d = tempfile::tempdir().unwrap();
    let fresh = tempfile::tempdir().unwrap();
    fs::write(
        d.path().join("a.py"),
        "def target(): pass\ndef caller(): target()\n",
    )
    .unwrap();
    scan_project(d.path(), ScanOptions::default()).unwrap();
    let source = "def target(): pass\ndef caller(): target()\ndef added(): caller()\n";
    fs::write(d.path().join("a.py"), source).unwrap();
    fs::write(fresh.path().join("a.py"), source).unwrap();
    scan_project(d.path(), ScanOptions::default()).unwrap();
    scan_project(fresh.path(), ScanOptions::default()).unwrap();
    assert_eq!(
        serde_json::to_value(graphxploit::impact(d.path(), "target", 5).unwrap()).unwrap(),
        serde_json::to_value(graphxploit::impact(fresh.path(), "target", 5).unwrap()).unwrap()
    );
}

#[test]
fn unchanged_scan_does_not_advance_revision() {
    let d = tempfile::tempdir().unwrap();
    fs::write(d.path().join("a.rs"), "fn a() {}\n").unwrap();
    let first = scan_project(d.path(), ScanOptions::default()).unwrap();
    let second = scan_project(d.path(), ScanOptions::default()).unwrap();
    assert_eq!(first.generation, second.generation);
    assert_eq!(first.relationships, second.relationships);
}

#[test]
fn readers_work_during_writer_transaction() {
    let d = tempfile::tempdir().unwrap();
    fs::write(d.path().join("a.rs"), "fn a() {}\n").unwrap();
    let first = scan_project(d.path(), ScanOptions::default()).unwrap();
    let writer = rusqlite::Connection::open(first.database).unwrap();
    writer
        .execute_batch("BEGIN IMMEDIATE; UPDATE projects SET generation=generation+1;")
        .unwrap();
    let overview = Store::read(d.path()).unwrap().overview().unwrap();
    assert_eq!(overview["generation"], first.generation);
    writer.execute_batch("ROLLBACK;").unwrap();
}

#[test]
fn unrelated_global_name_is_not_a_call_target() {
    let d = tempfile::tempdir().unwrap();
    fs::write(d.path().join("other.py"), "def target():\n    pass\n").unwrap();
    fs::write(
        d.path().join("main.py"),
        "def caller():\n    obj.target()\n",
    )
    .unwrap();
    scan_project(d.path(), ScanOptions::default()).unwrap();
    assert!(graphxploit::impact(d.path(), "target", 3)
        .unwrap()
        .results
        .iter()
        .all(|n| n.name != "caller"));
}

#[test]
fn ignores_nested_patterns_and_keeps_negated_files() {
    let d = tempfile::tempdir().unwrap();
    fs::create_dir(d.path().join("src")).unwrap();
    fs::write(d.path().join("src/.gitignore"), "*.py\n!keep.py\n").unwrap();
    fs::write(d.path().join("src/hide.py"), "def hidden(): pass\n").unwrap();
    fs::write(d.path().join("src/keep.py"), "def kept(): pass\n").unwrap();
    let s = scan_project(d.path(), ScanOptions::default()).unwrap();
    assert_eq!(s.files_seen, 1);
}

#[test]
fn cli_rejects_unknown_flags_without_starting_ai() {
    let result = Command::new(env!("CARGO_BIN_EXE_graphxploit"))
        .arg("--not-a-real-flag")
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("unexpected argument"));
}

#[test]
fn process_deadline_covers_descendants_and_pipes() {
    #[cfg(windows)]
    let mut cmd = {
        let mut c = Command::new("powershell.exe");
        c.args(["-NoProfile", "-Command", "Start-Sleep -Seconds 30"]);
        c
    };
    #[cfg(unix)]
    let mut cmd = {
        let mut c = Command::new("sh");
        c.args(["-c", "sleep 30 & wait"]);
        c
    };
    let start = Instant::now();
    assert!(graphxploit::process::capture(&mut cmd, Duration::from_millis(250), 1024).is_err());
    assert!(start.elapsed() < Duration::from_secs(3));
}
