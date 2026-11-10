//! Bounded process-group supervision shared by Git and approved agent commands.
use anyhow::{bail, Result};
use command_group::CommandGroup;
use std::{
    io::Read,
    process::{Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

pub fn capture(
    command: &mut Command,
    timeout: Duration,
    limit: usize,
) -> Result<(ExitStatus, Vec<u8>, Vec<u8>)> {
    capture_input(command, timeout, limit, None)
}

pub(crate) fn capture_input(
    command: &mut Command,
    timeout: Duration,
    limit: usize,
    input: Option<Vec<u8>>,
) -> Result<(ExitStatus, Vec<u8>, Vec<u8>)> {
    command
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.group_spawn()?;
    let writer = input.map(|bytes| {
        let mut stdin = child.inner().stdin.take().expect("piped stdin");
        thread::spawn(move || {
            use std::io::Write;
            stdin.write_all(&bytes)
        })
    });
    let stdout = child.inner().stdout.take().expect("piped stdout");
    let stderr = child.inner().stderr.take().expect("piped stderr");
    let drain = move |r: Box<dyn Read + Send>| {
        thread::spawn(move || {
            let mut bytes = Vec::new();
            r.take(limit as u64 + 1)
                .read_to_end(&mut bytes)
                .map(|_| bytes)
        })
    };
    let out = drain(Box::new(stdout));
    let err = drain(Box::new(stderr));
    let deadline = Instant::now() + timeout;
    let mut status = None;
    loop {
        if status.is_none() {
            status = child.try_wait()?;
        }
        if status.is_some()
            && out.is_finished()
            && err.is_finished()
            && writer.as_ref().is_none_or(|w| w.is_finished())
        {
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            bail!("process group or output drain exceeded the deadline");
        }
        thread::sleep(Duration::from_millis(20));
    }
    let _ = child.kill(); // Never leave descendants running after returning.
    let out = out
        .join()
        .map_err(|_| anyhow::anyhow!("stdout reader failed"))??;
    let err = err
        .join()
        .map_err(|_| anyhow::anyhow!("stderr reader failed"))??;
    if let Some(writer) = writer {
        writer
            .join()
            .map_err(|_| anyhow::anyhow!("stdin writer failed"))??;
    }
    if out.len() > limit || err.len() > limit {
        bail!("process output exceeds byte limit");
    }
    Ok((status.expect("completed child"), out, err))
}

pub fn trusted_program(program: &str, root: &std::path::Path) -> Result<std::path::PathBuf> {
    if program.is_empty() || program.chars().any(|c| c == '/' || c == '\\' || c == ':') {
        bail!("program must be a name");
    }
    let root = root.canonicalize()?;
    for dir in std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()) {
        if !dir.is_absolute() {
            continue;
        }
        let Ok(dir) = dir.canonicalize() else {
            continue;
        };
        if dir.starts_with(&root) {
            continue;
        }
        for suffix in if cfg!(windows) {
            &["", ".exe"][..]
        } else {
            &[""][..]
        } {
            let candidate = dir.join(format!("{program}{suffix}"));
            if candidate.is_file() {
                let resolved = candidate.canonicalize()?;
                if !resolved.starts_with(&root) {
                    return Ok(resolved);
                }
            }
        }
    }
    bail!("program was not found in a trusted absolute PATH directory")
}
