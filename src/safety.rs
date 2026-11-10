//! Shared workspace boundary and display rules. Repository contents are untrusted.
use anyhow::{bail, Result};
use std::{
    fs,
    io::Read,
    path::{Component, Path, PathBuf},
};

pub fn terminal(value: &str) -> String {
    value
        .chars()
        .flat_map(|c| {
            if (c.is_control() && c != '\n' && c != '\t')
                || ('\u{202a}'..='\u{202e}').contains(&c)
                || ('\u{2066}'..='\u{2069}').contains(&c)
            {
                c.escape_unicode().collect::<Vec<_>>()
            } else {
                vec![c]
            }
        })
        .collect()
}

pub fn sensitive(path: &Path) -> bool {
    path.components().any(|c| {
        let n = c.as_os_str().to_string_lossy().to_ascii_lowercase();
        [".npmrc", ".netrc", ".pypirc"].contains(&n.as_str())
            || n == ".env"
            || n.starts_with(".env.")
            || n == ".git"
            || n == ".ssh"
            || n == ".aws"
            || n.contains("credentials")
            || n.contains("private_key")
            || n.starts_with("id_rsa")
            || n.starts_with("id_ed25519")
            || n == "secrets"
            || n.starts_with("secrets.")
            || [".pem", ".key", ".p12", ".pfx", ".keystore"]
                .iter()
                .any(|s| n.ends_with(s))
    })
}

pub fn linked(meta: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes() & 0x400 != 0 {
            return true;
        }
    }
    meta.file_type().is_symlink()
}

pub fn workspace_path(root: &Path, relative: &Path, missing_leaf: bool) -> Result<PathBuf> {
    if relative.as_os_str().is_empty() || sensitive(relative) {
        bail!("empty or sensitive workspace path");
    }
    let root = root.canonicalize()?;
    let mut p = root.clone();
    let parts = relative.components().collect::<Vec<_>>();
    for (i, c) in parts.iter().enumerate() {
        let Component::Normal(n) = c else {
            bail!("path must be workspace-relative");
        };
        if n.to_string_lossy().contains(':') {
            bail!("alternate data streams are not allowed");
        }
        p.push(n);
        match fs::symlink_metadata(&p) {
            Ok(m) if linked(&m) => bail!("links and reparse points are not allowed"),
            Ok(_) => {}
            Err(e)
                if missing_leaf
                    && i + 1 == parts.len()
                    && e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    if !p.starts_with(root) {
        bail!("path escapes workspace");
    }
    Ok(p)
}

pub fn walker(root: &Path) -> ignore::Walk {
    ignore::WalkBuilder::new(root)
        .follow_links(false)
        .max_depth(Some(128))
        .require_git(false)
        .parents(false)
        .git_global(false)
        .add_custom_ignore_filename(".graphxploitignore")
        .filter_entry(|e| {
            if e.depth() == 0 {
                return true;
            }
            let n = e.file_name().to_string_lossy();
            !sensitive(e.path())
                && ![
                    "target",
                    "node_modules",
                    "vendor",
                    "dist",
                    "build",
                    "venv",
                    "__pycache__",
                ]
                .contains(&n.as_ref())
                && !n.ends_with(".min.js")
                && e.metadata().is_ok_and(|m| !linked(&m))
        })
        .build()
}

pub fn read(root: &Path, relative: &Path, max: u64) -> Result<Vec<u8>> {
    let canonical = root.canonicalize()?;
    let root = canonical.as_path();
    let p = workspace_path(root, relative, false)?;
    if relative.components().any(|part| {
        let n = part.as_os_str().to_string_lossy();
        [
            "target",
            "node_modules",
            "vendor",
            "dist",
            "build",
            "venv",
            "__pycache__",
        ]
        .contains(&n.as_ref())
            || (n.starts_with('.')
                && ![
                    ".gitignore",
                    ".ignore",
                    ".graphxploitignore",
                    ".graphxploit.json",
                ]
                .contains(&n.as_ref()))
            || n.ends_with(".min.js")
    }) {
        bail!("file is excluded by workspace policy");
    }
    // Each ignore file is rooted in its own directory; child patterns override
    // file matches, but cannot re-include descendants of an excluded directory.
    let mut dir = root.to_path_buf();
    let mut directories = vec![dir.clone()];
    if let Some(parent) = relative.parent() {
        for part in parent.components() {
            dir.push(part);
            directories.push(dir.clone());
        }
    }
    let mut ignored = false;
    for (index, dir) in directories.iter().enumerate() {
        let mut builder = ignore::gitignore::GitignoreBuilder::new(dir);
        for name in [".gitignore", ".ignore", ".graphxploitignore"] {
            let file = dir.join(name);
            if let Ok(meta) = fs::symlink_metadata(&file) {
                if linked(&meta) || !meta.is_file() || meta.len() > 64 * 1024 {
                    bail!("unsafe or oversized ignore file");
                }
                if let Some(error) = builder.add(file) {
                    return Err(error.into());
                }
            }
        }
        let rules = builder.build()?;
        for child in directories.iter().skip(index + 1) {
            if rules.matched(child, true).is_ignore() {
                bail!("directory is excluded by ignore rules");
            }
        }
        match rules.matched(&p, false) {
            ignore::Match::Ignore(_) => ignored = true,
            ignore::Match::Whitelist(_) => ignored = false,
            ignore::Match::None => {}
        }
    }
    if ignored {
        bail!("file is excluded by ignore rules");
    }
    let file = fs::File::open(&p)?;
    if !file.metadata()?.is_file() {
        bail!("not a regular file");
    }
    let mut bytes = Vec::new();
    file.take(max + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max {
        bail!("file exceeds byte limit");
    }
    Ok(bytes)
}

pub fn private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_secret_and_escape_paths() {
        let d = tempfile::tempdir().unwrap();
        for p in [
            "../outside",
            ".env",
            "keys/id_ed25519",
            "secrets.py",
            "a:stream",
        ] {
            assert!(workspace_path(d.path(), Path::new(p), true).is_err());
        }
        assert_eq!(terminal("x\u{1b}[2J"), "x\\u{1b}[2J");
    }
    #[test]
    fn nested_ignores_apply_to_direct_reads() {
        let d = tempfile::tempdir().unwrap();
        fs::create_dir(d.path().join("src")).unwrap();
        fs::write(d.path().join("src/.gitignore"), "hidden.py\n").unwrap();
        fs::write(d.path().join("src/hidden.py"), "secret").unwrap();
        assert!(read(d.path(), Path::new("src/hidden.py"), 100).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn links_cannot_escape() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        fs::write(b.path().join("file.py"), "secret").unwrap();
        std::os::unix::fs::symlink(b.path(), a.path().join("linked")).unwrap();
        assert!(read(a.path(), Path::new("linked/file.py"), 100).is_err());
        assert!(!walker(a.path())
            .flatten()
            .any(|e| e.path().ends_with("file.py")));
    }
}
