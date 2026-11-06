use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    tauri_build::build();
    if env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("gnu") {
        embed_test_manifest();
        stage_runtime_dlls();
    }
}

/// Test binaries link tauri, which imports comctl32!TaskDialogIndirect. Without a
/// Common-Controls v6 manifest the loader binds comctl32 v5 and every test
/// executable dies with STATUS_ENTRYPOINT_NOT_FOUND before running. tauri-build only
/// embeds the manifest into the application binary, so test targets get their own here.
fn embed_test_manifest() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let rc = manifest_dir.join("windows-test-manifest.rc");
    if !rc.exists() {
        println!("cargo:warning=test manifest rc missing, skipping manifest embedding");
        return;
    }
    let Some(windres) = find_windres() else {
        println!("cargo:warning=windres not found; test binaries may fail to load");
        return;
    };
    let obj = out_dir.join("nullplinth-test-manifest.o");
    let status = Command::new(&windres)
        .arg("-i")
        .arg(&rc)
        .arg("-o")
        .arg(&obj)
        .arg("-O")
        .arg("coff")
        .arg("--include-dir")
        .arg(&manifest_dir)
        .status();
    match status {
        Ok(s) if s.success() => {
            println!("cargo:rustc-link-arg-tests={}", obj.display());
            println!("cargo:rerun-if-changed=windows-test-manifest.xml");
            println!("cargo:rerun-if-changed=windows-test-manifest.rc");
        }
        _ => println!("cargo:warning=windres failed; test binaries may fail to load"),
    }
}

fn find_windres() -> Option<PathBuf> {
    for candidate in [
        "C:/msys64/ucrt64/bin/windres.exe",
        "C:/msys64/mingw64/bin/windres.exe",
    ] {
        let p = PathBuf::from(candidate);
        if p.exists() {
            return Some(p);
        }
    }
    // Fall back to PATH lookup.
    let path = env::var("PATH").ok()?;
    for dir in env::split_paths(&path) {
        let candidate = dir.join("windres.exe");
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

/// Cargo does not place WebView2Loader.dll next to test executables, so stage it.
fn stage_runtime_dlls() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    // OUT_DIR = target/<profile>/build/nullplinth-<hash>/out
    let Some(profile_dir) = out_dir.ancestors().nth(3).map(Path::to_path_buf) else {
        return;
    };
    let build_dir = profile_dir.join("build");
    let Some(loader) = find_file(&build_dir, "WebView2Loader.dll", Some("x64")) else {
        return;
    };
    for dest_dir in [profile_dir.clone(), profile_dir.join("deps")] {
        if dest_dir.is_dir() {
            let _ = std::fs::copy(&loader, dest_dir.join("WebView2Loader.dll"));
        }
    }
}

fn find_file(root: &Path, name: &str, prefer_dir: Option<&str>) -> Option<PathBuf> {
    let mut fallback = None;
    let entries = std::fs::read_dir(root).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let hits = std::fs::read_dir(&path).ok()?;
            for hit in hits.flatten() {
                let candidate = hit.path();
                if candidate.is_dir() {
                    if prefer_dir.map(|d| d.eq_ignore_ascii_case(&d)) == Some(true) {
                        let direct = candidate.join(name);
                        if direct.exists() {
                            return Some(direct);
                        }
                    }
                    let nested = candidate.join(name);
                    if nested.exists() && fallback.is_none() {
                        fallback = Some(nested);
                    }
                } else if candidate.file_name().and_then(|f| f.to_str()) == Some(name) && fallback.is_none() {
                    fallback = Some(candidate);
                }
            }
        }
    }
    fallback
}