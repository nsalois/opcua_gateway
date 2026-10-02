use std::{env, path::PathBuf, process::Command};

fn main() {
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let memory_script = manifest_dir.join("memory.x");
    let identity_helper = manifest_dir.join("../../tools/firmware_identity.py");

    println!("cargo:rerun-if-changed={}", identity_helper.display());
    println!("cargo:rerun-if-changed=VERSION");
    println!("cargo:rerun-if-changed=Cargo.toml");
    for key in [
        "OPTA_FIRMWARE_VERSION",
        "OPTA_FIRMWARE_REVISION",
        "OPTA_FIRMWARE_FLAVOR",
        "OPTA_FIRMWARE_SOURCE_STATE",
        "SOURCE_DATE_EPOCH",
    ] {
        println!("cargo:rerun-if-env-changed={key}");
    }
    let status = Command::new("python3")
        .arg("-B")
        .arg(&identity_helper)
        .arg("--root")
        .arg(manifest_dir.join("../.."))
        .arg("--emit-rust")
        .arg(PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("build_info.rs"))
        .status()
        .expect("firmware identity generation requires Python 3.11 or newer");
    assert!(status.success(), "firmware identity validation failed");

    println!("cargo:rerun-if-changed={}", memory_script.display());
    println!("cargo:rustc-link-search={}", manifest_dir.display());
    println!("cargo:rustc-link-arg=-Tlink.x");
    println!("cargo:rustc-link-arg=--nmagic");
    println!("cargo:rustc-link-arg=--undefined=OPTA_FIRMWARE_IDENTITY");
}
