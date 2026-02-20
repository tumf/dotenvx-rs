use std::fs;
use std::process::Command;

use tempfile::tempdir;

#[test]
fn decrypt_invalid_ciphertext_exits_nonzero_without_panic() {
    let (sk, pk) = ecies::utils::generate_keypair();
    let public_key = hex::encode(pk.serialize_compressed());
    let private_key = hex::encode(sk.serialize());

    let dir = tempdir().unwrap();
    fs::write(
        dir.path().join(".env.keys"),
        format!("DOTENV_PRIVATE_KEY={private_key}\n"),
    )
    .unwrap();

    let env_file = dir.path().join(".env");
    fs::write(
        &env_file,
        format!("DOTENV_PUBLIC_KEY={public_key}\nFOO=encrypted:!!!\n"),
    )
    .unwrap();

    let exe = env!("CARGO_BIN_EXE_dotenvx");
    let output = Command::new(exe)
        .current_dir(dir.path())
        .args([
            "decrypt",
            "-f",
            env_file.to_string_lossy().as_ref(),
            "--stdout",
            "--format",
            "json",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("panicked at"), "stderr: {stderr}");
    assert!(
        !stderr.contains("called `Result::unwrap()`"),
        "stderr: {stderr}"
    );
}
