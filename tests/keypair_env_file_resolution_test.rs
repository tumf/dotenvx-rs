use std::fs;
use std::process::Command;

use tempfile::tempdir;

#[test]
fn kp_env_file_uses_explicit_file_path_over_cwd() {
    // Arrange: create two different keypairs.
    let (sk_a, pk_a) = ecies::utils::generate_keypair();
    let public_a = hex::encode(pk_a.serialize_compressed());
    let _private_a = hex::encode(sk_a.serialize());

    let (sk_b, pk_b) = ecies::utils::generate_keypair();
    let public_b = hex::encode(pk_b.serialize_compressed());
    let private_b = hex::encode(sk_b.serialize());

    // CWD contains an unrelated .env.openclaw with a different public key.
    let cwd_dir = tempdir().unwrap();
    fs::write(
        cwd_dir.path().join(".env.openclaw"),
        format!("DOTENV_PUBLIC_KEY_OPENCLAW={public_a}\n"),
    )
    .unwrap();
    // Provide the matching private key via .env.keys in CWD.
    fs::write(
        cwd_dir.path().join(".env.keys"),
        format!("DOTENV_PRIVATE_KEY_OPENCLAW={private_b}\n"),
    )
    .unwrap();

    // The explicitly passed env file path (outside CWD) contains the desired public key.
    let other_dir = tempdir().unwrap();
    let explicit_env_file = other_dir.path().join(".env.openclaw");
    fs::write(
        &explicit_env_file,
        format!("DOTENV_PUBLIC_KEY_OPENCLAW={public_b}\n"),
    )
    .unwrap();

    // Act
    let exe = env!("CARGO_BIN_EXE_dotenvx");
    let output = Command::new(exe)
        .current_dir(cwd_dir.path())
        .args([
            "kp",
            "-f",
            explicit_env_file.to_string_lossy().as_ref(),
            "--format",
            "shell",
        ])
        .output()
        .unwrap();

    // Assert: uses the key from the explicitly passed file, not the one in CWD.
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(&public_b), "stdout: {stdout}");
    assert!(!stdout.contains(&public_a), "stdout: {stdout}");
}
