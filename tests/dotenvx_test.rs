use std::env;
use std::sync::Mutex;

use tempfile::tempdir;
use totp_rs::{Algorithm, Secret, TOTP};

static ENV_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn test_dotenv_load() {
    let _guard = ENV_LOCK.lock().unwrap();

    let tmp = tempdir().unwrap();
    let old_dir = env::current_dir().unwrap();
    env::set_current_dir(tmp.path()).unwrap();
    std::fs::write(tmp.path().join(".env"), "HELLO=World\n").unwrap();

    dotenvx_rs::dotenv().unwrap();

    let value = env::var("HELLO").unwrap();
    assert_eq!(value, "World");

    unsafe {
        env::remove_var("HELLO");
    }
    env::set_current_dir(old_dir).unwrap();
}

#[test]
fn test_dotenv_load_example() {
    let _guard = ENV_LOCK.lock().unwrap();

    let tmp = tempdir().unwrap();
    let old_dir = env::current_dir().unwrap();
    env::set_current_dir(tmp.path()).unwrap();
    std::fs::write(tmp.path().join(".env.example"), "HELLO=World\n").unwrap();

    dotenvx_rs::from_path(".env.example").unwrap();

    let value = env::var("HELLO").unwrap();
    assert_eq!(value, "World");

    unsafe {
        env::remove_var("HELLO");
    }
    env::set_current_dir(old_dir).unwrap();
}

#[test]
fn test_totp() {
    let totp_url = "otpauth://totp/Dotenvx:demo@example.com?secret=VZOQR7AGS6KWMOOKUWFLSTETI74BW4VT&issuer=Dotenvx";
    let totp = TOTP::from_url(totp_url).unwrap();
    println!("{}", totp.generate_current().unwrap());
}

#[test]
fn test_generate_secret() {
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        Secret::default().to_bytes().unwrap(),
        Some("Dotenvx".to_string()),
        "john@example.com".to_string(),
    )
    .unwrap();
    println!("{}", totp.get_url())
}
