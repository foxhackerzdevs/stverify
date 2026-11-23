use std::env;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

fn get_bin() -> &'static str {
    env!("CARGO_BIN_EXE_stverify")
}

fn create_dummy_safetensors(path: &Path, content: &[u8]) {
    let mut file = File::create(path).unwrap();
    let header = b"{\"weights\":{\"dtype\":\"BF16\",\"shape\":[4096,4096],\"data_offsets\":[0,16777216]}}";
    let header_len = (header.len() as u64).to_le_bytes();
    file.write_all(&header_len).unwrap();
    file.write_all(header).unwrap();
    file.write_all(content).unwrap();
}

fn temp_dir(prefix: &str) -> PathBuf {
    let path = env::temp_dir().join(format!(
        "stverify_cli_test_{}_{}",
        prefix,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&path).unwrap();
    path
}

#[test]
fn test_cli_keygen_sign_verify_single() {
    let dir = temp_dir("single");
    let priv_key = dir.join("signing.priv");
    let pub_key = dir.join("signing.pub");
    let shard = dir.join("model-00001.safetensors");
    let sig = dir.join("model-00001.sig");

    create_dummy_safetensors(&shard, b"tensor_shard_1_initial_state");

    // 1. keygen
    let status = Command::new(get_bin())
        .args(["keygen", priv_key.to_str().unwrap(), pub_key.to_str().unwrap()])
        .status()
        .expect("Failed to execute keygen");
    assert!(status.success());
    assert!(priv_key.exists());
    assert!(pub_key.exists());

    // 2. sign
    let status = Command::new(get_bin())
        .args([
            "sign",
            shard.to_str().unwrap(),
            priv_key.to_str().unwrap(),
            sig.to_str().unwrap(),
        ])
        .status()
        .expect("Failed to execute sign");
    assert!(status.success());
    assert!(sig.exists());

    // 3. verify (valid)
    let status = Command::new(get_bin())
        .args([
            "verify",
            shard.to_str().unwrap(),
            pub_key.to_str().unwrap(),
            sig.to_str().unwrap(),
        ])
        .status()
        .expect("Failed to execute verify");
    assert_eq!(status.code(), Some(0));

    // 4. verify tampered shard (exit code 2)
    fs::write(&shard, b"tampered_weights_poisoned").unwrap();
    let status = Command::new(get_bin())
        .args([
            "verify",
            shard.to_str().unwrap(),
            pub_key.to_str().unwrap(),
            sig.to_str().unwrap(),
        ])
        .status()
        .expect("Failed to execute verify on tampered shard");
    assert_eq!(status.code(), Some(2));

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn test_cli_multishard_parallel_manifest_verification() {
    let dir = temp_dir("multishard");
    let priv_key = dir.join("signing.priv");
    let pub_key = dir.join("signing.pub");

    // 1. Generate keypair
    let status = Command::new(get_bin())
        .args(["keygen", priv_key.to_str().unwrap(), pub_key.to_str().unwrap()])
        .status()
        .expect("Failed keygen");
    assert!(status.success());

    // 2. Create 8 model shards
    let models_dir = dir.join("llama-3-70b");
    fs::create_dir_all(&models_dir).unwrap();

    for i in 1..=8 {
        let shard_path = models_dir.join(format!("model-0000{}-of-00008.safetensors", i));
        create_dummy_safetensors(&shard_path, format!("shard_payload_block_{}", i).as_bytes());
    }

    // 3. sign-dir
    let status = Command::new(get_bin())
        .args([
            "sign-dir",
            models_dir.to_str().unwrap(),
            priv_key.to_str().unwrap(),
        ])
        .status()
        .expect("Failed sign-dir");
    assert_eq!(status.code(), Some(0));

    let manifest_path = models_dir.join("stverify.manifest");
    let sig_path = models_dir.join("stverify.sig");
    assert!(manifest_path.exists());
    assert!(sig_path.exists());

    // 4. verify-dir (clean pass)
    let status = Command::new(get_bin())
        .args([
            "verify-dir",
            models_dir.to_str().unwrap(),
            pub_key.to_str().unwrap(),
        ])
        .status()
        .expect("Failed verify-dir");
    assert_eq!(status.code(), Some(0));

    // 5. Test rogue / injected shard detection
    let rogue_shard = models_dir.join("model-00009-of-00008-injected.safetensors");
    create_dummy_safetensors(&rogue_shard, b"injected_backdoor_shard");
    let status = Command::new(get_bin())
        .args([
            "verify-dir",
            models_dir.to_str().unwrap(),
            pub_key.to_str().unwrap(),
        ])
        .status()
        .expect("Failed verify-dir on injected rogue shard");
    assert_eq!(status.code(), Some(2));
    fs::remove_file(&rogue_shard).unwrap();

    // 6. Test missing shard detection
    let shard_1 = models_dir.join("model-00001-of-00008.safetensors");
    let backup_1 = dir.join("shard_1.bak");
    fs::copy(&shard_1, &backup_1).unwrap();
    fs::remove_file(&shard_1).unwrap();
    let status = Command::new(get_bin())
        .args([
            "verify-dir",
            models_dir.to_str().unwrap(),
            pub_key.to_str().unwrap(),
        ])
        .status()
        .expect("Failed verify-dir on missing shard");
    assert_eq!(status.code(), Some(2));
    fs::copy(&backup_1, &shard_1).unwrap();

    // 7. Test bit-level corruption
    create_dummy_safetensors(&shard_1, b"corrupted_bit_data");
    let status = Command::new(get_bin())
        .args([
            "verify-dir",
            models_dir.to_str().unwrap(),
            pub_key.to_str().unwrap(),
        ])
        .status()
        .expect("Failed verify-dir on corrupted shard");
    assert_eq!(status.code(), Some(2));

    fs::remove_dir_all(&dir).ok();
}
