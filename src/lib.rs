//! # stverify
//!
//! **Zero-bloat parallel cryptographic signer and integrity verifier for `.safetensors` model weights.**
//!
//! Purpose-built for multi-tenant GPU enclaves, sovereign AI clusters, and zero-trust inference pipelines.
//!
//! ## Features
//!
//! - **Constant-Memory Streaming**: Hashes multi-gigabyte tensor shards in 64 KB buffers via SHA-256 without loading files entirely into memory.
//! - **Parallel Multi-Shard Verification**: Uses [`rayon`] to parallelize hashing of dozens of shards across CPU cores.
//! - **Framing & Header Validation**: Validates the 8-byte little-endian `.safetensors` header length boundary with sanity caps.
//! - **Deterministic Ed25519 Signatures**: Fast, constant-time signature generation and verification.
//! - **Canonical Manifest Integrity**: `sign-dir` / `verify-dir` builds and authenticates signed manifests (`<sha256> <filename>`), catching modified, deleted, or injected rogue shards.

pub use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::process;

/// Maximum sanity cap on JSON metadata header (100 MB).
pub const MAX_HEADER_SIZE: u64 = 100 * 1024 * 1024;

/// Prints the CLI usage instructions.
pub fn print_usage() {
    eprintln!("stverify - Parallel Cryptographic Integrity Verifier for Safetensors\n");
    eprintln!("Commands:");
    eprintln!("  keygen     <privkey.hex> <pubkey.hex>                   Generate Ed25519 keypair");
    eprintln!("  sign       <model.safetensors> <privkey.hex> <out.sig>  Sign single shard");
    eprintln!("  verify     <model.safetensors> <pubkey.hex> <model.sig> Verify single shard");
    eprintln!("  sign-dir   <model_dir> <privkey.hex>                    Parallel-sign all shards in directory");
    eprintln!("  verify-dir <model_dir> <pubkey.hex>                     Parallel-verify all shards in directory");
}

/// Validates basic `.safetensors` framing (8-byte little-endian header length)
/// and streams the entire file into SHA-256 in 64 KB chunks without loading it into RAM.
pub fn hash_safetensors(path: &Path) -> Result<[u8; 32], String> {
    let file = File::open(path).map_err(|e| format!("Failed to open {}: {}", path.display(), e))?;
    let metadata = file
        .metadata()
        .map_err(|e| format!("Metadata error on {}: {}", path.display(), e))?;

    if metadata.len() < 8 {
        return Err(format!(
            "Invalid safetensors file {}: smaller than 8-byte header prefix",
            path.display()
        ));
    }

    let mut reader = BufReader::with_capacity(64 * 1024, file);
    let mut len_buf = [0u8; 8];
    reader
        .read_exact(&mut len_buf)
        .map_err(|e| format!("Header read error on {}: {}", path.display(), e))?;

    let header_len = u64::from_le_bytes(len_buf);
    if header_len == 0 || header_len > MAX_HEADER_SIZE || header_len + 8 > metadata.len() {
        return Err(format!(
            "Malformed safetensors header length in {}: {} bytes",
            path.display(),
            header_len
        ));
    }

    let mut hasher = Sha256::new();
    hasher.update(len_buf);

    let mut chunk = [0u8; 64 * 1024];
    loop {
        let n = reader
            .read(&mut chunk)
            .map_err(|e| format!("Read error on {}: {}", path.display(), e))?;
        if n == 0 {
            break;
        }
        hasher.update(&chunk[..n]);
    }

    Ok(hasher.finalize().into())
}

/// Discovers all `.safetensors` shards in a directory, sorted deterministically by filename.
pub fn collect_shards(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let entries = fs::read_dir(dir)
        .map_err(|e| format!("Failed to read directory {}: {}", dir.display(), e))?;

    let mut shards: Vec<PathBuf> = entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| {
            path.is_file()
                && path
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .map(|ext| ext.eq_ignore_ascii_case("safetensors"))
                    .unwrap_or(false)
        })
        .collect();

    shards.sort_by(|a, b| a.file_name().cmp(&b.file_name()));

    if shards.is_empty() {
        return Err(format!(
            "No .safetensors shards found in {}",
            dir.display()
        ));
    }

    Ok(shards)
}

/// Builds a canonical, newline-delimited manifest (`<sha256_hex>  <filename>`) across every
/// shard in `dir`, hashed in parallel using Rayon.
pub fn build_canonical_manifest(dir: &Path) -> Result<String, String> {
    let shards = collect_shards(dir)?;

    let results: Vec<Result<String, String>> = shards
        .par_iter()
        .map(|shard_path| {
            let digest = hash_safetensors(shard_path)?;
            let filename = shard_path
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or_else(|| format!("Non-UTF8 filename: {}", shard_path.display()))?;
            Ok(format!("{}  {}", hex::encode(digest), filename))
        })
        .collect();

    let mut lines = Vec::with_capacity(results.len());
    for res in results {
        match res {
            Ok(line) => lines.push(line),
            Err(err) => return Err(err),
        }
    }

    Ok(lines.join("\n") + "\n")
}

/// Reads a 32-byte hex-encoded Ed25519 private key from disk.
pub fn load_signing_key(priv_path: &str) -> Result<SigningKey, String> {
    let priv_hex = fs::read_to_string(priv_path)
        .map_err(|e| format!("Failed reading private key {}: {}", priv_path, e))?;
    let priv_bytes: [u8; 32] = hex::decode(priv_hex.trim())
        .map_err(|e| format!("Invalid hex in private key: {}", e))?
        .try_into()
        .map_err(|_| "Private key must be 32 bytes".to_string())?;
    Ok(SigningKey::from_bytes(&priv_bytes))
}

/// Reads a 32-byte hex-encoded Ed25519 public key from disk.
pub fn load_verifying_key(pub_path: &str) -> Result<VerifyingKey, String> {
    let pub_hex = fs::read_to_string(pub_path)
        .map_err(|e| format!("Failed reading public key {}: {}", pub_path, e))?;
    let pub_bytes: [u8; 32] = hex::decode(pub_hex.trim())
        .map_err(|e| format!("Invalid hex in public key: {}", e))?
        .try_into()
        .map_err(|_| "Public key must be 32 bytes".to_string())?;
    VerifyingKey::from_bytes(&pub_bytes)
        .map_err(|e| format!("Invalid Ed25519 public key: {}", e))
}

/// Reads a 64-byte hex-encoded Ed25519 signature from disk.
pub fn load_signature(sig_path: &str) -> Result<Signature, String> {
    let sig_hex = fs::read_to_string(sig_path)
        .map_err(|e| format!("Failed reading signature {}: {}", sig_path, e))?;
    let sig_bytes: [u8; 64] = hex::decode(sig_hex.trim())
        .map_err(|e| format!("Invalid hex in signature: {}", e))?
        .try_into()
        .map_err(|_| "Signature must be 64 bytes".to_string())?;
    Ok(Signature::from_bytes(&sig_bytes))
}

/// Generates a new random Ed25519 keypair and writes them as hex files.
pub fn generate_keypair(priv_out: &str, pub_out: &str) -> Result<(), String> {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();

    fs::write(priv_out, hex::encode(signing_key.to_bytes()))
        .map_err(|e| format!("Failed writing private key {}: {}", priv_out, e))?;
    fs::write(pub_out, hex::encode(verifying_key.to_bytes()))
        .map_err(|e| format!("Failed writing public key {}: {}", pub_out, e))?;

    Ok(())
}

/// Signs a single `.safetensors` file, writing the 64-byte hex signature to `sig_out`.
pub fn sign_single(model_path: &Path, priv_path: &str, sig_out: &str) -> Result<[u8; 32], String> {
    let signing_key = load_signing_key(priv_path)?;
    let digest = hash_safetensors(model_path)?;
    let signature = signing_key.sign(&digest);

    fs::write(sig_out, hex::encode(signature.to_bytes()))
        .map_err(|e| format!("Failed writing signature {}: {}", sig_out, e))?;

    Ok(digest)
}

/// Verifies a single `.safetensors` file against an expected signature and public key.
pub fn verify_single(model_path: &Path, pub_path: &str, sig_path: &str) -> Result<[u8; 32], String> {
    let verifying_key = load_verifying_key(pub_path)?;
    let signature = load_signature(sig_path)?;
    let digest = hash_safetensors(model_path)?;

    verifying_key
        .verify(&digest, &signature)
        .map_err(|_| format!("SIGNATURE MISMATCH OR TAMPERED SHARD: {}", model_path.display()))?;

    Ok(digest)
}

/// Computes SHA-256 for all shards in parallel, writes `stverify.manifest` and `stverify.sig`.
pub fn sign_dir(dir: &Path, priv_path: &str) -> Result<(usize, PathBuf, PathBuf), String> {
    let signing_key = load_signing_key(priv_path)?;
    let manifest = build_canonical_manifest(dir)?;
    let signature = signing_key.sign(manifest.as_bytes());

    let manifest_path = dir.join("stverify.manifest");
    let sig_path = dir.join("stverify.sig");

    fs::write(&manifest_path, &manifest)
        .map_err(|e| format!("Failed writing stverify.manifest: {}", e))?;
    fs::write(&sig_path, hex::encode(signature.to_bytes()))
        .map_err(|e| format!("Failed writing stverify.sig: {}", e))?;

    let shard_count = manifest.lines().count();
    Ok((shard_count, manifest_path, sig_path))
}

/// Verifies `stverify.manifest` signature and recomputes canonical manifest in parallel across disk.
pub fn verify_dir(dir: &Path, pub_path: &str) -> Result<usize, String> {
    let verifying_key = load_verifying_key(pub_path)?;

    let manifest_path = dir.join("stverify.manifest");
    let sig_path = dir.join("stverify.sig");

    let signed_manifest = fs::read_to_string(&manifest_path)
        .map_err(|e| format!("Missing or unreadable {}: {}", manifest_path.display(), e))?;

    let sig_str = sig_path
        .to_str()
        .ok_or_else(|| format!("Invalid path for signature: {}", sig_path.display()))?;
    let signature = load_signature(sig_str)?;

    // Step 1: Verify cryptographic authenticity of the committed manifest itself
    verifying_key
        .verify(signed_manifest.as_bytes(), &signature)
        .map_err(|_| format!("MANIFEST SIGNATURE INVALID: {}", manifest_path.display()))?;

    // Step 2: Recompute canonical manifest in parallel across all shards on disk
    let live_manifest = build_canonical_manifest(dir)?;

    if signed_manifest != live_manifest {
        return Err(format!(
            "SHARD MISMATCH IN {}: one or more shards were modified, deleted, or injected",
            dir.display()
        ));
    }

    Ok(live_manifest.lines().count())
}

/// CLI handler for `keygen` command.
pub fn cmd_keygen(priv_out: &str, pub_out: &str) {
    if let Err(e) = generate_keypair(priv_out, pub_out) {
        eprintln!("[!] {}", e);
        process::exit(1);
    }
    println!("[+] Generated Ed25519 keypair:");
    println!("    Private: {}", priv_out);
    println!("    Public:  {}", pub_out);
}

/// CLI handler for `sign` command.
pub fn cmd_sign(model_path: &str, priv_path: &str, sig_out: &str) {
    match sign_single(Path::new(model_path), priv_path, sig_out) {
        Ok(digest) => {
            println!("[+] Signed {}", model_path);
            println!("    SHA-256:   {}", hex::encode(digest));
            println!("    Signature: {}", sig_out);
        }
        Err(e) => {
            eprintln!("[!] {}", e);
            process::exit(1);
        }
    }
}

/// CLI handler for `verify` command.
pub fn cmd_verify(model_path: &str, pub_path: &str, sig_path: &str) {
    match verify_single(Path::new(model_path), pub_path, sig_path) {
        Ok(digest) => {
            println!("[OK] VERIFIED: {}", model_path);
            println!("     SHA-256: {}", hex::encode(digest));
        }
        Err(e) => {
            eprintln!("[FAIL] {}", e);
            process::exit(2);
        }
    }
}

/// CLI handler for `sign-dir` command.
pub fn cmd_sign_dir(dir_str: &str, priv_path: &str) {
    let dir = Path::new(dir_str);
    match sign_dir(dir, priv_path) {
        Ok((count, manifest_path, sig_path)) => {
            println!("[+] Signed {} shards in {}", count, dir.display());
            println!("    Manifest:  {}", manifest_path.display());
            println!("    Signature: {}", sig_path.display());
        }
        Err(e) => {
            eprintln!("[!] {}", e);
            process::exit(1);
        }
    }
}

/// CLI handler for `verify-dir` command.
pub fn cmd_verify_dir(dir_str: &str, pub_path: &str) {
    let dir = Path::new(dir_str);
    match verify_dir(dir, pub_path) {
        Ok(shard_count) => {
            println!(
                "[OK] VERIFIED ALL {} SHARDS IN {}",
                shard_count,
                dir.display()
            );
        }
        Err(e) => {
            eprintln!("[FAIL] {}", e);
            process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn create_dummy_safetensors(path: &Path, content: &[u8]) {
        let mut file = File::create(path).unwrap();
        let header = b"{\"dummy\":{\"dtype\":\"F32\",\"shape\":[1],\"data_offsets\":[0,1]}}";
        let header_len = (header.len() as u64).to_le_bytes();
        file.write_all(&header_len).unwrap();
        file.write_all(header).unwrap();
        file.write_all(content).unwrap();
    }

    fn tempfile_dir(prefix: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "stverify_lib_{}_{}",
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
    fn test_framing_and_hashing() {
        let temp_dir = tempfile_dir("test_hashing");
        let shard_path = temp_dir.join("test.safetensors");
        create_dummy_safetensors(&shard_path, b"random_weight_bytes_123");

        let hash_result = hash_safetensors(&shard_path);
        assert!(hash_result.is_ok());

        // Corrupt header length
        let corrupted_path = temp_dir.join("corrupted.safetensors");
        let mut corrupted = File::create(&corrupted_path).unwrap();
        corrupted.write_all(&[0u8; 8]).unwrap();
        assert!(hash_safetensors(&corrupted_path).is_err());

        fs::remove_dir_all(&temp_dir).ok();
    }

    #[test]
    fn test_keygen_sign_verify_single() {
        let temp_dir = tempfile_dir("test_single");
        let priv_path = temp_dir.join("signing.priv");
        let pub_path = temp_dir.join("signing.pub");
        let model_path = temp_dir.join("model-00001.safetensors");
        let sig_path = temp_dir.join("model-00001.sig");

        generate_keypair(priv_path.to_str().unwrap(), pub_path.to_str().unwrap()).unwrap();
        create_dummy_safetensors(&model_path, b"tensor_shard_1_weights");

        let sign_res = sign_single(
            &model_path,
            priv_path.to_str().unwrap(),
            sig_path.to_str().unwrap(),
        );
        assert!(sign_res.is_ok());

        let verify_res = verify_single(
            &model_path,
            pub_path.to_str().unwrap(),
            sig_path.to_str().unwrap(),
        );
        assert!(verify_res.is_ok());

        // Tamper with shard
        fs::write(&model_path, b"tampered_bytes_with_no_header").unwrap();
        let verify_tampered = verify_single(
            &model_path,
            pub_path.to_str().unwrap(),
            sig_path.to_str().unwrap(),
        );
        assert!(verify_tampered.is_err());

        fs::remove_dir_all(&temp_dir).ok();
    }

    #[test]
    fn test_parallel_multi_shard_manifest_and_tampering() {
        let temp_dir = tempfile_dir("test_multi_shard");
        let priv_path = temp_dir.join("signing.priv");
        let pub_path = temp_dir.join("signing.pub");

        generate_keypair(priv_path.to_str().unwrap(), pub_path.to_str().unwrap()).unwrap();

        for i in 1..=4 {
            let shard_path = temp_dir.join(format!("model-0000{}-of-00004.safetensors", i));
            create_dummy_safetensors(&shard_path, format!("shard_payload_{}", i).as_bytes());
        }

        let sign_res = sign_dir(&temp_dir, priv_path.to_str().unwrap());
        assert!(sign_res.is_ok());
        let (shard_count, _, _) = sign_res.unwrap();
        assert_eq!(shard_count, 4);

        let verify_res = verify_dir(&temp_dir, pub_path.to_str().unwrap());
        assert!(verify_res.is_ok());
        assert_eq!(verify_res.unwrap(), 4);

        let shard_2 = temp_dir.join("model-00002-of-00004.safetensors");
        create_dummy_safetensors(&shard_2, b"tampered_content");
        assert!(verify_dir(&temp_dir, pub_path.to_str().unwrap()).is_err());

        create_dummy_safetensors(&shard_2, b"shard_payload_2");
        assert!(verify_dir(&temp_dir, pub_path.to_str().unwrap()).is_ok());

        let rogue_shard = temp_dir.join("model-00005-of-00004.safetensors");
        create_dummy_safetensors(&rogue_shard, b"rogue_injected_weights");
        assert!(verify_dir(&temp_dir, pub_path.to_str().unwrap()).is_err());

        fs::remove_file(&rogue_shard).unwrap();
        assert!(verify_dir(&temp_dir, pub_path.to_str().unwrap()).is_ok());

        fs::remove_file(&shard_2).unwrap();
        assert!(verify_dir(&temp_dir, pub_path.to_str().unwrap()).is_err());

        fs::remove_dir_all(&temp_dir).ok();
    }
}
