use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::env;
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::Path;
use std::process;

const MAX_HEADER_SIZE: u64 = 100 * 1024 * 1024; // 100 MB sanity cap on JSON metadata header

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_usage();
        process::exit(1);
    }

    match args[1].as_str() {
        "keygen" => {
            if args.len() != 4 {
                eprintln!("Usage: stverify keygen <privkey.hex> <pubkey.hex>");
                process::exit(1);
            }
            cmd_keygen(&args[2], &args[3]);
        }
        "sign" => {
            if args.len() != 5 {
                eprintln!("Usage: stverify sign <model.safetensors> <privkey.hex> <out.sig>");
                process::exit(1);
            }
            cmd_sign(&args[2], &args[3], &args[4]);
        }
        "verify" => {
            if args.len() != 5 {
                eprintln!("Usage: stverify verify <model.safetensors> <pubkey.hex> <model.sig>");
                process::exit(1);
            }
            cmd_verify(&args[2], &args[3], &args[4]);
        }
        _ => {
            print_usage();
            process::exit(1);
        }
    }
}

fn print_usage() {
    eprintln!("stverify - Cryptographic Integrity Verifier for Safetensors\n");
    eprintln!("Commands:");
    eprintln!("  keygen <privkey.hex> <pubkey.hex>                 Generate Ed25519 keypair");
    eprintln!("  sign   <model.safetensors> <privkey.hex> <out.sig> Sign model shard");
    eprintln!("  verify <model.safetensors> <pubkey.hex> <model.sig> Verify model shard");
}

/// Validates basic safetensors framing (8-byte little-endian header length)
/// and streams the entire file into SHA-256 without loading it into memory.
fn hash_safetensors(path: &str) -> [u8; 32] {
    let file = File::open(path).unwrap_or_else(|e| {
        eprintln!("[!] Failed to open {}: {}", path, e);
        process::exit(1);
    });

    let metadata = file.metadata().unwrap();
    if metadata.len() < 8 {
        eprintln!("[!] Invalid safetensors file: smaller than 8-byte header prefix");
        process::exit(1);
    }

    let mut reader = BufReader::with_capacity(64 * 1024, file);
    let mut len_buf = [0u8; 8];
    reader.read_exact(&mut len_buf).unwrap();

    let header_len = u64::from_le_bytes(len_buf);
    if header_len == 0 || header_len > MAX_HEADER_SIZE || header_len + 8 > metadata.len() {
        eprintln!(
            "[!] Malformed safetensors header length: {} bytes",
            header_len
        );
        process::exit(1);
    }

    let mut hasher = Sha256::new();
    hasher.update(len_buf);

    let mut chunk = [0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut chunk).unwrap_or_else(|e| {
            eprintln!("[!] Read error on {}: {}", path, e);
            process::exit(1);
        });
        if n == 0 {
            break;
        }
        hasher.update(&chunk[..n]);
    }

    hasher.finalize().into()
}

fn cmd_keygen(priv_out: &str, pub_out: &str) {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();

    fs::write(priv_out, hex::encode(signing_key.to_bytes())).expect("Failed writing private key");
    fs::write(pub_out, hex::encode(verifying_key.to_bytes())).expect("Failed writing public key");

    println!("[+] Generated Ed25519 keypair:");
    println!("    Private: {}", priv_out);
    println!("    Public:  {}", pub_out);
}

fn cmd_sign(model_path: &str, priv_path: &str, sig_out: &str) {
    let priv_hex = fs::read_to_string(priv_path).expect("Failed reading private key");
    let priv_bytes: [u8; 32] = hex::decode(priv_hex.trim())
        .expect("Invalid hex in private key")
        .try_into()
        .expect("Private key must be 32 bytes");

    let signing_key = SigningKey::from_bytes(&priv_bytes);
    let digest = hash_safetensors(model_path);
    let signature = signing_key.sign(&digest);

    fs::write(sig_out, hex::encode(signature.to_bytes())).expect("Failed writing signature");
    println!("[+] Signed {}", Path::new(model_path).display());
    println!("    SHA-256:   {}", hex::encode(digest));
    println!("    Signature: {}", sig_out);
}

fn cmd_verify(model_path: &str, pub_path: &str, sig_path: &str) {
    let pub_hex = fs::read_to_string(pub_path).expect("Failed reading public key");
    let pub_bytes: [u8; 32] = hex::decode(pub_hex.trim())
        .expect("Invalid hex in public key")
        .try_into()
        .expect("Public key must be 32 bytes");

    let sig_hex = fs::read_to_string(sig_path).expect("Failed reading signature");
    let sig_bytes: [u8; 64] = hex::decode(sig_hex.trim())
        .expect("Invalid hex in signature")
        .try_into()
        .expect("Signature must be 64 bytes");

    let verifying_key = VerifyingKey::from_bytes(&pub_bytes).expect("Invalid Ed25519 public key");
    let signature = Signature::from_bytes(&sig_bytes);
    let digest = hash_safetensors(model_path);

    match verifying_key.verify(&digest, &signature) {
        Ok(_) => {
            println!("[OK] VERIFIED: {}", Path::new(model_path).display());
            println!("     SHA-256: {}", hex::encode(digest));
        }
        Err(_) => {
            eprintln!("[FAIL] SIGNATURE MISMATCH OR TAMPERED SHARD: {}", model_path);
            process::exit(2);
        }
    }
}
