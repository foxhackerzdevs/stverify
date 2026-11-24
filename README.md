# `stverify`

[![Crates.io](https://img.shields.io/crates/v/stverify.svg)](https://crates.io/crates/stverify)
[![docs.rs](https://docs.rs/stverify/badge.svg)](https://docs.rs/stverify)
[![CI](https://github.com/foxhackerzdevs/stverify/actions/workflows/ci.yml/badge.svg)](https://github.com/foxhackerzdevs/stverify/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Zero-bloat parallel cryptographic signer and integrity verifier for `.safetensors` model weights.**

Available as both a **standalone static CLI binary** and a **Rust library crate**.

Built by [Fox Hackerz](https://github.com/foxhackerzdevs) for multi-tenant GPU enclaves, sovereign AI clusters, and zero-trust inference pipelines.

---

## Why `stverify`?

As hyperscale AI factories come online—such as [Larsen & Toubro’s](https://www.larsentoubro.com/) multi-thousand-GPU NVIDIA B300 deployments in India—hardware-enforced Confidential Computing (CC TEEs, NVLink inline encryption, and InfiniBand PKey partitioning) protects **data in use** and **data in transit**.

However, silicon isolation cannot protect a workload if **tampered, poisoned, or backdoored model weights** are loaded into GPU memory at startup.

`stverify` closes the artifact supply-chain gap before weights ever touch VRAM:

- **⚡ High-Throughput Parallel Shard Hashing**: Powered by `rayon`, hashes dozens of tensor shards concurrently across CPU cores—tailored for 70B–405B+ parameter models (e.g., Llama-3, DeepSeek, Qwen) split across multi-gigabyte files.
- **🦀 Zero-Bloat Static Binary & Library**: Pure Rust with minimal, audited cryptographic primitives (`ed25519-dalek` and `sha2`). No Python runtime, no OpenSSL dynamic linking, no container bloat.
- **💾 Constant-Memory Streaming**: Hashes multi-gigabyte tensor shards in 64 KB streaming buffers—verifies massive models inside memory-constrained confidential VMs without OOM spikes.
- **📜 Canonical Manifest Integrity**: `sign-dir` builds a deterministic, canonical manifest (`<sha256> <filename>`) across all shards, cryptographically signed with Ed25519. `verify-dir` detects missing shards, injected rogue shards, and bit-level modifications in a single parallel pass.
- **🔍 Framing Validation**: Validates 8-byte little-endian `.safetensors` header length boundaries and enforces sanity caps (100 MB max header size) before reading payload bytes.
- **🔐 Deterministic Ed25519 Signatures**: Fast, constant-time signature verification designed for automated Kubernetes init-containers, model registry gates, and KMS attestation.

---

## Threat Model Fit

> For an in-depth breakdown of the four cryptographic defense layers, hardware attestation, and the multi-tenant GPU threat model, read the engineering architecture post:  
> 📖 [**Zero-Trust Silicon to VRAM: Securing Multi-Tenant Sovereign AI Factories**](https://abhrankan.duckdns.org/writing/zero-trust-silicon-to-vram/).

| Layer | Security Control |
| :--- | :--- |
| **Silicon & Boot** | NVIDIA GPU Hardware Root of Trust + SPDM Remote Attestation |
| **Memory & Interconnect** | CPU-to-GPU TEE Boundary + 5th-Gen NVLink Line-Rate Encryption |
| **Fabric** | Quantum InfiniBand Hardware Partition Keys (PKeys) |
| **Model Weights & Shards** | `stverify` |

---

## Installation

### 1. Install CLI via Cargo
```bash
cargo install stverify
```

### 2. Add as a Rust Library
```bash
cargo add stverify
```

### 3. Build from Source
```bash
git clone https://github.com/foxhackerzdevs/stverify.git
cd stverify
cargo build --release
```
The compiled static binary will be located at `./target/release/stverify`.

---

## CLI Usage

### 1. Generate an Ed25519 Signing Keypair
```bash
stverify keygen signing.priv signing.pub
```

### 2. Multi-Shard Directory Verification (Recommended for 70B+ Models)

In production setups, large models are split into multiple `.safetensors` shards. `sign-dir` deterministically sorts shards, computes SHA-256 in parallel using Rayon, generates `stverify.manifest`, and signs it into `stverify.sig`.

#### Sign an Entire Model Directory
Run immediately after weight quantization or export:
```bash
stverify sign-dir ./models/llama-3-70b-instruct/ signing.priv
```
Output:
```text
[+] Signed 30 shards in ./models/llama-3-70b-instruct/
    Manifest:  ./models/llama-3-70b-instruct/stverify.manifest
    Signature: ./models/llama-3-70b-instruct/stverify.sig
```

#### Verify the Directory Prior to GPU Allocation
Run inside your enclave init-container or inference pod entrypoint before `mmap` or weight loading:
```bash
stverify verify-dir ./models/llama-3-70b-instruct/ signing.pub
```
Output:
```text
[OK] VERIFIED ALL 30 SHARDS IN ./models/llama-3-70b-instruct/
```

`verify-dir` guarantees:
1. The `stverify.manifest` was authentic and signed by the trusted private key.
2. Every declared shard matches its cryptographic hash.
3. No shards are missing.
4. No unmanifested rogue or backdoored shards have been injected into the directory.

---

### 3. Single Shard Sign & Verify

#### Sign a Single `.safetensors` File
```bash
stverify sign model-00001-of-00004.safetensors signing.priv model-00001.sig
```

#### Verify a Single `.safetensors` File
```bash
stverify verify model-00001-of-00004.safetensors signing.pub model-00001.sig
```

---

## Rust Library API

You can integrate `stverify` directly into custom Rust inference runtimes (e.g. Candle, Burn, vLLM Rust wrappers) or orchestration agents:

```rust
use std::path::Path;
use stverify::{verify_dir, verify_single, sign_dir};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Verify an entire multi-shard model directory in parallel before loading weights
    let verified_shards = verify_dir(
        Path::new("/models/llama-3-70b"),
        "/etc/stverify/signing.pub",
    )?;
    println!("[OK] Verified {} shards in parallel", verified_shards);

    // Verify a single shard
    let digest = verify_single(
        Path::new("model-00001.safetensors"),
        "signing.pub",
        "model-00001.sig",
    )?;
    println!("SHA-256: {}", hex::encode(digest));

    Ok(())
}
```

Full API documentation and signatures are available on [docs.rs/stverify](https://docs.rs/stverify).

---

## Exit Codes

`stverify` returns explicit, machine-readable exit codes suitable for orchestration and automation scripts:

| Exit Code | Meaning | Description |
| :---: | :--- | :--- |
| `0` | **Success** | All shard signatures and manifest framing verified successfully. |
| `1` | **System / I/O Error** | Usage error, file not found, permission denied, or malformed `.safetensors` header. |
| `2` | **Verification Failure** | Cryptographic signature invalid, tampered weights, missing shard, or rogue shard injected. |

---

## Docker & Container Usage

The container image is built multi-stage with `musl` into a minimal `FROM scratch` runtime (~1.5 MB static binary) with zero shell, zero libc, and running as non-root UID `65532:65532`.

### Build & Run Locally
```bash
# Build static scratch image
docker build -t foxhackerz/stverify:0.2.4 .

# Verify a model directory with mounted read-only keys
docker run --rm \
  -v $(pwd)/models:/models:ro \
  -v $(pwd)/keys:/keys:ro \
  foxhackerz/stverify:0.2.4 verify-dir /models/llama-3-70b /keys/signing.pub
```

---

## Kubernetes Confidential GPU Pod Integration

In Confidential Computing clusters (e.g. multi-tenant NVIDIA B300 nodes), `stverify` acts as a pre-load gate in an `initContainer`. The main inference runtime container cannot start unless `stverify` exits with code `0`. Mounting weights `readOnly: true` prevents post-verification tampering.

See full deployment manifest in [`deploy/k8s-confidential-pod.yaml`](./deploy/k8s-confidential-pod.yaml):

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: confidential-llm-inference
  labels:
    app: sovereign-llm
    security.foxhackerz.dev/verified-weights: "true"
spec:
  restartPolicy: Never

  # InitContainer blocks GPU workload startup unless all safetensors shards verify
  initContainers:
    - name: stverify-gate
      image: ghcr.io/foxhackerzdevs/stverify:0.2.4
      args:
        - "verify-dir"
        - "/models/llama-3-70b"
        - "/etc/stverify/signing.pub"
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        runAsNonRoot: true
        runAsUser: 65532
        capabilities:
          drop: ["ALL"]
      volumeMounts:
        - name: model-weights
          mountPath: /models/llama-3-70b
          readOnly: true
        - name: signing-pubkey
          mountPath: /etc/stverify
          readOnly: true

  # Main GPU Inference Runtime (only executes after stverify exits 0)
  containers:
    - name: vllm-inference
      image: vllm/vllm-openai:latest
      args:
        - "--model=/models/llama-3-70b"
        - "--load-format=safetensors"
      resources:
        limits:
          nvidia.com/gpu: 4
      volumeMounts:
        - name: model-weights
          mountPath: /models/llama-3-70b
          readOnly: true

  volumes:
    - name: model-weights
      persistentVolumeClaim:
        claimName: verified-model-pvc
    - name: signing-pubkey
      configMap:
        name: stverify-release-pubkey
```

---

## License

MIT License — see [LICENSE](./LICENSE) for details.
