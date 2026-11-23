# `stverify`

**Zero-bloat parallel cryptographic signer and integrity verifier for `.safetensors` model weights.**

Built by [Fox Hackerz](https://github.com/foxhackerzdevs) for multi-tenant GPU enclaves, sovereign AI clusters, and zero-trust inference pipelines.

---

## Why `stverify`?

As hyperscale AI factories come online—such as [Larsen & Toubro’s](https://www.larsentoubro.com/) multi-thousand-GPU NVIDIA B300 deployments in India—hardware-enforced Confidential Computing (CC TEEs, NVLink inline encryption, and InfiniBand PKey partitioning) protects **data in use** and **data in transit**.

However, silicon isolation cannot protect a workload if **tampered, poisoned, or backdoored model weights** are loaded into GPU memory at startup.

`stverify` closes the artifact supply-chain gap before weights ever touch VRAM:

- **⚡ High-Throughput Parallel Shard Hashing**: Powered by `rayon`, hashes dozens of tensor shards in parallel across CPU cores—tailored for 70B–405B+ parameter models (e.g., Llama-3, DeepSeek, Qwen) split across multi-gigabyte files.
- **🦀 Zero-Bloat Static Binary**: Pure Rust with minimal, audited cryptographic primitives (`ed25519-dalek` and `sha2`). No Python runtime, no OpenSSL dynamic linking, no container bloat.
- **💾 Constant-Memory Streaming**: Hashes multi-gigabyte tensor shards in 64 KB streaming buffers—verifies massive models inside memory-constrained confidential VMs without OOM spikes.
- **📜 Canonical Manifest Integrity**: `sign-dir` builds a deterministic, canonical manifest (`<sha256> <filename>`) across all shards, cryptographically signed with Ed25519. `verify-dir` detects missing shards, injected rogue shards, and bit-level modifications in a single parallel pass.
- **🔍 Framing Validation**: Validates 8-byte little-endian `.safetensors` header length boundaries and enforces sanity caps (100 MB max header size) before reading payload bytes.
- **🔐 Deterministic Ed25519 Signatures**: Fast, constant-time signature verification designed for automated Kubernetes init-containers, model registry gates, and KMS attestation.

---

## Threat Model Fit

| Layer | Security Control |
| :--- | :--- |
| **Silicon & Boot** | NVIDIA GPU Hardware Root of Trust + SPDM Remote Attestation |
| **Memory & Interconnect** | CPU-to-GPU TEE Boundary + 5th-Gen NVLink Line-Rate Encryption |
| **Fabric** | Quantum InfiniBand Hardware Partition Keys (PKeys) |
| **Model Weights & Shards** | `stverify` |

---

## Installation

### Build from Source
```bash
git clone https://github.com/foxhackerzdevs/stverify.git
cd stverify
cargo build --release
```

The compiled static binary will be located at `./target/release/stverify`.

---

## Usage

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

## Exit Codes

`stverify` returns explicit, machine-readable exit codes suitable for orchestration and automation scripts:

| Exit Code | Meaning | Description |
| :---: | :--- | :--- |
| `0` | **Success** | All shard signatures and manifest framing verified successfully. |
| `1` | **System / I/O Error** | Usage error, file not found, permission denied, or malformed `.safetensors` header. |
| `2` | **Verification Failure** | Cryptographic signature invalid, tampered weights, missing shard, or rogue shard injected. |

---

## Kubernetes Init-Container Integration

Deploy `stverify` as a lightweight init-container to gate model execution in Confidential GPU pods:

```yaml
initContainers:
  - name: verify-model-weights
    image: ghcr.io/foxhackerzdevs/stverify:latest
    command: ["stverify", "verify-dir", "/models/llama-3-70b", "/etc/keys/model-signer.pub"]
    volumeMounts:
      - name: model-weights
        mountPath: /models/llama-3-70b
      - name: signing-pubkey
        mountPath: /etc/keys/model-signer.pub
        subPath: model-signer.pub
        readOnly: true
```

---

## License

MIT License — see [LICENSE](file:///LICENSE) for details.
