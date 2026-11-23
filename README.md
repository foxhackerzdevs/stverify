`stverify`

**Zero-bloat cryptographic signer and integrity verifier for.safetensors model weights.**

Built by [Fox Hackerz](https://github.com/foxhackerzdevs) for multi-tenant GPU enclaves, sovereign AI clusters, and zero-trust inference pipelines.

Why `stverify`?

As hyperscale AI factories come online—such as [Larsen & Toubro’s](https://www.larsentoubro.com/) multi-thousand-GPU NVIDIA B300 deployments in India—hardware-enforced Confidential C TEEs, NVLink inline encryption, and InfiniBand PKey partitioning) protects **data in use** and **data in transit**.

However, silicon isolation cannot protect a workload if **tampered or poisoned model weights** are loaded into GPU memory at startup.

`stverify` closes the artifact supply-chain gap before weights ever touch VRAM:

- Zero-Bloat Static Binary: Written in pure Rust with minimal, audited cryptographic primitives (ed25519-dalek and sha2). No Python runtime, no OpenSSL dynamic linking, no container bloat.
- Constant-Memory Streaming: Hashes multi-gigabyte tensor shards in 64 KB chunks—capable of verifying 70B+ parameter shards inside memory-constrained confidential VMs without OOM spikes.
- Framing Validation: Validates the 8-byte little-endian.safetensors header boundary and enforces sanity caps before reading payload bytes.
- Deterministic Ed25519 Signatures: Fast, constant-time signature verification designed for automated init-containers and KMS release gates.

Threat Model Fit

| Layer | Security Control |
| --- | --- |
| Silicon & Boot | NVIDIA GPU Hardware Root of Trust + SPDM Remote Attestation |
| Memory & Interconnect | CPU-to-GPU TEE Boundary + 5th-Gen NVLink Line-Rate Encryption |
| Fabric | Quantum InfiniBand Hardware Partition Keys (PKeys) |
| Model Artifacts | `stverify` |

Installation

Build a static release binary from source:

```
git clone https://github.com
cd stverify
cargo build --release
```

The compiled binary will be located at `./target/release/stverify`.

Usage

1. Generate an Ed25519 Signing Keypair

```
stverify keygen signing.priv signing.pub
```

2. Sign a `.safetensors` Shard

Run this in your environment immediately after exporting weights:

```
stverify sign model-00001-of-00004.safetensors signing.priv model-00001.sig
```

3. Verify Before Loading into GPU Memory

Run this inside your enclave init-container or inference entrypoint prior to `mmap` / weight loading:

```
stverify verify model-00001-of-00004.safetensors signing.pub model-00001.sig
```

**Exit Codes:**

- 0 — Signature valid; file framing intact.
- 1 — Usage error, I/O failure, or malformed.safetensors header.
- 2 — Cryptographic verification failed (tampered weights or mismatched public key).

License

MIT License — see `LICENSE` for details.
