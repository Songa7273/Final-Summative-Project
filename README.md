# Blockchain-Based Library Lending Tracker

This project implements a compact C-based blockchain library lending simulator. It includes:

- book and member registries loaded from file
- copy-level inventory tracking
- pending lending actions and mining confirmation
- Merkle root calculation for block integrity checks
- OpenSSL ECDSA P-256 message signatures for generated lending records
- proof-of-work mining with nonce and difficulty validation
- overdue detection, renewals, and reservation queues
- simple state persistence via `save` and `load` style files

## Build

In MSYS2 UCRT64:

`make`

The build links against OpenSSL `libcrypto` for ECDSA P-256 keys and signatures.
The default Makefile expects MSYS2 UCRT64 at `C:/msys64/ucrt64`.

Run the automated checks with:

`make test`

## Example commands

- `./library seed`
- `./library demo`
- `./library load`
- `./library borrow B001 M001`
- `./library mine miner1`
- `./library verify`
- `./library save state.txt`

## Demo flow

```bash
./library seed
./library demo
./library borrow B001 M001
./library mine miner1
./library verify
```

Mining performs proof-of-work at the configured `BLOCK_DIFFICULTY`, and
`verify` checks the chain links, Merkle roots, block hashes, and proof-of-work.

The project is designed as a working prototype for the ALU blockchain summative assignment rather than a production-grade library system.
