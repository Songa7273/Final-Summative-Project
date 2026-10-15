# Blockchain-Based Library Lending Tracker

This project implements a compact C-based blockchain library lending simulator. It includes:

- book and member registries loaded from file
- copy-level inventory tracking
- pending lending actions and mining confirmation
- Merkle root calculation for block integrity checks
- ECDSA-style message signatures for generated lending records
- overdue detection, renewals, and reservation queues
- simple state persistence via `save` and `load` style files

## Build

`gcc -std=c11 -Wall -Wextra -O2 -Iinclude src/main.c src/ledger.c src/sha256.c src/ecdsa.c -lm -o library`

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

The project is designed as a working prototype for the ALU blockchain summative assignment rather than a production-grade library system.
