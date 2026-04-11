# Omni Core — QSB (Quantum-Safe Bitcoin) Support

## Overview

This release adds support for Quantum-Safe Bitcoin (QSB) transactions as a
recognized input and output type in the Omni protocol. QSB uses HORS
(Hash to Obtain Random Subsets) one-time signatures with RIPEMD-160 puzzles
to provide quantum-resistant transaction authorization.

## Consensus Changes

- New activation parameter: `QSB_BLOCK`
  - Mainnet: TBD (disabled until activation height is set)
  - Testnet: 0 (immediate activation)
  - Regtest: 0 (immediate activation)
- New script type: `TX_QSB_BARE` — bare scripts containing HORS commitments
- `IsAllowedInputType()` and `IsAllowedOutputType()` accept `TX_QSB_BARE`
  after the activation block

## Address Format

QSB addresses use Bech32 encoding with network-specific human-readable parts:
- Mainnet: `qs1...`
- Testnet: `qst1...`
- Regtest: `qsrt1...`

The address payload is the Hash160 of the concatenated HORS commitments
extracted from the bare script.

## Script Detection

QSB bare scripts are identified by:
1. Size: 5,000–10,000 bytes (Config A baseline ~9,650 bytes)
2. Pinning section fingerprint: `OP_OVER OP_CHECKSIGVERIFY OP_RIPEMD160 OP_SWAP OP_CHECKSIGVERIFY`
3. HORS commitments: ≥20 pushes of exactly 20 bytes each

## Technical Details

Based on Config A from the QSB paper by Avihu Levy:
- Known pinned result: sequence=151205, locktime=656535577
- QSB scripts use legacy FindAndDelete (incompatible with SegWit/BIP143)
- Scripts exceed the 520-byte P2SH push limit, requiring bare output

## Files Modified

- `src/script/standard.h` — `TX_QSB_BARE` enum, `QSBHash` type, `CTxDestination` variant
- `src/script/standard.cpp` — `MatchQSBBare()`, `Solver()`, `ExtractDestination()`, visitors
- `src/omnicore/rules.h` — `QSB_BLOCK` in `CConsensusParams`
- `src/omnicore/rules.cpp` — Activation blocks, `IsAllowedInputType/OutputType`
- `src/omnicore/script.h` — `SolverQSB()`, `SerializeHORSCommitments()` declarations
- `src/omnicore/script.cpp` — `SolverQSB()` implementation, `SafeSolver()` extension
- `src/key_io.cpp` — Bech32 encode/decode for `qs`/`qst`/`qsrt` addresses
- `src/rpc/util.cpp` — `DescribeAddressVisitor` for QSB
- `src/wallet/rpcwallet.cpp` — `DescribeWalletAddressVisitor` for QSB
