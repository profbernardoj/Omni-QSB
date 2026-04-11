// Copyright (c) 2026 The Omni Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <omnicore/qsb/qsb_local_verifier.h>

#include <crypto/ripemd160.h>
#include <crypto/sha256.h>
#include <hash.h>

#include <algorithm>
#include <cstring>
#include <set>

// ---------------------------------------------------------------------------
// Hash utilities
// ---------------------------------------------------------------------------

std::vector<unsigned char> ComputeRIPEMD160(const std::vector<unsigned char>& data)
{
    std::vector<unsigned char> result(CRIPEMD160::OUTPUT_SIZE);
    CRIPEMD160().Write(data.data(), data.size()).Finalize(result.data());
    return result;
}

std::vector<unsigned char> ComputeHash160(const std::vector<unsigned char>& data)
{
    // Hash160 = RIPEMD160(SHA256(data))
    unsigned char sha_buf[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(data.data(), data.size()).Finalize(sha_buf);

    std::vector<unsigned char> result(CRIPEMD160::OUTPUT_SIZE);
    CRIPEMD160().Write(sha_buf, sizeof(sha_buf)).Finalize(result.data());
    return result;
}

// ---------------------------------------------------------------------------
// DER signature validation (mirrors Bitcoin Core interpreter logic)
// ---------------------------------------------------------------------------

/**
 * Strict DER signature encoding check.
 *
 * Validates that a byte sequence conforms to BIP66 strict DER encoding.
 * This is a self-contained implementation mirroring the logic in
 * src/script/interpreter.cpp IsValidSignatureEncoding().
 *
 * Format: 0x30 [total-len] 0x02 [R-len] [R] 0x02 [S-len] [S]
 *
 * Rules:
 *   - Minimum 8 bytes (empty R and S), maximum 72 bytes
 *   - Leading byte is 0x30 (compound type)
 *   - Total length byte matches actual remaining length
 *   - R and S are each prefixed with 0x02 (integer type)
 *   - R and S lengths are non-zero
 *   - R and S have no unnecessary leading zeros
 *   - R and S are not negative (high bit of first byte must be 0)
 */
bool IsValidDERSignature(const std::vector<unsigned char>& sig)
{
    // Minimum DER sig: 30 06 02 01 [R] 02 01 [S] = 8 bytes
    // Maximum DER sig: 30 44 02 20 [32-byte R] 02 20 [32-byte S] = 70 bytes
    // With sighash appended it can be 73, but here we check raw DER only
    if (sig.size() < 8 || sig.size() > 72) {
        return false;
    }

    // Compound type
    if (sig[0] != 0x30) {
        return false;
    }

    // Total length must match remaining bytes
    if (sig[1] != sig.size() - 2) {
        return false;
    }

    // Extract R
    if (sig[2] != 0x02) {
        return false;
    }
    unsigned int lenR = sig[3];
    if (lenR == 0) {
        return false;
    }
    if (lenR > sig.size() - 7) {
        return false; // Not enough room for S
    }

    // R must not be negative
    if (sig[4] & 0x80) {
        return false;
    }

    // R must not have unnecessary leading zeros
    if (lenR > 1 && sig[4] == 0x00 && !(sig[5] & 0x80)) {
        return false;
    }

    // Extract S
    unsigned int sOffset = 4 + lenR;
    if (sOffset + 2 > sig.size()) {
        return false;
    }
    if (sig[sOffset] != 0x02) {
        return false;
    }
    unsigned int lenS = sig[sOffset + 1];
    if (lenS == 0) {
        return false;
    }

    // Total length consistency: 2 (type+len for R) + lenR + 2 (type+len for S) + lenS
    if (sOffset + 2 + lenS != sig.size()) {
        return false;
    }

    unsigned int sDataOffset = sOffset + 2;

    // S must not be negative
    if (sig[sDataOffset] & 0x80) {
        return false;
    }

    // S must not have unnecessary leading zeros
    if (lenS > 1 && sig[sDataOffset] == 0x00 && !(sig[sDataOffset + 1] & 0x80)) {
        return false;
    }

    return true;
}

// ---------------------------------------------------------------------------
// Compressed pubkey validation
// ---------------------------------------------------------------------------

bool IsValidCompressedPubKey(const std::vector<unsigned char>& pubkey)
{
    // Compressed pubkey: exactly 33 bytes, prefix 0x02 or 0x03
    if (pubkey.size() != 33) {
        return false;
    }
    if (pubkey[0] != 0x02 && pubkey[0] != 0x03) {
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Pinning verification
// ---------------------------------------------------------------------------

bool VerifyPinningResult(
    const QSBPinningResult& result,
    const std::vector<unsigned char>& scriptcode_midstate,
    QSBVerifyError& error)
{
    // 1. Validate recovered pubkey is a valid compressed public key
    if (!IsValidCompressedPubKey(result.recovered_pubkey)) {
        error.code = "INVALID_PUBKEY";
        error.message = "Recovered pubkey is not a valid 33-byte compressed public key";
        return false;
    }

    // 2. Verify RIPEMD160(recovered_pubkey) matches the claimed hash
    //
    //    The pinning puzzle requires finding a (sequence, locktime) pair such that
    //    the implicit ECDSA pubkey recovery from the sighash produces a pubkey
    //    whose RIPEMD160 hash satisfies the DER-valid constraint.
    //
    //    The provider returns the recovered pubkey and its RIPEMD160. We verify
    //    the hash is correctly computed.
    std::vector<unsigned char> computed_hash = ComputeRIPEMD160(result.recovered_pubkey);

    if (result.ripemd160_hash.size() != 20) {
        error.code = "INVALID_HASH_SIZE";
        error.message = "RIPEMD160 hash must be exactly 20 bytes";
        return false;
    }

    if (computed_hash != result.ripemd160_hash) {
        error.code = "HASH_MISMATCH";
        error.message = "RIPEMD160(recovered_pubkey) does not match claimed hash";
        return false;
    }

    // 3. Verify the RIPEMD160 hash is a valid DER-encoded signature
    //
    //    The QSB pinning puzzle requires that RIPEMD160(pubkey) happens to be
    //    a valid DER-encoded signature (or prefix thereof). This is the core
    //    proof-of-work: finding a pubkey whose hash looks like a DER signature.
    //
    //    The 20-byte RIPEMD160 output must parse as a valid DER structure.
    //    Since 20 bytes is shorter than a full ECDSA signature (typically 70-72
    //    bytes), we check that the first bytes form a valid DER prefix:
    //      0x30 [len] 0x02 [R-len] [R bytes...]
    //
    //    This is the "DER-valid RIPEMD160" target from the spec.
    if (result.ripemd160_hash.size() < 4) {
        error.code = "DER_TOO_SHORT";
        error.message = "RIPEMD160 hash too short for DER prefix check";
        return false;
    }

    // Check DER prefix structure in the 20-byte hash:
    //   Byte 0: 0x30 (SEQUENCE tag)
    //   Byte 1: length byte (must be <= 18 for remaining 18 bytes)
    //   Byte 2: 0x02 (INTEGER tag for R)
    //   Byte 3: R length (must be > 0 and fit within remaining bytes)
    if (result.ripemd160_hash[0] != 0x30) {
        error.code = "DER_BAD_TAG";
        error.message = "RIPEMD160 hash byte 0 is not 0x30 (SEQUENCE)";
        return false;
    }

    unsigned char total_len = result.ripemd160_hash[1];
    if (total_len > 18) { // 20 - 2 (tag + length byte) = 18 max
        error.code = "DER_BAD_LENGTH";
        error.message = "DER total length exceeds available bytes in 20-byte hash";
        return false;
    }

    if (result.ripemd160_hash[2] != 0x02) {
        error.code = "DER_BAD_R_TAG";
        error.message = "RIPEMD160 hash byte 2 is not 0x02 (INTEGER for R)";
        return false;
    }

    unsigned char r_len = result.ripemd160_hash[3];
    if (r_len == 0 || r_len > total_len - 2) {
        error.code = "DER_BAD_R_LEN";
        error.message = "DER R-length is zero or exceeds total length";
        return false;
    }

    // R must not be negative (high bit of first R byte must be 0)
    if (4 < result.ripemd160_hash.size() && (result.ripemd160_hash[4] & 0x80)) {
        error.code = "DER_R_NEGATIVE";
        error.message = "DER R value is negative (high bit set)";
        return false;
    }

    // 4. Verify scriptcode midstate consistency
    //
    //    The scriptcode_midstate is the SHA-256 internal state after hashing
    //    the fixed script prefix. The provider used this to compute sighashes
    //    efficiently. We verify it's the expected 32 bytes.
    //
    //    NOTE: Full sighash recomputation (midstate + sequence + locktime →
    //    sighash → pubkey recovery → RIPEMD160) requires the secp256k1 recovery
    //    API and is planned for Stage 3 Segment 4 (integration test).
    //    For now we verify the algebraic constraints on the result.
    if (scriptcode_midstate.size() != 32) {
        error.code = "INVALID_MIDSTATE";
        error.message = "scriptcode_midstate must be exactly 32 bytes";
        return false;
    }

    return true;
}

// ---------------------------------------------------------------------------
// Digest verification
// ---------------------------------------------------------------------------

bool VerifyDigestResult(
    const QSBDigestResult& result,
    const HORSKeyMaterial& keys,
    int expected_subset_size,
    QSBVerifyError& error)
{
    // 1. Validate round number
    if (result.round != 1 && result.round != 2) {
        error.code = "INVALID_ROUND";
        error.message = "Digest round must be 1 or 2, got " + std::to_string(result.round);
        return false;
    }

    // 2. Validate subset size
    if ((int)result.subset_indices.size() != expected_subset_size) {
        error.code = "WRONG_SUBSET_SIZE";
        error.message = "Expected " + std::to_string(expected_subset_size)
                      + " subset indices, got " + std::to_string(result.subset_indices.size());
        return false;
    }

    // 3. Validate preimage count matches index count
    if (result.preimages.size() != result.subset_indices.size()) {
        error.code = "PREIMAGE_COUNT_MISMATCH";
        error.message = "Number of preimages (" + std::to_string(result.preimages.size())
                      + ") does not match subset indices (" + std::to_string(result.subset_indices.size()) + ")";
        return false;
    }

    // 4. Validate all indices are in range and unique
    std::set<int> seen;
    for (int idx : result.subset_indices) {
        if (idx < 0 || idx >= keys.num_keys) {
            error.code = "INDEX_OUT_OF_RANGE";
            error.message = "Subset index " + std::to_string(idx)
                          + " out of range [0, " + std::to_string(keys.num_keys) + ")";
            return false;
        }
        if (!seen.insert(idx).second) {
            error.code = "DUPLICATE_INDEX";
            error.message = "Duplicate subset index: " + std::to_string(idx);
            return false;
        }
    }

    // 5. Verify each preimage hashes to the corresponding commitment
    //
    //    For each (index, preimage) pair:
    //      Hash160(preimage) must equal commitments[index]
    //
    //    This is the core HORS verification: the provider found preimages
    //    whose hashes match the public commitments at the required indices.
    //    The subset of indices is determined by the sighash of the transaction
    //    (which the provider computed via GPU brute-force).
    for (size_t i = 0; i < result.subset_indices.size(); ++i) {
        int idx = result.subset_indices[i];

        // Preimage must be exactly 32 bytes
        if (result.preimages[i].size() != 32) {
            error.code = "INVALID_PREIMAGE_SIZE";
            error.message = "Preimage at position " + std::to_string(i)
                          + " is " + std::to_string(result.preimages[i].size())
                          + " bytes, expected 32";
            return false;
        }

        // Commitment must exist and be 20 bytes
        if (idx >= (int)keys.commitments.size() || keys.commitments[idx].size() != 20) {
            error.code = "MISSING_COMMITMENT";
            error.message = "No valid 20-byte commitment at index " + std::to_string(idx);
            return false;
        }

        // Hash160(preimage) == commitment[index]
        std::vector<unsigned char> computed = ComputeHash160(result.preimages[i]);
        if (computed != keys.commitments[idx]) {
            error.code = "COMMITMENT_MISMATCH";
            error.message = "Hash160(preimage[" + std::to_string(i)
                          + "]) does not match commitment[" + std::to_string(idx) + "]";
            return false;
        }
    }

    return true;
}
