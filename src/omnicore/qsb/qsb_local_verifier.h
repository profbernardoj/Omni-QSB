// Copyright (c) 2026 The Omni Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef OMNICORE_QSB_LOCAL_VERIFIER_H
#define OMNICORE_QSB_LOCAL_VERIFIER_H

#include <cstdint>
#include <string>
#include <vector>

/**
 * QSB Local Verifier — Segment 1 of Stage 3 (Morpheus Compute Integration)
 *
 * Verifies GPU compute results returned by Morpheus providers entirely locally.
 * No network calls, no trust in the provider. Verification completes in <1 ms.
 *
 * Two verification types:
 *   1. Pinning:  RIPEMD160(recovered_pubkey) must match target + DER validity
 *   2. Digest:   HORS subset indices must hash to matching commitments
 */

//! Result of a pinning job returned by a Morpheus provider
struct QSBPinningResult {
    uint32_t sequence;                          //!< nSequence that produces valid pin
    uint32_t locktime;                          //!< nLockTime that produces valid pin
    std::vector<unsigned char> recovered_pubkey; //!< 33-byte compressed pubkey
    std::vector<unsigned char> ripemd160_hash;   //!< 20-byte RIPEMD160 result
};

//! Result of a digest job (round 1 or 2) returned by a Morpheus provider
struct QSBDigestResult {
    int round;                                              //!< 1 or 2
    std::vector<int> subset_indices;                        //!< HORS subset (typically 9 indices)
    std::vector<std::vector<unsigned char>> preimages;      //!< 32-byte preimages for each index
};

//! HORS key material held by the wallet (never leaves the secure device)
struct HORSKeyMaterial {
    std::vector<std::vector<unsigned char>> commitments;    //!< 20-byte Hash160 commitments (public)
    std::vector<std::vector<unsigned char>> preimages;      //!< 32-byte secret preimages (private)
    int num_keys;                                           //!< Total number of HORS keys (e.g. 150)
};

//! Verification error detail
struct QSBVerifyError {
    std::string code;       //!< Machine-readable error code
    std::string message;    //!< Human-readable description
};

/**
 * Verify a pinning result from a Morpheus provider.
 *
 * Checks:
 *   1. recovered_pubkey is a valid 33-byte compressed public key
 *   2. ripemd160_hash == RIPEMD160(recovered_pubkey)
 *   3. The hash satisfies the DER-valid target constraint
 *
 * @param[in]  result          Pinning result from provider
 * @param[in]  scriptcode_midstate  SHA-256 midstate of the fixed script prefix (32 bytes)
 * @param[out] error           Populated on failure with detail
 * @return true if the pinning result is valid
 */
bool VerifyPinningResult(
    const QSBPinningResult& result,
    const std::vector<unsigned char>& scriptcode_midstate,
    QSBVerifyError& error);

/**
 * Verify a digest result from a Morpheus provider.
 *
 * Checks:
 *   1. Round is 1 or 2
 *   2. All subset_indices are in range [0, num_keys)
 *   3. No duplicate indices
 *   4. Each preimage hashes to the corresponding commitment:
 *      Hash160(preimage[i]) == commitments[subset_indices[i]]
 *   5. Correct number of indices for the HORS security parameter
 *
 * @param[in]  result          Digest result from provider
 * @param[in]  keys            HORS key material (commitments only; preimages not checked here)
 * @param[in]  expected_subset_size  Expected number of indices per round (typically 9)
 * @param[out] error           Populated on failure with detail
 * @return true if the digest result is valid
 */
bool VerifyDigestResult(
    const QSBDigestResult& result,
    const HORSKeyMaterial& keys,
    int expected_subset_size,
    QSBVerifyError& error);

/**
 * Check if a byte sequence is a valid DER-encoded signature.
 *
 * Wraps the Bitcoin Core DER validation logic for use by the pinning verifier.
 * This is a strict check: the signature must be canonical DER with low-S.
 *
 * @param[in] sig  Raw signature bytes (without sighash byte)
 * @return true if valid DER encoding
 */
bool IsValidDERSignature(const std::vector<unsigned char>& sig);

/**
 * Check if a byte sequence is a valid compressed public key (33 bytes, 02/03 prefix).
 *
 * @param[in] pubkey  Raw public key bytes
 * @return true if valid compressed pubkey
 */
bool IsValidCompressedPubKey(const std::vector<unsigned char>& pubkey);

/**
 * Compute RIPEMD160 of a byte vector.
 *
 * @param[in] data  Input bytes
 * @return 20-byte RIPEMD160 hash
 */
std::vector<unsigned char> ComputeRIPEMD160(const std::vector<unsigned char>& data);

/**
 * Compute Hash160 (SHA256 + RIPEMD160) of a byte vector.
 *
 * @param[in] data  Input bytes
 * @return 20-byte Hash160
 */
std::vector<unsigned char> ComputeHash160(const std::vector<unsigned char>& data);

#endif // OMNICORE_QSB_LOCAL_VERIFIER_H
