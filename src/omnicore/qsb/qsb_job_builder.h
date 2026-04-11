// Copyright (c) 2026 The Omni Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef OMNICORE_QSB_JOB_BUILDER_H
#define OMNICORE_QSB_JOB_BUILDER_H

#include <omnicore/qsb/qsb_local_verifier.h>

#include <univalue.h>

#include <cstdint>
#include <string>
#include <vector>

/**
 * QSB Job Builder — Segment 2 of Stage 3 (Morpheus Compute Integration)
 *
 * Constructs the three JSON job payloads for Morpheus P2P compute:
 *   1. qsb_pinning  — find (sequence, locktime) producing valid DER RIPEMD160
 *   2. qsb_digest round 1 — find HORS subset for first digest round
 *   3. qsb_digest round 2 — find HORS subset for second digest round
 *
 * All data in the jobs is PUBLIC-ONLY. Private pre-images never leave the
 * secure device. Providers cannot reconstruct the spending key from job params.
 */

//! A constructed QSB job ready for Morpheus marketplace submission
struct QSBJob {
    std::string type;       //!< "qsb_pinning" or "qsb_digest"
    int version;            //!< Protocol version (currently 1)
    UniValue payload;       //!< Full JSON ready to send to Morpheus marketplace
    std::string job_id;     //!< Populated after submission (empty until then)
};

//! Configuration for QSB job construction
struct QSBJobConfig {
    std::string qsb_config;             //!< Config name (e.g. "Config_A")
    uint32_t search_range_start;         //!< nSequence search range start
    uint32_t search_range_end;           //!< nSequence search range end
    uint32_t sequence_hint;              //!< Hint for providers (last known good)
    uint32_t locktime_hint;              //!< Hint for providers (last known good)
    std::string escrow_contract;         //!< Base address for MOR escrow contract
    uint32_t timeout_blocks;             //!< Escrow timeout in blocks
    std::string mor_amount_per_solution; //!< MOR payment per valid solution

    //! Default constructor with Config A defaults
    QSBJobConfig()
        : qsb_config("Config_A")
        , search_range_start(0)
        , search_range_end(4294967295U)
        , sequence_hint(151205)
        , locktime_hint(656535577)
        , escrow_contract("")
        , timeout_blocks(7200)
        , mor_amount_per_solution("") {}
};

/**
 * Build all three QSB jobs from HORS key material.
 *
 * Returns a vector of 3 QSBJob objects:
 *   [0] qsb_pinning
 *   [1] qsb_digest (round 1)
 *   [2] qsb_digest (round 2)
 *
 * @param[in] keys    HORS key material (commitments + midstate + dummy_sigs)
 * @param[in] config  Job configuration (search ranges, escrow, hints)
 * @return Vector of 3 QSBJob objects
 * @throws std::invalid_argument if keys are incomplete
 */
std::vector<QSBJob> BuildQSBJobs(
    const HORSKeyMaterial& keys,
    const QSBJobConfig& config = QSBJobConfig());

/**
 * Build a pinning job payload.
 *
 * The pinning job asks a provider to find a (sequence, locktime) pair such that
 * ECDSA pubkey recovery from the resulting sighash produces a pubkey whose
 * RIPEMD160 is a valid DER-encoded prefix.
 *
 * @param[in] keys    HORS key material (only scriptcode_midstate used)
 * @param[in] config  Job configuration
 * @return UniValue JSON object matching the qsb_pinning schema
 */
UniValue BuildPinningJob(
    const HORSKeyMaterial& keys,
    const QSBJobConfig& config = QSBJobConfig());

/**
 * Build a digest job payload for the specified round.
 *
 * The digest job asks a provider to find HORS subset indices whose preimages
 * hash to the committed values, for the given round's dummy signatures.
 *
 * @param[in] keys    HORS key material (commitments + dummy_sigs)
 * @param[in] round   Digest round (1 or 2)
 * @param[in] config  Job configuration
 * @return UniValue JSON object matching the qsb_digest schema
 * @throws std::invalid_argument if round is not 1 or 2
 */
UniValue BuildDigestJob(
    const HORSKeyMaterial& keys,
    int round,
    const QSBJobConfig& config = QSBJobConfig());

/**
 * Validate that HORSKeyMaterial has all required fields for job construction.
 *
 * Checks:
 *   - scriptcode_midstate is 32 bytes
 *   - commitments are present and all 20 bytes
 *   - dummy_sigs are present
 *   - num_keys matches commitments count
 *
 * @param[in]  keys   HORS key material to validate
 * @param[out] error  Populated on failure
 * @return true if keys are valid for job construction
 */
bool ValidateKeyMaterial(const HORSKeyMaterial& keys, QSBVerifyError& error);

#endif // OMNICORE_QSB_JOB_BUILDER_H
