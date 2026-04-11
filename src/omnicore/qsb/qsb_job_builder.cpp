// Copyright (c) 2026 The Omni Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <omnicore/qsb/qsb_job_builder.h>

#include <util/strencodings.h>

#include <stdexcept>

// ---------------------------------------------------------------------------
// Key material validation
// ---------------------------------------------------------------------------

bool ValidateKeyMaterial(const HORSKeyMaterial& keys, QSBVerifyError& error)
{
    // scriptcode_midstate must be exactly 32 bytes (SHA-256 internal state)
    if (keys.scriptcode_midstate.size() != 32) {
        error.code = "INVALID_MIDSTATE";
        error.message = "scriptcode_midstate must be exactly 32 bytes, got "
                      + std::to_string(keys.scriptcode_midstate.size());
        return false;
    }

    // Must have commitments
    if (keys.commitments.empty()) {
        error.code = "NO_COMMITMENTS";
        error.message = "HORSKeyMaterial has no commitments";
        return false;
    }

    // num_keys must match commitments count
    if (keys.num_keys != (int)keys.commitments.size()) {
        error.code = "KEY_COUNT_MISMATCH";
        error.message = "num_keys (" + std::to_string(keys.num_keys)
                      + ") does not match commitments count ("
                      + std::to_string(keys.commitments.size()) + ")";
        return false;
    }

    // All commitments must be exactly 20 bytes (Hash160)
    for (size_t i = 0; i < keys.commitments.size(); ++i) {
        if (keys.commitments[i].size() != 20) {
            error.code = "INVALID_COMMITMENT_SIZE";
            error.message = "Commitment at index " + std::to_string(i)
                          + " is " + std::to_string(keys.commitments[i].size())
                          + " bytes, expected 20";
            return false;
        }
    }

    // dummy_sigs must be present (at least 1 per round)
    if (keys.dummy_sigs.empty()) {
        error.code = "NO_DUMMY_SIGS";
        error.message = "HORSKeyMaterial has no dummy signatures";
        return false;
    }

    return true;
}

// ---------------------------------------------------------------------------
// Pinning job builder
// ---------------------------------------------------------------------------

UniValue BuildPinningJob(const HORSKeyMaterial& keys, const QSBJobConfig& config)
{
    QSBVerifyError error;
    if (!ValidateKeyMaterial(keys, error)) {
        throw std::invalid_argument("Invalid key material: " + error.message);
    }

    // Top-level job object
    UniValue job(UniValue::VOBJ);
    job.pushKV("type", "qsb_pinning");
    job.pushKV("version", 1);

    // params: public search parameters for the pinning puzzle
    //
    // The provider uses scriptcode_midstate to efficiently compute sighashes
    // across the (sequence, locktime) search space without re-hashing the
    // entire scriptCode each time.
    UniValue params(UniValue::VOBJ);
    params.pushKV("scriptcode_midstate", "0x" + HexStr(keys.scriptcode_midstate));
    params.pushKV("search_range_start", (uint64_t)config.search_range_start);
    params.pushKV("search_range_end", (uint64_t)config.search_range_end);
    params.pushKV("target", "der_valid_ripemd160");
    params.pushKV("sighash_type", "SIGHASH_ALL");
    job.pushKV("params", params);

    // verification: tells the provider (and ourselves) how results are checked
    UniValue verification(UniValue::VOBJ);
    verification.pushKV("method", "local_ripemd160_der_check");
    verification.pushKV("expected_probability", "2^-46");
    job.pushKV("verification", verification);

    // payment: MOR escrow on Base (populated by wallet before submission)
    UniValue payment(UniValue::VOBJ);
    payment.pushKV("token", "MOR");
    payment.pushKV("amount_per_solution", config.mor_amount_per_solution);
    payment.pushKV("escrow_contract", config.escrow_contract);
    payment.pushKV("timeout_blocks", (uint64_t)config.timeout_blocks);
    job.pushKV("payment", payment);

    // metadata: hints for providers to narrow search space
    UniValue metadata(UniValue::VOBJ);
    metadata.pushKV("qsb_config", config.qsb_config);
    metadata.pushKV("sequence_hint", (uint64_t)config.sequence_hint);
    metadata.pushKV("locktime_hint", (uint64_t)config.locktime_hint);
    job.pushKV("metadata", metadata);

    return job;
}

// ---------------------------------------------------------------------------
// Digest job builder
// ---------------------------------------------------------------------------

UniValue BuildDigestJob(const HORSKeyMaterial& keys, int round, const QSBJobConfig& config)
{
    if (round != 1 && round != 2) {
        throw std::invalid_argument("Digest round must be 1 or 2, got " + std::to_string(round));
    }

    QSBVerifyError error;
    if (!ValidateKeyMaterial(keys, error)) {
        throw std::invalid_argument("Invalid key material: " + error.message);
    }

    // Top-level job object
    UniValue job(UniValue::VOBJ);
    job.pushKV("type", "qsb_digest");
    job.pushKV("version", 1);

    // params: round number, midstate, dummy sigs, and HORS commitments
    //
    // The provider brute-forces the sighash space to find a subset of HORS
    // commitment indices whose preimages are "revealed" by the digest process.
    // Only PUBLIC commitments are sent — private preimages stay on the wallet.
    UniValue params(UniValue::VOBJ);
    params.pushKV("round", round);
    params.pushKV("scriptcode_midstate", "0x" + HexStr(keys.scriptcode_midstate));

    // dummy_sigs: ~150 DER-encoded dummy signatures used in the script
    UniValue dummySigs(UniValue::VARR);
    for (const auto& sig : keys.dummy_sigs) {
        dummySigs.push_back("0x" + HexStr(sig));
    }
    params.pushKV("dummy_sigs", dummySigs);

    // commitments: public Hash160 commitments (the HORS public key)
    UniValue commitments(UniValue::VARR);
    for (const auto& comm : keys.commitments) {
        commitments.push_back("0x" + HexStr(comm));
    }
    params.pushKV("commitments", commitments);

    job.pushKV("params", params);

    // verification: HORS subset check
    UniValue verification(UniValue::VOBJ);
    verification.pushKV("method", "local_hors_subset_check");
    verification.pushKV("expected_probability", "2^-46");
    job.pushKV("verification", verification);

    // payment: MOR escrow on Base
    UniValue payment(UniValue::VOBJ);
    payment.pushKV("token", "MOR");
    payment.pushKV("amount_per_solution", config.mor_amount_per_solution);
    payment.pushKV("escrow_contract", config.escrow_contract);
    payment.pushKV("timeout_blocks", (uint64_t)config.timeout_blocks);
    job.pushKV("payment", payment);

    return job;
}

// ---------------------------------------------------------------------------
// Combined job builder
// ---------------------------------------------------------------------------

std::vector<QSBJob> BuildQSBJobs(const HORSKeyMaterial& keys, const QSBJobConfig& config)
{
    std::vector<QSBJob> jobs(3);

    // Job 0: Pinning — find valid (sequence, locktime) for DER puzzle
    jobs[0].type = "qsb_pinning";
    jobs[0].version = 1;
    jobs[0].payload = BuildPinningJob(keys, config);

    // Job 1: Digest round 1 — find HORS subset for first round
    jobs[1].type = "qsb_digest";
    jobs[1].version = 1;
    jobs[1].payload = BuildDigestJob(keys, 1, config);

    // Job 2: Digest round 2 — find HORS subset for second round
    jobs[2].type = "qsb_digest";
    jobs[2].version = 1;
    jobs[2].payload = BuildDigestJob(keys, 2, config);

    return jobs;
}
