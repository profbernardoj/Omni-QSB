// Copyright (c) 2026 The Omni Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <omnicore/qsb/qsb_job_builder.h>
#include <omnicore/qsb/qsb_local_verifier.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <stdexcept>

// ---------------------------------------------------------------------------
// Test fixture: builds a valid HORSKeyMaterial for reuse across tests
// ---------------------------------------------------------------------------

struct QSBJobBuilderFixture : BasicTestingSetup {
    HORSKeyMaterial keys;
    QSBJobConfig config;

    QSBJobBuilderFixture()
    {
        // 32-byte midstate (deterministic test value)
        keys.scriptcode_midstate.resize(32);
        for (int i = 0; i < 32; ++i) {
            keys.scriptcode_midstate[i] = static_cast<unsigned char>(i);
        }

        // 150 HORS commitments (20 bytes each)
        keys.num_keys = 150;
        for (int i = 0; i < 150; ++i) {
            std::vector<unsigned char> preimage(32, static_cast<unsigned char>(i));
            keys.preimages.push_back(preimage);
            keys.commitments.push_back(ComputeHash160(preimage));
        }

        // 150 dummy signatures (minimal valid DER)
        for (int i = 0; i < 150; ++i) {
            // Minimal DER: 30 06 02 01 [R] 02 01 [S]
            std::vector<unsigned char> sig = {
                0x30, 0x06, 0x02, 0x01, static_cast<unsigned char>(i % 127 + 1),
                0x02, 0x01, static_cast<unsigned char>((i * 7) % 127 + 1)
            };
            keys.dummy_sigs.push_back(sig);
        }

        // Default config with Config_A settings
        config.qsb_config = "Config_A";
        config.escrow_contract = "0x1234567890abcdef1234567890abcdef12345678";
        config.mor_amount_per_solution = "0.5";
    }
};

BOOST_FIXTURE_TEST_SUITE(qsb_job_builder_tests, QSBJobBuilderFixture)

// ---------------------------------------------------------------------------
// ValidateKeyMaterial tests
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(validate_valid_keys)
{
    QSBVerifyError error;
    BOOST_CHECK(ValidateKeyMaterial(keys, error));
}

BOOST_AUTO_TEST_CASE(validate_missing_midstate)
{
    keys.scriptcode_midstate.clear();
    QSBVerifyError error;
    BOOST_CHECK(!ValidateKeyMaterial(keys, error));
    BOOST_CHECK_EQUAL(error.code, "INVALID_MIDSTATE");
}

BOOST_AUTO_TEST_CASE(validate_no_commitments)
{
    keys.commitments.clear();
    QSBVerifyError error;
    BOOST_CHECK(!ValidateKeyMaterial(keys, error));
    BOOST_CHECK_EQUAL(error.code, "NO_COMMITMENTS");
}

BOOST_AUTO_TEST_CASE(validate_key_count_mismatch)
{
    keys.num_keys = 100; // Doesn't match 150 commitments
    QSBVerifyError error;
    BOOST_CHECK(!ValidateKeyMaterial(keys, error));
    BOOST_CHECK_EQUAL(error.code, "KEY_COUNT_MISMATCH");
}

BOOST_AUTO_TEST_CASE(validate_bad_commitment_size)
{
    keys.commitments[50] = std::vector<unsigned char>(19, 0xFF); // 19 bytes, not 20
    QSBVerifyError error;
    BOOST_CHECK(!ValidateKeyMaterial(keys, error));
    BOOST_CHECK_EQUAL(error.code, "INVALID_COMMITMENT_SIZE");
}

BOOST_AUTO_TEST_CASE(validate_no_dummy_sigs)
{
    keys.dummy_sigs.clear();
    QSBVerifyError error;
    BOOST_CHECK(!ValidateKeyMaterial(keys, error));
    BOOST_CHECK_EQUAL(error.code, "NO_DUMMY_SIGS");
}

// ---------------------------------------------------------------------------
// BuildPinningJob tests
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(pinning_job_structure)
{
    UniValue job = BuildPinningJob(keys, config);

    BOOST_CHECK_EQUAL(job["type"].get_str(), "qsb_pinning");
    BOOST_CHECK_EQUAL(job["version"].get_int(), 1);

    // params
    const UniValue& params = job["params"];
    BOOST_CHECK(params["scriptcode_midstate"].get_str().substr(0, 2) == "0x");
    BOOST_CHECK_EQUAL(params["scriptcode_midstate"].get_str().size(), 66); // "0x" + 64 hex chars
    BOOST_CHECK_EQUAL(params["target"].get_str(), "der_valid_ripemd160");
    BOOST_CHECK_EQUAL(params["sighash_type"].get_str(), "SIGHASH_ALL");

    // verification
    const UniValue& verif = job["verification"];
    BOOST_CHECK_EQUAL(verif["method"].get_str(), "local_ripemd160_der_check");
    BOOST_CHECK_EQUAL(verif["expected_probability"].get_str(), "2^-46");

    // payment
    const UniValue& payment = job["payment"];
    BOOST_CHECK_EQUAL(payment["token"].get_str(), "MOR");
    BOOST_CHECK_EQUAL(payment["escrow_contract"].get_str(), config.escrow_contract);

    // metadata
    const UniValue& metadata = job["metadata"];
    BOOST_CHECK_EQUAL(metadata["qsb_config"].get_str(), "Config_A");
}

BOOST_AUTO_TEST_CASE(pinning_job_midstate_hex)
{
    UniValue job = BuildPinningJob(keys, config);

    // Verify midstate hex encoding matches raw bytes
    std::string midstate_hex = job["params"]["scriptcode_midstate"].get_str();
    BOOST_CHECK_EQUAL(midstate_hex, "0x" + HexStr(keys.scriptcode_midstate));
}

BOOST_AUTO_TEST_CASE(pinning_job_invalid_keys_throws)
{
    keys.scriptcode_midstate.clear();
    BOOST_CHECK_THROW(BuildPinningJob(keys, config), std::invalid_argument);
}

// ---------------------------------------------------------------------------
// BuildDigestJob tests
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(digest_job_round1_structure)
{
    UniValue job = BuildDigestJob(keys, 1, config);

    BOOST_CHECK_EQUAL(job["type"].get_str(), "qsb_digest");
    BOOST_CHECK_EQUAL(job["version"].get_int(), 1);

    const UniValue& params = job["params"];
    BOOST_CHECK_EQUAL(params["round"].get_int(), 1);
    BOOST_CHECK(params["scriptcode_midstate"].get_str().substr(0, 2) == "0x");

    // dummy_sigs array
    const UniValue& sigs = params["dummy_sigs"];
    BOOST_CHECK_EQUAL(sigs.size(), 150);
    BOOST_CHECK(sigs[0].get_str().substr(0, 2) == "0x");

    // commitments array
    const UniValue& comms = params["commitments"];
    BOOST_CHECK_EQUAL(comms.size(), 150);
    BOOST_CHECK(comms[0].get_str().substr(0, 2) == "0x");
    BOOST_CHECK_EQUAL(comms[0].get_str().size(), 42); // "0x" + 40 hex chars (20 bytes)

    // verification
    BOOST_CHECK_EQUAL(job["verification"]["method"].get_str(), "local_hors_subset_check");
}

BOOST_AUTO_TEST_CASE(digest_job_round2_structure)
{
    UniValue job = BuildDigestJob(keys, 2, config);
    BOOST_CHECK_EQUAL(job["params"]["round"].get_int(), 2);
}

BOOST_AUTO_TEST_CASE(digest_job_invalid_round_throws)
{
    BOOST_CHECK_THROW(BuildDigestJob(keys, 0, config), std::invalid_argument);
    BOOST_CHECK_THROW(BuildDigestJob(keys, 3, config), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(digest_job_commitment_hex_roundtrip)
{
    UniValue job = BuildDigestJob(keys, 1, config);
    const UniValue& comms = job["params"]["commitments"];

    // Verify first commitment hex matches raw bytes
    std::string expected = "0x" + HexStr(keys.commitments[0]);
    BOOST_CHECK_EQUAL(comms[0].get_str(), expected);
}

// ---------------------------------------------------------------------------
// BuildQSBJobs tests (combined)
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(build_all_jobs_returns_three)
{
    auto jobs = BuildQSBJobs(keys, config);
    BOOST_CHECK_EQUAL(jobs.size(), 3);

    BOOST_CHECK_EQUAL(jobs[0].type, "qsb_pinning");
    BOOST_CHECK_EQUAL(jobs[0].version, 1);

    BOOST_CHECK_EQUAL(jobs[1].type, "qsb_digest");
    BOOST_CHECK_EQUAL(jobs[1].version, 1);

    BOOST_CHECK_EQUAL(jobs[2].type, "qsb_digest");
    BOOST_CHECK_EQUAL(jobs[2].version, 1);
}

BOOST_AUTO_TEST_CASE(build_all_jobs_digest_rounds_differ)
{
    auto jobs = BuildQSBJobs(keys, config);

    // Round 1 and round 2 payloads should have different round numbers
    BOOST_CHECK_EQUAL(jobs[1].payload["params"]["round"].get_int(), 1);
    BOOST_CHECK_EQUAL(jobs[2].payload["params"]["round"].get_int(), 2);
}

BOOST_AUTO_TEST_CASE(build_all_jobs_job_id_initially_empty)
{
    auto jobs = BuildQSBJobs(keys, config);

    // job_id should be empty until submission
    for (const auto& job : jobs) {
        BOOST_CHECK(job.job_id.empty());
    }
}

BOOST_AUTO_TEST_CASE(build_all_jobs_json_serializable)
{
    auto jobs = BuildQSBJobs(keys, config);

    // All payloads must serialize to valid JSON strings
    for (const auto& job : jobs) {
        std::string json_str = job.payload.write();
        BOOST_CHECK(!json_str.empty());
        BOOST_CHECK(json_str[0] == '{'); // Must be a JSON object
    }
}

BOOST_AUTO_TEST_CASE(custom_config_applied)
{
    QSBJobConfig custom;
    custom.qsb_config = "Config_B";
    custom.search_range_start = 1000;
    custom.search_range_end = 2000;
    custom.sequence_hint = 42;
    custom.locktime_hint = 99;
    custom.escrow_contract = "0xdeadbeef";
    custom.timeout_blocks = 3600;
    custom.mor_amount_per_solution = "1.5";

    UniValue job = BuildPinningJob(keys, custom);

    BOOST_CHECK_EQUAL(job["metadata"]["qsb_config"].get_str(), "Config_B");
    BOOST_CHECK_EQUAL(job["metadata"]["sequence_hint"].get_int64(), 42);
    BOOST_CHECK_EQUAL(job["metadata"]["locktime_hint"].get_int64(), 99);
    BOOST_CHECK_EQUAL(job["payment"]["escrow_contract"].get_str(), "0xdeadbeef");
    BOOST_CHECK_EQUAL(job["payment"]["timeout_blocks"].get_int64(), 3600);
    BOOST_CHECK_EQUAL(job["payment"]["amount_per_solution"].get_str(), "1.5");
}

BOOST_AUTO_TEST_SUITE_END()
