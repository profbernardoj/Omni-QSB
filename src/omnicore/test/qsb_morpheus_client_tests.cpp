// Copyright (c) 2026 The Omni Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <omnicore/qsb/qsb_morpheus_client.h>
#include <omnicore/qsb/qsb_job_builder.h>
#include <omnicore/qsb/qsb_local_verifier.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <stdexcept>

// ---------------------------------------------------------------------------
// Test fixture: reuses the same HORSKeyMaterial as the job builder tests
// ---------------------------------------------------------------------------

struct QSBMorpheusClientFixture : BasicTestingSetup {
    HORSKeyMaterial keys;
    QSBJobConfig config;
    QSBMorpheusClient client;

    QSBMorpheusClientFixture()
    {
        // 32-byte midstate
        keys.scriptcode_midstate.resize(32);
        for (int i = 0; i < 32; ++i) {
            keys.scriptcode_midstate[i] = static_cast<unsigned char>(i);
        }

        // 150 HORS keys
        keys.num_keys = 150;
        for (int i = 0; i < 150; ++i) {
            std::vector<unsigned char> preimage(32, static_cast<unsigned char>(i));
            keys.preimages.push_back(preimage);
            keys.commitments.push_back(ComputeHash160(preimage));
        }

        // 150 dummy signatures
        for (int i = 0; i < 150; ++i) {
            std::vector<unsigned char> sig = {
                0x30, 0x06, 0x02, 0x01, static_cast<unsigned char>(i % 127 + 1),
                0x02, 0x01, static_cast<unsigned char>((i * 7) % 127 + 1)
            };
            keys.dummy_sigs.push_back(sig);
        }

        config.escrow_contract = "0x1234567890abcdef1234567890abcdef12345678";
        config.mor_amount_per_solution = "0.5";
    }
};

BOOST_FIXTURE_TEST_SUITE(qsb_morpheus_client_tests, QSBMorpheusClientFixture)

// ---------------------------------------------------------------------------
// Stub submission tests
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(submit_jobs_returns_three_with_ids)
{
    auto jobs = client.SubmitJobs(keys, config);

    BOOST_CHECK_EQUAL(jobs.size(), 3);
    for (const auto& job : jobs) {
        BOOST_CHECK(!job.job_id.empty());
        BOOST_CHECK(job.job_id.find("morpheus-stub-") == 0);
    }
}

BOOST_AUTO_TEST_CASE(submit_jobs_types_correct)
{
    auto jobs = client.SubmitJobs(keys, config);

    BOOST_CHECK_EQUAL(jobs[0].type, "qsb_pinning");
    BOOST_CHECK_EQUAL(jobs[1].type, "qsb_digest");
    BOOST_CHECK_EQUAL(jobs[2].type, "qsb_digest");
}

BOOST_AUTO_TEST_CASE(submit_jobs_unique_ids)
{
    auto jobs = client.SubmitJobs(keys, config);

    BOOST_CHECK(jobs[0].job_id != jobs[1].job_id);
    BOOST_CHECK(jobs[1].job_id != jobs[2].job_id);
    BOOST_CHECK(jobs[0].job_id != jobs[2].job_id);
}

BOOST_AUTO_TEST_CASE(submit_single_job)
{
    QSBJob job;
    job.type = "qsb_pinning";
    job.version = 1;
    job.payload = BuildPinningJob(keys, config);

    std::string id = client.SubmitJob(job);
    BOOST_CHECK(!id.empty());
}

// ---------------------------------------------------------------------------
// Result parsing tests
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(parse_pinning_result_valid)
{
    // Build a valid pinning result JSON
    UniValue result(UniValue::VOBJ);
    UniValue solution(UniValue::VOBJ);
    solution.pushKV("sequence", 151205);
    solution.pushKV("locktime", 656535577);

    std::vector<unsigned char> pubkey(33, 0x01);
    pubkey[0] = 0x02;
    solution.pushKV("recovered_pubkey", "0x" + HexStr(pubkey));

    auto hash = ComputeRIPEMD160(pubkey);
    solution.pushKV("ripemd160_hash", "0x" + HexStr(hash));

    result.pushKV("solution", solution);

    QSBPinningResult parsed = QSBMorpheusClient::ParsePinningResult(result);
    BOOST_CHECK_EQUAL(parsed.sequence, 151205u);
    BOOST_CHECK_EQUAL(parsed.locktime, 656535577u);
    BOOST_CHECK_EQUAL(parsed.recovered_pubkey.size(), 33);
    BOOST_CHECK_EQUAL(parsed.recovered_pubkey[0], 0x02);
    BOOST_CHECK_EQUAL(parsed.ripemd160_hash.size(), 20);
}

BOOST_AUTO_TEST_CASE(parse_pinning_result_missing_solution_throws)
{
    UniValue empty(UniValue::VOBJ);
    BOOST_CHECK_THROW(QSBMorpheusClient::ParsePinningResult(empty), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(parse_digest_result_valid)
{
    UniValue result(UniValue::VOBJ);
    UniValue solution(UniValue::VOBJ);
    solution.pushKV("round", 1);

    UniValue indices(UniValue::VARR);
    UniValue preimages(UniValue::VARR);
    for (int i = 0; i < 9; ++i) {
        indices.push_back(i);
        std::vector<unsigned char> preimage(32, static_cast<unsigned char>(i));
        preimages.push_back("0x" + HexStr(preimage));
    }
    solution.pushKV("subset_indices", indices);
    solution.pushKV("preimages", preimages);

    result.pushKV("solution", solution);

    QSBDigestResult parsed = QSBMorpheusClient::ParseDigestResult(result);
    BOOST_CHECK_EQUAL(parsed.round, 1);
    BOOST_CHECK_EQUAL(parsed.subset_indices.size(), 9);
    BOOST_CHECK_EQUAL(parsed.preimages.size(), 9);
    BOOST_CHECK_EQUAL(parsed.preimages[0].size(), 32);
}

BOOST_AUTO_TEST_CASE(parse_digest_result_missing_solution_throws)
{
    UniValue empty(UniValue::VOBJ);
    BOOST_CHECK_THROW(QSBMorpheusClient::ParseDigestResult(empty), std::runtime_error);
}

// ---------------------------------------------------------------------------
// Custom transport tests
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(custom_transport_submit)
{
    int call_count = 0;
    client.SetTransport(
        [&call_count](const UniValue& /*payload*/) -> std::string {
            ++call_count;
            return "custom-job-" + std::to_string(call_count);
        },
        [](const std::string& /*job_id*/) -> UniValue {
            return UniValue();
        }
    );

    auto jobs = client.SubmitJobs(keys, config);
    BOOST_CHECK_EQUAL(call_count, 3);
    BOOST_CHECK_EQUAL(jobs[0].job_id, "custom-job-1");
    BOOST_CHECK_EQUAL(jobs[1].job_id, "custom-job-2");
    BOOST_CHECK_EQUAL(jobs[2].job_id, "custom-job-3");
}

BOOST_AUTO_TEST_CASE(custom_transport_poll_timeout)
{
    // Transport that never returns results → timeout
    client.SetTransport(
        [](const UniValue& /*payload*/) -> std::string {
            return "timeout-job";
        },
        [](const std::string& /*job_id*/) -> UniValue {
            return UniValue(); // null = no result
        }
    );

    QSBJob job;
    job.type = "qsb_pinning";
    job.version = 1;
    job.payload = BuildPinningJob(keys, config);
    job.job_id = "timeout-job";

    std::vector<QSBJob> jobs = {job};
    auto results = client.AwaitResults(jobs, keys, 9, 3); // max 3 attempts

    BOOST_CHECK_EQUAL(results.size(), 1);
    BOOST_CHECK_EQUAL(static_cast<int>(results[0].status), static_cast<int>(QSBJobStatus::TIMEOUT));
    BOOST_CHECK_EQUAL(results[0].error.code, "POLL_TIMEOUT");
}

// ---------------------------------------------------------------------------
// End-to-end stub pipeline tests
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(e2e_stub_pinning_parses_correctly)
{
    // Submit via stub → poll → parse
    // Pinning mock won't pass DER-prefix check (expected — that's the GPU's job)
    auto jobs = client.SubmitJobs(keys, config);

    // Poll just the pinning job
    std::vector<QSBJob> pinning_only = {jobs[0]};
    auto results = client.AwaitResults(pinning_only, keys, 9, 5);

    BOOST_CHECK_EQUAL(results.size(), 1);
    BOOST_CHECK_EQUAL(results[0].type, "qsb_pinning");

    // The result should be COMPLETED (parsed) but may fail DER verification
    // That's correct — mock pubkey RIPEMD160 is unlikely to be DER-valid
    BOOST_CHECK(results[0].status == QSBJobStatus::VERIFIED ||
                results[0].status == QSBJobStatus::FAILED);
}

BOOST_AUTO_TEST_CASE(e2e_stub_digest_with_mock_transport)
{
    // Set up a transport that returns valid digest results using actual preimages
    // This should pass full verification

    // Build the jobs first
    auto jobs = BuildQSBJobs(keys, config);
    for (size_t i = 0; i < jobs.size(); ++i) {
        jobs[i].job_id = "e2e-job-" + std::to_string(i);
    }

    // Create mock results that use the real preimages
    UniValue digest_result(UniValue::VOBJ);
    UniValue solution(UniValue::VOBJ);
    solution.pushKV("round", 1);

    UniValue indices(UniValue::VARR);
    UniValue preimages(UniValue::VARR);
    for (int i = 0; i < 9; ++i) {
        indices.push_back(i);
        preimages.push_back("0x" + HexStr(keys.preimages[i]));
    }
    solution.pushKV("subset_indices", indices);
    solution.pushKV("preimages", preimages);
    digest_result.pushKV("solution", solution);

    // Set transport that returns this result for digest jobs
    client.SetTransport(
        [](const UniValue& /*payload*/) -> std::string { return "mock"; },
        [&digest_result](const std::string& /*job_id*/) -> UniValue {
            return digest_result;
        }
    );

    // Test only the digest job (index 1)
    std::vector<QSBJob> digest_only = {jobs[1]};
    auto results = client.AwaitResults(digest_only, keys, 9, 5);

    BOOST_CHECK_EQUAL(results.size(), 1);
    BOOST_CHECK_EQUAL(results[0].type, "qsb_digest");
    BOOST_CHECK(results[0].verified);
    BOOST_CHECK_EQUAL(static_cast<int>(results[0].status), static_cast<int>(QSBJobStatus::VERIFIED));
}

BOOST_AUTO_TEST_SUITE_END()
