// Copyright (c) 2026 The Omni Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <omnicore/qsb/qsb_lumerin_transport.h>
#include <omnicore/qsb/qsb_morpheus_client.h>
#include <omnicore/qsb/qsb_job_builder.h>
#include <omnicore/qsb/qsb_local_verifier.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(qsb_lumerin_transport_tests, BasicTestingSetup)

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(config_defaults)
{
    LumerinTransportConfig config;
    BOOST_CHECK_EQUAL(config.base_url, "http://localhost:3333");
    BOOST_CHECK(config.api_key.empty());
    BOOST_CHECK_EQUAL(config.timeout_ms, 30000);
    BOOST_CHECK_EQUAL(config.max_retries, 3);
    BOOST_CHECK_EQUAL(config.initial_backoff_ms, 1000);
    BOOST_CHECK_EQUAL(config.max_backoff_ms, 30000);
}

BOOST_AUTO_TEST_CASE(config_custom)
{
    LumerinTransportConfig config;
    config.base_url = "http://test.example.com:8080";
    config.api_key = "test-api-key-12345";
    config.max_retries = 5;

    QSBLumerinTransport transport(config);
    BOOST_CHECK_EQUAL(transport.GetConfig().base_url, "http://test.example.com:8080");
    BOOST_CHECK_EQUAL(transport.GetConfig().api_key, "test-api-key-12345");
}

// ---------------------------------------------------------------------------
// Mock HTTP backend (unit tests)
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(mock_submit_returns_job_id)
{
    QSBLumerinTransport transport;

    UniValue payload(UniValue::VOBJ);
    payload.pushKV("type", "qsb_pinning");
    payload.pushKV("version", 1);

    LumerinTransportError error;
    std::string job_id = transport.SubmitJob(payload, error);

    BOOST_CHECK(!job_id.empty());
    BOOST_CHECK(job_id.find("lumerin-job-") == 0);
    BOOST_CHECK(error.kind == LumerinErrorKind::NONE);
}

BOOST_AUTO_TEST_CASE(mock_poll_returns_completed)
{
    QSBLumerinTransport transport;

    LumerinTransportError error;
    UniValue result = transport.PollJob("test-job-123", error);

    BOOST_CHECK(result.isObject());
    BOOST_CHECK(result.exists("job_id"));
    BOOST_CHECK_EQUAL(result["job_id"].get_str(), "test-job-123");
    BOOST_CHECK_EQUAL(result["status"].get_str(), "completed");
}

BOOST_AUTO_TEST_CASE(mock_escrow_returns_deterministic_hex)
{
    QSBLumerinTransport transport;

    std::string escrow1 = transport.CreateEscrow("0.5");
    std::string escrow2 = transport.CreateEscrow("1.0");

    BOOST_CHECK(escrow1.find("0x") == 0);
    BOOST_CHECK_EQUAL(escrow1.length(), 66);  // 0x + 64 hex chars
    BOOST_CHECK(escrow1 != escrow2);  // Different amounts → different txid
}

BOOST_AUTO_TEST_CASE(mock_invalid_json_rejected)
{
    QSBLumerinTransport transport;

    // Manually invoke mockPOST with invalid JSON
    // Since the mock is internal, we test via SubmitJob which validates
    // Actually, the mock uses UniValue::write() which always produces valid JSON
    // Test that SubmitJob handles malformed response by mocking error response

    // Use custom mock that returns error
    HTTPPostFn errorPost = [](const std::string& url, const std::string& body, const std::string& auth)
        -> LumerinHTTPResponse {
        LumerinHTTPResponse resp;
        resp.status_code = 400;
        resp.error = "Invalid JSON in request body";
        return resp;
    };

    HTTPGetFn okGet = [](const std::string& url, const std::string& auth)
        -> LumerinHTTPResponse {
        LumerinHTTPResponse resp;
        resp.status_code = 200;
        resp.body = "{}";
        return resp;
    };

    transport.SetHTTPBackend(errorPost, okGet);

    UniValue payload(UniValue::VOBJ);
    payload.pushKV("type", "qsb_pinning");

    LumerinTransportError error;
    std::string job_id = transport.SubmitJob(payload, error);

    BOOST_CHECK(job_id.empty());
    BOOST_CHECK_EQUAL(error.http_status, 400);
    BOOST_CHECK(error.kind == LumerinErrorKind::PERMANENT);
}

// ---------------------------------------------------------------------------
// HTTP status classification (Grok spec: error classification)
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(classify_2xx_success)
{
    BOOST_CHECK(QSBLumerinTransport::ClassifyHTTPStatus(200) == LumerinErrorKind::NONE);
    BOOST_CHECK(QSBLumerinTransport::ClassifyHTTPStatus(201) == LumerinErrorKind::NONE);
    BOOST_CHECK(QSBLumerinTransport::ClassifyHTTPStatus(204) == LumerinErrorKind::NONE);
}

BOOST_AUTO_TEST_CASE(classify_5xx_transient)
{
    BOOST_CHECK(QSBLumerinTransport::ClassifyHTTPStatus(500) == LumerinErrorKind::TRANSIENT);
    BOOST_CHECK(QSBLumerinTransport::ClassifyHTTPStatus(502) == LumerinErrorKind::TRANSIENT);
    BOOST_CHECK(QSBLumerinTransport::ClassifyHTTPStatus(503) == LumerinErrorKind::TRANSIENT);
    BOOST_CHECK(QSBLumerinTransport::ClassifyHTTPStatus(504) == LumerinErrorKind::TRANSIENT);
}

BOOST_AUTO_TEST_CASE(classify_429_rate_limit)
{
    BOOST_CHECK(QSBLumerinTransport::ClassifyHTTPStatus(429) == LumerinErrorKind::TRANSIENT);
}

BOOST_AUTO_TEST_CASE(classify_4xx_permanent)
{
    BOOST_CHECK(QSBLumerinTransport::ClassifyHTTPStatus(400) == LumerinErrorKind::PERMANENT);
    BOOST_CHECK(QSBLumerinTransport::ClassifyHTTPStatus(401) == LumerinErrorKind::PERMANENT);
    BOOST_CHECK(QSBLumerinTransport::ClassifyHTTPStatus(403) == LumerinErrorKind::PERMANENT);
    BOOST_CHECK(QSBLumerinTransport::ClassifyHTTPStatus(404) == LumerinErrorKind::PERMANENT);
}

BOOST_AUTO_TEST_CASE(classify_0_timeout)
{
    BOOST_CHECK(QSBLumerinTransport::ClassifyHTTPStatus(0) == LumerinErrorKind::TIMEOUT);
}

// ---------------------------------------------------------------------------
// Backoff calculation (Grok spec: backoff_exponential)
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(backoff_exponential)
{
    // Initial: 1000ms
    // Attempt 0: 1000ms
    // Attempt 1: 2000ms
    // Attempt 2: 4000ms
    // Attempt 3: 8000ms

    BOOST_CHECK_EQUAL(QSBLumerinTransport::CalculateBackoff(0, 1000, 30000), 1000);
    BOOST_CHECK_EQUAL(QSBLumerinTransport::CalculateBackoff(1, 1000, 30000), 2000);
    BOOST_CHECK_EQUAL(QSBLumerinTransport::CalculateBackoff(2, 1000, 30000), 4000);
    BOOST_CHECK_EQUAL(QSBLumerinTransport::CalculateBackoff(3, 1000, 30000), 8000);
}

BOOST_AUTO_TEST_CASE(backoff_capped_at_max)
{
    // With max=5000:
    // Attempt 2: would be 4000, capped at 5000
    // Attempt 3: would be 8000, capped at 5000

    BOOST_CHECK_EQUAL(QSBLumerinTransport::CalculateBackoff(2, 1000, 5000), 4000);
    BOOST_CHECK_EQUAL(QSBLumerinTransport::CalculateBackoff(3, 1000, 5000), 5000);
    BOOST_CHECK_EQUAL(QSBLumerinTransport::CalculateBackoff(10, 1000, 5000), 5000);
}

// ---------------------------------------------------------------------------
// Transport pluggability (Grok spec: drop-in replacement)
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(install_on_client)
{
    QSBLumerinTransport transport;

    QSBMorpheusClient client;
    transport.InstallOn(client);

    // Client should now use Lumerin transport instead of stub
    // Verify by submitting a job and checking the job_id prefix

    HORSKeyMaterial keys;
    keys.scriptcode_midstate.resize(32);
    keys.num_keys = 150;
    for (int i = 0; i < 150; ++i) {
        std::vector<unsigned char> preimage(32, static_cast<unsigned char>(i));
        keys.preimages.push_back(preimage);
        keys.commitments.push_back(ComputeHash160(preimage));
        keys.dummy_sigs.push_back({0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01});
    }

    QSBJobConfig config;
    config.escrow_contract = "0x1234567890abcdef";

    auto jobs = client.SubmitJobs(keys, config);

    BOOST_CHECK_EQUAL(jobs.size(), 3);
    for (const auto& job : jobs) {
        BOOST_CHECK(!job.job_id.empty());
        // Lumerin mock prefix, not "morpheus-stub-"
        BOOST_CHECK(job.job_id.find("lumerin-job-") == 0);
    }
}

// ---------------------------------------------------------------------------
// Auth header (Grok spec: auth_header_includes_api_key)
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(auth_header_with_api_key)
{
    LumerinTransportConfig config;
    config.api_key = "secret-key-xyz";

    QSBLumerinTransport transport(config);

    // Auth header is private, but we can verify via custom HTTP backend
    std::string captured_auth;
    HTTPPostFn capturePost = [&captured_auth](const std::string& url, const std::string& body, const std::string& auth)
        -> LumerinHTTPResponse {
        captured_auth = auth;
        LumerinHTTPResponse resp;
        resp.status_code = 201;
        resp.body = R"({"job_id": "test"})";
        return resp;
    };

    HTTPGetFn okGet = [](const std::string& url, const std::string& auth)
        -> LumerinHTTPResponse {
        LumerinHTTPResponse resp;
        resp.status_code = 200;
        resp.body = R"({"job_id": "test", "status": "completed"})";
        return resp;
    };

    transport.SetHTTPBackend(capturePost, okGet);

    UniValue payload(UniValue::VOBJ);
    LumerinTransportError error;
    transport.SubmitJob(payload, error);

    BOOST_CHECK_EQUAL(captured_auth, "Bearer secret-key-xyz");
}

BOOST_AUTO_TEST_CASE(auth_header_without_api_key)
{
    LumerinTransportConfig config;  // api_key is empty

    QSBLumerinTransport transport(config);

    std::string captured_auth;
    HTTPPostFn capturePost = [&captured_auth](const std::string& url, const std::string& body, const std::string& auth)
        -> LumerinHTTPResponse {
        captured_auth = auth;
        LumerinHTTPResponse resp;
        resp.status_code = 201;
        resp.body = R"({"job_id": "test"})";
        return resp;
    };

    HTTPGetFn okGet = [](const std::string& url, const std::string& auth)
        -> LumerinHTTPResponse {
        LumerinHTTPResponse resp;
        resp.status_code = 200;
        resp.body = R"({"job_id": "test", "status": "completed"})";
        return resp;
    };

    transport.SetHTTPBackend(capturePost, okGet);

    UniValue payload(UniValue::VOBJ);
    LumerinTransportError error;
    transport.SubmitJob(payload, error);

    BOOST_CHECK(captured_auth.empty());
}

// ---------------------------------------------------------------------------
// Retry logic (Grok spec: http_post_retry_on_5xx)
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(retry_on_transient_error)
{
    int attempt_count = 0;

    HTTPPostFn retryPost = [&attempt_count](const std::string& url, const std::string& body, const std::string& auth)
        -> LumerinHTTPResponse {
        ++attempt_count;
        LumerinHTTPResponse resp;

        if (attempt_count < 3) {
            // Fail first 2 attempts with 503 (transient)
            resp.status_code = 503;
            resp.error = "Service unavailable";
        } else {
            // Succeed on 3rd attempt
            resp.status_code = 201;
            resp.body = R"({"job_id": "retry-success"})";
        }
        return resp;
    };

    HTTPGetFn okGet = [](const std::string& url, const std::string& auth)
        -> LumerinHTTPResponse {
        LumerinHTTPResponse resp;
        resp.status_code = 200;
        resp.body = R"({"status": "completed"})";
        return resp;
    };

    LumerinTransportConfig config;
    config.max_retries = 3;
    config.initial_backoff_ms = 1;  // Fast for tests
    config.max_backoff_ms = 10;

    QSBLumerinTransport transport(config);
    transport.SetHTTPBackend(retryPost, okGet);

    UniValue payload(UniValue::VOBJ);
    LumerinTransportError error;
    std::string job_id = transport.SubmitJob(payload, error);

    BOOST_CHECK_EQUAL(job_id, "retry-success");
    BOOST_CHECK_EQUAL(attempt_count, 3);  // 1 initial + 2 retries
}

BOOST_AUTO_TEST_CASE(no_retry_on_permanent_error)
{
    int attempt_count = 0;

    HTTPPostFn failPost = [&attempt_count](const std::string& url, const std::string& body, const std::string& auth)
        -> LumerinHTTPResponse {
        ++attempt_count;
        LumerinHTTPResponse resp;
        resp.status_code = 400;  // Permanent error
        resp.error = "Bad request";
        return resp;
    };

    HTTPGetFn okGet = [](const std::string& url, const std::string& auth)
        -> LumerinHTTPResponse {
        LumerinHTTPResponse resp;
        resp.status_code = 200;
        return resp;
    };

    LumerinTransportConfig config;
    config.max_retries = 3;

    QSBLumerinTransport transport(config);
    transport.SetHTTPBackend(failPost, okGet);

    UniValue payload(UniValue::VOBJ);
    LumerinTransportError error;
    std::string job_id = transport.SubmitJob(payload, error);

    BOOST_CHECK(job_id.empty());
    BOOST_CHECK_EQUAL(attempt_count, 1);  // No retries on 400
}

// ---------------------------------------------------------------------------
// Escrow integration (Grok spec: submit_job_with_escrow_stub)
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(escrow_added_to_job_payload)
{
    LumerinTransportConfig config;
    config.escrow_contract = "0xabcdef1234567890";

    QSBLumerinTransport transport(config);

    std::string captured_body;
    HTTPPostFn capturePost = [&captured_body](const std::string& url, const std::string& body, const std::string& auth)
        -> LumerinHTTPResponse {
        captured_body = body;
        LumerinHTTPResponse resp;
        resp.status_code = 201;
        resp.body = R"({"job_id": "test"})";
        return resp;
    };

    HTTPGetFn okGet = [](const std::string& url, const std::string& auth)
        -> LumerinHTTPResponse {
        LumerinHTTPResponse resp;
        resp.status_code = 200;
        return resp;
    };

    transport.SetHTTPBackend(capturePost, okGet);

    // Payload with payment info
    UniValue payload(UniValue::VOBJ);
    payload.pushKV("type", "qsb_pinning");

    UniValue payment(UniValue::VOBJ);
    payment.pushKV("amount_per_solution", "0.5");
    payload.pushKV("payment", payment);

    LumerinTransportError error;
    transport.SubmitJob(payload, error);

    // Verify escrow_txid was added
    UniValue submitted;
    submitted.read(captured_body);
    BOOST_CHECK(submitted.exists("escrow_txid"));
    BOOST_CHECK(submitted["escrow_txid"].get_str().find("0x") == 0);
}

// ---------------------------------------------------------------------------
// Poll job status (Grok spec: poll_job_returns_valid_status)
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(poll_job_pending_returns_null)
{
    HTTPGetFn pendingGet = [](const std::string& url, const std::string& auth)
        -> LumerinHTTPResponse {
        LumerinHTTPResponse resp;
        resp.status_code = 404;  // Job not found = still pending
        return resp;
    };

    HTTPPostFn okPost = [](const std::string& url, const std::string& body, const std::string& auth)
        -> LumerinHTTPResponse {
        LumerinHTTPResponse resp;
        resp.status_code = 201;
        resp.body = R"({"job_id": "test"})";
        return resp;
    };

    QSBLumerinTransport transport;
    transport.SetHTTPBackend(okPost, pendingGet);

    LumerinTransportError error;
    UniValue result = transport.PollJob("pending-job-123", error);

    BOOST_CHECK(result.isNull());
}

BOOST_AUTO_TEST_CASE(poll_job_completed_returns_result)
{
    HTTPGetFn completedGet = [](const std::string& url, const std::string& auth)
        -> LumerinHTTPResponse {
        LumerinHTTPResponse resp;
        resp.status_code = 200;
        resp.body = R"({
            "job_id": "completed-job-456",
            "status": "completed",
            "solution": {
                "sequence": 151205,
                "locktime": 656535577
            }
        })";
        return resp;
    };

    HTTPPostFn okPost = [](const std::string& url, const std::string& body, const std::string& auth)
        -> LumerinHTTPResponse {
        LumerinHTTPResponse resp;
        resp.status_code = 201;
        return resp;
    };

    QSBLumerinTransport transport;
    transport.SetHTTPBackend(okPost, completedGet);

    LumerinTransportError error;
    UniValue result = transport.PollJob("completed-job-456", error);

    BOOST_CHECK(result.isObject());
    BOOST_CHECK_EQUAL(result["status"].get_str(), "completed");
    BOOST_CHECK(result.exists("solution"));
}

// ---------------------------------------------------------------------------
// Error propagation (Grok spec: job_failure_proper_error_propagation)
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(error_message_includes_url_and_status)
{
    HTTPPostFn failPost = [](const std::string& url, const std::string& body, const std::string& auth)
        -> LumerinHTTPResponse {
        LumerinHTTPResponse resp;
        resp.status_code = 500;
        resp.error = "Internal server error";
        return resp;
    };

    HTTPGetFn okGet = [](const std::string& url, const std::string& auth)
        -> LumerinHTTPResponse {
        LumerinHTTPResponse resp;
        resp.status_code = 200;
        return resp;
    };

    LumerinTransportConfig config;
    config.base_url = "http://test.example.com/api";
    config.max_retries = 0;  // Don't retry

    QSBLumerinTransport transport(config);
    transport.SetHTTPBackend(failPost, okGet);

    UniValue payload(UniValue::VOBJ);
    LumerinTransportError error;
    std::string job_id = transport.SubmitJob(payload, error);

    BOOST_CHECK(job_id.empty());
    BOOST_CHECK_EQUAL(error.http_status, 500);
    BOOST_CHECK(error.message.find("http://test.example.com/api/v1/jobs") != std::string::npos);
    BOOST_CHECK(error.message.find("500") != std::string::npos);
}

BOOST_AUTO_TEST_SUITE_END()