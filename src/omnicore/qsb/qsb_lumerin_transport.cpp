// Copyright (c) 2026 The Omni Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <omnicore/qsb/qsb_lumerin_transport.h>

#include <util/strencodings.h>

#include <algorithm>
#include <sstream>
#include <thread>

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

QSBLumerinTransport::QSBLumerinTransport(const LumerinTransportConfig& config)
    : m_config(config)
{
    // Default to mock HTTP backend
    m_http_post = [this](const std::string& url, const std::string& body, const std::string& auth)
        -> LumerinHTTPResponse {
        return MockPost(url, body, auth);
    };
    m_http_get = [this](const std::string& url, const std::string& auth)
        -> LumerinHTTPResponse {
        return MockGet(url, auth);
    };
}

// ---------------------------------------------------------------------------
// HTTP backend configuration
// ---------------------------------------------------------------------------

void QSBLumerinTransport::SetHTTPBackend(HTTPPostFn postFn, HTTPGetFn getFn)
{
    m_http_post = std::move(postFn);
    m_http_get = std::move(getFn);
}

void QSBLumerinTransport::InstallOn(QSBMorpheusClient& client)
{
    // Capture 'this' in transport callbacks for QSBMorpheusClient
    client.SetTransport(
        [this](const UniValue& payload) -> std::string {
            LumerinTransportError error;
            std::string job_id = SubmitJob(payload, error);
            if (job_id.empty()) {
                throw std::runtime_error("Lumerin submit failed: " + error.message);
            }
            return job_id;
        },
        [this](const std::string& job_id) -> UniValue {
            LumerinTransportError error;
            return PollJob(job_id, error);
        }
    );
}

// ---------------------------------------------------------------------------
// Job submission
// ---------------------------------------------------------------------------

std::string QSBLumerinTransport::SubmitJob(const UniValue& payload, LumerinTransportError& error)
{
    // Enrich payload with escrow txid
    UniValue enriched = payload;
    if (payload.exists("payment")) {
        std::string mor_amount = "0";
        if (payload["payment"].exists("amount_per_solution")) {
            mor_amount = payload["payment"]["amount_per_solution"].get_str();
        }
        enriched.pushKV("escrow_txid", CreateEscrow(mor_amount));
    }

    std::string url = m_config.base_url + "/v1/jobs";
    std::string body = enriched.write();

    LumerinHTTPResponse response = PostWithRetry(url, body);

    if (!response.IsSuccess()) {
        error.kind = ClassifyHTTPStatus(response.status_code);
        error.http_status = response.status_code;
        error.message = "HTTP POST " + url + " failed: " + std::to_string(response.status_code)
                      + " " + response.error;
        return "";
    }

    // Parse job_id from response
    UniValue result;
    if (!result.read(response.body)) {
        error.kind = LumerinErrorKind::PARSE_ERROR;
        error.message = "Failed to parse response JSON from " + url;
        return "";
    }

    if (!result.exists("job_id")) {
        error.kind = LumerinErrorKind::PARSE_ERROR;
        error.message = "Response missing 'job_id' field";
        return "";
    }

    return result["job_id"].get_str();
}

// ---------------------------------------------------------------------------
// Job polling
// ---------------------------------------------------------------------------

UniValue QSBLumerinTransport::PollJob(const std::string& job_id, LumerinTransportError& error)
{
    std::string url = m_config.base_url + "/v1/jobs/" + job_id;

    LumerinHTTPResponse response = GetWithRetry(url);

    if (!response.IsSuccess()) {
        // 404 means job still pending (not found yet)
        if (response.status_code == 404) {
            return UniValue();  // null = pending
        }

        error.kind = ClassifyHTTPStatus(response.status_code);
        error.http_status = response.status_code;
        error.message = "HTTP GET " + url + " failed: " + std::to_string(response.status_code)
                      + " " + response.error;
        return UniValue();
    }

    UniValue result;
    if (!result.read(response.body)) {
        error.kind = LumerinErrorKind::PARSE_ERROR;
        error.message = "Failed to parse poll response JSON";
        return UniValue();
    }

    // Check if job is still computing (no result yet)
    if (result.exists("status")) {
        std::string status = result["status"].get_str();
        if (status == "pending" || status == "computing") {
            return UniValue();  // null = still working
        }
    }

    return result;
}

// ---------------------------------------------------------------------------
// Escrow creation (stub)
// ---------------------------------------------------------------------------

std::string QSBLumerinTransport::CreateEscrow(const std::string& mor_amount)
{
    // TODO: Real implementation will:
    //   1. Connect to Base chain RPC
    //   2. Call MOR escrow contract: lock(amount, timeout_blocks)
    //   3. Return actual transaction hash
    //
    // For now: deterministic placeholder based on amount content
    // This allows the pipeline to be tested end-to-end without Base chain
    std::ostringstream oss;
    oss << "0x";
    // Use amount content for deterministic but unique txid
    for (size_t i = 0; i < mor_amount.size(); ++i) {
        oss << std::hex << ((mor_amount[i] + i) % 16);
    }
    // Pad to 64 hex chars (32 bytes)
    for (size_t i = mor_amount.size(); i < 64; ++i) {
        oss << std::hex << (i % 16);
    }
    return oss.str();
}

// ---------------------------------------------------------------------------
// Error classification
// ---------------------------------------------------------------------------

LumerinErrorKind QSBLumerinTransport::ClassifyHTTPStatus(int status_code)
{
    if (status_code >= 200 && status_code < 300) {
        return LumerinErrorKind::NONE;
    }
    if (status_code == 0) {
        return LumerinErrorKind::TIMEOUT;  // network error / no response
    }
    if (status_code == 429 || status_code == 500 || status_code == 502 ||
        status_code == 503 || status_code == 504) {
        return LumerinErrorKind::TRANSIENT;
    }
    return LumerinErrorKind::PERMANENT;  // 400, 401, 403, 404, etc.
}

// ---------------------------------------------------------------------------
// Backoff calculation
// ---------------------------------------------------------------------------

int QSBLumerinTransport::CalculateBackoff(int attempt, int initial_backoff_ms, int max_backoff_ms)
{
    // Exponential: initial * 2^attempt, capped at max
    int delay = initial_backoff_ms;
    for (int i = 0; i < attempt; ++i) {
        delay *= 2;
        if (delay > max_backoff_ms) {
            delay = max_backoff_ms;
            break;
        }
    }
    return std::min(delay, max_backoff_ms);
}

// ---------------------------------------------------------------------------
// Retry logic
// ---------------------------------------------------------------------------

LumerinHTTPResponse QSBLumerinTransport::PostWithRetry(const std::string& url, const std::string& body)
{
    std::string auth = BuildAuthHeader();
    LumerinHTTPResponse last_response;

    for (int attempt = 0; attempt <= m_config.max_retries; ++attempt) {
        last_response = m_http_post(url, body, auth);

        if (last_response.IsSuccess() || !last_response.IsTransient()) {
            return last_response;
        }

        // Transient error — backoff and retry
        if (attempt < m_config.max_retries) {
            int delay = CalculateBackoff(attempt, m_config.initial_backoff_ms, m_config.max_backoff_ms);
            std::this_thread::sleep_for(std::chrono::milliseconds(delay));
        }
    }

    return last_response;
}

LumerinHTTPResponse QSBLumerinTransport::GetWithRetry(const std::string& url)
{
    std::string auth = BuildAuthHeader();
    LumerinHTTPResponse last_response;

    for (int attempt = 0; attempt <= m_config.max_retries; ++attempt) {
        last_response = m_http_get(url, auth);

        if (last_response.IsSuccess() || !last_response.IsTransient()) {
            return last_response;
        }

        if (attempt < m_config.max_retries) {
            int delay = CalculateBackoff(attempt, m_config.initial_backoff_ms, m_config.max_backoff_ms);
            std::this_thread::sleep_for(std::chrono::milliseconds(delay));
        }
    }

    return last_response;
}

// ---------------------------------------------------------------------------
// Auth header
// ---------------------------------------------------------------------------

std::string QSBLumerinTransport::BuildAuthHeader() const
{
    if (m_config.api_key.empty()) {
        return "";
    }
    return "Bearer " + m_config.api_key;
}

// ---------------------------------------------------------------------------
// Mock HTTP backend
// ---------------------------------------------------------------------------

LumerinHTTPResponse QSBLumerinTransport::MockPost(
    const std::string& /*url*/,
    const std::string& body,
    const std::string& /*auth*/)
{
    LumerinHTTPResponse resp;

    // Validate that body is valid JSON
    UniValue parsed;
    if (!parsed.read(body)) {
        resp.status_code = 400;
        resp.error = "Invalid JSON in request body";
        return resp;
    }

    ++m_mock_counter;

    // Return a mock job_id
    UniValue result(UniValue::VOBJ);
    result.pushKV("job_id", "lumerin-job-" + std::to_string(m_mock_counter));
    result.pushKV("status", "pending");

    resp.status_code = 201;
    resp.body = result.write();
    return resp;
}

LumerinHTTPResponse QSBLumerinTransport::MockGet(
    const std::string& url,
    const std::string& /*auth*/)
{
    LumerinHTTPResponse resp;

    // Extract job_id from URL: .../v1/jobs/{job_id}
    size_t last_slash = url.rfind('/');
    if (last_slash == std::string::npos) {
        resp.status_code = 404;
        resp.error = "Invalid URL format";
        return resp;
    }

    std::string job_id = url.substr(last_slash + 1);

    // Mock: return completed status with a minimal result
    UniValue result(UniValue::VOBJ);
    result.pushKV("job_id", job_id);
    result.pushKV("status", "completed");

    // Minimal solution stub
    UniValue solution(UniValue::VOBJ);
    solution.pushKV("found", true);
    result.pushKV("solution", solution);

    resp.status_code = 200;
    resp.body = result.write();
    return resp;
}
