// Copyright (c) 2026 The Omni Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef OMNICORE_QSB_LUMERIN_TRANSPORT_H
#define OMNICORE_QSB_LUMERIN_TRANSPORT_H

#include <omnicore/qsb/qsb_morpheus_client.h>

#include <univalue.h>

#include <cstdint>
#include <functional>
#include <string>

/**
 * QSB Lumerin HTTP Transport — Segment 5 of Stage 3 (Morpheus Compute Integration)
 *
 * Real network layer for the Morpheus P2P compute marketplace.
 * Replaces the stub transport in QSBMorpheusClient with actual HTTP
 * calls to the Lumerin proxy-router.
 *
 * Architecture:
 *   - Pluggable HTTP backend via std::function (mock for tests, curl for live)
 *   - Exponential backoff with configurable retries
 *   - Error classification: transient (retry) vs permanent (fail fast)
 *   - Escrow creation stub (MOR lock on Base chain)
 *   - Zero private key exposure — only public job payloads sent
 *
 * Usage:
 *   LumerinTransportConfig cfg;
 *   cfg.base_url = "http://localhost:3333";  // Lumerin proxy-router
 *   QSBLumerinTransport transport(cfg);
 *
 *   QSBMorpheusClient client;
 *   transport.InstallOn(client);  // replaces stub transport
 *
 *   auto jobs = client.SubmitJobs(keys, config);
 */

//! HTTP response from the Lumerin proxy-router
struct LumerinHTTPResponse {
    int status_code;          //!< HTTP status (200, 400, 429, 500, etc.)
    std::string body;         //!< Raw response body
    std::string error;        //!< Error message (empty on success)

    LumerinHTTPResponse() : status_code(0) {}

    bool IsSuccess() const { return status_code >= 200 && status_code < 300; }
    bool IsTransient() const {
        return status_code == 429 || status_code == 502 ||
               status_code == 503 || status_code == 504 || status_code == 0;
    }
};

//! Pluggable HTTP backend (POST/GET)
using HTTPPostFn = std::function<LumerinHTTPResponse(
    const std::string& url,
    const std::string& body,
    const std::string& auth_header)>;

using HTTPGetFn = std::function<LumerinHTTPResponse(
    const std::string& url,
    const std::string& auth_header)>;

//! Transport configuration
struct LumerinTransportConfig {
    std::string base_url = "http://localhost:3333";  //!< Lumerin proxy-router endpoint
    std::string api_key;                              //!< Bearer token for auth
    int timeout_ms = 30000;                           //!< HTTP request timeout
    int max_retries = 3;                              //!< Max retry attempts for transient errors
    int initial_backoff_ms = 1000;                    //!< Initial backoff delay
    int max_backoff_ms = 30000;                       //!< Max backoff cap
    std::string escrow_contract;                      //!< Base chain MOR escrow contract

    LumerinTransportConfig() = default;
};

//! Error classification for transport failures
enum class LumerinErrorKind {
    NONE,           //!< No error
    TRANSIENT,      //!< Retryable (429, 5xx, network error)
    PERMANENT,      //!< Non-retryable (400, 401, 403, 404)
    TIMEOUT,        //!< Request timed out
    PARSE_ERROR     //!< Response body not valid JSON
};

//! Transport error with classification
struct LumerinTransportError {
    LumerinErrorKind kind = LumerinErrorKind::NONE;
    int http_status = 0;
    std::string message;

    bool IsRetryable() const { return kind == LumerinErrorKind::TRANSIENT; }
};

/**
 * Lumerin HTTP Transport for Morpheus P2P compute marketplace.
 *
 * Handles job submission (POST /jobs), result polling (GET /jobs/{id}),
 * and escrow creation stubs. Uses exponential backoff for transient errors.
 */
class QSBLumerinTransport {
public:
    explicit QSBLumerinTransport(const LumerinTransportConfig& config = LumerinTransportConfig());

    /**
     * Set the HTTP backend implementation.
     * Must be called before SubmitJob/PollJob if not using mock.
     */
    void SetHTTPBackend(HTTPPostFn postFn, HTTPGetFn getFn);

    /**
     * Install this transport on a QSBMorpheusClient.
     * Replaces the client's stub transport with live HTTP calls.
     */
    void InstallOn(QSBMorpheusClient& client);

    /**
     * Submit a job to the Lumerin proxy-router.
     *
     * POST {base_url}/v1/jobs
     * Body: job payload JSON + escrow_txid
     * Returns: job_id from Lumerin
     *
     * @param[in]  payload  Job payload (UniValue object)
     * @param[out] error    Populated on failure
     * @return Job ID string (empty on failure)
     */
    std::string SubmitJob(const UniValue& payload, LumerinTransportError& error);

    /**
     * Poll a job result from the Lumerin proxy-router.
     *
     * GET {base_url}/v1/jobs/{job_id}
     * Returns: job result JSON (or null if still pending)
     *
     * @param[in]  job_id  Lumerin job identifier
     * @param[out] error   Populated on failure
     * @return Result payload (null UniValue if pending or failed)
     */
    UniValue PollJob(const std::string& job_id, LumerinTransportError& error);

    /**
     * Create a MOR escrow on Base chain (stub).
     *
     * In production: locks MOR tokens in escrow smart contract.
     * Currently returns a deterministic placeholder txid.
     *
     * @param[in] mor_amount  Amount of MOR to escrow
     * @return Escrow transaction ID (hex)
     */
    std::string CreateEscrow(const std::string& mor_amount);

    /**
     * Get the transport configuration (for diagnostics).
     */
    const LumerinTransportConfig& GetConfig() const { return m_config; }

    /**
     * Classify an HTTP response into an error kind.
     */
    static LumerinErrorKind ClassifyHTTPStatus(int status_code);

    /**
     * Calculate backoff delay for a given retry attempt.
     *
     * @param[in] attempt            Retry attempt number (0-indexed)
     * @param[in] initial_backoff_ms Base delay
     * @param[in] max_backoff_ms     Cap
     * @return Delay in milliseconds
     */
    static int CalculateBackoff(int attempt, int initial_backoff_ms, int max_backoff_ms);

private:
    LumerinTransportConfig m_config;

    //! Pluggable HTTP backend
    HTTPPostFn m_http_post;
    HTTPGetFn m_http_get;

    //! Default mock HTTP backend
    LumerinHTTPResponse MockPost(const std::string& url, const std::string& body, const std::string& auth);
    LumerinHTTPResponse MockGet(const std::string& url, const std::string& auth);

    //! Mock job storage
    uint64_t m_mock_counter = 0;

    //! Build Authorization header
    std::string BuildAuthHeader() const;

    //! Execute POST with retry logic
    LumerinHTTPResponse PostWithRetry(const std::string& url, const std::string& body);

    //! Execute GET with retry logic
    LumerinHTTPResponse GetWithRetry(const std::string& url);
};

#endif // OMNICORE_QSB_LUMERIN_TRANSPORT_H
