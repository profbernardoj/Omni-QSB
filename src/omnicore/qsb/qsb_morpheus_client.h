// Copyright (c) 2026 The Omni Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef OMNICORE_QSB_MORPHEUS_CLIENT_H
#define OMNICORE_QSB_MORPHEUS_CLIENT_H

#include <omnicore/qsb/qsb_job_builder.h>
#include <omnicore/qsb/qsb_local_verifier.h>

#include <univalue.h>

#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <vector>

/**
 * QSB Morpheus Client — Segment 3 of Stage 3 (Morpheus Compute Integration)
 *
 * Submits QSB jobs to the Morpheus P2P marketplace (Lumerin proxy-router),
 * polls for results, and verifies them locally using the Segment 1 verifier.
 *
 * This implementation uses a pluggable transport layer:
 *   - Stub mode: returns mock results for testing (default)
 *   - Live mode: HTTP POST/GET to Lumerin router (future)
 *
 * The client never handles private key material. All verification is local.
 */

//! Job submission status
enum class QSBJobStatus {
    PENDING,     //!< Submitted, waiting for provider
    COMPUTING,   //!< Provider claimed job, compute in progress
    COMPLETED,   //!< Provider returned a result
    VERIFIED,    //!< Result passed local verification
    FAILED,      //!< Result failed verification or provider timed out
    TIMEOUT      //!< Escrow timeout reached, refund triggered
};

//! Result of a Morpheus job (pinning or digest)
struct MorpheusJobResult {
    std::string job_id;          //!< Morpheus-assigned job identifier
    std::string type;            //!< "qsb_pinning" or "qsb_digest"
    QSBJobStatus status;         //!< Current job status
    UniValue raw_result;         //!< Raw result payload from provider
    bool verified;               //!< True if local verifier passed
    QSBVerifyError error;        //!< Populated if verification failed
};

//! Transport callback type for job submission (returns job_id)
using SubmitTransport = std::function<std::string(const UniValue& payload)>;

//! Transport callback type for result polling (returns raw result or empty)
using PollTransport = std::function<UniValue(const std::string& job_id)>;

/**
 * Morpheus P2P compute client for QSB job orchestration.
 *
 * Usage:
 *   QSBMorpheusClient client;
 *   // Optionally set live transport: client.SetTransport(submitFn, pollFn);
 *   auto jobs = client.SubmitJobs(keys, config);
 *   auto results = client.AwaitResults(jobs, keys);
 */
class QSBMorpheusClient {
public:
    QSBMorpheusClient();

    /**
     * Replace the default stub transport with a live implementation.
     *
     * @param[in] submitFn  Function that POSTs a job payload and returns job_id
     * @param[in] pollFn    Function that GETs a job result by job_id
     */
    void SetTransport(SubmitTransport submitFn, PollTransport pollFn);

    /**
     * Submit all 3 QSB jobs to the Morpheus marketplace.
     *
     * Builds job payloads from HORS key material, submits via transport,
     * and returns the submitted jobs with job_ids populated.
     *
     * @param[in] keys    HORS key material
     * @param[in] config  Job configuration
     * @return Vector of 3 QSBJob objects with job_ids set
     */
    std::vector<QSBJob> SubmitJobs(
        const HORSKeyMaterial& keys,
        const QSBJobConfig& config = QSBJobConfig());

    /**
     * Submit a single job to the Morpheus marketplace.
     *
     * @param[in] job  Job to submit (payload must be populated)
     * @return Morpheus-assigned job_id
     */
    std::string SubmitJob(const QSBJob& job);

    /**
     * Poll for results and verify locally.
     *
     * Blocks until all jobs have results (or timeout). Each result is
     * verified using the Segment 1 local verifier before being returned.
     *
     * @param[in] jobs              Submitted jobs (with job_ids)
     * @param[in] keys              HORS key material (for digest verification)
     * @param[in] expected_subset_size  HORS subset size (default 9)
     * @param[in] max_poll_attempts Maximum polling iterations before timeout
     * @return Vector of verified (or failed) results
     */
    std::vector<MorpheusJobResult> AwaitResults(
        const std::vector<QSBJob>& jobs,
        const HORSKeyMaterial& keys,
        int expected_subset_size = 9,
        int max_poll_attempts = 100);

    /**
     * Parse a raw pinning result from Morpheus provider JSON.
     *
     * @param[in] raw  Raw JSON result payload
     * @return Parsed QSBPinningResult
     * @throws std::runtime_error if parsing fails
     */
    static QSBPinningResult ParsePinningResult(const UniValue& raw);

    /**
     * Parse a raw digest result from Morpheus provider JSON.
     *
     * @param[in] raw  Raw JSON result payload
     * @return Parsed QSBDigestResult
     * @throws std::runtime_error if parsing fails
     */
    static QSBDigestResult ParseDigestResult(const UniValue& raw);

private:
    SubmitTransport m_submit_fn;   //!< Transport for job submission
    PollTransport m_poll_fn;       //!< Transport for result polling

    //! Internal job counter for stub mode
    uint64_t m_stub_counter;

    //! Default stub transport: generates mock results
    std::string StubSubmit(const UniValue& payload);
    UniValue StubPoll(const std::string& job_id);

    //! Mock result storage (stub mode only)
    std::map<std::string, UniValue> m_stub_results;

    //! Generate a mock pinning result
    UniValue GenerateMockPinningResult();

    //! Generate a mock digest result for the given round and key material
    UniValue GenerateMockDigestResult(int round, const HORSKeyMaterial& keys);
};

#endif // OMNICORE_QSB_MORPHEUS_CLIENT_H
