// Copyright (c) 2026 The Omni Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <omnicore/qsb/qsb_morpheus_client.h>

#include <util/strencodings.h>

#include <stdexcept>

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

QSBMorpheusClient::QSBMorpheusClient()
    : m_stub_counter(0)
{
    // Default to stub transport (mock responses for testing)
    m_submit_fn = [this](const UniValue& payload) -> std::string {
        return StubSubmit(payload);
    };
    m_poll_fn = [this](const std::string& job_id) -> UniValue {
        return StubPoll(job_id);
    };
}

// ---------------------------------------------------------------------------
// Transport configuration
// ---------------------------------------------------------------------------

void QSBMorpheusClient::SetTransport(SubmitTransport submitFn, PollTransport pollFn)
{
    m_submit_fn = submitFn;
    m_poll_fn = pollFn;
}

// ---------------------------------------------------------------------------
// Job submission
// ---------------------------------------------------------------------------

std::vector<QSBJob> QSBMorpheusClient::SubmitJobs(
    const HORSKeyMaterial& keys,
    const QSBJobConfig& config)
{
    auto jobs = BuildQSBJobs(keys, config);

    for (auto& job : jobs) {
        job.job_id = SubmitJob(job);
    }

    return jobs;
}

std::string QSBMorpheusClient::SubmitJob(const QSBJob& job)
{
    return m_submit_fn(job.payload);
}

// ---------------------------------------------------------------------------
// Result polling + verification
// ---------------------------------------------------------------------------

std::vector<MorpheusJobResult> QSBMorpheusClient::AwaitResults(
    const std::vector<QSBJob>& jobs,
    const HORSKeyMaterial& keys,
    int expected_subset_size,
    int max_poll_attempts)
{
    std::vector<MorpheusJobResult> results;
    results.reserve(jobs.size());

    for (const auto& job : jobs) {
        MorpheusJobResult res;
        res.job_id = job.job_id;
        res.type = job.type;
        res.status = QSBJobStatus::PENDING;
        res.verified = false;

        // Poll until we get a result or hit max attempts
        UniValue raw;
        bool got_result = false;
        for (int attempt = 0; attempt < max_poll_attempts; ++attempt) {
            raw = m_poll_fn(job.job_id);
            if (!raw.isNull() && raw.isObject()) {
                got_result = true;
                break;
            }
        }

        if (!got_result) {
            res.status = QSBJobStatus::TIMEOUT;
            res.error.code = "POLL_TIMEOUT";
            res.error.message = "Max poll attempts (" + std::to_string(max_poll_attempts)
                              + ") reached for job " + job.job_id;
            results.push_back(res);
            continue;
        }

        res.raw_result = raw;
        res.status = QSBJobStatus::COMPLETED;

        // Verify locally based on job type
        if (job.type == "qsb_pinning") {
            try {
                QSBPinningResult pinning = ParsePinningResult(raw);
                res.verified = VerifyPinningResult(pinning, keys.scriptcode_midstate, res.error);
            } catch (const std::exception& e) {
                res.verified = false;
                res.error.code = "PARSE_ERROR";
                res.error.message = std::string("Failed to parse pinning result: ") + e.what();
            }
        } else if (job.type == "qsb_digest") {
            try {
                QSBDigestResult digest = ParseDigestResult(raw);
                res.verified = VerifyDigestResult(digest, keys, expected_subset_size, res.error);
            } catch (const std::exception& e) {
                res.verified = false;
                res.error.code = "PARSE_ERROR";
                res.error.message = std::string("Failed to parse digest result: ") + e.what();
            }
        } else {
            res.verified = false;
            res.error.code = "UNKNOWN_JOB_TYPE";
            res.error.message = "Unknown job type: " + job.type;
        }

        res.status = res.verified ? QSBJobStatus::VERIFIED : QSBJobStatus::FAILED;
        results.push_back(res);
    }

    return results;
}

// ---------------------------------------------------------------------------
// Result parsing
// ---------------------------------------------------------------------------

QSBPinningResult QSBMorpheusClient::ParsePinningResult(const UniValue& raw)
{
    if (!raw.isObject() || !raw.exists("solution")) {
        throw std::runtime_error("Missing 'solution' object in pinning result");
    }

    const UniValue& sol = raw["solution"];
    QSBPinningResult result;

    if (!sol.exists("sequence") || !sol.exists("locktime") ||
        !sol.exists("recovered_pubkey") || !sol.exists("ripemd160_hash")) {
        throw std::runtime_error("Pinning solution missing required fields");
    }

    result.sequence = sol["sequence"].get_int();
    result.locktime = sol["locktime"].get_int();

    // Parse hex-encoded pubkey (strip 0x prefix if present)
    std::string pubkey_hex = sol["recovered_pubkey"].get_str();
    if (pubkey_hex.substr(0, 2) == "0x") pubkey_hex = pubkey_hex.substr(2);
    result.recovered_pubkey = ParseHex(pubkey_hex);

    // Parse hex-encoded RIPEMD160 hash
    std::string hash_hex = sol["ripemd160_hash"].get_str();
    if (hash_hex.substr(0, 2) == "0x") hash_hex = hash_hex.substr(2);
    result.ripemd160_hash = ParseHex(hash_hex);

    return result;
}

QSBDigestResult QSBMorpheusClient::ParseDigestResult(const UniValue& raw)
{
    if (!raw.isObject() || !raw.exists("solution")) {
        throw std::runtime_error("Missing 'solution' object in digest result");
    }

    const UniValue& sol = raw["solution"];
    QSBDigestResult result;

    if (!sol.exists("round") || !sol.exists("subset_indices") || !sol.exists("preimages")) {
        throw std::runtime_error("Digest solution missing required fields");
    }

    result.round = sol["round"].get_int();

    // Parse subset indices
    const UniValue& indices = sol["subset_indices"];
    for (size_t i = 0; i < indices.size(); ++i) {
        result.subset_indices.push_back(indices[i].get_int());
    }

    // Parse preimages (hex-encoded 32-byte values)
    const UniValue& preimages = sol["preimages"];
    for (size_t i = 0; i < preimages.size(); ++i) {
        std::string hex = preimages[i].get_str();
        if (hex.substr(0, 2) == "0x") hex = hex.substr(2);
        result.preimages.push_back(ParseHex(hex));
    }

    return result;
}

// ---------------------------------------------------------------------------
// Stub transport (mock responses for testing)
// ---------------------------------------------------------------------------

std::string QSBMorpheusClient::StubSubmit(const UniValue& payload)
{
    ++m_stub_counter;
    std::string job_id = "morpheus-stub-" + std::to_string(m_stub_counter);

    // Determine job type and generate appropriate mock result
    if (payload.exists("type")) {
        std::string type = payload["type"].get_str();
        if (type == "qsb_pinning") {
            m_stub_results[job_id] = GenerateMockPinningResult();
        }
        // Digest results require key material, stored when AwaitResults calls StubPoll
    }

    return job_id;
}

UniValue QSBMorpheusClient::StubPoll(const std::string& job_id)
{
    auto it = m_stub_results.find(job_id);
    if (it != m_stub_results.end()) {
        return it->second;
    }
    // Return null if no result yet (shouldn't happen in stub mode)
    return UniValue();
}

UniValue QSBMorpheusClient::GenerateMockPinningResult()
{
    // Generate a deterministic mock pinning result
    //
    // Note: This mock will NOT pass DER-prefix verification because the
    // RIPEMD160 of a random pubkey is unlikely to start with 0x30.
    // That's correct behavior — in production, the GPU provider does the
    // hard work of finding a pubkey whose hash IS DER-valid.
    //
    // For integration testing, we generate a structurally valid result
    // so the parsing + verification pipeline can be exercised.
    UniValue result(UniValue::VOBJ);
    UniValue solution(UniValue::VOBJ);

    solution.pushKV("sequence", 151205);
    solution.pushKV("locktime", 656535577);

    // Deterministic 33-byte compressed pubkey
    std::vector<unsigned char> pubkey(33, 0x01);
    pubkey[0] = 0x02;
    solution.pushKV("recovered_pubkey", "0x" + HexStr(pubkey));

    // Correct RIPEMD160 for the pubkey above
    auto hash = ComputeRIPEMD160(pubkey);
    solution.pushKV("ripemd160_hash", "0x" + HexStr(hash));

    result.pushKV("solution", solution);
    return result;
}

UniValue QSBMorpheusClient::GenerateMockDigestResult(int round, const HORSKeyMaterial& keys)
{
    // Generate a mock digest result that WILL pass verification
    //
    // We use the actual preimages from the key material to construct
    // a valid result. In production, the GPU provider finds these
    // by brute-forcing the sighash space.
    UniValue result(UniValue::VOBJ);
    UniValue solution(UniValue::VOBJ);

    solution.pushKV("round", round);

    // Pick 9 indices (0-8) and use their actual preimages
    UniValue indices(UniValue::VARR);
    UniValue preimages(UniValue::VARR);

    int subset_size = std::min(9, keys.num_keys);
    for (int i = 0; i < subset_size; ++i) {
        indices.push_back(i);
        if (i < (int)keys.preimages.size()) {
            preimages.push_back("0x" + HexStr(keys.preimages[i]));
        }
    }

    solution.pushKV("subset_indices", indices);
    solution.pushKV("preimages", preimages);

    result.pushKV("solution", solution);
    return result;
}
