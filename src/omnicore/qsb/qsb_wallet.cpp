// Copyright (c) 2026 The Omni Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <omnicore/qsb/qsb_wallet.h>

#include <omnicore/qsb/qsb_job_builder.h>
#include <omnicore/qsb/qsb_local_verifier.h>

#include <bech32.h>
#include <chainparams.h>

#include <memory>

// Static constexpr member definitions (required for C++11/14)
constexpr int QSBWallet::DEFAULT_MIN_POOL_SIZE;
constexpr int QSBWallet::DEFAULT_MAX_POOL_SIZE;
constexpr int QSBWallet::DEFAULT_HORS_NUM_KEYS;

// ---------------------------------------------------------------------------
// Construction / Initialization
// ---------------------------------------------------------------------------

QSBWallet::QSBWallet()
{
    QSBPoolConfig pool_config;
    pool_config.min_size = DEFAULT_MIN_POOL_SIZE;
    pool_config.max_size = DEFAULT_MAX_POOL_SIZE;
    pool_config.hors_num_keys = DEFAULT_HORS_NUM_KEYS;

    m_pool.reset(new QSBPreGenPool(pool_config));
    m_client.reset(new QSBMorpheusClient());
    m_transport.reset(new QSBLumerinTransport());
}

QSBWallet::~QSBWallet()
{
    Shutdown();
}

void QSBWallet::Initialize()
{
    if (m_initialized) {
        return;
    }

    // Connect Lumerin transport to Morpheus client
    m_transport->InstallOn(*m_client);

    // Start the pre-gen pool worker thread
    m_pool->Start();

    m_initialized = true;
}

void QSBWallet::Shutdown()
{
    if (!m_initialized) {
        return;
    }

    m_pool->Stop();
    m_initialized = false;
}

// ---------------------------------------------------------------------------
// Pool Operations
// ---------------------------------------------------------------------------

bool QSBWallet::AcquireReadyOutput(QSBPoolEntry& entry)
{
    if (!m_initialized) {
        return false;
    }

    return m_pool->Acquire(entry);
}

bool QSBWallet::AcquireReadyOutputBlocking(QSBPoolEntry& entry, int timeout_ms)
{
    if (!m_initialized) {
        return false;
    }

    return m_pool->AcquireBlocking(entry, static_cast<uint64_t>(timeout_ms));
}

void QSBWallet::GetPoolStatus(int& ready_count, int& target_count, bool& is_running)
{
    ready_count = static_cast<int>(m_pool->Size());
    target_count = DEFAULT_MAX_POOL_SIZE;
    is_running = m_pool->IsRunning();
}

// ---------------------------------------------------------------------------
// Address Encoding / Decoding
// ---------------------------------------------------------------------------

std::string QSBWallet::EncodeAddress(const CScript& script, const CChainParams& params)
{
    // Extract the script data for Bech32 encoding
    std::vector<unsigned char> data;
    data.reserve(script.size());
    for (auto it = script.begin(); it != script.end(); ++it) {
        data.push_back(static_cast<unsigned char>(*it));
    }

    // Get the Bech32 HRP based on network
    std::string hrp;
    if (params.NetworkIDString() == "main") {
        hrp = "qs";
    } else if (params.NetworkIDString() == "test") {
        hrp = "qst";
    } else if (params.NetworkIDString() == "regtest") {
        hrp = "qsrt";
    } else {
        hrp = "qs";  // Default to mainnet
    }

    return bech32::Encode(hrp, data);
}

bool QSBWallet::DecodeAddress(const std::string& addr, CScript& script, std::string& error)
{
    if (addr.empty()) {
        error = "Empty address";
        return false;
    }

    // Decode Bech32
    auto result = bech32::Decode(addr);
    std::string& hrp = result.first;
    std::vector<uint8_t>& data = result.second;

    if (hrp.empty()) {
        error = "Invalid Bech32 encoding";
        return false;
    }

    // Verify HRP is a QSB prefix
    if (hrp != "qs" && hrp != "qst" && hrp != "qsrt") {
        error = "Invalid QSB address prefix: " + hrp;
        return false;
    }

    // Convert to script
    script.clear();
    for (uint8_t c : data) {
        script << static_cast<opcodetype>(c);
    }

    return true;
}

// ---------------------------------------------------------------------------
// Job Creation / Verification
// ---------------------------------------------------------------------------

bool QSBWallet::CreateQSBJob(const QSBPoolEntry& entry, const QSBJobConfig& config, QSBJob& job)
{
    if (!m_initialized) {
        return false;
    }

    // Validate key material
    QSBVerifyError verr;
    if (!ValidateKeyMaterial(entry.keys, verr)) {
        return false;
    }

    // Build all jobs (pinning + digest for each round)
    std::vector<QSBJob> jobs = BuildQSBJobs(entry.keys, config);
    if (jobs.empty()) {
        return false;
    }

    // Return the first job (pinning job)
    job = jobs[0];
    return true;
}

bool QSBWallet::VerifyResult(const QSBJob& job, const MorpheusJobResult& result, const HORSKeyMaterial& keys)
{
    // Always verify locally — never trust provider results
    // NOTE: Full verification uses the local verifier with the actual
    // parsed result structures (QSBPinningResult/QSBDigestResult).
    // This wallet-level wrapper does type dispatch.
    //
    // For pinning jobs, parse result into QSBPinningResult and verify.
    // For digest jobs, parse result into QSBDigestResult and verify.
    //
    // TODO: Wire up result parsing from MorpheusJobResult to specific types
    // once the Lumerin transport returns real (non-mock) results.
    // For now, this delegates to the Morpheus client's built-in verification.

    if (job.type == "qsb_pinning") {
        // Client already verified in AwaitResults() — return cached status
        return result.verified;
    } else if (job.type == "qsb_digest") {
        return result.verified;
    }

    return false;
}