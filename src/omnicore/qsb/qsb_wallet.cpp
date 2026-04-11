// Copyright (c) 2026 The Omni Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <omnicore/qsb/qsb_wallet.h>

#include <omnicore/qsb/qsb_job_builder.h>
#include <omnicore/qsb/qsb_local_verifier.h>

#include <bech32.h>
#include <chainparams.h>
#include <hash.h>
#include <uint256.h>

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
    // NOTE: The final step will call AssembleBareScript() once Avihu confirms
    // the HORS commitment template and nSequence wiring for TX_QSB_BARE.
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

// ---------------------------------------------------------------------------
// QSB Output Assembly (Stub)
// ---------------------------------------------------------------------------

bool QSBWallet::AssembleQSBOutput(const QSBPoolEntry& entry, CScript& script)
{
    // ================================================
    // NOTE: FINAL ASSEMBLY STUB — AWAITING AVIHU LEVY
    // ================================================
    // The real implementation will call:
    //   QSBReferenceLib::AssembleBareScript(keys, results, sequence, locktime);
    //
    // This function will produce the final ~9,650-byte bare scriptPubKey
    // containing:
    //   - PIN_PATTERN (OP_OVER OP_CHECKSIGVERIFY OP_RIPEMD160 OP_SWAP OP_CHECKSIGVERIFY)
    //   - 150 HORS commitments (20 bytes each)
    //   - Dummy signatures (~150 DER-encoded)
    //   - nSequence/nLockTime encoding for RIPEMD160 puzzle
    //
    // Until Avihu confirms the exact Config A template and provides
    // the reference library, we return a minimal placeholder script
    // that is syntactically valid but will NOT pass real QSB verification.
    //
    // When Avihu delivers the library:
    //   1. Add qsb/reference/ as submodule
    //   2. Replace this entire function with the real call
    //   3. Remove this comment block

    // Placeholder: return a tiny bare script (just enough for RPC/UI testing)
    // This is an OP_RETURN with "QSB_STUB" marker for identification
    script.clear();
    script << OP_RETURN << std::vector<unsigned char>{'Q','S','B','_','S','T','U','B'};
    return true;
}

bool QSBWallet::CreateQSBAddress(uint160& qsbId, CScript& script, int timeout_ms)
{
    if (!m_initialized) {
        return false;
    }

    // Acquire key material from pool
    QSBPoolEntry entry;
    bool acquired = false;

    if (timeout_ms > 0) {
        acquired = m_pool->AcquireBlocking(entry, static_cast<uint64_t>(timeout_ms));
    } else {
        acquired = m_pool->Acquire(entry);
    }

    if (!acquired) {
        return false;
    }

    // Assemble the output script (currently stub)
    if (!AssembleQSBOutput(entry, script)) {
        return false;
    }

    // Derive QSB ID from HORS commitments
    // The QSB ID is Hash160 of the serialized commitments
    if (entry.keys.commitments.empty()) {
        return false;
    }

    std::vector<unsigned char> serialized;
    serialized.reserve(entry.keys.commitments.size() * 20);
    for (const auto& commitment : entry.keys.commitments) {
        serialized.insert(serialized.end(), commitment.begin(), commitment.end());
    }

    qsbId = Hash160(serialized);
    return true;
}