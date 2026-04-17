// Copyright (c) 2026 The Omni Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <omnicore/qsb/qsb_wallet.h>
#include <omnicore/qsb/qsb_script_assembler.h>
#include <omnicore/qsb/qsb_spend_builder.h>

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
// QSB Output Assembly — Production Implementation
// ---------------------------------------------------------------------------

bool QSBWallet::AssembleQSBOutput(const QSBPoolEntry& entry, CScript& script)
{
    // ============================================================
    // PRODUCTION IMPLEMENTATION
    // ============================================================
    // Based on Avihu Levy's QSBScriptBuilder from:
    // https://github.com/avihu28/Quantum-Safe-Bitcoin-Transactions
    //
    // This produces the ~9,650-byte bare scriptPubKey containing:
    //   - PIN_PATTERN (5 ops)
    //   - ROUND 1: 150 HORS commitments + dummy sigs + selections + puzzle
    //   - ROUND 2: 150 HORS commitments + dummy sigs + selections + puzzle
    //
    // Config A: n=150, t1_signed=8, t1_bonus=1, t2_signed=8, t2_bonus=0
    // ============================================================

    // Check if the pool entry has valid material for both rounds
    // The pre-gen pool generates flat HORSKeyMaterial, but we need two rounds
    // For now, we generate the second round on-demand from the first round's seed
    
    // Generate script material using the assembler.
    // Reference scripts: github.com/avihu28/Quantum-Safe-Bitcoin-Transactions
    //   pipeline/bitcoin_tx.py  (QSBScriptBuilder)
    //   script/script_8p1b_8.txt (Config A template)
    QSBConfig config = QSBConfig::ConfigA();  // Config A (full security)
    QSBScriptMaterial material = QSBScriptAssembler::GenerateMaterial(config, false);
    
    // Override round 0 with pool-provided HORS material if available.
    // TODO: Pool should store full QSBScriptMaterial (both rounds) instead of
    //       flat HORSKeyMaterial — eliminates this override and the on-demand
    //       GenerateMaterial() call for round 1.
    if (!entry.keys.commitments.empty() && !entry.keys.preimages.empty()) {
        material.rounds[0] = entry.keys;
    }
    
    // Assemble the full script
    script = QSBScriptAssembler::Assemble(material, config);
    
    // Validate the assembled script is reasonable
    // A real QSB script should be ~9,650 bytes for Config A
    // The assembly should always succeed given valid material
    if (script.size() < 1000) {
        // Fallback to stub if assembly produced something tiny
        // This shouldn't happen in production
        script.clear();
        script << OP_RETURN << std::vector<unsigned char>{'Q','S','B','_','E','R','R','O','R'};
        return false;
    }
    
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

// ---------------------------------------------------------------------------
// Spend Side (Segment 7)
// ---------------------------------------------------------------------------

static std::string OutpointKey(const COutPoint& op)
{
    return op.hash.ToString() + ":" + std::to_string(op.n);
}

void QSBWallet::StoreMaterial(const COutPoint& outpoint,
                               const QSBScriptMaterial& material,
                               const QSBConfig& config,
                               const CScript& script,
                               CAmount amount)
{
    StoredMaterial sm;
    sm.material = material;
    sm.config = config;
    sm.script = script;
    sm.amount = amount;
    m_material_store[OutpointKey(outpoint)] = std::move(sm);
}

bool QSBWallet::CreateQSBSpendTx(const COutPoint& qsbOutpoint,
                                   const CScript& destScript,
                                   const std::vector<unsigned char>& omniPayload,
                                   uint32_t locktime,
                                   const std::vector<int>& r1_indices,
                                   const std::vector<int>& r2_indices,
                                   CMutableTransaction& outTx,
                                   std::string& outError)
{
    if (!m_initialized) {
        outError = "QSB wallet not initialized";
        return false;
    }

    // Look up stored material
    std::string key = OutpointKey(qsbOutpoint);
    auto it = m_material_store.find(key);
    if (it == m_material_store.end()) {
        outError = "No QSB material found for outpoint " + key;
        return false;
    }

    const StoredMaterial& sm = it->second;

    // Validate index counts match config
    if ((int)r1_indices.size() != sm.config.T1Total()) {
        outError = "Round 1 index count mismatch: expected " +
                   std::to_string(sm.config.T1Total()) + ", got " +
                   std::to_string(r1_indices.size());
        return false;
    }
    if ((int)r2_indices.size() != sm.config.T2Total()) {
        outError = "Round 2 index count mismatch: expected " +
                   std::to_string(sm.config.T2Total()) + ", got " +
                   std::to_string(r2_indices.size());
        return false;
    }

    // Build spend params
    QSBSpendParams params;
    params.locktime = locktime;
    params.round1_indices = r1_indices;
    params.round2_indices = r2_indices;
    params.funding_outpoint = qsbOutpoint;
    params.funding_amount = sm.amount;

    // Build the spending transaction
    outTx = QSBSpendBuilder::BuildSpendTx(
        sm.material, sm.config, params, destScript, omniPayload);

    return true;
}