// Copyright (c) 2026 The Omni Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef OMNICORE_QSB_WALLET_H
#define OMNICORE_QSB_WALLET_H

#include <omnicore/qsb/qsb_pregen_pool.h>
#include <omnicore/qsb/qsb_morpheus_client.h>
#include <omnicore/qsb/qsb_lumerin_transport.h>

#include <script/script.h>
#include <uint256.h>

#include <memory>
#include <string>

/**
 * QSB Wallet Integration — Gateway to Morpheus Compute
 *
 * This is the main entry point for the wallet layer. Program expects
 * to allocate a QSBWallet instance and call:
 *
 *   QSBWallet qsb;
 *   qsb.Initialize();                      // Start pre-gen pool
 *   CScript script = qsb.GetReadyOutput(); // Get pre-generated HORS output
 *   std::string addr = qsb.EncodeAddress(script);
 *   // Use script in transaction construction
 *
 * On shutdown:
 *   qsb.Shutdown();                        // Stop pool worker
 *
 * Thread Safety:
 *   - QSBWallet is fully thread-safe
 *   - Internal pool uses mutex + condition_variable
 *   - Multiple threads can call GetReadyOutput() concurrently
 *
 * Memory:
 *   - Pool stores ~150 keys × 32 bytes × (3-5 entries) = ~15-25 KB
 *   - No persistent state (regenerates on restart)
 *   - Private preimages never leave the pool
 */

class CWallet;

/**
 * QSB Wallet Transaction Builder
 *
 * Constructs QSB bare scripts and integrates with the QSB pipeline:
 *   1. Pre-gen pool provides ready HORS key material
 *   2. Job builder constructs pinning + digest jobs
 *   3. Morpheus client submits to Lumerin proxy-router
 *   4. Local verifier validates results
 *   5. Final script assembly (after Avihu confirms template)
 */
class QSBWallet {
public:
    //! Pool configuration defaults
    static constexpr int DEFAULT_MIN_POOL_SIZE = 3;
    static constexpr int DEFAULT_MAX_POOL_SIZE = 5;
    static constexpr int DEFAULT_HORS_NUM_KEYS = 150;

    /**
     * Construct QSB wallet integration.
     * Does not start the pool until Initialize() is called.
     */
    QSBWallet();

    //! Non-copyable (owns background thread)
    QSBWallet(const QSBWallet&) = delete;
    QSBWallet& operator=(const QSBWallet&) = delete;

    //! Destructor calls Shutdown()
    ~QSBWallet();

    /**
     * Initialize the QSB pipeline.
     * Starts the pre-gen pool worker thread.
     */
    void Initialize();

    /**
     * Shutdown the QSB pipeline.
     * Stops the pool worker thread and releases resources.
     */
    void Shutdown();

    /**
     * Get a ready QSB output script.
     * This acquires a pre-generated HORS key entry from the pool.
     *
     * @param[out] entry  The pool entry containing HORS key material
     * @return true if a ready entry was available, false if pool is empty
     *
     * Thread-safe. Non-blocking.
     */
    bool AcquireReadyOutput(QSBPoolEntry& entry);

    /**
     * Get a ready QSB output script (blocking).
     * Waits for a ready entry if the pool is empty.
     *
     * @param[out] entry      The pool entry containing HORS key material
     * @param[in]  timeout_ms Maximum time to wait (0 = wait forever)
     * @return true if acquired, false on timeout or shutdown
     *
     * Thread-safe. Blocks until ready or timeout.
     */
    bool AcquireReadyOutputBlocking(QSBPoolEntry& entry, int timeout_ms = 0);

    /**
     * Get the current pool status.
     *
     * @param[out] ready_count   Number of ready entries
     * @param[out] target_count  Target pool size
     * @param[out] is_running    True if worker thread is running
     */
    void GetPoolStatus(int& ready_count, int& target_count, bool& is_running);

    /**
     * Encode a QSB script to a Bech32 address.
     * HRP is "qs1" (mainnet), "qst1" (testnet), "qsrt1" (regtest).
     *
     * @param[in] script  The QSB output script
     * @param[in] params   Chain parameters for HRP selection
     * @return Bech32-encoded address string
     */
    static std::string EncodeAddress(const CScript& script, const class CChainParams& params);

    /**
     * Decode a QSB Bech32 address to script.
     *
     * @param[in]  addr    The Bech32 address (qs1... / qst1... / qsrt1...)
     * @param[out] script  The decoded QSB output script
     * @param[out] error   Error message if decoding fails
     * @return true if valid QSB address, false otherwise
     */
    static bool DecodeAddress(const std::string& addr, CScript& script, std::string& error);

    /**
     * Create a QSB job for submission to Morpheus compute.
     * This constructs the JSON payload for Lumerin submission.
     *
     * @param[in]  entry   Pre-generated HORS key entry
     * @param[in]  config  Job configuration (escrow contract, etc.)
     * @param[out] job     The constructed job payload
     * @return true on success, false on configuration error
     */
    bool CreateQSBJob(const QSBPoolEntry& entry, const QSBJobConfig& config, QSBJob& job);

    /**
     * Verify a result from Morpheus compute.
     * Always verifies locally — never trusts provider results.
     *
     * @param[in] job     The job that was submitted
     * @param[in] result  The result from Morpheus
     * @param[in] keys    The HORS key material used
     * @return true if verification passes, false otherwise
     */
    bool VerifyResult(const QSBJob& job, const MorpheusJobResult& result, const HORSKeyMaterial& keys);

    /**
     * Assemble the final QSB output script (bare scriptPubKey).
     *
     * NOTE: This is a STUB implementation awaiting Avihu Levy's reference library.
     * The real implementation will call QSBReferenceLib::AssembleBareScript()
     * to produce the ~9,650-byte script with HORS commitments and pinning puzzle.
     *
     * This stub returns a minimal OP_RETURN placeholder for RPC/UI testing.
     *
     * @param[in]  entry   Pre-generated HORS key entry from pool
     * @param[out] script  The assembled output script (placeholder)
     * @return true on success (always true for stub)
     */
    bool AssembleQSBOutput(const QSBPoolEntry& entry, CScript& script);

    /**
     * Create a ready-to-use QSB address.
     * Acquires key material from pool, assembles output script, and derives the QSB ID.
     *
     * @param[out] qsbId      The QSB identifier (Hash160 of serialized commitments)
     * @param[out] script     The bare scriptPubKey
     * @param[in]  timeout_ms  Max time to wait for pool (0 = non-blocking)
     * @return true if address created, false if pool empty or QSB not initialized
     */
    bool CreateQSBAddress(uint160& qsbId, CScript& script, int timeout_ms = 0);

private:
    std::unique_ptr<QSBPreGenPool> m_pool;
    std::unique_ptr<QSBMorpheusClient> m_client;
    std::unique_ptr<QSBLumerinTransport> m_transport;

    bool m_initialized = false;
};

#endif // OMNICORE_QSB_WALLET_H