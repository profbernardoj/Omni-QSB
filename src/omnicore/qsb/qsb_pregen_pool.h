// Copyright (c) 2026 The Omni Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef OMNICORE_QSB_PREGEN_POOL_H
#define OMNICORE_QSB_PREGEN_POOL_H

#include <omnicore/qsb/qsb_local_verifier.h>

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <thread>

/**
 * QSB Pre-generated Pool — Segment 4 of Stage 3 (Morpheus Compute Integration)
 *
 * Maintains a pool of pre-generated HORS key material to enable instant
 * QSB transaction creation. Without pre-generation, HORS key generation
 * (150 keys × 32-byte preimages) adds ~50-100ms latency.
 *
 * Architecture:
 *   - Background thread generates HORS key material when pool is low
 *   - Pool is thread-safe (mutex + condition_variable)
 *   - Wallet calls Acquire() to get pre-generated entries
 *   - Pool worker auto-refills when size drops below min_size
 *
 * Security:
 *   - Private preimages never leave the pool
 *   - Only commitments (Hash160) are exposed in transaction output
 *   - Each entry is single-use (HORS is one-time signature)
 *
 * Usage:
 *   QSBPreGenPool pool(3, 5);  // min=3, max=5 entries
 *   pool.Start();
 *
 *   // When wallet needs QSB material:
 *   QSBPoolEntry entry;
 *   if (pool.Acquire(entry)) {
 *     // Use entry.keys for transaction
 *   }
 *
 *   // On shutdown:
 *   pool.Stop();
 */

//! Configuration for pre-gen pool behavior
struct QSBPoolConfig {
    int min_size = 3;                  //!< Refill when pool < min_size
    int max_size = 5;                  //!< Stop generating when pool >= max_size
    int hors_num_keys = 150;           //!< Number of HORS keys per entry
    int refill_interval_ms = 100;      //!< Check interval (ms)
    uint64_t seed_entropy = 0;         //!< Optional: derive from wallet entropy

    QSBPoolConfig() = default;
    QSBPoolConfig(int min_sz, int max_sz, int num_keys = 150)
        : min_size(min_sz), max_size(max_sz), hors_num_keys(num_keys) {}
};

//! A single pre-generated entry in the pool
struct QSBPoolEntry {
    HORSKeyMaterial keys;    //!< Complete HORS key material
    std::string entry_id;    //!< Unique identifier (hex of first preimage)
    int64_t created_time;    //!< Unix timestamp when generated
    int64_t acquired_time;   //!< Unix timestamp when acquired (0 if unused)

    QSBPoolEntry() : created_time(0), acquired_time(0) {}

    //! Returns true if this entry has been acquired for use
    bool IsAcquired() const { return acquired_time > 0; }
};

/**
 * Thread-safe pool of pre-generated HORS key material.
 *
 * The pool runs a background worker thread that keeps the pool populated
 * with ready-to-use QSB entries. Call Acquire() to claim an entry for
 * transaction construction.
 */
class QSBPreGenPool {
public:
    /**
     * Construct a pool with the given configuration.
     * @param[in] config  Pool size and generation parameters
     */
    explicit QSBPreGenPool(const QSBPoolConfig& config = QSBPoolConfig());

    //! Non-copyable (owns thread)
    QSBPreGenPool(const QSBPreGenPool&) = delete;
    QSBPreGenPool& operator=(const QSBPreGenPool&) = delete;

    //! Destructor stops the worker thread if running
    ~QSBPreGenPool();

    /**
     * Start the background worker thread.
     * Safe to call multiple times (no-op if already running).
     */
    void Start();

    /**
     * Stop the background worker thread.
     * Blocks until worker exits. Safe to call multiple times.
     */
    void Stop();

    /**
     * Check if the pool is running.
     */
    bool IsRunning() const;

    /**
     * Acquire a pre-generated entry from the pool (non-blocking).
     * Removes the entry from the pool and marks it as acquired.
     *
     * @param[out] entry  The acquired entry (valid only if returns true)
     * @return true if an entry was acquired, false if pool is empty
     */
    bool Acquire(QSBPoolEntry& entry);

    /**
     * Acquire a pre-generated entry, blocking until one is available.
     * Waits until the worker produces an entry or timeout_ms elapses.
     * Matches Grok's GetReadyQSBOutput() behavior.
     *
     * @param[out] entry       The acquired entry
     * @param[in]  timeout_ms  Maximum wait (0 = wait forever)
     * @return true if acquired, false on timeout or pool stopped
     */
    bool AcquireBlocking(QSBPoolEntry& entry, uint64_t timeout_ms = 0);

    /**
     * Get the current pool size (number of ready entries).
     * Thread-safe.
     */
    size_t Size() const;

    /**
     * Wait for the pool to reach at least min_size entries.
     * Useful during wallet initialization.
     *
     * @param[in] timeout_ms  Maximum time to wait (0 = no wait)
     * @return true if pool has >= min_size entries, false on timeout
     */
    bool WaitForFill(uint64_t timeout_ms = 5000);

    /**
     * Get pool statistics (for diagnostics).
     */
    struct Stats {
        size_t current_size;
        size_t total_generated;
        size_t total_acquired;
        int64_t last_generation_time_ms;
    };
    Stats GetStats() const;

private:
    /**
     * Generate a single HORS key material entry.
     * Called by the worker thread to refill the pool.
     *
     * @param[in] seed_entropy  Optional entropy source (wallet-derived)
     * @param[in] num_keys      Number of HORS keys to generate
     * @return Complete key material for one QSB entry
     */
    static HORSKeyMaterial GenerateHORSKeyMaterial(uint64_t seed_entropy, int num_keys);

    /**
     * Background worker thread function.
     * Loops until stop requested, refilling pool when below min_size.
     */
    void WorkerThread();

    //! Pool configuration
    QSBPoolConfig m_config;

    //! Thread-safe queue of ready entries
    mutable std::mutex m_mutex;
    std::deque<QSBPoolEntry> m_pool;
    std::condition_variable m_cv;

    //! Worker thread
    std::thread m_worker;
    std::atomic<bool> m_running;
    std::atomic<bool> m_stop_requested;

    //! Statistics
    std::atomic<size_t> m_total_generated;
    std::atomic<size_t> m_total_acquired;
    std::atomic<int64_t> m_last_generation_time_ms;
};

#endif // OMNICORE_QSB_PREGEN_POOL_H