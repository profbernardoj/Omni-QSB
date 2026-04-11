// Copyright (c) 2026 The Omni Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <omnicore/qsb/qsb_pregen_pool.h>

#include <chrono>
#include <iomanip>
#include <random>
#include <sstream>

#include <crypto/sha256.h>
#include <util/time.h>

// ---------------------------------------------------------------------------
// Constructor / Destructor
// ---------------------------------------------------------------------------

QSBPreGenPool::QSBPreGenPool(const QSBPoolConfig& config)
    : m_config(config)
    , m_running(false)
    , m_stop_requested(false)
    , m_total_generated(0)
    , m_total_acquired(0)
    , m_last_generation_time_ms(0)
{
}

QSBPreGenPool::~QSBPreGenPool()
{
    Stop();
}

// ---------------------------------------------------------------------------
// Thread control
// ---------------------------------------------------------------------------

void QSBPreGenPool::Start()
{
    if (m_running.load()) return;

    m_stop_requested.store(false);
    m_running.store(true);
    m_worker = std::thread(&QSBPreGenPool::WorkerThread, this);
}

void QSBPreGenPool::Stop()
{
    if (!m_running.load()) return;

    m_stop_requested.store(true);
    m_cv.notify_all();

    if (m_worker.joinable()) {
        m_worker.join();
    }

    m_running.store(false);
}

bool QSBPreGenPool::IsRunning() const
{
    return m_running.load();
}

// ---------------------------------------------------------------------------
// Pool operations
// ---------------------------------------------------------------------------

bool QSBPreGenPool::Acquire(QSBPoolEntry& entry)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_pool.empty()) {
        return false;
    }

    entry = std::move(m_pool.front());
    m_pool.pop_front();

    // Mark as acquired
    entry.acquired_time = GetTime();

    m_total_acquired.fetch_add(1);

    // Wake up worker to refill if needed
    m_cv.notify_one();

    return true;
}

bool QSBPreGenPool::AcquireBlocking(QSBPoolEntry& entry, uint64_t timeout_ms)
{
    std::unique_lock<std::mutex> lock(m_mutex);

    auto predicate = [this]() {
        return !m_pool.empty() || m_stop_requested.load();
    };

    if (timeout_ms > 0) {
        if (!m_cv.wait_for(lock, std::chrono::milliseconds(timeout_ms), predicate)) {
            return false;
        }
    } else {
        m_cv.wait(lock, predicate);
    }

    if (m_pool.empty()) {
        return false;  // stop_requested with empty pool
    }

    entry = std::move(m_pool.front());
    m_pool.pop_front();
    entry.acquired_time = GetTime();
    m_total_acquired.fetch_add(1);

    // Wake worker to refill
    m_cv.notify_one();

    return true;
}

size_t QSBPreGenPool::Size() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_pool.size();
}

bool QSBPreGenPool::WaitForFill(uint64_t timeout_ms)
{
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);

    std::unique_lock<std::mutex> lock(m_mutex);

    while (m_pool.size() < static_cast<size_t>(m_config.min_size)) {
        if (m_cv.wait_until(lock, deadline) == std::cv_status::timeout) {
            return false;
        }
    }

    return true;
}

QSBPreGenPool::Stats QSBPreGenPool::GetStats() const
{
    Stats stats;
    stats.current_size = Size();
    stats.total_generated = m_total_generated.load();
    stats.total_acquired = m_total_acquired.load();
    stats.last_generation_time_ms = m_last_generation_time_ms.load();
    return stats;
}

// ---------------------------------------------------------------------------
// Key material generation
// ---------------------------------------------------------------------------

HORSKeyMaterial QSBPreGenPool::GenerateHORSKeyMaterial(uint64_t seed_entropy, int num_keys)
{
    HORSKeyMaterial keys;
    keys.num_keys = num_keys;

    // Initialize RNG
    std::mt19937_64 rng;

    if (seed_entropy != 0) {
        rng.seed(seed_entropy);
    } else {
        // Use high-resolution time + hardware entropy
        std::random_device rd;
        std::hash<std::thread::id> hasher;
        std::seed_seq::result_type thread_hash = static_cast<std::seed_seq::result_type>(hasher(std::this_thread::get_id()));
        std::seed_seq seed{rd(), rd(), rd(), static_cast<std::seed_seq::result_type>(GetTimeMicros()), thread_hash};
        rng.seed(seed);
    }

    // Generate scriptcode_midstate (random 32 bytes for now)
    // In production, this comes from the actual script (tx outputs + scriptCode)
    // We just need the SHA-256 internal state, not the final hash.
    // For pre-gen, we use random bytes and the wallet will recompute later.
    keys.scriptcode_midstate.resize(32);
    for (int i = 0; i < 32; ++i) {
        keys.scriptcode_midstate[i] = static_cast<unsigned char>(rng() & 0xFF);
    }

    // Generate dummy signatures (minimal valid DER for testing)
    // In production, these come from wallet signing dummy data
    keys.dummy_sigs.reserve(num_keys);
    for (int i = 0; i < num_keys; ++i) {
        std::vector<unsigned char> sig = {
            0x30, 0x06,  // DER sequence, 6 bytes
            0x02, 0x01, static_cast<unsigned char>((i % 127) + 1),  // R
            0x02, 0x01, static_cast<unsigned char>(((i * 7) % 127) + 1)  // S
        };
        keys.dummy_sigs.push_back(std::move(sig));
    }

    // Generate HORS preimages and compute commitments
    keys.preimages.reserve(num_keys);
    keys.commitments.reserve(num_keys);

    for (int i = 0; i < num_keys; ++i) {
        // Preimage: 32 random bytes
        std::vector<unsigned char> preimage(32);
        for (int j = 0; j < 32; ++j) {
            preimage[j] = static_cast<unsigned char>(rng() & 0xFF);
        }
        keys.preimages.push_back(preimage);

        // Commitment: Hash160(preimage) = RIPEMD160(SHA256(preimage))
        std::vector<unsigned char> commitment = ComputeHash160(preimage);
        keys.commitments.push_back(std::move(commitment));
    }

    return keys;
}

// ---------------------------------------------------------------------------
// Worker thread
// ---------------------------------------------------------------------------

void QSBPreGenPool::WorkerThread()
{
    while (!m_stop_requested.load()) {
        // Check if refill needed
        {
            std::unique_lock<std::mutex> lock(m_mutex);

            if (m_pool.size() >= static_cast<size_t>(m_config.max_size)) {
                // Pool is full, wait for notification or timeout
                m_cv.wait_for(lock, std::chrono::milliseconds(m_config.refill_interval_ms),
                    [this]() {
                        return m_stop_requested.load() ||
                               m_pool.size() < static_cast<size_t>(m_config.min_size);
                    });
                continue;
            }
        }

        // Generate new entry (outside lock to not block Acquire)
        int64_t start = GetTimeMicros();

        QSBPoolEntry entry;
        entry.keys = GenerateHORSKeyMaterial(m_config.seed_entropy, m_config.hors_num_keys);
        entry.created_time = GetTime();

        // Derive entry_id from first preimage
        std::ostringstream oss;
        oss << std::hex;
        for (unsigned char c : entry.keys.preimages[0]) {
            oss << std::setw(2) << std::setfill('0') << static_cast<int>(c);
        }
        entry.entry_id = oss.str();

        // Add to pool
        {
            std::lock_guard<std::mutex> lock(m_mutex);

            if (m_pool.size() < static_cast<size_t>(m_config.max_size)) {
                m_pool.push_back(std::move(entry));
                m_total_generated.fetch_add(1);

                int64_t elapsed_ms = (GetTimeMicros() - start) / 1000;
                m_last_generation_time_ms.store(elapsed_ms);
            }
        }

        // Notify any waiters
        m_cv.notify_one();
    }
}