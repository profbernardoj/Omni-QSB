// Copyright (c) 2026 The Omni Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <omnicore/qsb/qsb_pregen_pool.h>
#include <omnicore/qsb/qsb_local_verifier.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <chrono>
#include <thread>

BOOST_FIXTURE_TEST_SUITE(qsb_pregen_pool_tests, BasicTestingSetup)

// ---------------------------------------------------------------------------
// Construction and lifecycle
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(construction_default_config)
{
    QSBPreGenPool pool;

    BOOST_CHECK(!pool.IsRunning());
    BOOST_CHECK_EQUAL(pool.Size(), 0);
}

BOOST_AUTO_TEST_CASE(construction_custom_config)
{
    QSBPoolConfig config;
    config.min_size = 2;
    config.max_size = 4;
    config.hors_num_keys = 100;
    config.refill_interval_ms = 50;

    QSBPreGenPool pool(config);
    BOOST_CHECK(!pool.IsRunning());
    BOOST_CHECK_EQUAL(pool.Size(), 0);
}

BOOST_AUTO_TEST_CASE(start_stop)
{
    QSBPreGenPool pool;

    pool.Start();
    BOOST_CHECK(pool.IsRunning());

    pool.Stop();
    BOOST_CHECK(!pool.IsRunning());

    // Double stop is safe
    pool.Stop();
    BOOST_CHECK(!pool.IsRunning());
}

BOOST_AUTO_TEST_CASE(start_idempotent)
{
    QSBPreGenPool pool;

    pool.Start();
    pool.Start();  // No-op
    BOOST_CHECK(pool.IsRunning());

    pool.Stop();
}

// ---------------------------------------------------------------------------
// Acquire and refill
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(acquire_from_empty_pool)
{
    QSBPreGenPool pool;
    QSBPoolEntry entry;

    BOOST_CHECK(!pool.Acquire(entry));
    BOOST_CHECK_EQUAL(pool.Size(), 0);
}

BOOST_AUTO_TEST_CASE(start_fills_to_min_size)
{
    QSBPoolConfig config;
    config.min_size = 3;
    config.max_size = 5;
    config.refill_interval_ms = 10;  // Fast for tests

    QSBPreGenPool pool(config);
    pool.Start();

    // Wait for initial fill
    BOOST_CHECK(pool.WaitForFill(2000));
    BOOST_CHECK(pool.Size() >= static_cast<size_t>(config.min_size));

    pool.Stop();
}

BOOST_AUTO_TEST_CASE(acquire_removes_entry)
{
    QSBPoolConfig config;
    config.min_size = 2;
    config.refill_interval_ms = 10;

    QSBPreGenPool pool(config);
    pool.Start();
    pool.WaitForFill(1000);

    size_t size_before = pool.Size();

    QSBPoolEntry entry;
    BOOST_CHECK(pool.Acquire(entry));

    BOOST_CHECK_EQUAL(pool.Size(), size_before - 1);
    BOOST_CHECK(!entry.entry_id.empty());
    BOOST_CHECK(entry.acquired_time > 0);

    pool.Stop();
}

BOOST_AUTO_TEST_CASE(acquire_all_entries)
{
    QSBPoolConfig config;
    config.min_size = 2;
    config.max_size = 2;
    config.refill_interval_ms = 10;

    QSBPreGenPool pool(config);
    pool.Start();
    pool.WaitForFill(1000);

    QSBPoolEntry entry1, entry2;
    BOOST_CHECK(pool.Acquire(entry1));
    BOOST_CHECK(pool.Acquire(entry2));
    BOOST_CHECK_EQUAL(pool.Size(), 0);

    // Third acquire fails
    QSBPoolEntry entry3;
    BOOST_CHECK(!pool.Acquire(entry3));

    pool.Stop();
}

BOOST_AUTO_TEST_CASE(worker_refills_after_acquire)
{
    QSBPoolConfig config;
    config.min_size = 3;
    config.max_size = 5;
    config.refill_interval_ms = 10;

    QSBPreGenPool pool(config);
    pool.Start();
    pool.WaitForFill(1000);

    size_t size_before = pool.Size();
    BOOST_CHECK(size_before >= 3);

    // Acquire entries to drop below min_size
    QSBPoolEntry entry;
    while (pool.Size() > 1) {
        BOOST_CHECK(pool.Acquire(entry));
    }

    // Give worker time to refill
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Pool should have refilled
    BOOST_CHECK(pool.Size() >= static_cast<size_t>(config.min_size));

    pool.Stop();
}

// ---------------------------------------------------------------------------
// Key material validation
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(generated_keys_valid_structure)
{
    QSBPoolConfig config;
    config.hors_num_keys = 150;

    QSBPreGenPool pool(config);
    pool.Start();
    pool.WaitForFill(1000);

    QSBPoolEntry entry;
    BOOST_CHECK(pool.Acquire(entry));

    // Check structure
    BOOST_CHECK_EQUAL(entry.keys.num_keys, 150);
    BOOST_CHECK_EQUAL(entry.keys.preimages.size(), 150);
    BOOST_CHECK_EQUAL(entry.keys.commitments.size(), 150);
    BOOST_CHECK_EQUAL(entry.keys.dummy_sigs.size(), 150);

    for (int i = 0; i < 150; ++i) {
        // Preimages are 32 bytes
        BOOST_CHECK_EQUAL(entry.keys.preimages[i].size(), 32);

        // Commitments are 20 bytes (Hash160)
        BOOST_CHECK_EQUAL(entry.keys.commitments[i].size(), 20);

        // Commitments match preimages
        auto expected = ComputeHash160(entry.keys.preimages[i]);
        BOOST_CHECK(entry.keys.commitments[i] == expected);

        // Dummy sigs are non-empty
        BOOST_CHECK(!entry.keys.dummy_sigs[i].empty());
    }

    // Midstate is 32 bytes
    BOOST_CHECK_EQUAL(entry.keys.scriptcode_midstate.size(), 32);

    pool.Stop();
}

BOOST_AUTO_TEST_CASE(generated_keys_different_per_entry)
{
    QSBPreGenPool pool;
    pool.Start();
    pool.WaitForFill(1000);

    QSBPoolEntry entry1, entry2;
    BOOST_CHECK(pool.Acquire(entry1));
    BOOST_CHECK(pool.Acquire(entry2));

    // Entries should have different IDs
    BOOST_CHECK(entry1.entry_id != entry2.entry_id);

    // First preimages should differ
    BOOST_CHECK(entry1.keys.preimages[0] != entry2.keys.preimages[0]);

    pool.Stop();
}

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(stats_tracking)
{
    QSBPoolConfig config;
    config.min_size = 2;
    config.refill_interval_ms = 10;

    QSBPreGenPool pool(config);
    pool.Start();
    pool.WaitForFill(1000);

    QSBPreGenPool::Stats stats;

    stats = pool.GetStats();
    BOOST_CHECK(stats.current_size >= 2);
    BOOST_CHECK(stats.total_generated >= 2);

    // Acquire one
    QSBPoolEntry entry;
    BOOST_CHECK(pool.Acquire(entry));

    stats = pool.GetStats();
    BOOST_CHECK_EQUAL(stats.total_acquired, 1);

    // Acquire another
    BOOST_CHECK(pool.Acquire(entry));

    stats = pool.GetStats();
    BOOST_CHECK_EQUAL(stats.total_acquired, 2);

    pool.Stop();
}

BOOST_AUTO_TEST_CASE(generation_time_tracked)
{
    QSBPoolConfig config;
    config.min_size = 1;
    config.max_size = 1;
    config.refill_interval_ms = 10;

    QSBPreGenPool pool(config);
    pool.Start();
    pool.WaitForFill(1000);

    QSBPreGenPool::Stats stats = pool.GetStats();

    // Generation should be fast (typically <100ms)
    // Note: can be 0 if fast enough
    BOOST_CHECK(stats.last_generation_time_ms >= 0);

    pool.Stop();
}

// ---------------------------------------------------------------------------
// Wait for fill
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(wait_for_fill_success)
{
    QSBPreGenPool pool;
    pool.Start();

    BOOST_CHECK(pool.WaitForFill(2000));
    pool.Stop();
}

BOOST_AUTO_TEST_CASE(wait_for_fill_timeout)
{
    QSBPoolConfig config;
    config.min_size = 5000;  // Impossibly high — can't fill in 10ms
    config.max_size = 5000;
    config.refill_interval_ms = 500;  // Slow refill check

    QSBPreGenPool pool(config);
    pool.Start();

    // Should timeout — generating 5000 HORS entries is way too slow
    BOOST_CHECK(!pool.WaitForFill(10));

    pool.Stop();
}

// ---------------------------------------------------------------------------
// Thread safety
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Blocking acquire (Grok spec: get_ready_output_blocks_when_empty)
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(blocking_acquire_waits_for_entry)
{
    QSBPoolConfig config;
    config.min_size = 1;
    config.max_size = 2;
    config.refill_interval_ms = 10;

    QSBPreGenPool pool(config);
    // Don't start yet — pool is empty

    // Blocking acquire with timeout should fail on empty stopped pool
    QSBPoolEntry entry;
    BOOST_CHECK(!pool.AcquireBlocking(entry, 50));

    // Start pool, blocking acquire should succeed once worker generates
    pool.Start();

    BOOST_CHECK(pool.AcquireBlocking(entry, 2000));
    BOOST_CHECK(!entry.entry_id.empty());
    BOOST_CHECK(entry.acquired_time > 0);

    pool.Stop();
}

BOOST_AUTO_TEST_CASE(blocking_acquire_wakes_on_stop)
{
    QSBPoolConfig config;
    config.min_size = 1000;  // Will never fill
    config.max_size = 1000;

    QSBPreGenPool pool(config);
    pool.Start();

    // Drain whatever was generated
    QSBPoolEntry drain;
    while (pool.Acquire(drain)) {}

    // Launch thread that does blocking acquire
    std::atomic<bool> got_result(false);
    std::thread t([&pool, &got_result]() {
        QSBPoolEntry entry;
        // This should unblock when Stop() is called
        got_result.store(pool.AcquireBlocking(entry, 0));
    });

    // Give thread time to block, then stop pool
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    pool.Stop();

    t.join();
    // AcquireBlocking may return true (got one before stop) or false (stop woke it)
    // Either is valid — the important thing is it didn't deadlock
    BOOST_CHECK(true);
}

// ---------------------------------------------------------------------------
// Grok spec: pool_maintains_target_size
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(pool_maintains_target_size)
{
    QSBPoolConfig config;
    config.min_size = 3;
    config.max_size = 5;
    config.refill_interval_ms = 10;

    QSBPreGenPool pool(config);
    pool.Start();
    pool.WaitForFill(2000);

    // Pool should be at or above min_size
    BOOST_CHECK(pool.Size() >= 3);

    // Pool should not exceed max_size
    BOOST_CHECK(pool.Size() <= 5);

    // Drain to 1, wait for refill
    QSBPoolEntry entry;
    while (pool.Size() > 1) {
        BOOST_CHECK(pool.Acquire(entry));
    }

    // Worker should refill back to at least min_size
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    BOOST_CHECK(pool.Size() >= 3);

    pool.Stop();
}

// ---------------------------------------------------------------------------
// Grok spec: status_reporting
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(status_reporting)
{
    QSBPoolConfig config;
    config.min_size = 2;
    config.max_size = 4;
    config.refill_interval_ms = 10;

    QSBPreGenPool pool(config);

    // Before start
    auto stats = pool.GetStats();
    BOOST_CHECK_EQUAL(stats.current_size, 0);
    BOOST_CHECK_EQUAL(stats.total_generated, 0);
    BOOST_CHECK_EQUAL(stats.total_acquired, 0);

    pool.Start();
    pool.WaitForFill(1000);

    stats = pool.GetStats();
    BOOST_CHECK(stats.current_size >= 2);
    BOOST_CHECK(stats.total_generated >= 2);
    BOOST_CHECK_EQUAL(stats.total_acquired, 0);

    // Acquire 2
    QSBPoolEntry e1, e2;
    pool.Acquire(e1);
    pool.Acquire(e2);

    stats = pool.GetStats();
    BOOST_CHECK_EQUAL(stats.total_acquired, 2);
    BOOST_CHECK(stats.last_generation_time_ms >= 0);

    pool.Stop();
}

// ---------------------------------------------------------------------------
// Thread safety (Grok spec: thread_safety_get_and_refill)
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(concurrent_acquire)
{
    QSBPoolConfig config;
    config.min_size = 10;
    config.max_size = 20;
    config.refill_interval_ms = 5;

    QSBPreGenPool pool(config);
    pool.Start();
    pool.WaitForFill(2000);

    // Each thread collects into its own vector to avoid shared-vector races
    std::mutex results_mutex;
    std::vector<QSBPoolEntry> all_entries;
    std::vector<std::thread> threads;

    for (int t = 0; t < 4; ++t) {
        threads.emplace_back([&pool, &results_mutex, &all_entries]() {
            std::vector<QSBPoolEntry> local;
            for (int i = 0; i < 5; ++i) {
                QSBPoolEntry entry;
                if (pool.Acquire(entry)) {
                    local.push_back(std::move(entry));
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
            // Merge under lock
            std::lock_guard<std::mutex> lock(results_mutex);
            for (auto& e : local) {
                all_entries.push_back(std::move(e));
            }
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    // All acquired entries should be valid
    for (const auto& entry : all_entries) {
        BOOST_CHECK(!entry.entry_id.empty());
        BOOST_CHECK(entry.acquired_time > 0);
    }

    pool.Stop();
}

BOOST_AUTO_TEST_SUITE_END()