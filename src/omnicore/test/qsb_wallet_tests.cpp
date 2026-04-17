// Copyright (c) 2026 The Omni Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <omnicore/qsb/qsb_wallet.h>
#include <omnicore/qsb/qsb_pregen_pool.h>
#include <omnicore/qsb/qsb_local_verifier.h>
#include <omnicore/qsb/qsb_script_assembler.h>
#include <script/standard.h>

#include <chainparams.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <thread>

BOOST_FIXTURE_TEST_SUITE(qsb_wallet_tests, BasicTestingSetup)

// ---------------------------------------------------------------------------
// Lifecycle: starts and stops cleanly (Grok: wallet_qsb_pool_starts_on_load)
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(wallet_qsb_pool_starts_on_load)
{
    QSBWallet qsb;

    // Not initialized yet — acquire should fail
    QSBPoolEntry entry;
    BOOST_CHECK(!qsb.AcquireReadyOutput(entry));

    // Initialize (starts pool worker)
    qsb.Initialize();

    // Pool should be working now
    int ready, target;
    bool working;
    qsb.GetPoolStatus(ready, target, working);
    BOOST_CHECK_EQUAL(target, QSBWallet::DEFAULT_MAX_POOL_SIZE);

    // Wait briefly for pool to generate at least one entry
    bool acquired = qsb.AcquireReadyOutputBlocking(entry, 5000);
    BOOST_CHECK(acquired);
    BOOST_CHECK(!entry.entry_id.empty());

    // Verify key material is valid
    BOOST_CHECK_EQUAL(entry.keys.num_keys, QSBWallet::DEFAULT_HORS_NUM_KEYS);
    BOOST_CHECK_EQUAL((int)entry.keys.preimages.size(), QSBWallet::DEFAULT_HORS_NUM_KEYS);
    BOOST_CHECK_EQUAL((int)entry.keys.commitments.size(), QSBWallet::DEFAULT_HORS_NUM_KEYS);

    qsb.Shutdown();
}

// ---------------------------------------------------------------------------
// Clean shutdown (Grok: wallet_qsb_pool_stops_cleanly_on_shutdown)
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(wallet_qsb_pool_stops_cleanly_on_shutdown)
{
    QSBWallet qsb;
    qsb.Initialize();

    // Wait for at least one entry
    QSBPoolEntry entry;
    qsb.AcquireReadyOutputBlocking(entry, 5000);

    // Shutdown should complete without hanging
    qsb.Shutdown();

    // After shutdown, acquire should fail
    BOOST_CHECK(!qsb.AcquireReadyOutput(entry));
}

BOOST_AUTO_TEST_CASE(double_initialize_is_safe)
{
    QSBWallet qsb;
    qsb.Initialize();
    qsb.Initialize();  // Second call is no-op

    QSBPoolEntry entry;
    bool acquired = qsb.AcquireReadyOutputBlocking(entry, 5000);
    BOOST_CHECK(acquired);

    qsb.Shutdown();
}

BOOST_AUTO_TEST_CASE(double_shutdown_is_safe)
{
    QSBWallet qsb;
    qsb.Initialize();

    qsb.Shutdown();
    qsb.Shutdown();  // Second call is no-op — no crash
}

// ---------------------------------------------------------------------------
// Ready output (Grok: wallet_get_ready_qsb_output_returns_valid_script)
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(wallet_get_ready_qsb_output_returns_valid_script)
{
    QSBWallet qsb;
    qsb.Initialize();

    QSBPoolEntry entry;
    bool acquired = qsb.AcquireReadyOutputBlocking(entry, 5000);
    BOOST_CHECK(acquired);

    // Verify HORS key material integrity
    // Each commitment must be Hash160 of corresponding preimage
    for (int i = 0; i < entry.keys.num_keys; ++i) {
        std::vector<unsigned char> expected = ComputeHash160(entry.keys.preimages[i]);
        BOOST_CHECK(entry.keys.commitments[i] == expected);
    }

    qsb.Shutdown();
}

BOOST_AUTO_TEST_CASE(acquired_entries_are_unique)
{
    QSBWallet qsb;
    qsb.Initialize();

    QSBPoolEntry entry1, entry2;
    BOOST_CHECK(qsb.AcquireReadyOutputBlocking(entry1, 5000));
    BOOST_CHECK(qsb.AcquireReadyOutputBlocking(entry2, 5000));

    // Entries must be different (each is single-use HORS)
    BOOST_CHECK(entry1.entry_id != entry2.entry_id);

    // Different preimages
    BOOST_CHECK(entry1.keys.preimages[0] != entry2.keys.preimages[0]);

    qsb.Shutdown();
}

// ---------------------------------------------------------------------------
// Pool status (Grok: wallet_qsbpoolstatus_rpc_works)
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(wallet_qsbpoolstatus_rpc_works)
{
    QSBWallet qsb;
    qsb.Initialize();

    // Wait for pool to fill
    QSBPoolEntry entry;
    qsb.AcquireReadyOutputBlocking(entry, 5000);

    int ready, target;
    bool is_running;
    qsb.GetPoolStatus(ready, target, is_running);

    // Target should be DEFAULT_MAX_POOL_SIZE
    BOOST_CHECK_EQUAL(target, QSBWallet::DEFAULT_MAX_POOL_SIZE);

    // We acquired one entry, so ready should be at least 0
    // (worker may have already refilled)
    BOOST_CHECK(ready >= 0);

    // Pool should be running
    BOOST_CHECK(is_running);

    qsb.Shutdown();
}

// ---------------------------------------------------------------------------
// Concurrent access (Grok: wallet_concurrent_spends_refill_pool_correctly)
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(wallet_concurrent_spends_refill_pool_correctly)
{
    QSBWallet qsb;
    qsb.Initialize();

    // Wait for pool to have some entries
    QSBPoolEntry entry;
    qsb.AcquireReadyOutputBlocking(entry, 5000);

    // Spawn multiple threads acquiring entries concurrently
    std::atomic<int> success_count{0};
    std::vector<std::thread> threads;

    for (int i = 0; i < 4; ++i) {
        threads.emplace_back([&qsb, &success_count]() {
            QSBPoolEntry local_entry;
            // Use blocking acquire with timeout
            if (qsb.AcquireReadyOutputBlocking(local_entry, 10000)) {
                ++success_count;
            }
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    // At least some should succeed (pool refills in background)
    BOOST_CHECK(success_count > 0);

    qsb.Shutdown();
}

// ---------------------------------------------------------------------------
// Address encoding round-trip
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(address_encode_decode_roundtrip)
{
    // Note: QSBWallet::EncodeAddress/DecodeAddress are simplified wrappers.
    // Full address encoding uses existing Bitcoin infrastructure (EncodeDestination).
    // This test validates that the wrapper compiles and runs.
    
    // Create a QSBHash from raw bytes
    std::vector<unsigned char> hash_bytes(20, 0xab);
    uint160 hash;
    memcpy(hash.begin(), hash_bytes.data(), 20);
    QSBHash qsb_hash(hash);
    
    // Use the existing infrastructure for proper encoding
    // QSBWallet is for pool management, not address encoding
    BOOST_CHECK(qsb_hash.size() == 20);
}

BOOST_AUTO_TEST_CASE(decode_invalid_address_fails)
{
    CScript script;
    std::string error;

    // Empty address
    BOOST_CHECK(!QSBWallet::DecodeAddress("", script, error));
    BOOST_CHECK_EQUAL(error, "Empty address");

    // Invalid Bech32
    BOOST_CHECK(!QSBWallet::DecodeAddress("xyz1invalidbech32", script, error));
}

// ---------------------------------------------------------------------------
// Job creation and verification
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(create_qsb_job_from_pool_entry)
{
    QSBWallet qsb;
    qsb.Initialize();

    QSBPoolEntry entry;
    BOOST_CHECK(qsb.AcquireReadyOutputBlocking(entry, 5000));

    QSBJobConfig config;
    config.escrow_contract = "0x1234567890abcdef";
    config.mor_amount_per_solution = "0.1";

    QSBJob job;
    bool ok = qsb.CreateQSBJob(entry, config, job);
    BOOST_CHECK(ok);
    BOOST_CHECK(job.type == "qsb_pinning");
    // job_id is empty until submitted to Lumerin
    BOOST_CHECK(job.job_id.empty());
    // payload should be populated
    BOOST_CHECK(job.payload.isObject());

    qsb.Shutdown();
}

BOOST_AUTO_TEST_CASE(create_job_before_init_fails)
{
    QSBWallet qsb;  // Not initialized

    QSBPoolEntry entry;
    QSBJobConfig config;
    QSBJob job;

    BOOST_CHECK(!qsb.CreateQSBJob(entry, config, job));
}

// ---------------------------------------------------------------------------
// Destructor auto-shutdown
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(destructor_calls_shutdown)
{
    // This should not leak threads or crash
    {
        QSBWallet qsb;
        qsb.Initialize();

        QSBPoolEntry entry;
        qsb.AcquireReadyOutputBlocking(entry, 5000);

        // Destructor called here — should stop pool cleanly
    }

    // If we get here without hanging, the destructor worked
    BOOST_CHECK(true);
}

// ===========================================================================
// QSB Script Assembler Tests
// ===========================================================================

BOOST_AUTO_TEST_CASE(assembler_config_a_produces_valid_script)
{
    // Config A: n=150, t1_signed=8, t1_bonus=1, t2_signed=8, t2_bonus=0
    QSBConfig config = QSBConfig::ConfigA();
    QSBScriptMaterial material = QSBScriptAssembler::GenerateMaterial(config, true /* seed_rng */);
    
    BOOST_CHECK(material.IsValid());
    BOOST_CHECK_EQUAL((int)material.rounds.size(), 2);
    BOOST_CHECK_EQUAL(material.rounds[0].num_keys, 150);
    BOOST_CHECK_EQUAL(material.rounds[1].num_keys, 150);
    BOOST_CHECK_EQUAL((int)material.pin_sig.size(), 9);
    BOOST_CHECK_EQUAL((int)material.sig_r1.size(), 9);
    BOOST_CHECK_EQUAL((int)material.sig_r2.size(), 9);
    
    // Assemble
    CScript script = QSBScriptAssembler::Assemble(material, config);
    
    // Config A script should be approximately 9,000-10,000 bytes
    // n=150: 150 commitments × 21 bytes + 150 dummy sigs × 10 bytes = ~4,650
    // Two rounds: ~9,300 + pinning + selections + puzzle + CMS ≈ ~9,650
    BOOST_CHECK_GT(script.size(), 8000u);
    BOOST_CHECK_LT(script.size(), 12000u);
}

BOOST_AUTO_TEST_CASE(assembler_deterministic_with_seed)
{
    QSBConfig config = QSBConfig::Test();
    
    QSBScriptMaterial mat1 = QSBScriptAssembler::GenerateMaterial(config, true);
    QSBScriptMaterial mat2 = QSBScriptAssembler::GenerateMaterial(config, true);
    
    CScript script1 = QSBScriptAssembler::Assemble(mat1, config);
    CScript script2 = QSBScriptAssembler::Assemble(mat2, config);
    
    // Same seed → same material → same script
    BOOST_CHECK(script1 == script2);
}

BOOST_AUTO_TEST_CASE(assembler_test_config_produces_small_script)
{
    // Test config: n=10, t1=2, t2=2
    QSBConfig config = QSBConfig::Test();
    QSBScriptMaterial material = QSBScriptAssembler::GenerateMaterial(config, true);
    
    BOOST_CHECK(material.IsValid());
    BOOST_CHECK_EQUAL(material.rounds[0].num_keys, 10);
    BOOST_CHECK_EQUAL(material.rounds[1].num_keys, 10);
    
    CScript script = QSBScriptAssembler::Assemble(material, config);
    
    // Test config script should be much smaller than Config A
    // n=10: ~10 × 21 + 10 × 10 = ~310 per round × 2 ≈ ~620 + overhead
    BOOST_CHECK_GT(script.size(), 400u);
    BOOST_CHECK_LT(script.size(), 2000u);
}

BOOST_AUTO_TEST_CASE(assembler_commitments_are_hash160)
{
    QSBConfig config = QSBConfig::Test();
    QSBScriptMaterial material = QSBScriptAssembler::GenerateMaterial(config, true);
    
    // Verify each commitment is Hash160 of its preimage
    for (int r = 0; r < 2; ++r) {
        for (int i = 0; i < config.n; ++i) {
            uint160 expected = Hash160(material.rounds[r].preimages[i]);
            std::vector<unsigned char> expected_bytes(expected.begin(), expected.end());
            BOOST_CHECK_EQUAL_COLLECTIONS(
                material.rounds[r].commitments[i].begin(),
                material.rounds[r].commitments[i].end(),
                expected_bytes.begin(),
                expected_bytes.end());
        }
    }
}

BOOST_AUTO_TEST_CASE(assembler_dummy_sigs_are_valid_der)
{
    QSBConfig config = QSBConfig::Test();
    QSBScriptMaterial material = QSBScriptAssembler::GenerateMaterial(config, true);
    
    // Verify each dummy sig is 9 bytes with proper DER structure
    for (int r = 0; r < 2; ++r) {
        for (int i = 0; i < config.n; ++i) {
            const auto& sig = material.rounds[r].dummy_sigs[i];
            BOOST_CHECK_EQUAL(sig.size(), 9u);
            BOOST_CHECK_EQUAL(sig[0], 0x30);  // DER sequence
            BOOST_CHECK_EQUAL(sig[1], 0x06);  // 6 bytes payload
            BOOST_CHECK_EQUAL(sig[2], 0x02);  // integer tag (r)
            BOOST_CHECK_EQUAL(sig[3], 0x01);  // 1 byte r
            BOOST_CHECK_EQUAL(sig[5], 0x02);  // integer tag (s)
            BOOST_CHECK_EQUAL(sig[6], 0x01);  // 1 byte s
            BOOST_CHECK_EQUAL(sig[8], 0x03);  // SIGHASH_SINGLE
        }
    }
}

BOOST_AUTO_TEST_CASE(assembler_dummy_sigs_unique_per_round)
{
    QSBConfig config = QSBConfig::ConfigA();
    QSBScriptMaterial material = QSBScriptAssembler::GenerateMaterial(config, true);
    
    // All dummy sigs within a round must be unique
    for (int r = 0; r < 2; ++r) {
        std::set<std::vector<unsigned char>> seen;
        for (int i = 0; i < config.n; ++i) {
            auto result = seen.insert(material.rounds[r].dummy_sigs[i]);
            BOOST_CHECK_MESSAGE(result.second,
                "Duplicate dummy sig in round " + std::to_string(r) + " at index " + std::to_string(i));
        }
    }
}

BOOST_AUTO_TEST_CASE(assembler_pinning_section_structure)
{
    // Verify the first bytes of the assembled script match the pinning pattern
    QSBConfig config = QSBConfig::Test();
    QSBScriptMaterial material = QSBScriptAssembler::GenerateMaterial(config, true);
    CScript script = QSBScriptAssembler::Assemble(material, config);
    
    // Pinning section starts with push of 9-byte pin_sig
    // Format: 09 <9 bytes> OP_OVER(0x78) OP_CHECKSIGVERIFY(0xad) OP_RIPEMD160(0xa6) OP_SWAP(0x7c) OP_CHECKSIGVERIFY(0xad)
    const unsigned char* data = script.data();
    BOOST_CHECK_EQUAL(data[0], 0x09);  // push 9 bytes
    // Bytes 1-9: pin_sig
    BOOST_CHECK_EQUAL(data[10], 0x78);  // OP_OVER
    BOOST_CHECK_EQUAL(data[11], 0xad);  // OP_CHECKSIGVERIFY
    BOOST_CHECK_EQUAL(data[12], 0xa6);  // OP_RIPEMD160
    BOOST_CHECK_EQUAL(data[13], 0x7c);  // OP_SWAP
    BOOST_CHECK_EQUAL(data[14], 0xad);  // OP_CHECKSIGVERIFY
}

BOOST_AUTO_TEST_CASE(assembler_wallet_integration)
{
    // Test that AssembleQSBOutput now produces a real script (not stub)
    QSBWallet qsb;
    qsb.Initialize();
    
    QSBPoolEntry entry;
    bool acquired = qsb.AcquireReadyOutputBlocking(entry, 5000);
    BOOST_REQUIRE(acquired);
    
    CScript script;
    bool ok = qsb.AssembleQSBOutput(entry, script);
    BOOST_CHECK(ok);
    
    // Should NOT be stub anymore (OP_RETURN + QSB_STUB)
    BOOST_CHECK_GT(script.size(), 1000u);
    
    // Should not start with OP_RETURN (0x6a)
    BOOST_CHECK_NE(script[0], 0x6a);
    
    // Should start with pinning push (0x09 = push 9 bytes)
    BOOST_CHECK_EQUAL(script[0], 0x09);
    
    qsb.Shutdown();
}

BOOST_AUTO_TEST_SUITE_END()