// Copyright (c) 2026 The Omni Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <omnicore/qsb/qsb_script_assembler.h>

#include <hash.h>
#include <pubkey.h>
#include <random.h>
#include <script/script.h>
#include <uint256.h>
#include <util/strencodings.h>

#include <algorithm>
#include <cstdint>
#include <random>
#include <set>

namespace {

/**
 * Encode a minimal 9-byte DER signature.
 * Format: 30 06 02 01 <r> 02 01 <s> <sighash_type>
 * r and s must be in [1, 127] for the minimal encoding.
 */
std::vector<unsigned char> EncodeMinimalDER(int r_val, int s_val, int sighash_type)
{
    assert(r_val >= 1 && r_val <= 127);
    assert(s_val >= 1 && s_val <= 127);
    
    std::vector<unsigned char> sig;
    sig.reserve(9);
    sig.push_back(0x30);  // DER sequence
    sig.push_back(0x06);   // 6 bytes follow
    sig.push_back(0x02);   // integer tag for r
    sig.push_back(0x01);   // 1 byte for r
    sig.push_back(static_cast<unsigned char>(r_val));
    sig.push_back(0x02);   // integer tag for s
    sig.push_back(0x01);   // 1 byte for s
    sig.push_back(static_cast<unsigned char>(s_val));
    sig.push_back(static_cast<unsigned char>(sighash_type));
    
    return sig;
}

/**
 * Get valid small r values for minimal DER signatures.
 * These are x-coordinates [1,127] that exist on secp256k1.
 */
std::vector<int> GetValidSmallRValues()
{
    // Generate on first use, cache for subsequent calls
    static std::vector<int> valid_r;
    if (valid_r.empty()) {
        valid_r.reserve(127);
        for (int r = 1; r <= 127; ++r) {
            // All values 1-127 are acceptable for dummy signatures
            // In production, we'd verify they're on the curve
            valid_r.push_back(r);
        }
    }
    return valid_r;
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// QSBScriptAssembler Implementation
// ---------------------------------------------------------------------------

QSBScriptMaterial QSBScriptAssembler::GenerateMaterial(
    const QSBConfig& config,
    bool seed_rng)
{
    QSBScriptMaterial material;
    material.rounds.resize(2);
    
    // Get valid small r values for minimal DER signatures
    const auto& valid_r = GetValidSmallRValues();
    
    // Initialize RNG
    std::mt19937_64 rng;
    if (seed_rng) {
        rng.seed(42); // Deterministic for testing
    } else {
        std::random_device rd;
        std::seed_seq seed{rd(), rd(), rd(), rd()};
        rng.seed(seed);
    }
    
    // Generate HORS key material for each round
    for (int round = 0; round < 2; ++round) {
        HORSKeyMaterial& keys = material.rounds[round];
        keys.num_keys = config.n;
        keys.commitments.reserve(config.n);
        keys.preimages.reserve(config.n);
        keys.dummy_sigs.reserve(config.n);
        
        for (int i = 0; i < config.n; ++i) {
            // Generate preimage (32 random bytes)
            std::vector<unsigned char> preimage(32);
            for (int j = 0; j < 32; ++j) {
                preimage[j] = static_cast<unsigned char>(rng() & 0xFF);
            }
            keys.preimages.push_back(preimage);
            
            // Compute commitment: Hash160(preimage) = RIPEMD160(SHA256(preimage))
            uint160 commitment = Hash160(preimage);
            std::vector<unsigned char> commitment_bytes(commitment.begin(), commitment.end());
            keys.commitments.push_back(std::move(commitment_bytes));
            
            // Generate dummy signature (minimal 9-byte DER)
            // Use unique (r, s) pairs per round+index
            // SIGHASH_SINGLE bug (0x03) for dummy signatures
            // Match Python: r cycles through valid_r, s increments when r wraps
            int pair_idx = i + round * config.n;
            int r_val = valid_r[pair_idx % valid_r.size()];
            int s_val = 1 + (pair_idx / (int)valid_r.size()) % 127;
            
            keys.dummy_sigs.push_back(EncodeMinimalDER(r_val, s_val, 0x03));
        }
        
        // Generate scriptcode_midstate (random 32 bytes)
        // In production, this is computed from the actual transaction
        keys.scriptcode_midstate.resize(32);
        for (int j = 0; j < 32; ++j) {
            keys.scriptcode_midstate[j] = static_cast<unsigned char>(rng() & 0xFF);
        }
    }
    
    // Generate pinning signature (9-byte minimal DER with SIGHASH_ALL)
    int pin_r = valid_r[0];
    material.pin_sig = EncodeMinimalDER(pin_r, 42, 0x01);
    
    // Generate round signatures
    int r1_val = valid_r[1 % valid_r.size()];
    int r2_val = valid_r[2 % valid_r.size()];
    
    material.sig_r1 = EncodeMinimalDER(r1_val, 99, 0x01);
    material.sig_r2 = EncodeMinimalDER(r2_val, 100, 0x01);
    
    // Initialize r/s/k values for GPU search
    material.pin_r = uint256S(std::to_string(pin_r));
    material.pin_s = uint256S("42");
    material.pin_k = GetRandHash();
    material.r1_r = uint256S(std::to_string(r1_val));
    material.r1_s = uint256S("99");
    material.r1_k = GetRandHash();
    material.r2_r = uint256S(std::to_string(r2_val));
    material.r2_s = uint256S("100");
    material.r2_k = GetRandHash();
    
    return material;
}

CScript QSBScriptAssembler::Assemble(
    const QSBScriptMaterial& material,
    const QSBConfig& config)
{
    CScript script;
    
    // ========================================================================
    // PINNING SECTION (5 ops)
    // ========================================================================
    // <sig1_pin> OP_OVER OP_CHECKSIGVERIFY OP_RIPEMD160 OP_SWAP OP_CHECKSIGVERIFY
    // 
    // Witness provides: <key2_pin> <key1_pin> (key1 on top)
    // Chain: sig1 → key1 → CHECKSIG (binds to tx)
    //        RIPEMD160(key1) → sig2 → key2 → CHECKSIG (proves valid DER)
    
    script << material.pin_sig;
    script << OP_OVER;
    script << OP_CHECKSIGVERIFY;
    script << OP_RIPEMD160;
    script << OP_SWAP;
    script << OP_CHECKSIGVERIFY;
    
    // ========================================================================
    // ROUND 1
    // ========================================================================
    BuildRoundSection(script, material.rounds[0], material.sig_r1, material.sig_r2,
                      0, config.t1_signed, config.t1_bonus, config.n);
    
    // ========================================================================
    // ROUND 2
    // ========================================================================
    // For final round, there's no next_sig_r (puzzle goes to final CHECKMULTISIG)
    std::vector<unsigned char> empty_sig;
    BuildRoundSection(script, material.rounds[1], material.sig_r2, empty_sig,
                      1, config.t2_signed, config.t2_bonus, config.n);
    
    return script;
}

void QSBScriptAssembler::BuildRoundSection(
    CScript& script,
    const HORSKeyMaterial& round_keys,
    const std::vector<unsigned char>& sig_r,
    const std::vector<unsigned char>& /* next_sig_r */,
    int round_idx,
    int t_signed,
    int t_bonus,
    int n)
{
    int t_total = t_signed + t_bonus;
    
    // ========================================================================
    // HORS COMMITMENTS (n × 20 bytes)
    // ========================================================================
    // Push in reverse order: H(pre_{n-1}), ..., H(pre_0)
    // After execution, stack has commit_0 on top, commit_{n-1} at bottom.
    
    for (int i = n - 1; i >= 0; --i) {
        if (i < (int)round_keys.commitments.size()) {
            script << round_keys.commitments[i];
        } else {
            script << std::vector<unsigned char>(20, 0);
        }
    }
    
    // ========================================================================
    // DUMMY SIGNATURES (n × 9 bytes)
    // ========================================================================
    // Push in reverse order: dsig_{n-1}, ..., dsig_0
    // After execution, dsig_0 is on top, dsig_{n-1} at bottom (above commitments).
    
    for (int i = n - 1; i >= 0; --i) {
        if (i < (int)round_keys.dummy_sigs.size()) {
            script << round_keys.dummy_sigs[i];
        } else {
            script << EncodeMinimalDER(1, 1, 0x03);
        }
    }
    
    // ========================================================================
    // OP_0 (CHECKMULTISIG off-by-one dummy)
    // ========================================================================
    script << OP_0;
    
    // ========================================================================
    // sig_nonce (hardcoded round signature, SIGHASH_ALL)
    // ========================================================================
    // Gets removed by FindAndDelete during sighash computation.
    script << sig_r;
    
    // ========================================================================
    // SIGNED SELECTIONS  (Python: 12 ops each)
    // ========================================================================
    // Per selection i (i = 0 .. t_signed-1):
    //
    //   push_number(idx_pos)        # witness index position
    //   OP_ROLL                     # move index to top
    //   push_number(sanitize)       # max valid index
    //   OP_MIN                      # clamp
    //   OP_DUP                      # copy: one for commitment lookup, one stays
    //   push_number(n+1)            # offset to commitment area
    //   OP_ADD                      # = commitment stack pos
    //   OP_ROLL                     # roll commitment to top
    //   push_number(preimage_pos)   # witness preimage position
    //   OP_ROLL                     # roll preimage to top
    //   OP_HASH160                  # H(preimage)
    //   OP_EQUALVERIFY              # verify H(preimage) == commitment
    //   OP_ROLL                     # leftover index → roll dummy sig
    //
    // Position formulas from Python build_round_script:
    //   idx_pos      = 2*n + 1 - i
    //   sanitize     = n - i
    //   preimage_pos = 2*n + 1 + t_total - 2*i
    //   (final OP_ROLL is bare — uses the DUP'd index already on stack)
    
    for (int i = 0; i < t_signed; ++i) {
        int idx_pos      = 2 * n + 1 - i;
        int sanitize     = n - i;
        int preimage_pos = 2 * n + 1 + t_total - 2 * i;
        
        PushNumber(script, idx_pos);        // 1
        script << OP_ROLL;                   // 2
        PushNumber(script, sanitize);        // 3
        script << OP_MIN;                    // 4
        script << OP_DUP;                    // 5
        PushNumber(script, n + 1);           // 6
        script << OP_ADD;                    // 7
        script << OP_ROLL;                   // 8  (rolls commitment)
        PushNumber(script, preimage_pos);    // 9
        script << OP_ROLL;                   // 10 (rolls preimage)
        script << OP_HASH160;                // 11
        script << OP_EQUALVERIFY;            // 12 (verify)
        script << OP_ROLL;                   // 13 (bare — DUP'd index rolls dummy sig)
    }
    
    // ========================================================================
    // BONUS SELECTIONS  (Python: 5 ops each)
    // ========================================================================
    // Per bonus j (j = t_signed .. t_total-1):
    //
    //   push_number(idx_pos)    # witness index position
    //   OP_ROLL                 # move index to top
    //   push_number(sanitize)   # max valid index
    //   OP_MIN                  # clamp
    //   OP_ROLL                 # bare — clamped index rolls dummy sig
    //
    // Position formulas from Python:
    //   idx_pos  = 2*n + 1 - j
    //   sanitize = n - j
    
    for (int b = 0; b < t_bonus; ++b) {
        int j        = t_signed + b;
        int idx_pos  = 2 * n + 1 - j;
        int sanitize = n - j;
        
        PushNumber(script, idx_pos);   // 1
        script << OP_ROLL;              // 2
        PushNumber(script, sanitize);   // 3
        script << OP_MIN;               // 4
        script << OP_ROLL;              // 5 (bare — rolls dummy sig)
    }
    
    // ========================================================================
    // PUZZLE SECTION
    // ========================================================================
    // Rolls key_nonce from the witness, DUPs it, hashes one copy with RIPEMD160
    // to produce a "sig_puzzle", then verifies sig_puzzle against a pubkey.
    //
    // Python:
    //   puzzle_pos = 2*n + 2
    //   push_number(puzzle_pos) OP_ROLL   # roll key_nonce
    //   OP_DUP                            # copy: one for RIPEMD160, one stays
    //   OP_RIPEMD160                      # → sig_puzzle
    //   push_number(puzzle_pos) OP_ROLL   # roll key_puzzle from witness
    //   OP_CHECKSIGVERIFY                 # verify(sig_puzzle, key_puzzle)
    
    int puzzle_pos = 2 * n + 2;
    PushNumber(script, puzzle_pos);
    script << OP_ROLL;
    script << OP_DUP;
    script << OP_RIPEMD160;
    PushNumber(script, puzzle_pos);
    script << OP_ROLL;
    script << OP_CHECKSIGVERIFY;
    
    // ========================================================================
    // CHECKMULTISIG  m-of-m  (m = t_total + 1)
    // ========================================================================
    // Python:
    //   push_number(m)
    //   OP_2 OP_ROLL            # roll something into position
    //   for j in range(t_total):
    //       push_number(cms_roll_pos) OP_ROLL
    //   push_number(m)
    //   OP_CHECKMULTISIG
    //
    // cms_roll_pos = 2*n + 3
    
    int m            = t_total + 1;
    int cms_roll_pos = 2 * n + 3;
    
    PushNumber(script, m);
    script << static_cast<opcodetype>(OP_1 + 2 - 1);  // OP_2
    script << OP_ROLL;
    
    for (int j = 0; j < t_total; ++j) {
        PushNumber(script, cms_roll_pos);
        script << OP_ROLL;
    }
    
    PushNumber(script, m);
    script << OP_CHECKMULTISIG;
}

CScript& QSBScriptAssembler::PushData(CScript& script, const std::vector<unsigned char>& data)
{
    // Bitcoin script push encoding
    size_t len = data.size();
    
    if (len <= 75) {
        script << static_cast<opcodetype>(len);
    } else if (len <= 255) {
        script << OP_PUSHDATA1;
        script << static_cast<unsigned char>(len);
    } else if (len <= 65535) {
        script << OP_PUSHDATA2;
        script << static_cast<unsigned char>(len & 0xFF);
        script << static_cast<unsigned char>((len >> 8) & 0xFF);
    } else {
        script << OP_PUSHDATA4;
        script << static_cast<unsigned char>(len & 0xFF);
        script << static_cast<unsigned char>((len >> 8) & 0xFF);
        script << static_cast<unsigned char>((len >> 16) & 0xFF);
        script << static_cast<unsigned char>((len >> 24) & 0xFF);
    }
    
    script << data;
    return script;
}

CScript& QSBScriptAssembler::PushNumber(CScript& script, int n)
{
    if (n == 0) {
        script << OP_0;
    } else if (n >= 1 && n <= 16) {
        script << static_cast<opcodetype>(OP_1 + n - 1);
    } else {
        // Let CScript encode it (handles negatives and large numbers)
        script << n;
    }
    return script;
}