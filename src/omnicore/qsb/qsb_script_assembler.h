// Copyright (c) 2026 The Omni Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef OMNICORE_QSB_SCRIPT_ASSEMBLER_H
#define OMNICORE_QSB_SCRIPT_ASSEMBLER_H

#include <omnicore/qsb/qsb_local_verifier.h>

#include <script/script.h>
#include <uint256.h>

#include <cstdint>
#include <string>
#include <vector>

/**
 * QSB Script Assembler — Production Implementation
 *
 * Ports Avihu Levy's QSBScriptBuilder from Python to C++.
 * Builds the ~9,650-byte bare scriptPubKey for Quantum-Safe Bitcoin.
 *
 * Script Structure (Config A: n=150, t1_signed=8, t1_bonus=1, t2_signed=8, t2_bonus=0):
 * 
 *   PINNING (5 ops):
 *     <sig1_pin> OP_OVER OP_CHECKSIGVERIFY OP_RIPEMD160 OP_SWAP OP_CHECKSIGVERIFY
 *
 *   ROUND 1 (n=150, t_signed=8, t_bonus=1):
 *     - 150 HORS commitments (20 bytes each)
 *     - 150 dummy signatures (9 bytes each)
 *     - OP_0 (CHECKMULTISIG dummy)
 *     - sig_r_1 (hardcoded 9-byte signature)
 *     - 8 signed selections (9 ops each = 72 ops)
 *     - 1 bonus selection (3 ops)
 *     - Puzzle: key_r_1 → sig_r_2 (3 ops)
 *     - CHECKMULTISIG 10-of-10 (21 ops)
 *
 *   ROUND 2 (n=150, t_signed=8, t_bonus=0):
 *     - 150 HORS commitments (20 bytes each)
 *     - 150 dummy signatures (9 bytes each)
 *     - OP_0 (CHECKMULTISIG dummy)
 *     - sig_r_2 (hardcoded 9-byte signature)
 *     - 8 signed selections (9 ops each = 72 ops)
 *     - Puzzle: key_r_2 → sig_r_3 (3 ops)
 *     - CHECKMULTISIG 9-of-9 (19 ops)
 *
 * Total: ~9,650 bytes
 *
 * References:
 *   - https://github.com/avihu28/Quantum-Safe-Bitcoin-Transactions
 *   - pipeline/qsb_pipeline.py (QSBScriptBuilder class)
 *   - pipeline/bitcoin_tx.py (QSBScriptBuilder implementation)
 */

//! QSB Configuration parameters
struct QSBConfig {
    int n;           //!< Total HORS keys per round (default: 150)
    int t1_signed;   //!< Signed selections in round 1 (default: 8)
    int t1_bonus;    //!< Bonus selections in round 1 (default: 1)
    int t2_signed;   //!< Signed selections in round 2 (default: 8)
    int t2_bonus;    //!< Bonus selections in round 2 (default: 0)

    QSBConfig()
        : n(150), t1_signed(8), t1_bonus(1), t2_signed(8), t2_bonus(0) {}

    QSBConfig(int n_, int t1s, int t1b, int t2s, int t2b)
        : n(n_), t1_signed(t1s), t1_bonus(t1b), t2_signed(t2s), t2_bonus(t2b) {}

    //! Config A (full security, ~20h GPU search)
    static QSBConfig ConfigA() { return QSBConfig(150, 8, 1, 8, 0); }
    
    //! Config A120 (faster, ~3h GPU search)
    static QSBConfig ConfigA120() { return QSBConfig(120, 8, 1, 8, 0); }
    
    //! Config A100 (quick,~1h GPU search)
    static QSBConfig ConfigA100() { return QSBConfig(100, 8, 1, 8, 0); }
    
    //! Test config (minimal, for unit tests)
    static QSBConfig Test() { return QSBConfig(10, 2, 0, 2, 0); }
    
    int T1Total() const { return t1_signed + t1_bonus; }
    int T2Total() const { return t2_signed + t2_bonus; }
};

//! Complete script material for both rounds
struct QSBScriptMaterial {
    //! HORS key material for each round (round 0 and round 1)
    std::vector<HORSKeyMaterial> rounds;
    
    //! Pinning signature (9 bytes minimal DER with SIGHASH_ALL)
    std::vector<unsigned char> pin_sig;
    
    //! Round signature nonces (9 bytes each, with SIGHASH_ALL)
    std::vector<unsigned char> sig_r1;  //! Round 1 nonce sig
    std::vector<unsigned char> sig_r2;  //! Round 2 nonce sig
    
    //! r values for pinning (for GPU search parameters)
    uint256 pin_r;
    uint256 pin_s;
    uint256 pin_k;  //!< private key for pinning (not used in script, but needed for spending)
    
    //! Round r values (for GPU search parameters)
    uint256 r1_r;
    uint256 r1_s;
    uint256 r1_k;
    uint256 r2_r;
    uint256 r2_s;
    uint256 r2_k;
    
    QSBScriptMaterial() = default;
    
    //! Check if material is complete and valid
    bool IsValid() const {
        if (rounds.size() != 2) return false;
        if (pin_sig.size() != 9) return false;
        if (sig_r1.size() != 9) return false;
        if (sig_r2.size() != 9) return false;
        for (int i = 0; i < 2; ++i) {
            if (rounds[i].commitments.empty()) return false;
            if (rounds[i].preimages.empty()) return false;
            if (rounds[i].dummy_sigs.empty()) return false;
        }
        return true;
    }
};

/**
 * QSB Script Assembler
 *
 * Builds production-ready QSB bare scripts from key material.
 */
class QSBScriptAssembler {
public:
    /**
     * Generate complete script material for the given configuration.
     * This generates:
     *   - HORS key pairs for both rounds (n keys each)
     *   - Dummy signatures (minimal 9-byte DER)
     *   - Pinning and round nonce signatures
     *
     * @param[in] config     QSB configuration (n, t1, t2)
     * @param[in] seed_rng    Optional seed for reproducible generation (testing)
     * @return Complete script material ready for assembly
     */
    static QSBScriptMaterial GenerateMaterial(
        const QSBConfig& config = QSBConfig::ConfigA(),
        bool seed_rng = false);
    
    /**
     * Assemble the full QSB scriptPubKey from script material.
     * This produces the ~9,650-byte bare script ready for use in a transaction output.
     *
     * @param[in] material   Complete script material (both rounds)
     * @param[in] config     QSB configuration
     * @return CScript containing the complete QSB scriptPubKey
     */
    static CScript Assemble(
        const QSBScriptMaterial& material,
        const QSBConfig& config = QSBConfig::ConfigA());

    //! Push data with proper Bitcoin script encoding
    static CScript& PushData(CScript& script, const std::vector<unsigned char>& data);
    
    //! Push a number using OP_0..OP_16 for small values, CScriptNum for larger
    static CScript& PushNumber(CScript& script, int n);

private:
    //! Build the pinning section (5 ops)
    static CScript BuildPinningSection(
        const std::vector<unsigned char>& pin_sig);
    
    //! Build a round section (commitments + dummy_sigs + selections + puzzle + CHECKMULTISIG)
    static void BuildRoundSection(
        CScript& script,
        const HORSKeyMaterial& round_keys,
        const std::vector<unsigned char>& sig_r,
        const std::vector<unsigned char>& next_sig_r,
        int round_idx,
        int t_signed,
        int t_bonus,
        int n);
};

#endif // OMNICORE_QSB_SCRIPT_ASSEMBLER_H