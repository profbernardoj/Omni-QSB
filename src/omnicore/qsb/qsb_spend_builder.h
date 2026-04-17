// Copyright (c) 2026 The Omni Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef OMNICORE_QSB_SPEND_BUILDER_H
#define OMNICORE_QSB_SPEND_BUILDER_H

#include <omnicore/qsb/qsb_script_assembler.h>
#include <omnicore/qsb/qsb_local_verifier.h>

#include <primitives/transaction.h>
#include <pubkey.h>
#include <script/script.h>
#include <uint256.h>

#include <cstdint>
#include <string>
#include <vector>

/**
 * QSB Spend Builder — Segment 7 (Spending Transaction Construction)
 *
 * Builds the spending transaction for a QSB-locked UTXO.
 * Ports the witness construction from Avihu Levy's qsb_pipeline.py (Phase 4).
 *
 * The QSB design requires the QSB input to be at index >= num_outputs so that
 * SIGHASH_SINGLE triggers the z=1 bug for dummy signature verification.
 * Standard layout: helper input at index 0, QSB input at index 1, 1 output.
 *
 * Spending flow:
 *   1. Load stored QSBScriptMaterial for the UTXO
 *   2. Import GPU search results (locktime, round1 indices, round2 indices)
 *   3. Compute sighash with FindAndDelete (remove selected dummy sigs)
 *   4. Recover EC pubkeys from sighash via ECDSA recovery
 *   5. Build witness stack (scriptSig for P2SH)
 *   6. Attach OP_RETURN Omni payload + optional change output
 *
 * References:
 *   - github.com/avihu28/Quantum-Safe-Bitcoin-Transactions
 *   - pipeline/qsb_pipeline.py (cmd_assemble, Phase 4)
 */

//! GPU search results for spending a QSB UTXO
struct QSBSpendParams {
    uint32_t locktime;                          //!< Found by GPU pinning search
    std::vector<int> round1_indices;            //!< HORS indices for round 1 (t1 values)
    std::vector<int> round2_indices;            //!< HORS indices for round 2 (t2 values)
    COutPoint funding_outpoint;                 //!< The QSB UTXO to spend
    CAmount funding_amount;                     //!< Value of the QSB UTXO in satoshis
};

//! Recovered EC material for one round (from sighash + ECDSA recovery)
struct QSBRoundRecovery {
    std::vector<unsigned char> key_nonce;       //!< Compressed pubkey recovered from sig_nonce
    std::vector<unsigned char> key_puzzle;      //!< Compressed pubkey recovered from sig_puzzle
    std::vector<unsigned char> sig_puzzle;      //!< RIPEMD160(key_nonce) — used as signature
    std::vector<std::vector<unsigned char>> dummy_pubkeys;  //!< Recovered from dummy sigs (z=1)
    std::vector<std::vector<unsigned char>> preimages;      //!< HORS preimages for signed indices
    std::vector<int> subset;                    //!< All selected indices
    std::vector<int> signed_indices;            //!< Indices with HORS verification
    std::vector<int> bonus_indices;             //!< Bonus indices (no HORS check)
};

//! Complete spending solution
struct QSBSpendSolution {
    uint32_t locktime;
    std::vector<unsigned char> pin_key_nonce;   //!< Pinning key_nonce
    std::vector<unsigned char> pin_key_puzzle;  //!< Pinning key_puzzle
    std::vector<unsigned char> pin_sig_puzzle;  //!< RIPEMD160(pin_key_nonce)
    QSBRoundRecovery round1;
    QSBRoundRecovery round2;
};

/**
 * QSB Spend Builder
 *
 * Constructs spending transactions for QSB-locked UTXOs.
 */
class QSBSpendBuilder {
public:
    /**
     * Build a complete spending transaction.
     *
     * @param[in] material        The QSBScriptMaterial used to create the UTXO
     * @param[in] config          The QSBConfig used to create the UTXO
     * @param[in] params          GPU search results + funding info
     * @param[in] dest_script     Destination scriptPubKey (P2PKH, P2WPKH, etc.)
     * @param[in] omni_payload    Optional Omni OP_RETURN payload (empty = no Omni output)
     * @param[in] fee             Transaction fee in satoshis
     * @return The complete signed spending transaction
     */
    static CMutableTransaction BuildSpendTx(
        const QSBScriptMaterial& material,
        const QSBConfig& config,
        const QSBSpendParams& params,
        const CScript& dest_script,
        const std::vector<unsigned char>& omni_payload = {},
        CAmount fee = 5000);

    /**
     * Build the scriptSig (witness stack) for a QSB input.
     *
     * Stack layout (bottom → top):
     *   Round 2: key_puzzle, key_nonce, dummy_pubs(rev), preimages(rev), indices(rev)
     *   Round 1: key_puzzle, key_nonce, dummy_pubs(rev), preimages(rev), indices(rev)
     *   Pinning: key_puzzle, key_nonce
     *   Redeem script (full QSB script)
     *
     * @param[in] solution        Complete spending solution with all recovered keys
     * @param[in] redeem_script   The full QSB scriptPubKey (redeem script for P2SH)
     * @param[in] config          QSB configuration
     * @return Serialized scriptSig bytes
     */
    static CScript BuildScriptSig(
        const QSBSpendSolution& solution,
        const CScript& redeem_script,
        const QSBConfig& config);

    /**
     * Compute the sighash for the pinning signature.
     * Applies FindAndDelete to remove pin_sig from the scriptCode.
     *
     * @param[in] tx              The spending transaction
     * @param[in] full_script     The full QSB script
     * @param[in] pin_sig         The pinning signature to FindAndDelete
     * @param[in] input_index     Index of the QSB input
     * @return The sighash value
     */
    static uint256 ComputePinningSighash(
        const CTransaction& tx,
        const CScript& full_script,
        const std::vector<unsigned char>& pin_sig,
        unsigned int input_index);

    /**
     * Compute the sighash for a round signature.
     * Applies FindAndDelete to remove sig_nonce + selected dummy sigs.
     *
     * @param[in] tx              The spending transaction
     * @param[in] full_script     The full QSB script
     * @param[in] sig_nonce       The round's hardcoded signature
     * @param[in] dummy_sigs      All dummy sigs for this round
     * @param[in] selected        Indices of dummy sigs to FindAndDelete
     * @param[in] input_index     Index of the QSB input
     * @return The sighash value
     */
    static uint256 ComputeRoundSighash(
        const CTransaction& tx,
        const CScript& full_script,
        const std::vector<unsigned char>& sig_nonce,
        const std::vector<std::vector<unsigned char>>& dummy_sigs,
        const std::vector<int>& selected,
        unsigned int input_index);

    // ------------------------------------------------------------------
    // EC Recovery (ECDSA pubkey recovery from sighash + known signatures)
    // ------------------------------------------------------------------

    /**
     * Low-level ECDSA recovery: given a sighash, DER signature, and recovery ID,
     * recover the compressed public key.
     */
    static bool RecoverPubkey(
        const uint256& sighash,
        const std::vector<unsigned char>& der_sig,
        int recid,
        CPubKey& out_pubkey);

    /**
     * QSB-specific recovery: try both recovery IDs and return the one whose
     * Hash160(recovered_pubkey) looks like valid DER (the QSB criterion).
     *
     * @param[in]  sighash         The computed sighash
     * @param[in]  der_sig         The known DER signature
     * @param[out] out_key_nonce   The recovered compressed pubkey (key_nonce)
     * @param[out] out_sig_puzzle  RIPEMD160(SHA256(key_nonce)) — used as sig_puzzle
     * @return true if a valid recovery was found
     */
    static bool RecoverQSBPubkey(
        const uint256& sighash,
        const std::vector<unsigned char>& der_sig,
        CPubKey& out_key_nonce,
        std::vector<unsigned char>& out_sig_puzzle);

    /**
     * Check if a 20-byte sig_puzzle value looks like valid DER.
     * In real GPU search, this is always true DER. Easy mode also accepts
     * (byte[0] >> 4) == 3 as a relaxed criterion.
     */
    static bool IsValidDERSigPuzzle(const std::vector<unsigned char>& sig_puzzle);

    /**
     * Recover a dummy pubkey using SIGHASH_SINGLE bug (z=1).
     * Used when QSB input index >= num_outputs.
     */
    static bool RecoverDummyPubkey(
        const std::vector<unsigned char>& der_sig,
        CPubKey& out_pubkey);
};

#endif // OMNICORE_QSB_SPEND_BUILDER_H
