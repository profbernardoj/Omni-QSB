// Copyright (c) 2026 The Omni Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <omnicore/qsb/qsb_spend_builder.h>
#include <omnicore/qsb/qsb_script_assembler.h>

#include <hash.h>
#include <key.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/sign.h>
#include <serialize.h>
#include <uint256.h>
#include <util/strencodings.h>

#include <cassert>
#include <vector>

// Bitcoin Core's FindAndDelete and SignatureHash are declared in interpreter.h
// FindAndDelete(CScript& script, const CScript& b) → int
// SignatureHash(scriptCode, tx, nIn, nHashType, amount, sigversion, cache) → uint256

// ---------------------------------------------------------------------------
// Sighash computation with FindAndDelete
// ---------------------------------------------------------------------------

uint256 QSBSpendBuilder::ComputePinningSighash(
    const CTransaction& tx,
    const CScript& full_script,
    const std::vector<unsigned char>& pin_sig,
    unsigned int input_index)
{
    // scriptCode = full_script with FindAndDelete(pin_sig)
    CScript scriptCode(full_script);
    CScript pattern;
    pattern << pin_sig;
    FindAndDelete(scriptCode, pattern);

    // Legacy sighash (SIGHASH_ALL = 0x01), no witness, amount irrelevant
    return SignatureHash(scriptCode, tx, input_index, SIGHASH_ALL,
                         0, SigVersion::BASE, nullptr);
}

uint256 QSBSpendBuilder::ComputeRoundSighash(
    const CTransaction& tx,
    const CScript& full_script,
    const std::vector<unsigned char>& sig_nonce,
    const std::vector<std::vector<unsigned char>>& dummy_sigs,
    const std::vector<int>& selected,
    unsigned int input_index)
{
    // scriptCode = full_script
    //   - FindAndDelete(sig_nonce)
    //   - FindAndDelete(each selected dummy sig)
    CScript scriptCode(full_script);

    // Remove the round's hardcoded signature
    CScript nonce_pattern;
    nonce_pattern << sig_nonce;
    FindAndDelete(scriptCode, nonce_pattern);

    // Remove each selected dummy signature
    for (int idx : selected) {
        assert(idx >= 0 && idx < (int)dummy_sigs.size());
        CScript dummy_pattern;
        dummy_pattern << dummy_sigs[idx];
        FindAndDelete(scriptCode, dummy_pattern);
    }

    return SignatureHash(scriptCode, tx, input_index, SIGHASH_ALL,
                         0, SigVersion::BASE, nullptr);
}

// ---------------------------------------------------------------------------
// Witness / scriptSig construction
// ---------------------------------------------------------------------------

CScript QSBSpendBuilder::BuildScriptSig(
    const QSBSpendSolution& solution,
    const CScript& redeem_script,
    const QSBConfig& config)
{
    // Witness layout (bottom → top of stack, pushed in this order):
    //   Round 2: key_puzzle, key_nonce, dummy_pubs(rev), preimages(rev), indices(rev)
    //   Round 1: key_puzzle, key_nonce, dummy_pubs(rev), preimages(rev), indices(rev)
    //   Pinning: key_puzzle, key_nonce
    //   Redeem script (full QSB script for P2SH)
    //
    // Reference: qsb_pipeline.py cmd_assemble() Step 4

    CScript scriptSig;

    // Helper to push round data
    auto pushRound = [&](const QSBRoundRecovery& rr) {
        scriptSig << rr.key_puzzle;
        scriptSig << rr.key_nonce;

        // Dummy pubkeys in reverse order
        for (auto it = rr.dummy_pubkeys.rbegin(); it != rr.dummy_pubkeys.rend(); ++it) {
            scriptSig << *it;
        }

        // Preimages in reverse order
        for (auto it = rr.preimages.rbegin(); it != rr.preimages.rend(); ++it) {
            scriptSig << *it;
        }

        // Indices in reverse order
        for (auto it = rr.subset.rbegin(); it != rr.subset.rend(); ++it) {
            QSBScriptAssembler::PushNumber(scriptSig, *it);
        }
    };

    // Round 2 first (bottom of stack)
    pushRound(solution.round2);

    // Round 1 next
    pushRound(solution.round1);

    // Pinning data (top of stack)
    scriptSig << solution.pin_key_puzzle;
    scriptSig << solution.pin_key_nonce;

    // P2SH: push the redeem script at the end
    std::vector<unsigned char> redeemBytes(redeem_script.begin(), redeem_script.end());
    scriptSig << redeemBytes;

    return scriptSig;
}

// ---------------------------------------------------------------------------
// Full spending transaction
// ---------------------------------------------------------------------------

CMutableTransaction QSBSpendBuilder::BuildSpendTx(
    const QSBScriptMaterial& material,
    const QSBConfig& config,
    const QSBSpendParams& params,
    const CScript& dest_script,
    const std::vector<unsigned char>& omni_payload,
    CAmount fee)
{
    assert(material.IsValid());
    assert((int)params.round1_indices.size() == config.T1Total());
    assert((int)params.round2_indices.size() == config.T2Total());

    CMutableTransaction tx;
    tx.nVersion = 1;
    tx.nLockTime = params.locktime;

    // ========================================================================
    // Inputs
    // ========================================================================
    // Input 0: Helper input (for SIGHASH_SINGLE bug: QSB input index >= num_outputs)
    // Input 1: QSB input
    CTxIn helper_in;
    helper_in.prevout = COutPoint(uint256(), 0);  // placeholder
    helper_in.nSequence = 0xfffffffe;             // allows nLockTime
    tx.vin.push_back(helper_in);

    CTxIn qsb_in;
    qsb_in.prevout = params.funding_outpoint;
    qsb_in.nSequence = 0xfffffffe;
    tx.vin.push_back(qsb_in);

    const unsigned int QSB_INPUT_INDEX = 1;

    // ========================================================================
    // Outputs
    // ========================================================================
    CAmount dest_value = params.funding_amount - fee;

    // Output 0: OP_RETURN Omni payload (if provided)
    if (!omni_payload.empty()) {
        CTxOut op_return;
        op_return.nValue = 0;
        op_return.scriptPubKey = CScript() << OP_RETURN << omni_payload;
        tx.vout.push_back(op_return);
    }

    // Output 1 (or 0 if no Omni): Destination
    CTxOut dest_out;
    dest_out.nValue = dest_value;
    dest_out.scriptPubKey = dest_script;
    tx.vout.push_back(dest_out);

    // ========================================================================
    // Assemble the QSB script (redeem script)
    // ========================================================================
    CScript full_script = QSBScriptAssembler::Assemble(material, config);

    // ========================================================================
    // Compute sighashes and recover keys
    // ========================================================================
    // NOTE: Real EC recovery requires secp256k1 ECDSA recovery.
    // This implementation prepares the transaction structure and sighash
    // computation. The actual EC recovery would use:
    //   secp256k1_ecdsa_recover(ctx, &pubkey, &sig, msg_hash)
    //
    // For now, we compute the correct sighashes so that:
    //   1. FindAndDelete is applied correctly
    //   2. The transaction structure is valid
    //   3. The scriptSig can be populated with recovered keys
    //
    // The EC recovery step will be wired once we have GPU results.

    CTransaction ctx_tx(tx);

    // Pinning sighash
    uint256 pin_hash = ComputePinningSighash(
        ctx_tx, full_script, material.pin_sig, QSB_INPUT_INDEX);

    // Round 1 sighash
    uint256 r1_hash = ComputeRoundSighash(
        ctx_tx, full_script, material.sig_r1,
        material.rounds[0].dummy_sigs, params.round1_indices,
        QSB_INPUT_INDEX);

    // Round 2 sighash
    uint256 r2_hash = ComputeRoundSighash(
        ctx_tx, full_script, material.sig_r2,
        material.rounds[1].dummy_sigs, params.round2_indices,
        QSB_INPUT_INDEX);

    // ========================================================================
    // Build spending solution (placeholder — real keys come from EC recovery)
    // ========================================================================
    // TODO: Wire up secp256k1 ECDSA recovery to populate these from sighashes.
    // For now, the sighash computation and transaction structure are correct.
    // The scriptSig will be populated when GPU results + EC recovery are available.

    (void)pin_hash;  // Used by EC recovery (not yet wired)
    (void)r1_hash;
    (void)r2_hash;

    return tx;
}
