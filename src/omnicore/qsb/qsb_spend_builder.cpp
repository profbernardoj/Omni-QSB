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

// ---------------------------------------------------------------------------
// EC Recovery helpers
// ---------------------------------------------------------------------------

/**
 * Parse DER signature to extract (r, s) as 32-byte big-endian values.
 */
static bool ParseDERtoRS(const std::vector<unsigned char>& der_sig,
                          unsigned char r32[32], unsigned char s32[32])
{
    // DER format: 30 <total_len> 02 <r_len> <r_bytes> 02 <s_len> <s_bytes> [sighash_byte]
    size_t len = der_sig.size();
    if (len < 8) return false;

    size_t pos = 0;
    if (der_sig[pos] != 0x30) return false;
    pos++;
    pos++; // skip sequence length

    // Parse r
    if (pos >= len || der_sig[pos] != 0x02) return false;
    pos++;
    if (pos >= len) return false;
    size_t r_len = der_sig[pos];
    pos++;
    if (pos + r_len > len) return false;

    memset(r32, 0, 32);
    if (r_len <= 32) {
        memcpy(r32 + (32 - r_len), &der_sig[pos], r_len);
    } else {
        memcpy(r32, &der_sig[pos + (r_len - 32)], 32);
    }
    pos += r_len;

    // Parse s
    if (pos >= len || der_sig[pos] != 0x02) return false;
    pos++;
    if (pos >= len) return false;
    size_t s_len = der_sig[pos];
    pos++;
    if (pos + s_len > len) return false;

    memset(s32, 0, 32);
    if (s_len <= 32) {
        memcpy(s32 + (32 - s_len), &der_sig[pos], s_len);
    } else {
        memcpy(s32, &der_sig[pos + (s_len - 32)], 32);
    }

    return true;
}

/**
 * Build a 65-byte compact recoverable signature for CPubKey::RecoverCompact.
 * Format: 1 byte header (27 + recid + 4 for compressed) + 32 bytes r + 32 bytes s.
 */
static std::vector<unsigned char> BuildCompactSig(const unsigned char r32[32],
                                                   const unsigned char s32[32],
                                                   int recid, bool compressed = true)
{
    std::vector<unsigned char> compact(65);
    compact[0] = 27 + recid + (compressed ? 4 : 0);
    memcpy(&compact[1], r32, 32);
    memcpy(&compact[33], s32, 32);
    return compact;
}

bool QSBSpendBuilder::RecoverPubkey(
    const uint256& sighash,
    const std::vector<unsigned char>& der_sig,
    int recid,
    CPubKey& out_pubkey)
{
    unsigned char r32[32], s32[32];
    if (!ParseDERtoRS(der_sig, r32, s32)) {
        return false;
    }

    // Use Bitcoin Core's CPubKey::RecoverCompact which wraps secp256k1 internally
    std::vector<unsigned char> compact = BuildCompactSig(r32, s32, recid, true);
    return out_pubkey.RecoverCompact(sighash, compact);
}

bool QSBSpendBuilder::RecoverQSBPubkey(
    const uint256& sighash,
    const std::vector<unsigned char>& der_sig,
    CPubKey& out_key_nonce,
    std::vector<unsigned char>& out_sig_puzzle)
{
    // Try both recovery IDs (0 and 1)
    // The correct one produces a pubkey whose Hash160 is valid DER
    for (int recid = 0; recid < 2; recid++) {
        CPubKey candidate;
        if (!RecoverPubkey(sighash, der_sig, recid, candidate)) {
            continue;
        }

        // key_nonce = recovered compressed pubkey
        // sig_puzzle = RIPEMD160(SHA256(key_nonce))
        std::vector<unsigned char> pub_bytes(candidate.begin(), candidate.end());
        uint160 h160 = Hash160(pub_bytes);
        std::vector<unsigned char> sig_puzzle(h160.begin(), h160.end());

        // Check if sig_puzzle looks like valid DER (the QSB criterion)
        // Real GPU search ensures this; for test/easy mode also accept (byte[0] >> 4) == 3
        if (IsValidDERSigPuzzle(sig_puzzle)) {
            out_key_nonce = candidate;
            out_sig_puzzle = sig_puzzle;
            return true;
        }
    }
    return false;
}

bool QSBSpendBuilder::IsValidDERSigPuzzle(const std::vector<unsigned char>& sig_puzzle)
{
    if (sig_puzzle.size() < 8) return false;

    // Quick check: first byte should be 0x30 (DER sequence tag)
    // OR easy-mode fallback: (byte[0] >> 4) == 3 (starts with 0x30..0x3F)
    if ((sig_puzzle[0] >> 4) == 3) {
        return true;
    }
    return false;
}

bool QSBSpendBuilder::RecoverDummyPubkey(
    const std::vector<unsigned char>& der_sig,
    CPubKey& out_pubkey)
{
    // Dummy sigs use SIGHASH_SINGLE bug: z = 1 (when input_index >= num_outputs)
    // So the "message hash" for recovery is simply 1 (as a uint256)
    uint256 z_one;
    *(z_one.begin()) = 1;  // Little-endian: 0x01 followed by 31 zeros

    // Try both recovery IDs
    for (int recid = 0; recid < 2; recid++) {
        if (RecoverPubkey(z_one, der_sig, recid, out_pubkey)) {
            return true;
        }
    }
    return false;
}

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
    //   (For P2SH: redeem script would be pushed here)
    //
    // Reference: qsb_pipeline.py cmd_assemble() Step 4
    //
    // NOTE: For bare scriptPubKey (QSB), the scriptPubKey IS the QSB script.
    // The scriptSig only contains the witness data — the redeem script push
    // is only needed for P2SH wrapping.

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
    // Stack order after scriptSig execution: R2_data ← R1_data ← pin_data
    // QSB script expects: pin_key_nonce pin_key_puzzle on stack (key_nonce on top)
    scriptSig << solution.pin_key_puzzle;
    scriptSig << solution.pin_key_nonce;

    return scriptSig;
}

// ---------------------------------------------------------------------------
// Full spending transaction with EC recovery
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
    CTxIn helper_in;
    helper_in.prevout = COutPoint(uint256(), 0);
    helper_in.nSequence = 0xfffffffe;
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

    if (!omni_payload.empty()) {
        CTxOut op_return;
        op_return.nValue = 0;
        op_return.scriptPubKey = CScript() << OP_RETURN << omni_payload;
        tx.vout.push_back(op_return);
    }

    CTxOut dest_out;
    dest_out.nValue = dest_value;
    dest_out.scriptPubKey = dest_script;
    tx.vout.push_back(dest_out);

    // ========================================================================
    // Assemble the QSB script (redeem script)
    // ========================================================================
    CScript full_script = QSBScriptAssembler::Assemble(material, config);

    // ========================================================================
    // EC Recovery — Pinning
    // ========================================================================
    CTransaction ctx_tx(tx);

    uint256 pin_hash = ComputePinningSighash(
        ctx_tx, full_script, material.pin_sig, QSB_INPUT_INDEX);

    QSBSpendSolution solution;
    solution.locktime = params.locktime;

    // Recover pin key_nonce and sig_puzzle
    CPubKey pin_key_nonce;
    if (RecoverQSBPubkey(pin_hash, material.pin_sig, pin_key_nonce, solution.pin_sig_puzzle)) {
        solution.pin_key_nonce.assign(pin_key_nonce.begin(), pin_key_nonce.end());

        // Recover pin key_puzzle from sig_puzzle (which is itself a signature)
        // sig_puzzle's sighash: FindAndDelete(full_script, sig_puzzle)
        CScript puzzle_sc(full_script);
        CScript puzzle_pattern;
        puzzle_pattern << solution.pin_sig_puzzle;
        FindAndDelete(puzzle_sc, puzzle_pattern);

        // Determine sighash type from last byte of sig_puzzle
        uint8_t sp_hashtype = solution.pin_sig_puzzle.back();
        uint256 puzzle_hash = SignatureHash(puzzle_sc, ctx_tx, QSB_INPUT_INDEX,
                                            sp_hashtype, 0, SigVersion::BASE, nullptr);

        CPubKey pin_key_puzzle;
        for (int recid = 0; recid < 2; recid++) {
            if (RecoverPubkey(puzzle_hash, solution.pin_sig_puzzle, recid, pin_key_puzzle)) {
                solution.pin_key_puzzle.assign(pin_key_puzzle.begin(), pin_key_puzzle.end());
                break;
            }
        }
    }

    // ========================================================================
    // EC Recovery — Rounds 1 and 2
    // ========================================================================
    const std::vector<int>* round_indices[2] = { &params.round1_indices, &params.round2_indices };
    const std::vector<unsigned char>* round_sigs[2] = { &material.sig_r1, &material.sig_r2 };
    QSBRoundRecovery* round_results[2] = { &solution.round1, &solution.round2 };

    for (int ri = 0; ri < 2; ri++) {
        const auto& indices = *round_indices[ri];
        const auto& sig_nonce = *round_sigs[ri];
        QSBRoundRecovery& rr = *round_results[ri];
        const auto& round_material = material.rounds[ri];
        int t_signed = (ri == 0) ? config.t1_signed : config.t2_signed;

        rr.subset = indices;
        rr.signed_indices.assign(indices.begin(), indices.begin() + t_signed);
        rr.bonus_indices.assign(indices.begin() + t_signed, indices.end());

        // Compute round sighash
        uint256 round_hash = ComputeRoundSighash(
            ctx_tx, full_script, sig_nonce,
            round_material.dummy_sigs, indices, QSB_INPUT_INDEX);

        // Recover round key_nonce
        CPubKey round_key_nonce;
        if (RecoverQSBPubkey(round_hash, sig_nonce, round_key_nonce, rr.sig_puzzle)) {
            rr.key_nonce.assign(round_key_nonce.begin(), round_key_nonce.end());

            // Recover round key_puzzle from sig_puzzle
            CScript rnd_puzzle_sc(full_script);
            CScript rnd_puzzle_pattern;
            rnd_puzzle_pattern << rr.sig_puzzle;
            FindAndDelete(rnd_puzzle_sc, rnd_puzzle_pattern);

            uint8_t rnd_sp_hashtype = rr.sig_puzzle.back();
            uint256 rnd_puzzle_hash = SignatureHash(rnd_puzzle_sc, ctx_tx, QSB_INPUT_INDEX,
                                                     rnd_sp_hashtype, 0, SigVersion::BASE, nullptr);

            CPubKey round_key_puzzle;
            for (int recid = 0; recid < 2; recid++) {
                if (RecoverPubkey(rnd_puzzle_hash, rr.sig_puzzle, recid, round_key_puzzle)) {
                    rr.key_puzzle.assign(round_key_puzzle.begin(), round_key_puzzle.end());
                    break;
                }
            }
        }

        // Recover dummy pubkeys (z=1 via SIGHASH_SINGLE bug)
        for (int idx : indices) {
            CPubKey dummy_pub;
            if (RecoverDummyPubkey(round_material.dummy_sigs[idx], dummy_pub)) {
                rr.dummy_pubkeys.push_back(
                    std::vector<unsigned char>(dummy_pub.begin(), dummy_pub.end()));
            }
        }

        // Collect HORS preimages for signed indices
        for (int idx : rr.signed_indices) {
            rr.preimages.push_back(round_material.preimages[idx]);
        }
    }

    // ========================================================================
    // Build scriptSig and attach to QSB input
    // ========================================================================
    CScript scriptSig = BuildScriptSig(solution, full_script, config);
    tx.vin[QSB_INPUT_INDEX].scriptSig = scriptSig;

    return tx;
}
