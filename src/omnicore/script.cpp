#include <omnicore/script.h>

#include <amount.h>
#include <hash.h>
#include <policy/feerate.h>
#include <policy/policy.h>
#include <script/script.h>
#include <script/standard.h>
#include <serialize.h>
#include <util/strencodings.h>

#include <string>
#include <utility>
#include <vector>

/** The minimum transaction relay fee. */
extern CFeeRate minRelayTxFee;

/**
 * Determines the minimum output amount to be spent by an output, based on the
 * scriptPubKey size in relation to the minimum relay fee.
 *
 * @param scriptPubKey[in]  The scriptPubKey
 * @return The dust threshold value
 */
int64_t OmniGetDustThreshold(const CScript& scriptPubKey)
{
    CTxOut txOut(0, scriptPubKey);

    return GetDustThreshold(txOut, minRelayTxFee) * 3;
}

/**
 * Identifies standard output types based on a scriptPubKey.
 *
 * Note: whichTypeRet is set to TX_NONSTANDARD, if no standard script was found.
 *
 * @param scriptPubKey[in]   The script
 * @param whichTypeRet[out]  The output type
 * @return True if a standard script was found
 */
bool GetOutputType(const CScript& scriptPubKey, txnouttype& whichTypeRet)
{
    std::vector<std::vector<unsigned char> > vSolutions;

    if (SafeSolver(scriptPubKey, whichTypeRet, vSolutions)) {
        return true;
    }
    whichTypeRet = TX_NONSTANDARD;

    return false;
}

/**
 * Extracts the pushed data as hex-encoded string from a script.
 *
 * @param script[in]      The script
 * @param vstrRet[out]    The extracted pushed data as hex-encoded string
 * @param fSkipFirst[in]  Whether the first push operation should be skipped (default: false)
 * @return True if the extraction was successful (result can be empty)
 */
bool GetScriptPushes(const CScript& script, std::vector<std::string>& vstrRet, bool fSkipFirst)
{
    int count = 0;
    CScript::const_iterator pc = script.begin();

    while (pc < script.end()) {
        opcodetype opcode;
        std::vector<unsigned char> data;
        if (!script.GetOp(pc, opcode, data))
            return false;
        if (0x00 <= opcode && opcode <= OP_PUSHDATA4)
            if (count++ || !fSkipFirst) vstrRet.push_back(HexStr(data));
    }

    return true;
}

/**
 * Returns public keys or hashes from scriptPubKey, for standard transaction types.
 *
 * Note: in contrast to the script/standard/Solver, this Solver is not affected by
 * user settings, and in particular any OP_RETURN size is considered as standard.
 *
 * @param scriptPubKey[in]    The script
 * @param typeRet[out]        The output type
 * @param vSolutionsRet[out]  The extracted public keys or hashes
 * @return True if a standard script was found
 */
bool SafeSolver(const CScript& scriptPubKey, txnouttype& typeRet, std::vector<std::vector<unsigned char> >& vSolutionsRet)
{
    // Templates
    static std::multimap<txnouttype, CScript> mTemplates;
    if (mTemplates.empty())
    {
        // Standard tx, sender provides pubkey, receiver adds signature
        mTemplates.insert(std::make_pair(TX_PUBKEY, CScript() << OP_PUBKEY << OP_CHECKSIG));

        // Bitcoin address tx, sender provides hash of pubkey, receiver provides signature and pubkey
        mTemplates.insert(std::make_pair(TX_PUBKEYHASH, CScript() << OP_DUP << OP_HASH160 << OP_PUBKEYHASH << OP_EQUALVERIFY << OP_CHECKSIG));

        // Sender provides N pubkeys, receivers provides M signatures
        mTemplates.insert(std::make_pair(TX_MULTISIG, CScript() << OP_SMALLINTEGER << OP_PUBKEYS << OP_SMALLINTEGER << OP_CHECKMULTISIG));

        // Empty, provably prunable, data-carrying output
        mTemplates.insert(std::make_pair(TX_NULL_DATA, CScript() << OP_RETURN));
    }

    vSolutionsRet.clear();

    // Shortcut for pay-to-script-hash, which are more constrained than the other types:
    // it is always OP_HASH160 20 [20 byte hash] OP_EQUAL
    if (scriptPubKey.IsPayToScriptHash())
    {
        typeRet = TX_SCRIPTHASH;
        std::vector<unsigned char> hashBytes(scriptPubKey.begin()+2, scriptPubKey.begin()+22);
        vSolutionsRet.push_back(hashBytes);
        return true;
    }

    int witnessversion;
    std::vector<unsigned char> witnessprogram;
    if (scriptPubKey.IsWitnessProgram(witnessversion, witnessprogram)) {
        if (witnessversion == 0 && witnessprogram.size() == 20) {
            typeRet = TX_WITNESS_V0_KEYHASH;
            vSolutionsRet.push_back(witnessprogram);
            return true;
        }
        if (witnessversion == 0 && witnessprogram.size() == 32) {
            typeRet = TX_WITNESS_V0_SCRIPTHASH;
            vSolutionsRet.push_back(witnessprogram);
            return true;
        }
        return false;
    }

    // Provably prunable, data-carrying output
    //
    // So long as script passes the IsUnspendable() test and all but the first
    // byte passes the IsPushOnly() test we don't care what exactly is in the
    // script.
    if (scriptPubKey.size() >= 2 && scriptPubKey[0] == OP_RETURN)
    {
        CScript script(scriptPubKey.begin()+1, scriptPubKey.end());
        if (script.IsPushOnly()) {
            typeRet = TX_NULL_DATA;
            return true;
        }
    }

    // Scan templates
    const CScript& script1 = scriptPubKey;
    for(const auto& tplate : mTemplates)
    {
        const CScript& script2 = tplate.second;
        vSolutionsRet.clear();

        opcodetype opcode1, opcode2;
        std::vector<unsigned char> vch1, vch2;

        // Compare
        CScript::const_iterator pc1 = script1.begin();
        CScript::const_iterator pc2 = script2.begin();
        while (true)
        {
            if (pc1 == script1.end() && pc2 == script2.end())
            {
                // Found a match
                typeRet = tplate.first;
                if (typeRet == TX_MULTISIG)
                {
                    // Additional checks for TX_MULTISIG:
                    unsigned char m = vSolutionsRet.front()[0];
                    unsigned char n = vSolutionsRet.back()[0];
                    if (m < 1 || n < 1 || m > n || vSolutionsRet.size()-2 != n)
                        return false;
                }
                return true;
            }
            if (!script1.GetOp(pc1, opcode1, vch1))
                break;
            if (!script2.GetOp(pc2, opcode2, vch2))
                break;

            // Template matching opcodes:
            if (opcode2 == OP_PUBKEYS)
            {
                while (vch1.size() >= 33 && vch1.size() <= 65)
                {
                    vSolutionsRet.push_back(vch1);
                    if (!script1.GetOp(pc1, opcode1, vch1))
                        break;
                }
                if (!script2.GetOp(pc2, opcode2, vch2))
                    break;
                // Normal situation is to fall through
                // to other if/else statements
            }

            if (opcode2 == OP_PUBKEY)
            {
                if (vch1.size() < 33 || vch1.size() > 65)
                    break;
                vSolutionsRet.push_back(vch1);
            }
            else if (opcode2 == OP_PUBKEYHASH)
            {
                if (vch1.size() != sizeof(uint160))
                    break;
                vSolutionsRet.push_back(vch1);
            }
            else if (opcode2 == OP_SMALLINTEGER)
            {   // Single-byte small integer pushed onto vSolutions
                if (opcode1 == OP_0 ||
                    (opcode1 >= OP_1 && opcode1 <= OP_16))
                {
                    char n = (char)CScript::DecodeOP_N(opcode1);
                    vSolutionsRet.push_back(std::vector<unsigned char>(1, n));
                }
                else
                    break;
            }
            else if (opcode1 != opcode2 || vch1 != vch2)
            {
                // Others must match exactly
                break;
            }
        }
    }

    // QSB bare script detection: check for the distinctive pinning pattern
    // QSB scripts are large (>5000 bytes) and contain OP_RIPEMD160 + OP_CHECKSIGVERIFY puzzle
    if (scriptPubKey.size() >= 5000 && scriptPubKey.size() <= 10000) {
        std::vector<std::vector<unsigned char>> qsbCommitments;
        if (SolverQSB(scriptPubKey, qsbCommitments)) {
            typeRet = TX_QSB_BARE;
            // Return the Hash160 of serialized commitments as the "solution"
            std::vector<unsigned char> serialized = SerializeHORSCommitments(qsbCommitments);
            uint160 qsbId;
            CHash160().Write(serialized.data(), serialized.size()).Finalize(qsbId.begin());
            vSolutionsRet.push_back(std::vector<unsigned char>(qsbId.begin(), qsbId.end()));
            return true;
        }
    }

    vSolutionsRet.clear();
    typeRet = TX_NONSTANDARD;
    return false;
}

/**
 * Checks if a script matches the QSB bare script template.
 *
 * Detection strategy:
 * 1. Size check: QSB scripts are 5,000-10,000 bytes (Config A baseline ~9,650)
 * 2. Structural markers: the pinning section uses a distinctive opcode sequence:
 *    <sig_nonce> OP_OVER OP_CHECKSIGVERIFY OP_RIPEMD160 OP_SWAP OP_CHECKSIGVERIFY
 * 3. HORS commitments: 20-byte hash pushes following the dummy signatures section
 *
 * The template is designed to match Avihu Levy's Config A QSB script structure.
 * It will be tightened once the final template is confirmed end-to-end.
 */
bool SolverQSB(const CScript& scriptPubKey, std::vector<std::vector<unsigned char>>& commitmentsRet)
{
    commitmentsRet.clear();

    // Size gate: QSB scripts are large bare scripts
    if (scriptPubKey.size() < 5000 || scriptPubKey.size() > 10000) {
        return false;
    }

    // Scan for the pinning section's distinctive opcode sequence:
    // OP_OVER(0x78) OP_CHECKSIGVERIFY(0xad) OP_RIPEMD160(0xa6) OP_SWAP(0x7c) OP_CHECKSIGVERIFY(0xad)
    //
    // This 5-byte sequence is the fingerprint of QSB's hash-to-signature puzzle.
    // It appears near the beginning of the script (after the sig_nonce push).
    static const unsigned char PIN_PATTERN[] = {
        0x78, // OP_OVER
        0xad, // OP_CHECKSIGVERIFY
        0xa6, // OP_RIPEMD160
        0x7c, // OP_SWAP
        0xad  // OP_CHECKSIGVERIFY
    };
    const size_t PIN_PATTERN_LEN = sizeof(PIN_PATTERN);

    bool foundPinning = false;
    size_t pinEnd = 0;

    // Search within the first 200 bytes (pinning section is near the start)
    size_t searchLimit = std::min(scriptPubKey.size(), (size_t)200);
    for (size_t i = 0; i + PIN_PATTERN_LEN <= searchLimit; ++i) {
        if (memcmp(&scriptPubKey[i], PIN_PATTERN, PIN_PATTERN_LEN) == 0) {
            foundPinning = true;
            pinEnd = i + PIN_PATTERN_LEN;
            break;
        }
    }

    if (!foundPinning) {
        return false;
    }

    // After the pinning section, the script contains two digest rounds.
    // Each round starts with n HORS commitments (20-byte hash pushes)
    // followed by n dummy signatures (9-byte pushes).
    //
    // We extract the HORS commitments: sequences of exactly 20-byte pushes.
    // The pattern is: <push 20 bytes> repeated n times per round, 2 rounds.
    //
    // Walk the script from after the pinning section and collect 20-byte pushes.
    CScript::const_iterator pc = scriptPubKey.begin() + pinEnd;
    int commitmentCount = 0;
    const int MIN_COMMITMENTS = 20;  // minimum to recognize as QSB
    const int MAX_COMMITMENTS = 400; // 2 rounds × 150 max + margin

    while (pc < scriptPubKey.end() && commitmentCount < MAX_COMMITMENTS) {
        opcodetype opcode;
        std::vector<unsigned char> data;
        if (!scriptPubKey.GetOp(pc, opcode, data)) {
            break;
        }

        // HORS commitments are exactly 20 bytes pushed with a direct push opcode
        if (data.size() == 20 && opcode == 0x14) { // 0x14 = push exactly 20 bytes
            commitmentsRet.push_back(data);
            ++commitmentCount;
        }
    }

    // Require a minimum number of commitments to confirm QSB structure
    if (commitmentCount < MIN_COMMITMENTS) {
        commitmentsRet.clear();
        return false;
    }

    return true;
}

/**
 * Serializes HORS commitments into a contiguous byte vector for Hash160.
 *
 * The commitments are concatenated in order. This produces a deterministic
 * identifier for the QSB address: Hash160(serialize) = QSB address payload.
 */
std::vector<unsigned char> SerializeHORSCommitments(const std::vector<std::vector<unsigned char>>& commitments)
{
    std::vector<unsigned char> result;
    for (const auto& c : commitments) {
        result.insert(result.end(), c.begin(), c.end());
    }
    return result;
}
