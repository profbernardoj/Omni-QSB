#ifndef BITCOIN_OMNICORE_SCRIPT_H
#define BITCOIN_OMNICORE_SCRIPT_H

#include <string>
#include <vector>

class CScript;

#include <script/standard.h>

/** Determines the minimum output amount to be spent by an output. */
int64_t OmniGetDustThreshold(const CScript& scriptPubKey);

/** Identifies standard output types based on a scriptPubKey. */
bool GetOutputType(const CScript& scriptPubKey, txnouttype& whichTypeRet);

/** Extracts the pushed data as hex-encoded string from a script. */
bool GetScriptPushes(const CScript& script, std::vector<std::string>& vstrRet, bool fSkipFirst = false);

/** Returns public keys or hashes from scriptPubKey, for standard transaction types. */
bool SafeSolver(const CScript& scriptPubKey, txnouttype& typeRet, std::vector<std::vector<unsigned char> >& vSolutionsRet);

/**
 * Checks if a script matches the QSB bare script template.
 *
 * QSB scripts contain:
 * - A hardcoded sig_nonce (ECDSA signature with SIGHASH_ALL)
 * - OP_RIPEMD160 + OP_CHECKSIG puzzle pattern
 * - ~150 HORS hash commitments (20 bytes each)
 * - Total size ~9,650 bytes
 *
 * @param scriptPubKey[in]    The script to check
 * @param commitmentsRet[out] Extracted HORS commitments (20-byte hashes)
 * @return True if the script matches the QSB template
 */
bool SolverQSB(const CScript& scriptPubKey, std::vector<std::vector<unsigned char>>& commitmentsRet);

/** Serializes HORS commitments for address derivation (Hash160). */
std::vector<unsigned char> SerializeHORSCommitments(const std::vector<std::vector<unsigned char>>& commitments);


#endif // BITCOIN_OMNICORE_SCRIPT_H
