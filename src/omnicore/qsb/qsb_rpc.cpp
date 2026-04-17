/**
 * @file qsb_rpc.cpp
 *
 * RPC commands for Quantum-Safe Bitcoin (QSB) pool integration.
 */

#include <omnicore/qsb/qsb_wallet.h>
#include <omnicore/qsb/qsb_spend_builder.h>
#include <omnicore/qsb/qsb_pregen_pool.h>

#include <chainparams.h>
#include <core_io.h>
#include <key_io.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <script/standard.h>
#include <uint256.h>
#include <wallet/rpcwallet.h>
#include <wallet/wallet.h>

#include <univalue.h>

#ifdef ENABLE_WALLET

/**
 * Returns the QSB pool status.
 */
static UniValue qsbpoolstatus(const JSONRPCRequest& request)
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();

    RPCHelpMan{"qsbpoolstatus",
        "\nReturns the Quantum-Safe Bitcoin pool status.\n"
        "\nShows how many ready QSB outputs are available in the pre-generation pool.\n",
        {},
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::NUM, "ready", "Number of ready QSB outputs in pool"},
                {RPCResult::Type::NUM, "target", "Target pool size"},
                {RPCResult::Type::BOOL, "running", "Whether the pool worker is running"},
                {RPCResult::Type::OBJ, "config", "Pool configuration",
                {
                    {RPCResult::Type::NUM, "max_size", "Maximum pool size"},
                    {RPCResult::Type::NUM, "min_size", "Minimum pool size before refill"},
                    {RPCResult::Type::NUM, "hors_num_keys", "Number of HORS keys per output"},
                }},
            }
        },
        RPCExamples{
            HelpExampleCli("qsbpoolstatus", "")
            + HelpExampleRpc("qsbpoolstatus", "")
        }
    }.Check(request);

    if (!pwallet) {
        throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not found or not loaded");
    }

    int ready_count = 0;
    int target_count = 0;
    bool is_running = false;

    pwallet->GetQSBPoolStatus(ready_count, target_count, is_running);

    UniValue result(UniValue::VOBJ);
    result.pushKV("ready", ready_count);
    result.pushKV("target", target_count);
    result.pushKV("running", is_running);

    UniValue config(UniValue::VOBJ);
    config.pushKV("max_size", QSBWallet::DEFAULT_MAX_POOL_SIZE);
    config.pushKV("min_size", QSBWallet::DEFAULT_MIN_POOL_SIZE);
    config.pushKV("hors_num_keys", QSBWallet::DEFAULT_HORS_NUM_KEYS);
    result.pushKV("config", config);

    return result;
}

/**
 * Creates a new QSB address from the pool.
 */
static UniValue createqsbaddress(const JSONRPCRequest& request)
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();

    RPCHelpMan{"createqsbaddress",
        "\nCreates a new Quantum-Safe Bitcoin address from the pre-generation pool.\n"
        "\nThe address is derived from HORS commitments and uses the production\n"
        "QSB script assembly (Config A: n=150, t_signed=8 with bonus selections).\n"
        "\nScript size is approximately 9,650 bytes for Config A.\n",
        {
            {"config", RPCArg::Type::STR, RPCArg::Optional::OMITTED_NAMED_ARG, "QSB config name (default: \"Config_A\")", "Config_A"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "address", "The QSB address (Bech32 encoded: qs1... for mainnet, qst1... for testnet, qsrt1... for regtest)"},
                {RPCResult::Type::STR_HEX, "scriptPubKey", "The raw scriptPubKey (hex, ~9650 bytes for Config A)"},
                {RPCResult::Type::STR, "status", "Address creation status (\"ready\" or \"generating\")"},
                {RPCResult::Type::NUM, "pool_ready", "Number of ready outputs remaining in pool"},
                {RPCResult::Type::NUM, "script_size", "Size of assembled script in bytes"},
            }
        },
        RPCExamples{
            HelpExampleCli("createqsbaddress", "")
            + HelpExampleCli("createqsbaddress", "\"Config_A\"")
            + HelpExampleRpc("createqsbaddress", "")
            + HelpExampleRpc("createqsbaddress", "\"Config_A\"")
        }
    }.Check(request);

    if (!pwallet) {
        throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not found or not loaded");
    }

    // Ensure wallet is unlocked for key operations
    EnsureWalletIsUnlocked(pwallet);

    // Check if pool is running
    int ready_count = 0;
    int target_count = 0;
    bool is_running = false;
    pwallet->GetQSBPoolStatus(ready_count, target_count, is_running);

    if (!is_running) {
        throw JSONRPCError(RPC_MISC_ERROR, "QSB pool not initialized. The pool starts automatically when wallet loads. Try again in a few seconds.");
    }

    if (ready_count == 0) {
        throw JSONRPCError(RPC_MISC_ERROR, "QSB pool is empty. The background worker is still generating addresses (usually 1-5 seconds). Try again shortly.");
    }

    // Acquire ready output from pool
    uint160 qsbId;
    CScript scriptPubKey;

    if (!pwallet->CreateQSBAddress(qsbId, scriptPubKey)) {
        throw JSONRPCError(RPC_MISC_ERROR, "Failed to create QSB address. Pool may be exhausted. Try again in a few moments.");
    }

    // Encode the QSB ID as a Bech32 address
    // QSBHash is a CTxDestination subtype that encodes to qs1... / qst1... / qsrt1...
    QSBHash qsbHash(qsbId);
    std::string address = EncodeDestination(qsbHash);

    UniValue result(UniValue::VOBJ);
    result.pushKV("address", address);
    result.pushKV("scriptPubKey", HexStr(scriptPubKey));
    result.pushKV("status", "ready");
    result.pushKV("pool_ready", ready_count - 1);  // One was just consumed
    result.pushKV("script_size", static_cast<int>(scriptPubKey.size()));

    return result;
}

/**
 * Creates a QSB spending transaction.
 *
 * Constructs a spending transaction for a QSB-locked UTXO, using:
 *   - EC recovery (secp256k1 ECDSA key recovery from sighash + known sigs)
 *   - FindAndDelete for correct sighash computation
 *   - Witness stack construction matching Avihu’s Python reference
 *   - Optional Omni OP_RETURN payload
 */
static UniValue createqsbspend(const JSONRPCRequest& request)
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();

    RPCHelpMan{"createqsbspend",
        "\nCreates a spending transaction for a QSB-locked UTXO.\n"
        "\nRequires that the QSB material has been stored for this outpoint\n"
        "(automatically stored when createqsbaddress is used).\n",
        {
            {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The txid of the QSB UTXO"},
            {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "The vout index of the QSB UTXO"},
            {"destination", RPCArg::Type::STR, RPCArg::Optional::NO, "The destination address"},
            {"locktime", RPCArg::Type::NUM, RPCArg::Optional::NO, "nLockTime from GPU pinning search"},
            {"round1_indices", RPCArg::Type::ARR, RPCArg::Optional::NO, "Selected HORS indices for round 1",
                {{"index", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "A HORS index"}}},
            {"round2_indices", RPCArg::Type::ARR, RPCArg::Optional::NO, "Selected HORS indices for round 2",
                {{"index", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "A HORS index"}}},
            {"omni_payload", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED_NAMED_ARG, "Optional Omni OP_RETURN payload (hex)"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "txid", "The transaction id"},
                {RPCResult::Type::STR_HEX, "rawtx", "The raw transaction hex"},
                {RPCResult::Type::NUM, "size", "Transaction size in bytes"},
                {RPCResult::Type::STR, "status", "success"},
            }
        },
        RPCExamples{
            HelpExampleCli("createqsbspend",
                "\"abc123...\" 0 \"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\" 700000 "
                "\"[0,1,2,3,4,5,6,7,8]\" \"[0,1,2,3,4,5,6,7]\"")
        }
    }.Check(request);

    if (!pwallet) {
        throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not found");
    }

    EnsureWalletIsUnlocked(pwallet);

    // Parse outpoint
    uint256 txid = ParseHashV(request.params[0], "txid");
    int vout = request.params[1].get_int();
    COutPoint outpoint(txid, vout);

    // Parse destination address to script
    CTxDestination dest = DecodeDestination(request.params[2].get_str());
    if (!IsValidDestination(dest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid destination address");
    }
    CScript destScript = GetScriptForDestination(dest);

    // Parse locktime
    uint32_t locktime = static_cast<uint32_t>(request.params[3].get_int64());

    // Parse round indices
    std::vector<int> r1_indices, r2_indices;
    const UniValue& r1_arr = request.params[4].get_array();
    for (unsigned int i = 0; i < r1_arr.size(); i++) {
        r1_indices.push_back(r1_arr[i].get_int());
    }
    const UniValue& r2_arr = request.params[5].get_array();
    for (unsigned int i = 0; i < r2_arr.size(); i++) {
        r2_indices.push_back(r2_arr[i].get_int());
    }

    // Parse optional Omni payload
    std::vector<unsigned char> omniPayload;
    if (!request.params[6].isNull()) {
        omniPayload = ParseHexV(request.params[6], "omni_payload");
    }

    // Build the spend transaction
    CMutableTransaction tx;
    std::string error;

    if (!pwallet->CreateQSBSpendTx(outpoint, destScript, omniPayload,
                                    locktime, r1_indices, r2_indices, tx, error)) {
        throw JSONRPCError(RPC_MISC_ERROR, error);
    }

    CTransaction finalTx(tx);

    UniValue result(UniValue::VOBJ);
    result.pushKV("txid", finalTx.GetHash().ToString());
    result.pushKV("rawtx", EncodeHexTx(finalTx));
    result.pushKV("size", (int)::GetSerializeSize(finalTx, PROTOCOL_VERSION));
    result.pushKV("status", "success");
    return result;
}

// Register QSB RPC commands
static const CRPCCommand commands[] =
{ //  category              name                actor               argNames
  //  -------------------  ------------------  ------------------  ----------
    { "qsb",               "qsbpoolstatus",    &qsbpoolstatus,     {} },
    { "qsb",               "createqsbaddress", &createqsbaddress,  {"config"} },
    { "qsb",               "createqsbspend",   &createqsbspend,    {"txid", "vout", "destination", "locktime", "round1_indices", "round2_indices", "omni_payload"} },
};

void RegisterQSBRPCCommands(CRPCTable &tableRPC)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableRPC.appendCommand(commands[vcidx].name, &commands[vcidx]);
}

#endif // ENABLE_WALLET
