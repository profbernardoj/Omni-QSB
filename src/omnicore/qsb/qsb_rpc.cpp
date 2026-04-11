/**
 * @file qsb_rpc.cpp
 *
 * RPC commands for Quantum-Safe Bitcoin (QSB) pool integration.
 */

#include <omnicore/qsb/qsb_wallet.h>
#include <omnicore/qsb/qsb_pregen_pool.h>

#include <chainparams.h>
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
        "\nThe address is derived from HORS commitments and can be used for quantum-safe transactions.\n"
        "\nNOTE: This is a STUB implementation. The final assembly awaits Avihu Levy's reference library.\n",
        {
            {"config", RPCArg::Type::STR, RPCArg::Optional::OMITTED_NAMED_ARG, "QSB config name (default: \"Config_A\")", "Config_A"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "address", "The QSB address (Bech32 encoded: qs1... for mainnet, qst1... for testnet, qsrt1... for regtest)"},
                {RPCResult::Type::STR_HEX, "scriptPubKey", "The raw scriptPubKey (hex)"},
                {RPCResult::Type::STR, "status", "Address creation status (\"ready\" or \"generating\")"},
                {RPCResult::Type::NUM, "pool_ready", "Number of ready outputs remaining in pool"},
                {RPCResult::Type::STR, "warning", "Stub implementation notice"},
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
    result.pushKV("warning", "STUB: Final assembly awaits Avihu Levy's reference library. This address uses a placeholder script.");

    return result;
}

// Register QSB RPC commands
static const CRPCCommand commands[] =
{ //  category              name                actor               argNames
  //  -------------------  ------------------  ------------------  ----------
    { "qsb",               "qsbpoolstatus",    &qsbpoolstatus,     {} },
    { "qsb",               "createqsbaddress", &createqsbaddress,  {"config"} },
};

void RegisterQSBRPCCommands(CRPCTable &tableRPC)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableRPC.appendCommand(commands[vcidx].name, &commands[vcidx]);
}

#endif // ENABLE_WALLET
