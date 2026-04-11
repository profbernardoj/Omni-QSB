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
#include <wallet/rpcwallet.h>
#include <wallet/wallet.h>

#include <univalue.h>

#ifdef ENABLE_WALLET

/**
 * Returns the QSB pool status.
 *
 * Arguments: none
 *
 * Result:
 * {
 *   "ready": n,      (int) Number of ready QSB outputs in pool
 *   "target": n,     (int) Target pool size
 *   "running": bool, (bool) Whether pool worker is running
 *   "config": {      (object) Pool configuration
 *     "max_size": n,
 *     "min_size": n,
 *     "hors_num_keys": n
 *   }
 * }
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

    // TODO: Get QSBWallet from CWallet once integrated
    // For now, return a placeholder status
    UniValue result(UniValue::VOBJ);
    result.pushKV("ready", 0);
    result.pushKV("target", 5);
    result.pushKV("running", false);

    UniValue config(UniValue::VOBJ);
    config.pushKV("max_size", QSBWallet::DEFAULT_MAX_POOL_SIZE);
    config.pushKV("min_size", QSBWallet::DEFAULT_MIN_POOL_SIZE);
    config.pushKV("hors_num_keys", QSBWallet::DEFAULT_HORS_NUM_KEYS);
    result.pushKV("config", config);

    return result;
}

/**
 * Creates a new QSB address from the pool.
 *
 * Arguments:
 * 1. config        (string, optional) QSB config name (default: "Config_A")
 *
 * Result:
 * {
 *   "address": "qs1...",     (string) The QSB address (Bech32 encoded)
 *   "commitment": "hex",     (string) The commitment hash (hex)
 *   "config": "Config_A",    (string) The QSB config used
 * }
 */
static UniValue createqsbaddress(const JSONRPCRequest& request)
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();

    RPCHelpMan{"createqsbaddress",
        "\nCreates a new Quantum-Safe Bitcoin address from the pre-generation pool.\n"
        "\nThe address is derived from HORS commitments and can be used for quantum-safe transactions.\n",
        {
            {"config", RPCArg::Type::STR, RPCArg::Optional::OMITTED_NAMED_ARG, "QSB config name (default: \"Config_A\")", "Config_A"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "address", "The QSB address (Bech32 encoded, qs1... for mainnet)"},
                {RPCResult::Type::STR_HEX, "commitment", "The commitment hash (20 bytes, hex)"},
                {RPCResult::Type::STR, "config", "The QSB configuration used"},
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

    // Get config name (default: Config_A)
    std::string configName = "Config_A";
    if (request.params.size() > 0 && !request.params[0].isNull()) {
        configName = request.params[0].get_str();
    }

    // TODO: Integrate with CWallet to get QSBWallet instance
    // For now, return a placeholder response
    //
    // Future integration:
    // QSBWallet& qsb = pwallet->GetQSBWallet();
    // QSBPoolEntry entry;
    // if (!qsb.AcquireReadyOutputBlocking(entry, 5000)) {
    //     throw JSONRPCError(RPC_MISC_ERROR, "Failed to acquire QSB output from pool");
    // }

    UniValue result(UniValue::VOBJ);
    result.pushKV("address", "qs1qqqqqqqqqqqqqqqqqqqqqqqqqqqyqnpage"); // Placeholder
    result.pushKV("commitment", "0000000000000000000000000000000000000000"); // Placeholder
    result.pushKV("config", configName);

    return result;
}

// Register QSB RPC commands
static const CRPCCommand commands[] =
{ //  category              name              actor              argNames
   //  -------------------  ---------------- ------------------ ----------
    { "qsb",                "qsbpoolstatus",   &qsbpoolstatus,    {} },
    { "qsb",                "createqsbaddress", &createqsbaddress, {"config"} },
};

void RegisterQSBRPCCommands(CRPCTable &tableRPC)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableRPC.appendCommand(commands[vcidx].name, &commands[vcidx]);
}

#endif // ENABLE_WALLET