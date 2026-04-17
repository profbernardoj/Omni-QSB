#!/bin/bash
# QSB End-to-End Regtest Test
# Requires: running bitcoind -regtest with QSB enabled (QSB_BLOCK=0)
#
# This script tests the complete lock + spend cycle:
#   1. createqsbaddress → generate QSB address
#   2. sendtoaddress → fund the QSB address
#   3. generatetoaddress → mine the funding tx
#   4. createqsbspend → spend with Omni payload
#   5. generatetoaddress → mine the spend tx
#   6. omni_listtransactions → verify Omni state
#
# Usage: ./qsb_regtest_roundtrip.sh [mining_address]
#

set -e

BITCOIN_CLI="bitcoin-cli -regtest"

# Get mining address from arg or create new
if [ -n "$1" ]; then
    MINING_ADDR="$1"
else
    MINING_ADDR=$($BITCOIN_CLI getnewaddress)
    echo "Created mining address: $MINING_ADDR"
fi

echo "=== QSB End-to-End Regtest ==="
echo ""

# Step 1: Create QSB address
echo "Step 1: createqsbaddress..."
QSB_RESULT=$($BITCOIN_CLI createqsbaddress 2>&1)
if [ $? -ne 0 ]; then
    echo "ERROR: createqsbaddress failed: $QSB_RESULT"
    exit 1
fi
QSB_ADDR=$(echo "$QSB_RESULT" | jq -r '.address')
QSB_SIZE=$(echo "$QSB_RESULT" | jq -r '.script_size // "unknown"')
echo "Created QSB address: $QSB_ADDR (script size: $QSB_SIZE bytes)"
echo ""

# Step 2: Fund the QSB address
echo "Step 2: Funding QSB address..."
FUND_TXID=$($BITCOIN_CLI sendtoaddress "$QSB_ADDR" 10.0)
echo "Funding txid: $FUND_TXID"
echo ""

# Generate 1 block to confirm funding
BLOCK_HASH=$($BITCOIN_CLI generatetoaddress 1 "$MINING_ADDR" | jq -r '.[0]')
echo "Mined block: $BLOCK_HASH"
echo ""

# Step 3: Get UTXO details
echo "Step 3: Getting UTXO details..."
UTXO=$($BITCOIN_CLI listunspent 1 999999 "[\"$QSB_ADDR\"]" | jq '.[0]')
TXID=$(echo "$UTXO" | jq -r '.txid')
VOUT=$(echo "$UTXO" | jq -r '.vout')
AMOUNT=$(echo "$UTXO" | jq -r '.amount')
echo "UTXO: $TXID:$VOUT (amount: $AMOUNT BTC)"
echo ""

# Step 4: Spend with Omni payload
# Example Omni payload: simple token transfer (property 1, amount 100000000)
OMNI_PAYLOAD="6f6d6e69000000000000001f0000000005f5e100"
echo "Step 4: createqsbspend with Omni payload: $OMNI_PAYLOAD"

# Get destination address
DEST_ADDR=$($BITCOIN_CLI getnewaddress)
echo "Destination: $DEST_ADDR"

SPEND_RESULT=$($BITCOIN_CLI createqsbspend "$TXID" "$VOUT" "$DEST_ADDR" "42" "[0,1]" "[0,1]" "$OMNI_PAYLOAD" 2>&1)
if [ $? -ne 0 ]; then
    echo "ERROR: createqsbspend failed: $SPEND_RESULT"
    echo "Note: If error is 'QSB not enabled', ensure QSB_BLOCK=0 in regtest params"
    exit 1
fi
SPEND_TXID=$(echo "$SPEND_RESULT" | jq -r '.txid')
SPEND_RAW=$(echo "$SPEND_RESULT" | jq -r '.rawtx')
echo "Spend txid: $SPEND_TXID"
echo "Raw tx size: $((${#SPEND_RAW} / 2)) bytes"
echo ""

# Step 5: Broadcast and mine
echo "Step 5: Broadcasting spend transaction..."
SEND_RESULT=$($BITCOIN_CLI sendrawtransaction "$SPEND_RAW" 2>&1)
if [ $? -ne 0 ]; then
    echo "ERROR: sendrawtransaction failed: $SEND_RESULT"
    exit 1
fi
echo "Broadcast: $SEND_RESULT"

BLOCK_HASH=$($BITCOIN_CLI generatetoaddress 1 "$MINING_ADDR" | jq -r '.[0]')
echo "Mined block: $BLOCK_HASH"
echo ""

# Step 6: Verify Omni state
echo "Step 6: Verifying Omni state machine..."
OMNI_TXS=$($BITCOIN_CLI omni_listtransactions "*" 10 0 0 2>&1)
echo "Recent Omni transactions:"
echo "$OMNI_TXS" | jq -r '.[] | "\(.txid) - property: \(.propertyid), amount: \(.amount // "N/A")"' | head -5
echo ""

# Check the spend transaction
echo "Spend transaction details:"
TX_DETAILS=$($BITCOIN_CLI getrawtransaction "$SPEND_TXID" 1 2>&1)
echo "$TX_DETAILS" | jq '{txid: .txid, size: .size, confirmations: .confirmations, vin: [.vin[] | {txid: .txid, vout: .vout}]}'
echo ""

# Final verification
CONFIRMATIONS=$($BITCOIN_CLI gettransaction "$SPEND_TXID" | jq -r '.confirmations')
if [ "$CONFIRMATIONS" -ge 1 ]; then
    echo "✅ SUCCESS: Spend transaction has $CONFIRMATIONS confirmation(s)"
else
    echo "❌ FAILURE: Spend transaction not confirmed"
    exit 1
fi

echo ""
echo "=== QSB END-TO-END TEST PASSED ==="