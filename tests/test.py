#!/usr/bin/env python3
#coding: utf-8

import json
import sys
import os
import subprocess
import time

if len(sys.argv) < 4 or len(sys.argv) > 5:
    print("USAGE:\n    python {} <json-dir> <ckb-binary-path> <ckb-rpc-url> <polyjuice-rpc>".format(sys.argv[0]))
    exit(-1)

SENDER1 = "0xc8328aabcd9b9e8e64fbc566c4385c3bdeb219d7"
SENDER1_PRIVKEY = "d00c06bfd800d27397002dca6fb0993d5ba6399b4238b2f29ee9deb97593d2bc"
SENDER2 = "0x89750ca24e601604336276291d8b70280804d783"
ADDRESS2 = "ckt1qyqgjagv5f8xq9syxd38v2ga3dczszqy67psu2y8r4"
SENDER2_PRIVKEY = "3066aa42bfa95c6d033edfad9d1efb871991fd26f56270fedc171559823bee77"
target_dir = sys.argv[1]
ckb_bin_path = sys.argv[2]
ckb_rpc_url = sys.argv[3]
polyjuice_rpc_url = sys.argv[4] if len(sys.argv) == 5 else "http://localhost:8214"
ckb_dir = os.path.dirname(os.path.abspath(ckb_bin_path))
evm_contracts_dir = os.path.dirname(os.path.abspath(__file__))
evm_contracts_dir = os.path.join(evm_contracts_dir, "evm-contracts")
privkey1_path = os.path.join(target_dir, "{}.privkey".format(SENDER1))
privkey2_path = os.path.join(target_dir, "{}.privkey".format(SENDER2))
os.environ["API_URL"] = ckb_rpc_url

if not os.path.exists(privkey1_path):
    with open(privkey1_path, 'w') as f:
        f.write(SENDER1_PRIVKEY)
if not os.path.exists(privkey2_path):
    with open(privkey2_path, 'w') as f:
        f.write(SENDER2_PRIVKEY)

SIMPLE_STORAGE = "SimpleStorage"
LOG_EVENTS = "LogEvents"
SELF_DESTRUCT = "SelfDestruct"
ERC20 = "ERC20"
ERC721 = "KittyCore"
CREATE_CONTRACT = "CreateContract"
CALL_CONTRACT = "CallContract"
CALL_MULTI = "CallMultipleTimes"
CALL_SELFDESTRUCT = "CallSelfDestruct"
BLOCK_INFO = "BlockInfo"
DELEGATECALL = "DelegateCall"

contracts_binary = {
    SIMPLE_STORAGE: open(os.path.join(evm_contracts_dir, 'SimpleStorage.bin'), 'r').read().strip(),
    LOG_EVENTS: open(os.path.join(evm_contracts_dir, 'LogEvents.bin'), 'r').read().strip(),
    SELF_DESTRUCT: open(os.path.join(evm_contracts_dir, 'SelfDestruct.bin'), 'r').read().strip(),
    ERC20: open(os.path.join(evm_contracts_dir, 'ERC20.bin'), 'r').read().strip(),
    ERC721: open(os.path.join(evm_contracts_dir, 'KittyCore.bin'), 'r').read().strip(),
    CREATE_CONTRACT: open(os.path.join(evm_contracts_dir, 'CreateContract.bin'), 'r').read().strip(),
    CALL_CONTRACT: open(os.path.join(evm_contracts_dir, 'CallContract.bin'), 'r').read().strip(),
    CALL_MULTI: open(os.path.join(evm_contracts_dir, 'CallMultipleTimes.bin'), 'r').read().strip(),
    CALL_SELFDESTRUCT: open(os.path.join(evm_contracts_dir, 'CallSelfDestruct.bin'), 'r').read().strip(),
    BLOCK_INFO: open(os.path.join(evm_contracts_dir, 'BlockInfo.bin'), 'r').read().strip(),
    DELEGATECALL: open(os.path.join(evm_contracts_dir, 'DelegateCall.bin'), 'r').read().strip(),
}

def addr_to_arg(addr):
    return "000000000000000000000000{}".format(addr[2:])

def to_uint(number):
    output = hex(number)[2:]
    return '0' * (64 - len(output)) + output

def send_jsonrpc(method, params):
    payload = {
        "id": 0,
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
    }
    cmd = "curl -s -H 'content-type: application/json' -d '{}' {}".format(json.dumps(payload), polyjuice_rpc_url)
    output = subprocess.check_output(cmd, shell=True).strip().decode("utf-8")
    resp = json.loads(output)
    if "error" in resp:
        print("JSONRPC ERROR: {}".format(resp["error"]))
        exit(-1)
    return resp["result"]

def create_contract(binary, constructor_args="", sender=SENDER1):
    print("[create contract]:")
    print("  sender = {}".format(sender))
    print("  binary = 0x{}".format(binary))
    print("    args = 0x{}".format(constructor_args))
    result = send_jsonrpc("create", [sender, "0x{}{}".format(binary, constructor_args)])
    print("  >> created address = {}".format(result["entrance_contract"]))
    return result

def call_contract(contract_address, args, is_static=False, sender=SENDER1):
    method = "static_call" if is_static else "call"
    print("[{} contract]:".format(method))
    print("   sender = {}".format(sender))
    print("  address = {}".format(contract_address))
    print("     args = {}".format(args))
    return send_jsonrpc(method, [sender, contract_address, args])

def run_cmd(cmd, print_output=True):
    print("[RUN]: {}".format(cmd))
    output = subprocess.check_output(cmd, shell=True, env=os.environ).strip().decode("utf-8")
    if print_output:
        print("[Output]: {}".format(output))
    return output

def mine_blocks(n=5):
    run_cmd("{} miner -C {} -l {}".format(ckb_bin_path, ckb_dir, n))
    time.sleep(0.5)

def commit_tx(result, action_name, privkey_path=privkey1_path):
    result_path = os.path.join(target_dir, "{}.json".format(action_name))
    with open(result_path, "w") as f:
        json.dump(result, f, indent=4)
    tx_path = os.path.join(target_dir, "{}-tx.json".format(action_name))
    tx_raw_path = os.path.join(target_dir, "{}-raw-tx.json".format(action_name))
    # tx_moack_path = os.path.join(target_dir, "{}-mock-tx.json".format(action_name))
    run_cmd("polyjuice sign-tx --url {} -k {} -t {} -o {}".format(ckb_rpc_url, privkey_path, result_path, tx_path))
    run_cmd("cat {} | jq .transaction > {}".format(tx_path, tx_raw_path))
    # run_cmd("ckb-cli mock-tx dump --tx-file {} --output-file {}".format(tx_raw_path, tx_moack_path))
    for retry in range(3):
        tx_hash = run_cmd("ckb-cli tx send --tx-file {} --skip-check".format(tx_path)).strip()
        mine_blocks()
        tx_content = run_cmd("ckb-cli rpc get_transaction --hash {}".format(tx_hash), print_output=False)
        if tx_content.find(tx_hash) > -1:
            print("Transaction sent: {}".format(tx_hash))
            break;
        print("Retry send transaction: {}".format(retry))

def create_contract_by_name(name, constructor_args=""):
    result = create_contract(contracts_binary[name], constructor_args)
    action_name = "create-{}".format(name)
    commit_tx(result, action_name)
    return result["entrance_contract"]


def test_simple_storage():
    contract_name = SIMPLE_STORAGE
    print("[Start]: {}\n".format(contract_name))
    contract_address = create_contract_by_name(contract_name)

    for args in [
            "0x60fe47b10000000000000000000000000000000000000000000000000000000000000d10",
            "0x60fe47b10000000000000000000000000000000000000000000000000000000000000ccc",
    ]:
        result = call_contract(contract_address, args)
        action_name = "call-{}-{}-{}".format(contract_name, contract_address, args)
        commit_tx(result, action_name)
    print("[Finish]: {}\n".format(contract_name))


def test_log_events():
    contract_name = LOG_EVENTS
    print("[Start]: {}\n".format(contract_name))
    contract_address = create_contract_by_name(contract_name)

    args = "0x51973ec9"
    result = call_contract(contract_address, args, is_static=True)
    print("static call result: {}".format(result))
    print("[Finish]: {}\n".format(contract_name))


def test_self_destruct():
    contract_name = SELF_DESTRUCT
    print("[Start]: {}\n".format(contract_name))
    contract_address = create_contract_by_name(contract_name, "000000000000000000000000b2e61ff569acf041b3c2c17724e2379c581eeac3")

    args = "0xae8421e1"
    result = call_contract(contract_address, args)
    action_name = "call-{}-{}-{}".format(contract_name, contract_address, args)
    commit_tx(result, action_name)
    print("[Finish]: {}\n".format(contract_name))


def test_erc20():
    contract_name = ERC20
    print("[Start]: {}\n".format(contract_name))
    contract_address = create_contract_by_name(contract_name)

    for (args, is_static, return_data) in [
            # balanceOf(c8328aabcd9b9e8e64fbc566c4385c3bdeb219d7)
            ("0x70a08231000000000000000000000000c8328aabcd9b9e8e64fbc566c4385c3bdeb219d7", True, "0x000000000000000000000000000000000000000204fce5e3e250261100000000"),

            # balanceOf(d4c85f3cb8a625d25febb5acdade5e5bf4824fda)
            ("0x70a08231000000000000000000000000d4c85f3cb8a625d25febb5acdade5e5bf4824fda", True, "0x0000000000000000000000000000000000000000000000000000000000000000"),
            # transfer("d4c85f3cb8a625d25febb5acdade5e5bf4824fda", 0x22b)
            ("0xa9059cbb000000000000000000000000d4c85f3cb8a625d25febb5acdade5e5bf4824fda000000000000000000000000000000000000000000000000000000000000022b", False, None),
            # balanceOf(d4c85f3cb8a625d25febb5acdade5e5bf4824fda)
            ("0x70a08231000000000000000000000000d4c85f3cb8a625d25febb5acdade5e5bf4824fda", True, "0x000000000000000000000000000000000000000000000000000000000000022b"),
            # transfer("d4c85f3cb8a625d25febb5acdade5e5bf4824fda", 0x219)
            ("0xa9059cbb000000000000000000000000d4c85f3cb8a625d25febb5acdade5e5bf4824fda0000000000000000000000000000000000000000000000000000000000000219", False, None),
            # balanceOf(d4c85f3cb8a625d25febb5acdade5e5bf4824fda)
            ("0x70a08231000000000000000000000000d4c85f3cb8a625d25febb5acdade5e5bf4824fda", True, "0x0000000000000000000000000000000000000000000000000000000000000444"),

            # burn(8908)
            ("0x42966c6800000000000000000000000000000000000000000000000000000000000022cc", False, None),
            # balanceOf(c8328aabcd9b9e8e64fbc566c4385c3bdeb219d7)
            ("0x70a08231000000000000000000000000c8328aabcd9b9e8e64fbc566c4385c3bdeb219d7", True, "0x000000000000000000000000000000000000000204fce5e3e2502610ffffd8f0"),

            # approve(89750ca24e601604336276291d8b70280804d783, 0x3e8)
            ("0x095ea7b300000000000000000000000089750ca24e601604336276291d8b70280804d78300000000000000000000000000000000000000000000000000000000000003e8", False, None),
    ]:
        result = call_contract(contract_address, args, is_static)
        if is_static:
            print("static call result: {}".format(result))
            if result["return_data"] != return_data:
                print("Invalid return data")
                exit(-1)
        else:
            action_name = "call-{}-{}-{}".format(contract_name, contract_address, args)
            commit_tx(result, action_name)

    cmd = "ckb-cli --wait-for-sync wallet transfer --privkey-path {} --to-address {} --capacity 500 --tx-fee 0.001".format(privkey1_path, ADDRESS2)
    run_cmd(cmd)
    mine_blocks()
    # transferFrom(89750ca24e601604336276291d8b70280804d783, d4c85f3cb8a625d25febb5acdade5e5bf4824fda, 0x3e8)
    args = "0x23b872dd000000000000000000000000c8328aabcd9b9e8e64fbc566c4385c3bdeb219d7000000000000000000000000d4c85f3cb8a625d25febb5acdade5e5bf4824fda00000000000000000000000000000000000000000000000000000000000003e8"
    result = call_contract(contract_address, args, is_static, sender=SENDER2)
    action_name = "call-{}-{}-{}".format(contract_name, contract_address, args)
    commit_tx(result, action_name[:42], privkey_path=privkey2_path)

    print("[Finish]: {}\n".format(contract_name))


def test_erc721_kitty_core():
    contract_name = ERC721
    print("[Start]: {}\n".format(contract_name))
    contract_address = create_contract_by_name(contract_name)
    print("[Finish]: {}\n".format(contract_name))


def test_contract_create_contract():
    contract_name = CREATE_CONTRACT
    print("[Start]: {}\n".format(contract_name))

    result = create_contract(contracts_binary[contract_name])
    action_name = "create-{}".format(contract_name)
    commit_tx(result, action_name)

    ss_address = result["created_addresses"][1]
    static_call_args = "0x6d4ce63c"
    result = call_contract(ss_address, static_call_args, is_static=True)
    assert result["return_data"] == "0x00000000000000000000000000000000000000000000000000000000000000ff"
    print("[Finish]: {}\n".format(contract_name))


def test_contract_call_contract():
    contract_name = CALL_CONTRACT
    print("[Start]: {}\n".format(contract_name))
    ss_address = create_contract_by_name(SIMPLE_STORAGE)
    print("create SimpleStorage contract({}) for {}".format(ss_address, contract_name))

    args = "000000000000000000000000{}".format(ss_address[2:])
    assert len(args) == 64
    contract_address = create_contract_by_name(contract_name, constructor_args=args)

    # ethabi => proxySet(222)
    call_args = "0x28cc7b2500000000000000000000000000000000000000000000000000000000000000de"
    result = call_contract(contract_address, call_args)
    action_name = "call-{}-{}-{}".format(contract_name, contract_address, args)
    commit_tx(result, action_name[:42])
    print("[Finish]: {}\n".format(contract_name))


def test_call_multiple_times():
    contract_name = CALL_MULTI
    print("[Start]: {}\n".format(contract_name))
    ss1_address = create_contract_by_name(SIMPLE_STORAGE)
    print("create SimpleStorage.1 contract({}) for {}".format(ss1_address, contract_name))
    ss2_address = create_contract_by_name(SIMPLE_STORAGE)
    print("create SimpleStorage.2 contract({}) for {}".format(ss2_address, contract_name))

    args = "000000000000000000000000{}".format(ss1_address[2:])
    assert(len(args) == 64)
    contract_address = create_contract_by_name(contract_name, constructor_args=args)

    call_args = "0xbca0b9c2000000000000000000000000{}0000000000000000000000000000000000000000000000000000000000000014".format(ss2_address[2:])
    result = call_contract(contract_address, call_args)
    action_name = "call-{}-{}-{}".format(contract_name, contract_address, args)
    commit_tx(result, action_name[:42])

    static_call_args = "0x6d4ce63c"
    result = call_contract(ss1_address, static_call_args, is_static=True)
    assert result["return_data"] == "0x0000000000000000000000000000000000000000000000000000000000000016"
    result = call_contract(ss2_address, static_call_args, is_static=True)
    assert result["return_data"] == "0x0000000000000000000000000000000000000000000000000000000000000019"

    print("[Finish]: {}\n".format(contract_name))


def test_call_selfdestruct():
    contract_name = CALL_SELFDESTRUCT
    print("[Start]: {}\n".format(contract_name))

    destruct_address = create_contract_by_name(SELF_DESTRUCT, "000000000000000000000000b2e61ff569acf041b3c2c17724e2379c581eeac3")
    contract_address = create_contract_by_name(contract_name)

    call_args = "0x9a33d968000000000000000000000000{}".format(destruct_address[2:])
    result = call_contract(contract_address, call_args)
    action_name = "call-{}-{}-{}".format(contract_name, contract_address, call_args)
    commit_tx(result, action_name[:42])
    target_output = result["tx"]["outputs"][1]
    assert target_output["lock"]["args"] == "0xb2e61ff569acf041b3c2c17724e2379c581eeac3", "beneficiary address not match"
    assert target_output["type"] is None, "beneficiary type script not null"
    print("[Finish]: {}\n".format(contract_name))

def test_get_block_info():
    contract_name = BLOCK_INFO
    print("[Start]: {}\n".format(contract_name))
    contract_address = create_contract_by_name(contract_name)

    functions = {
        'getDifficulty': '0xb6baffe3',
        'getNumber': '0xf2c9ecd8',
        'getTimestamp': '0x188ec356',
    }

    result = call_contract(contract_address, functions['getDifficulty'], is_static=True)
    print('getDifficulty() => {}'.format(result['return_data']))
    assert result['return_data'] == '0x0000000000000000000000000000000000000000000000000000000000000100'

    result = call_contract(contract_address, functions['getNumber'], is_static=True)
    print('getNumber() => {}'.format(result['return_data']))
    assert result['return_data'] > '0x0000000000000000000000000000000000000000000000000000000000000001'
    assert result['return_data'] < '0x0000000000000000000000000000000000000000000000000000000000000100'

    result = call_contract(contract_address, functions['getTimestamp'], is_static=True)
    print('getTimestamp() => {}'.format(result['return_data']))
    assert result['return_data'] > '0x000000000000000000000000000000000000000000000000000000005f2b964a'
    # 2120.9.30
    assert result['return_data'] < '0x000000000000000000000000000000000000000000000000000000011b8b1c00'

    print("[Finish]: {}\n".format(contract_name))


def test_delegatecall():
    contract_name = DELEGATECALL
    print("[Start]: {}\n".format(contract_name))
    contract_address = create_contract_by_name(contract_name)
    static_call_args = "0x6d4ce63c"
    result = call_contract(contract_address, static_call_args, is_static=True)
    assert result["return_data"] == "0x000000000000000000000000000000000000000000000000000000000000007b"

    ss_address = create_contract_by_name(SIMPLE_STORAGE)
    print("create SimpleStorage contract({}) for {}".format(ss_address, contract_name))

    fn_set = "3825d828"
    fn_overwrite = "3144564b"
    fn_multi_call = "c6c211e9"
    for (fn_name, expected) in [
            (fn_set, "0x0000000000000000000000000000000000000000000000000000000000000022"),
            (fn_overwrite, "0x0000000000000000000000000000000000000000000000000000000000000023"),
            (fn_multi_call, "0x0000000000000000000000000000000000000000000000000000000000000024"),
    ]:
        call_args = "0x{}{}{}".format(
            fn_name,
            addr_to_arg(ss_address),
            "0000000000000000000000000000000000000000000000000000000000000022"
        )
        result = call_contract(contract_address, call_args)
        action_name = "call-{}-{}-{}".format(contract_name, contract_address, call_args)
        commit_tx(result, action_name[:42])

        result = call_contract(contract_address, static_call_args, is_static=True)
        print("return: {}, expected: {}".format(result["return_data"], expected))
        assert result["return_data"] == expected
        result = call_contract(ss_address, static_call_args, is_static=True)
        assert result["return_data"] == "0x000000000000000000000000000000000000000000000000000000000000007b"
    # TODO:
    #  1. call delegatecall multiple times
    #  2. call delegatecall then other action change current storage
    print("[Finish]: {}\n".format(contract_name))

def main():
    test_simple_storage()
    test_log_events()
    test_self_destruct()
    test_erc20()
    test_erc721_kitty_core()
    test_contract_create_contract()
    test_contract_call_contract()
    test_call_multiple_times()
    test_call_selfdestruct()
    test_get_block_info()
    test_delegatecall()

if __name__ == "__main__":
    main()
