#!/usr/bin/env python3
#coding: utf-8

import tempfile
import requests
import json
import sys
import os
import subprocess

URL = "http://localhost:8214"
SENDER1 = "0xc8328aabcd9b9e8e64fbc566c4385c3bdeb219d7"
SENDER1_PRIVKEY = "d00c06bfd800d27397002dca6fb0993d5ba6399b4238b2f29ee9deb97593d2bc"
SENDER2 = "0x89750ca24e601604336276291d8b70280804d783"
SENDER2_PRIVKEY = "3066aa42bfa95c6d033edfad9d1efb871991fd26f56270fedc171559823bee77"
target_dir = sys.argv[1]
ckb_bin_path = sys.argv[3]
ckb_dir = os.path.dirname(os.path.abspath(ckb_bin_path))
script_dir = os.path.dirname(os.path.abspath(__file__))
privkey1_path = os.path.join(target_dir, "{}.privkey".format(SENDER1))
privkey2_path = os.path.join(target_dir, "{}.privkey".format(SENDER2))

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

contracts_binary = {
    SIMPLE_STORAGE: "60806040525b607b60006000508190909055505b610018565b60db806100266000396000f3fe60806040526004361060295760003560e01c806360fe47b114602f5780636d4ce63c14605b576029565b60006000fd5b60596004803603602081101560445760006000fd5b81019080803590602001909291905050506084565b005b34801560675760006000fd5b50606e6094565b6040518082815260200191505060405180910390f35b8060006000508190909055505b50565b6000600060005054905060a2565b9056fea26469706673582212204e58804e375d4a732a7b67cce8d8ffa904fa534d4555e655a433ce0a5e0d339f64736f6c63430006060033",
    LOG_EVENTS: "60806040525b3373ffffffffffffffffffffffffffffffffffffffff167f33b708096f325a28269900b1f9361f84aa77ba6ca085f6b114e4a070a8239d5234600160405180838152602001821515151581526020019250505060405180910390a25b610066565b60c1806100746000396000f3fe608060405260043610601f5760003560e01c806351973ec914602557601f565b60006000fd5b602b602d565b005b3373ffffffffffffffffffffffffffffffffffffffff167f33b708096f325a28269900b1f9361f84aa77ba6ca085f6b114e4a070a8239d5234600060405180838152602001821515151581526020019250505060405180910390a25b56fea2646970667358221220febe0ec5c064e995607c65adef058679ddef92d16e1fff35675fc3505f8f6b4564736f6c63430006060033",
    SELF_DESTRUCT: "608060405260405161013c38038061013c833981810160405260208110156100275760006000fd5b81019080805190602001909291905050505b80600060006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055505b50610081565b60ad8061008f6000396000f3fe608060405234801560105760006000fd5b5060043610602c5760003560e01c8063ae8421e114603257602c565b60006000fd5b6038603a565b005b600060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16ff5b56fea2646970667358221220ead2c0723dcc5bc6fe1848ffcc748528c4f0638575fdee75e2c972c60fa1ea2d64736f6c63430006060033",
    ERC20: open(os.path.join(script_dir, 'ERC20.bin'), 'r').read().strip(),
    ERC721: open(os.path.join(script_dir, 'KittyCore.bin'), 'r').read().strip(),
}

if len(sys.argv) < 4:
    print("USAGE:\n    python {} <json-dir> <privkey-path> <ckb-binary-path>".format(sys.argv[0]))
    exit(-1)

def send_jsonrpc(method, params):
    payload = {
        "id": 0,
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
    }
    resp = requests.post(URL, json=payload).json()
    if "error" in resp:
        print("JSONRPC ERROR: {}".format(resp["error"]))
        exit(-1)
    return resp["result"]

def create_contract(binary, constructor_args="", sender=SENDER1):
    print("[create contract]:")
    print("  sender = {}".format(sender))
    print("  binary = {}".format(binary))
    print("    args = {}".format(constructor_args))
    result = send_jsonrpc("create", [sender, "0x{}{}".format(binary, constructor_args)])
    print("  >> created address = {}".format(result["contract_address"]))
    return result

def call_contract(contract_address, args, is_static=False, sender=SENDER1):
    print("[call contract]:")
    print("   sender = {}".format(sender))
    print("  address = {}".format(contract_address))
    print("     args = {}".format(args))
    method = "static_call" if is_static else "call"
    return send_jsonrpc(method, [sender, contract_address, args])

def run_cmd(cmd):
    print("[RUN]: {}".format(cmd))
    output = subprocess.check_output(cmd, shell=True).strip().decode("utf-8")
    print("[Output]: {}".format(output))

def commit_tx(result, action_name, privkey_path=privkey1_path):
    result_path = os.path.join(target_dir, "{}.json".format(action_name))
    with open(result_path, "w") as f:
        json.dump(result, f, indent=4)
    tx_path = os.path.join(target_dir, "{}-tx.json".format(action_name))
    run_cmd("polyjuice-ng sign-tx -k {} -t {} -o {}".format(privkey_path, result_path, tx_path))
    run_cmd("ckb-cli tx send --tx-file {} --skip-check".format(tx_path))
    run_cmd("{} miner -C {} -l 5".format(ckb_bin_path, ckb_dir))

def create_contract_by_name(name, constructor_args=""):
    result = create_contract(contracts_binary[name], constructor_args)
    action_name = "create-{}".format(name)
    commit_tx(result, action_name)
    return result["contract_address"]


def test_simple_storage():
    contract_name = SIMPLE_STORAGE
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
    contract_address = create_contract_by_name(contract_name)

    args = "0x51973ec9"
    result = call_contract(contract_address, args, is_static=True)
    print("static call result: {}".format(result))
    print("[Finish]: {}\n".format(contract_name))


def test_self_destruct():
    contract_name = SELF_DESTRUCT
    contract_address = create_contract_by_name(contract_name, "000000000000000000000000b2e61ff569acf041b3c2c17724e2379c581eeac3")

    args = "0xae8421e1"
    result = call_contract(contract_address, args)
    action_name = "call-{}-{}-{}".format(contract_name, contract_address, args)
    commit_tx(result, action_name)
    print("[Finish]: {}\n".format(contract_name))


def test_erc20():
    contract_name = ERC20
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

    # transferFrom(89750ca24e601604336276291d8b70280804d783, d4c85f3cb8a625d25febb5acdade5e5bf4824fda, 0x3e8)
    args = "0x23b872dd000000000000000000000000c8328aabcd9b9e8e64fbc566c4385c3bdeb219d7000000000000000000000000d4c85f3cb8a625d25febb5acdade5e5bf4824fda00000000000000000000000000000000000000000000000000000000000003e8"
    result = call_contract(contract_address, args, is_static, sender=SENDER2)
    action_name = "call-{}-{}-{}".format(contract_name, contract_address, args)
    commit_tx(result, action_name[:42], privkey_path=privkey2_path)

    print("[Finish]: {}\n".format(contract_name))


def main():
    # test_simple_storage()
    # test_log_events()
    # test_self_destruct()
    test_erc20()

if __name__ == "__main__":
    main()
