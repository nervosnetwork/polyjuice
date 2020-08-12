# Polyjuice

Nervos CKB is built on the cell model, which is a generalized version of the UTXO model. There seems to be a belief in the blockchain world that UTXO model is hard to program on, while the account model is easier for developers. Although cell model is a descendant of UTXO model, it is perfectly [possible](https://xuejie.space/2020_03_20_what_do_we_mean_when_we_say_account_model/) to build account model on top of cell model. The secret here also lies in abstraction. While at the lower level UTXO-style design can help achieve parallelism, at the higher level an abstraction layer can expose exactly an account model to the everyday developers.

That is also just our claim, as engineers we all know the famous quote "Talk is cheap. Show me the code." Following this principle, we designed and built polyjuice, which is an Ethereum compatible layer on top of Nervos CKB. Ethereum, up to this day, is probably the most used and flexible account model based blockchain. By polyjuice we want to showcase that it is perfectly possible to use account model on Nervos CKB. The flexibility here actually enables countless opportunities.

# Features
- [x] Contract creation
- [x] Contract destruction
- [x] Contract call contract
- [x] Contract logs
- [ ] Read block information from contract
- [ ] Value transfer

Polyjuice use [evmone](https://github.com/ethereum/evmone) as the EVM implementation in both `generator` and `validator`, almost all opcodes are supported except:

* `CREATE2` (will be supported)
* `DELEGATECALL` (will be supported)
* `COINBASE`  (will be supported)

# A short tutorial

**NOTE** : The tutorial currently only tested on Ubuntu 18.04.

Here we provide a short tutorial performing the following operations on a polyjuice on CKB setup:

* Simple contract creation
* Calling contract
* Reading storage data from a contract

Throughout the tutorial, we will work with the following 2 accounts:

* Account A
  - private key: `d00c06bfd800d27397002dca6fb0993d5ba6399b4238b2f29ee9deb97593d2bc`
  - CKB address: `ckt1qyqvsv5240xeh85wvnau2eky8pwrhh4jr8ts8vyj37`
  - Ethereum address: `0xc8328aabcd9b9e8e64fbc566c4385c3bdeb219d7`
* Account B
  - private key: `3066aa42bfa95c6d033edfad9d1efb871991fd26f56270fedc171559823bee77`
  - CKB address: `ckt1qyqgjagv5f8xq9syxd38v2ga3dczszqy67psu2y8r4`
  - Ethereum address: `0x89750ca24e601604336276291d8b70280804d783`

Note that Ethereum address is also CKB secp256k1 sighash lock args.

## Setting up CKB

You need to download latest CKB from github [release page](https://github.com/nervosnetwork/ckb/releases). For convenience, we will launch a dev chain locally and work from there.

To initialize the dev chain, you can just use the init command:

```bash
$ ckb init --chain dev --ba-arg 0xc8328aabcd9b9e8e64fbc566c4385c3bdeb219d7
```

Now we can launch CKB and the miner:

``` bash
$ ckb run

# in a different terminal
$ ckb miner
```

## Install ckb-cli / jq

Since we need to sign secp256k1 sighash locked inputs in polyjuice generated transaction, we need a little help from `ckb-cli`. You need to download latest(version >= 0.33.1) ckb-cli from github [release page](https://github.com/nervosnetwork/ckb-cli/releases), and put in your `$PATH`, so polyjuice can find it.

Some actions depend on `jq` to show/edit json information. You may install [jq](https://stedolan.github.io/jq/download/) by:

```bash
$ sudo apt install jq -y
```

## Setting up polyjuice

Now we are ready to setup polyjuice:

```bash
$ git clone https://github.com/nervosnetwork/polyjuice
$ cd polyjuice
$ git submodule update --init --recursive --progress
$ cargo build --release
```

Build c contracts:

``` bash
$ cd c
$ make all-via-docker
$ cd ..
```

It will build a `validator` for running in polyjuice type script, and a `generator` for generating CKB transaction.

Before deploy contracts we better save privkey to a file for convenience (NOTE: this is insecure):

```bash
echo "d00c06bfd800d27397002dca6fb0993d5ba6399b4238b2f29ee9deb97593d2bc" > privkey-0xc8328aabcd9b9e8e64fbc566c4385c3bdeb219d7
```

Then we use ckb-cli to deploy `validator` to dev chain:

```bash
$ ckb-cli wallet transfer \
        --privkey-path privkey-0xc8328aabcd9b9e8e64fbc566c4385c3bdeb219d7 \
        --to-address ckt1qyqgjagv5f8xq9syxd38v2ga3dczszqy67psu2y8r4 \
        --tx-fee 0.01 \
        --capacity 300000 \
        --to-data-path ./c/build/validator

# The transaction where validator contract's code located
0x1111000000000000000000000000000000000000000000000000000000000000
```

Since lock script is required for every cell and we want anyone can use the contract, here we deploy an always success contract for polyjuice cell's lock script:

```bash
$ ckb-cli wallet transfer \
        --privkey-path privkey-0xc8328aabcd9b9e8e64fbc566c4385c3bdeb219d7 \
        --to-address ckt1qyqgjagv5f8xq9syxd38v2ga3dczszqy67psu2y8r4 \
        --tx-fee 0.001 \
        --capacity 600 \
        --to-data 0x7f454c460201010000000000000000000200f3000100000078000100000000004000000000000000980000000000000005000000400038000100400003000200010000000500000000000000000000000000010000000000000001000000000082000000000000008200000000000000001000000000000001459308d00573000000002e7368737472746162002e74657874000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b000000010000000600000000000000780001000000000078000000000000000a0000000000000000000000000000000200000000000000000000000000000001000000030000000000000000000000000000000000000082000000000000001100000000000000000000000000000001000000000000000000000000000000

# The transaction where always success contract's code located
0x2222000000000000000000000000000000000000000000000000000000000000
```

Running polyjuice require a config file to tell polyjuice the `validator`/`always_success` contract's out point and code hash. We use `ckb-cli` to calculate the code hash:

```bash
# validator's code hash
$ ckb-cli util blake2b --binary-path ./c/build/validator
0xaaaa000000000000000000000000000000000000000000000000000000000000

# always_success's code hash
$ ckb-cli util blake2b --binary-hex 0x7f454c460201010000000000000000000200f3000100000078000100000000004000000000000000980000000000000005000000400038000100400003000200010000000500000000000000000000000000010000000000000001000000000082000000000000008200000000000000001000000000000001459308d00573000000002e7368737472746162002e74657874000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b000000010000000600000000000000780001000000000078000000000000000a0000000000000000000000000000000200000000000000000000000000000001000000030000000000000000000000000000000000000082000000000000001100000000000000000000000000000001000000000000000000000000000000
0x28e83a1277d48add8e72fadaa9248559e1b632bab2bd60b27955ebc4c03800a5
```

Then generate the config file:

``` bash
$ VALIDATOR_TX_HASH=0x1111000000000000000000000000000000000000000000000000000000000000
$ VALIDATOR_CODE_HASH=0xaaaa000000000000000000000000000000000000000000000000000000000000
$ ALWAYS_SUCCESS_TX_HASH=0x2222000000000000000000000000000000000000000000000000000000000000

$ cat > run_config.json << _RUN_CONFIG_
{
    "type_dep": {
        "out_point": {
            "tx_hash": "${VALIDATOR_TX_HASH}",
            "index": "0x0"
        },
        "dep_type": "code"
    },
    "type_script": {
        "code_hash": "${VALIDATOR_CODE_HASH}",
        "hash_type": "data",
        "args": "0x"
    },
    "lock_dep": {
        "out_point": {
            "tx_hash": "${ALWAYS_SUCCESS_TX_HASH}",
            "index": "0x0"
        },
        "dep_type": "code"
    },
    "lock_script": {
        "code_hash": "0x28e83a1277d48add8e72fadaa9248559e1b632bab2bd60b27955ebc4c03800a5",
        "hash_type": "data",
        "args": "0x"
    }
}
_RUN_CONFIG_
```

Then start polyjuice:

```bash
RUST_LOG=polyjuice=debug ./target/release/polyjuice run \
  --generator ./c/build/generator \
  --config ./run_config.json
```

## Interacting though RPC API

We will use curl to interact with polyjuice. Default RPC server listen address is `localhost:8214`.

### Create contract

First, let's create an [ERC20](https://etherscan.io/address/0xc3761eb917cd790b30dad99f6cc5b4ff93c4f9ea) contract:

``` bash
echo '{
    "id": 2,
    "jsonrpc": "2.0",
    "method": "create",
    "params": ["0xc8328aabcd9b9e8e64fbc566c4385c3bdeb219d7", "0x<the ERC20 contract binary>"]
}' \
| tr -d '\n' \
| curl -s -H 'content-type: application/json' -d @- http://localhost:8214 \
| jq .result > tx-receipt.json
```

```json
{
  "entrance_contract": "0x8c2eb9f3eb0f6ba73a2249fe8eeb02cafa7a25e0",
  "created_addresses": [
    "0x8c2eb9f3eb0f6ba73a2249fe8eeb02cafa7a25e0"
  ],
  "destructed_addresses": [],
  "logs": [],
  "return_data": "0x6060604 ...... 806500029",
  "tx_hash": "0x1111111111111111111111111111111111111111111111111111111111111111",
  "tx": {
    "cell_deps": [
      {
        "dep_type": "dep_group",
        "out_point": {
          "index": "0x0",
          "tx_hash": "0xace5ea83c478bb866edf122ff862085789158f5cbff155b7bb5f13058555b708"
        }
      },
      {
        "dep_type": "code",
        "out_point": {
          "index": "0x0",
          "tx_hash": "0xc6c27c3a371425011b3b20697e16342359746f9203cc29a0613dd6166c830a94"
        }
      },
      {
        "dep_type": "code",
        "out_point": {
          "index": "0x0",
          "tx_hash": "0x301a76aeafdefe55d822ff7b25373591438cfd7055d21285e9389b76e3e92c4b"
        }
      }
    ],
    "header_deps": [],
    "inputs": [
      {
        "previous_output": {
          "index": "0x1",
          "tx_hash": "0x6260fb79e81e8196233c32ee61392bf44332fd2883d889c81f22f03c0bbe7077"
        },
        "since": "0x0"
      }
    ],
    "outputs": [
      {
        "capacity": "0x4a817c800",
        "lock": {
          "args": "0x",
          "code_hash": "0x28e83a1277d48add8e72fadaa9248559e1b632bab2bd60b27955ebc4c03800a5",
          "hash_type": "data"
        },
        "type": {
          "args": "0x804988b0f61a786082cbed278d46a7e727954eca",
          "code_hash": "0x76aa92a7045c92289a0c1dbd74585d5a2b7660aa796f25d92052a6b2f705f181",
          "hash_type": "data"
        }
      },
      {
        "capacity": "0x1bc15206fd1b0a20",
        "lock": {
          "args": "0xc8328aabcd9b9e8e64fbc566c4385c3bdeb219d7",
          "code_hash": "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8",
          "hash_type": "type"
        },
        "type": null
      }
    ],
    "outputs_data": [
      "0x6cb306547af5f7e64e4f01d3624de0ad36e1625029f73f5d25529600e682388ae09ecb04e6e61109e7d392c7dc7fc110e8edf83ae661bb2074cef29a2dab3c77",
      "0x"
    ],
    "version": "0x0",
    "witnesses": [
      "0x5a150000 ...... f94c48fe00000000"
    ]
  }
}
```

The `entrance_contract` field which is `0x8c2eb9f3eb0f6ba73a2249fe8eeb02cafa7a25e0` here contrains the ERC20 contract address we will create. The following actions will require this value as argument.

Then we sign the transaction use polyjuice:

``` bash
$ ./target/release/polyjuice sign-tx \
  --privkey privkey-0xc8328aabcd9b9e8e64fbc566c4385c3bdeb219d7 \
  --tx-receipt tx-receipt.json \
  --output signed-tx.json
```

The last part is send the transaction to CKB use `ckb-cli`:

```bash
$ ckb-cli tx send --tx-file signed-tx.json --skip-check
0xedcede37f52fc402e021e17bf1cc1eb1b64cd4611e82dbe071440857ed375055
```

### Query the information of contract

The contract metadata:

```bash
echo '{
    "id": 2,
    "jsonrpc": "2.0",
    "method": "get_contracts",
    "params": [0, null]
}' \
| tr -d '\n' \
| curl -s -H 'content-type: application/json' -d @- http://localhost:8214 \
| jq
```

```json
{
  "jsonrpc": "2.0",
  "result": [
    {
      "address": "0x8c2eb9f3eb0f6ba73a2249fe8eeb02cafa7a25e0",
      "block_number": 14,
      "code": "0x608060405260043 ... 9f64736f6c63430006060033",
      "code_hash": "0x8e92ee4326804b8c5b911ad1cf31b1b44269a1f89453329b5162e5b04ac2eade",
      "destructed": false,
      "output_index": 0,
      "tx_hash": "0xedcede37f52fc402e021e17bf1cc1eb1b64cd4611e82dbe071440857ed375055"
    }
  ],
  "id": 2
}
```

The contract change:

```bash
echo '{
    "id": 2,
    "jsonrpc": "2.0",
    "method": "get_change",
    "params": ["0x8c2eb9f3eb0f6ba73a2249fe8eeb02cafa7a25e0", null]
}' \
| tr -d '\n' \
| curl -s -H 'content-type: application/json' -d @- http://localhost:8214 \
| jq

```

```json
{
  "jsonrpc": "2.0",
  "result": {
    "address": "0x8c2eb9f3eb0f6ba73a2249fe8eeb02cafa7a25e0",
    "is_create": true,
    "logs": [],
    "new_storage": [
      [
        "0xc883bc0d49add18e7c46e11b87235c3df58a5051abcb763ed021382a2fbd0a61",
        "0x000000000000000000000000000000000000000204fce5e3e250261100000000"
      ],
      [
        "0x0000000000000000000000000000000000000000000000000000000000000002",
        "0x0000000000000000000000000000000000000000000000000000000000000012"
      ],
      [
        "0x0000000000000000000000000000000000000000000000000000000000000003",
        "0x000000000000000000000000000000000000000204fce5e3e250261100000000"
      ],
      [
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0x455243323000000000000000000000000000000000000000000000000000000a"
      ],
      [
        "0x0000000000000000000000000000000000000000000000000000000000000001",
        "0x455243323000000000000000000000000000000000000000000000000000000a"
      ]
    ],
    "number": 14,
    "output_index": 0,
    "tx_hash": "0xedcede37f52fc402e021e17bf1cc1eb1b64cd4611e82dbe071440857ed375055",
    "tx_index": 1,
    "tx_origin": "0xc8328aabcd9b9e8e64fbc566c4385c3bdeb219d7"
  },
  "id": 2
}
```


### Call a contract

Before we make some changes to the contract let's query the balance of the ERC20 token issuer.

```bash
echo '{
    "id": 2,
    "jsonrpc": "2.0",
    "method": "static_call",
    "params": [
        "0xc8328aabcd9b9e8e64fbc566c4385c3bdeb219d7",
        "0x8c2eb9f3eb0f6ba73a2249fe8eeb02cafa7a25e0",
        "0x70a08231000000000000000000000000c8328aabcd9b9e8e64fbc566c4385c3bdeb219d7"
    ]
}' \
| tr -d '\n' \
| curl -s -H 'content-type: application/json' -d @- http://localhost:8214 \
| jq
```

```json
{
  "jsonrpc": "2.0",
  "result": {
    "logs": [],
    "return_data": "0x000000000000000000000000000000000000000204fce5e3e250261100000000"
  },
  "id": 2
}
```

Now, let's transfer `555` ERC20 token from `0xc8328aabcd9b9e8e64fbc566c4385c3bdeb219d7` to `d4c85f3cb8a625d25febb5acdade5e5bf4824fda`. The args generated from ethabi will be `0xa9059cbb000000000000000000000000d4c85f3cb8a625d25febb5acdade5e5bf4824fda000000000000000000000000000000000000000000000000000000000000022b`.

First, we create a CKB transaction use polyjuice:

```bash
echo '{
    "id": 2,
    "jsonrpc": "2.0",
    "method": "call",
    "params": [
        "0xc8328aabcd9b9e8e64fbc566c4385c3bdeb219d7",
        "0x8c2eb9f3eb0f6ba73a2249fe8eeb02cafa7a25e0",
        "0xa9059cbb000000000000000000000000d4c85f3cb8a625d25febb5acdade5e5bf4824fda000000000000000000000000000000000000000000000000000000000000022b"
    ]
}' \
| tr -d '\n' \
| curl -s -H 'content-type: application/json' -d @- http://localhost:8214 \
| jq .result > tx-receipt.json
```

```json
{
  "entrance_contract": "0x8c2eb9f3eb0f6ba73a2249fe8eeb02cafa7a25e0",
  "created_addresses": [],
  "destructed_addresses": [],
  "logs": [
    {
      "address": "0x8c2eb9f3eb0f6ba73a2249fe8eeb02cafa7a25e0",
      "data": "0x000000000000000000000000000000000000000000000000000000000000022b",
      "topics": [
        "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
        "0x000000000000000000000000c8328aabcd9b9e8e64fbc566c4385c3bdeb219d7",
        "0x000000000000000000000000d4c85f3cb8a625d25febb5acdade5e5bf4824fda"
      ]
    }
  ],
  "return_data": null,
  "tx": { ... },
  "tx_hash": "0x1111111111111111111111111111111111111111111111111111111111111111"
}

```

Then we sign the transaction use `polyjuice sign-tx` and send the transaction use `ckb-cli tx send`.

Then we query the balance of `0xc8328aabcd9b9e8e64fbc566c4385c3bdeb219d7` again:

```bash
echo '{
    "id": 2,
    "jsonrpc": "2.0",
    "method": "static_call",
    "params": [
        "0xc8328aabcd9b9e8e64fbc566c4385c3bdeb219d7",
        "0x8c2eb9f3eb0f6ba73a2249fe8eeb02cafa7a25e0",
        "0x70a08231000000000000000000000000c8328aabcd9b9e8e64fbc566c4385c3bdeb219d7"
    ]
}' \
| tr -d '\n' \
| curl -s -H 'content-type: application/json' -d @- http://localhost:8214 \
| jq
```

```json
{
  "jsonrpc": "2.0",
  "result": {
    "logs": [],
    "return_data": "0x000000000000000000000000000000000000000204fce5e3e2502610fffffdd5"
  },
  "id": 2
}
```

We can see the balance changed:

```
From:
0x000000000000000000000000000000000000000204fce5e3e250261100000000

To:
0x000000000000000000000000000000000000000204fce5e3e2502610fffffdd5
```

And query the balance of `0xd4c85f3cb8a625d25febb5acdade5e5bf4824fda`:

```bash
echo '{
    "id": 2,
    "jsonrpc": "2.0",
    "method": "static_call",
    "params": [
        "0xc8328aabcd9b9e8e64fbc566c4385c3bdeb219d7",
        "0x8c2eb9f3eb0f6ba73a2249fe8eeb02cafa7a25e0",
        "0x70a08231000000000000000000000000d4c85f3cb8a625d25febb5acdade5e5bf4824fda"
    ]
}' \
| tr -d '\n' \
| curl -s -H 'content-type: application/json' -d @- http://localhost:8214 \
| jq
```

```json
{
  "jsonrpc": "2.0",
  "result": {
    "logs": [],
    "return_data": "0x000000000000000000000000000000000000000000000000000000000000022b"
  },
  "id": 2
}
```


# The JSON-RPC API

## RPC methods:

``` rust
/// Create a contract
fn create(sender: H160, code: Bytes) -> TransactionReceipt;

/// Call a contract
fn call(sender: H160, contract_address: H160, input: Bytes) -> TransactionReceipt;

/// Static call a contract
fn static_call(sender: H160, contract_address: H160, input: Bytes) -> StaticCallResponse;

/// Get the code of a contract
fn get_code(contract_address: H160) -> ContractCodeJson;

/// Get contract list
fn get_contracts(from_block: u64, to_block: Option<u64>) -> Vec<ContractMetaJson>;

/// Get contract change record
fn get_change(contract_address: H160, block_number: Option<u64>) -> ContractChangeJson;

/// Get contract execution logs
fn get_logs(
  from_block: u64,
  to_block: Option<u64>,
  address: Option<H160>,
  filter_topics: Option<Vec<H256>>,
  limit: Option<u32>,
) -> Vec<LogInfo>;
```

## Response data structures:

``` rust
struct TransactionReceipt {
    tx: CkbTransaction,
    tx_hash: H256,
    entrance_contract: H160,
    /// The newly created contract's address
    created_addresses: Vec<H160>,
    /// Destructed contract addresses
    destructed_addresses: Vec<H160>,
    logs: Vec<LogEntry>,
    return_data: Option<Bytes>,
}

struct StaticCallResponse {
    return_data: Bytes,
    logs: Vec<LogEntry>,
}

struct ContractMetaJson {
    /// The block where the contract created
    block_number: u64,
    /// The contract address
    address: H160,

    /// The contract code
    code: Bytes,
    /// The contract code hash
    code_hash: H256,
    /// The hash of the transaction where the contract created
    tx_hash: H256,
    /// The output index of the transaction where the contract created
    output_index: u32,
    /// If the contract is destructed
    destructed: bool,
}

struct ContractChangeJson {
    tx_origin: H160,
    address: H160,
    /// Block number
    number: u64,
    /// Transaction index in current block
    tx_index: u32,
    /// Output index in current transaction
    output_index: u32,
    tx_hash: H256,
    new_storage: Vec<(H256, H256)>,
    logs: Vec<(Vec<H256>, Bytes)>,
    /// The change is create the contract
    is_create: bool,
}

struct ContractCodeJson {
    code: Bytes,
    /// The hash of the transaction where the contract created
    tx_hash: H256,
    /// The output index of the transaction where the contract created
    output_index: u32,
}

struct LogInfo {
    block_number: u64,
    tx_index: u32,
    log: LogEntry,
}

struct LogEntry {
    address: H160,
    topics: Vec<H256>,
    data: Bytes,
}
```
