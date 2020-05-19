use bincode::{deserialize, serialize};
use ckb_hash::blake2b_256;
use ckb_jsonrpc_types::{JsonBytes, OutPoint, ScriptHashType, Uint32};
use ckb_simple_account_layer::{run, CkbBlake2bHasher, Config, RunProofResult, RunResult};
use ckb_types::{bytes::Bytes, h256, packed, prelude::*, H160, H256, U256};
use rocksdb::{WriteBatch, DB};
use sparse_merkle_tree::{
    default_store::DefaultStore, traits::Store, SparseMerkleTree, H256 as SmtH256,
};
use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::iter::FromIterator;
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

use super::{db_get, value, Key, KeyType, Loader};
use crate::rpc_client::HttpRpcClient;
use crate::types::{ContractAddress, ContractChange, ContractCode, EoaAddress, WitnessData};

pub struct Indexer {
    pub db: Arc<DB>,
    pub loader: Loader,
    pub client: HttpRpcClient,
}

impl Indexer {
    pub fn from(db: Arc<DB>, ckb_uri: &str) -> Self {
        let loader = Loader::new(Arc::clone(&db), ckb_uri).unwrap();
        Indexer {
            db,
            loader,
            client: HttpRpcClient::new(ckb_uri.to_string()),
        }
    }

    // Ideally this should never return. The caller is responsible for wrapping
    // it into a separate thread.
    pub fn index(&mut self) -> Result<(), String> {
        let last_block_key_bytes = Bytes::from(&Key::Last);
        loop {
            let value::Last { number, hash } = match db_get(&self.db, &last_block_key_bytes)? {
                Some(last) => last,
                None => value::Last {
                    number: 0,
                    hash: self.client.get_block_hash(0)?.expect("get genesis hash"),
                },
            };

            let next_header = match self.client.get_header_by_number(number + 1)? {
                Some(header) if header.inner.parent_hash == hash => header,
                // Rollback
                Some(_header) => {
                    log::info!("Rollback block, nubmer={}, hash={}", number, hash);
                    let block_contracts_key = Bytes::from(&Key::BlockContracts(number));
                    let block_contracts: value::BlockContracts =
                        db_get(&self.db, &block_contracts_key)?
                            .unwrap_or_else(|| panic!("Can not load BlockContracts({})", number));
                    let last_block_info_opt = if number >= 1 {
                        let last_block_map_key = Bytes::from(&Key::BlockMap(number - 1));
                        let block_hash: value::BlockMap = db_get(&self.db, &last_block_map_key)?
                            .unwrap_or_else(|| panic!("Can not load BlockMap({})", number - 1));
                        Some(value::Last {
                            number: number - 1,
                            hash: block_hash.0,
                        })
                    } else {
                        None
                    };

                    let mut batch = WriteBatch::default();
                    for (address, is_create) in block_contracts.0 {
                        let change_start_key = Key::ContractChange {
                            address: address.clone(),
                            number: Some(number),
                            tx_index: None,
                            output_index: None,
                        };
                        let change_end_key = Key::ContractChange {
                            address: address.clone(),
                            number: Some(number + 1),
                            tx_index: None,
                            output_index: None,
                        };
                        let logs_start_key = Key::ContractLogs {
                            address: address.clone(),
                            number: Some(number),
                            tx_index: None,
                            output_index: None,
                        };
                        let logs_end_key = Key::ContractLogs {
                            address: address.clone(),
                            number: Some(number + 1),
                            tx_index: None,
                            output_index: None,
                        };
                        batch.delete_range(
                            &Bytes::from(&change_start_key),
                            &Bytes::from(&change_end_key),
                        );
                        batch.delete_range(
                            &Bytes::from(&logs_start_key),
                            &Bytes::from(&logs_end_key),
                        );
                        if is_create {
                            batch.delete(&Bytes::from(&Key::ContractCode(address)));
                        }
                    }
                    batch.delete(&Bytes::from(&Key::BlockMap(number)));
                    batch.delete(&block_contracts_key);
                    // Update last block info
                    if let Some(block_info) = last_block_info_opt {
                        let value_bytes = serialize(&block_info).map_err(|err| err.to_string())?;
                        batch.put(&last_block_key_bytes, &value_bytes);
                    }
                    self.db.write(batch).map_err(|err| err.to_string())?;
                    continue;
                }
                None => {
                    // Reach the tip, wait 200ms for next block
                    sleep(Duration::from_millis(200));
                    continue;
                }
            };

            let next_block = match self.client.get_block(next_header.hash.clone())? {
                Some(block) => block,
                None => {
                    log::warn!("Can not get block by hash: {:?}", next_header.hash);
                    sleep(Duration::from_millis(200));
                    continue;
                }
            };

            // FIXME: load code hash from db later
            pub const TYPE_CODE_HASH: H256 = h256!("0x1122");
            pub const TYPE_HASH_TYPE: ScriptHashType = ScriptHashType::Data;
            pub const TYPE_ARGS_LEN: usize = 20;
            // 32 bytes storage root + 32 bytes code_hash
            pub const OUTPUT_DATA_LEN: usize = 32 + 32;

            let mut block_changes: Vec<ContractChange> = Vec::new();
            let mut block_codes: Vec<ContractCode> = Vec::new();
            for (tx_index, (tx, tx_hash)) in next_block
                .transactions
                .into_iter()
                .map(|tx| (tx.inner, tx.hash))
                .enumerate()
            {
                // Information from upper level
                //   1. block number
                //   2. tx_hash
                //   3. tx_index

                let mut output_addresses: HashSet<ContractAddress> = HashSet::default();
                let mut contract_inputs: HashMap<ContractAddress, (HashMap<H256, H256>, Bytes)> =
                    HashMap::default();
                let mut contract_outputs: HashMap<usize, (ContractAddress, Bytes)> =
                    HashMap::default();

                for (input_index, input) in tx.inputs.into_iter().enumerate() {
                    // Information from input
                    //   1. is_create
                    //
                    //   - old storage
                    let cell_with_status =
                        self.client.get_live_cell(input.previous_output, true)?;
                    let cell_info = cell_with_status.cell.unwrap();
                    let output = cell_info.output;
                    let data = cell_info.data.unwrap().content.into_bytes();
                    let type_script = output.type_.clone().unwrap_or_default();
                    if data.len() == OUTPUT_DATA_LEN
                        && type_script.code_hash == TYPE_CODE_HASH
                        && type_script.hash_type == TYPE_HASH_TYPE
                        && type_script.args.len() == TYPE_ARGS_LEN
                    {
                        let address = ContractAddress::try_from(type_script.args.as_bytes())
                            .expect("checked length");
                        let change = self.loader.load_latest_contract_change(
                            address.clone(),
                            None,
                            false,
                        )?;
                        if contract_inputs
                            .insert(address, (change.new_storage, data))
                            .is_some()
                        {
                            panic!("Whey type script is not a type_id script?");
                        }
                    }
                }

                for (output_index, output) in tx.outputs.into_iter().enumerate() {
                    // Information from output
                    //   1. contract address
                    //   2. output_index
                    let data = tx.outputs_data[output_index].clone().into_bytes();
                    let type_script = output.type_.clone().unwrap_or_default();
                    if data.len() == OUTPUT_DATA_LEN
                        && type_script.code_hash == TYPE_CODE_HASH
                        && type_script.hash_type == TYPE_HASH_TYPE
                        && type_script.args.len() == TYPE_ARGS_LEN
                    {
                        let address = ContractAddress::try_from(type_script.args.as_bytes())
                            .expect("checked length");
                        if !output_addresses.insert(address.clone()) {
                            panic!("Why type script is not a type_id script?");
                        }
                        contract_outputs.insert(output_index, (address, data));
                    }
                }

                let mut tx_changes: Vec<ContractChange> = Vec::new();
                let mut tx_codes: Vec<ContractCode> = Vec::new();
                for (witness_index, witness) in tx.witnesses.into_iter().enumerate() {
                    // Information from witness
                    //   1. sender address (from signature in witness type field)
                    //   2. new_storage (after run the validator)
                    //   3. logs (after run the validator)

                    // NOTE:
                    //   1. output index must consist with witness index
                    //   2. witness data is in output_type field
                    if let Some((address, output_data)) = contract_outputs.get(&witness_index) {
                        let output_index = witness_index;
                        let is_create = !contract_inputs.contains_key(address);
                        match generate_change(
                            &tx_hash,
                            address,
                            output_data,
                            &witness.into_bytes(),
                            &contract_inputs,
                        ) {
                            Ok((sender, new_storage, logs, code)) => {
                                tx_changes.push(ContractChange {
                                    sender,
                                    new_storage,
                                    is_create,
                                    logs,
                                    address: address.clone(),
                                    number,
                                    tx_hash: tx_hash.clone(),
                                    tx_index: tx_index as u32,
                                    output_index: output_index as u32,
                                });
                                if is_create {
                                    tx_codes.push(ContractCode {
                                        address: address.clone(),
                                        code,
                                        tx_hash: tx_hash.clone(),
                                        output_index: output_index as u32,
                                    });
                                }
                            }
                            Err(err) => {
                                log::error!("Generate change error: {}", err);
                                tx_changes.clear();
                                tx_codes.clear();
                                break;
                            }
                        }
                    }
                }
                block_changes.extend(tx_changes);
                block_codes.extend(tx_codes);
            }

            let next_number = next_header.inner.number.value();
            let next_hash = next_header.hash;

            let mut batch = WriteBatch::default();
            // Key::BlockMap
            let block_map_value_bytes = serialize(&value::BlockMap(next_hash.clone())).unwrap();
            batch.put(
                &Bytes::from(&Key::BlockMap(next_number)),
                &block_map_value_bytes,
            );

            // Key::Last
            let last_block_info = value::Last {
                number: next_number,
                hash: next_hash.clone(),
            };
            let last_block_info_bytes = serialize(&last_block_info).unwrap();
            batch.put(&last_block_key_bytes, &last_block_key_bytes);

            let mut block_contracts: HashMap<ContractAddress, bool> = HashMap::default();
            for change in block_changes {
                block_contracts.insert(change.address.clone(), change.is_create);
                // Key::ContractChange
                let db_value_bytes = serialize(&change.db_value()).unwrap();
                batch.put(&Bytes::from(&change.db_key()), &db_value_bytes);
                // Key::ContractLogs
                if let Some(key_logs) = change.db_key_logs() {
                    let db_value_logs_bytes = serialize(&change.db_value_logs()).unwrap();
                    batch.put(&Bytes::from(&key_logs), &db_value_logs_bytes);
                }
            }
            for code in block_codes {
                // NOTE: May have another transaction after the contract created
                block_contracts.insert(code.address.clone(), true);
                // Key::ContractCode
                let db_value_bytes = serialize(&code.db_value()).unwrap();
                batch.put(&Bytes::from(&code.db_key()), &db_value_bytes);
            }
            // Key::BlockContracts
            let block_contracts = block_contracts.into_iter().collect::<Vec<_>>();
            let block_contracts_bytes = serialize(&value::BlockContracts(block_contracts)).unwrap();
            batch.put(
                &Bytes::from(&Key::BlockContracts(next_number)),
                &block_contracts_bytes,
            );

            self.db.write(batch).map_err(|err| err.to_string())?;
        }
        Ok(())
    }
}

fn generate_change(
    tx_hash: &H256,
    address: &ContractAddress,
    witness: &Bytes,
    output_data: &Bytes,
    contract_inputs: &HashMap<ContractAddress, (HashMap<H256, H256>, Bytes)>,
) -> Result<
    (
        EoaAddress,
        HashMap<H256, H256>,
        Vec<(Vec<H256>, Bytes)>,
        Bytes,
    ),
    String,
> {
    let witness_data = packed::WitnessArgs::from_slice(witness.as_ref())
        .map_err(|err| err.to_string())
        .and_then(|witness_args| {
            witness_args
                .output_type()
                .to_opt()
                .ok_or_else(|| String::from("can not find output_type in witness"))
        })
        .and_then(|witness_data| WitnessData::try_from(witness_data.as_slice()))?;
    let code_hash = blake2b_256(&witness_data.program.code);
    // FIXME: config should load from binary
    let config = Config::default();
    let program_data = witness_data.program_data();
    let mut tree = if let Some((old_storage, input_data)) = contract_inputs.get(address) {
        if &code_hash[..] != &input_data[32..64] {
            return Err(String::from("Code hash in input not match code in witness"));
        }
        if &input_data[32..64] != &output_data[32..64] {
            return Err(String::from(
                "input data code hash not match output data code hash",
            ));
        }

        let mut tree: SparseMerkleTree<CkbBlake2bHasher, SmtH256, DefaultStore<SmtH256>> =
            SparseMerkleTree::default();
        for (key, value) in old_storage {
            tree.update(h256_to_smth256(key), h256_to_smth256(value))
                .unwrap();
        }
        let old_root_hash: [u8; 32] = (*tree.root()).into();
        if &old_root_hash[..] != &input_data[0..32] {
            panic!("Storage root in input_data not match the state");
        }
        tree
    } else {
        SparseMerkleTree::default()
    };
    let result = run(&config, &tree, &program_data).map_err(|err| err.to_string())?;
    result.commit(&mut tree).unwrap();
    let new_root_hash: [u8; 32] = (*tree.root()).into();
    // FIXME: check output data match code hash (return data)
    if &new_root_hash[..] != &output_data[0..32] {
        return Err(String::from(
            "New storage root not match storage root in input data",
        ));
    }
    let new_storage: HashMap<H256, H256> = tree
        .store()
        .leaves_map()
        .values()
        .map(|leaf| (smth256_to_h256(&leaf.key), smth256_to_h256(&leaf.value)))
        .collect();

    let sender = witness_data.recover_sender(tx_hash)?;
    // FIXME: get logs from RunResult
    let logs = Vec::new();
    // FIXME: get code from return data
    let code = Bytes::default();
    Ok((sender, new_storage, logs, code))
}

fn smth256_to_h256(hash: &SmtH256) -> H256 {
    H256::from_slice(hash.as_slice()).unwrap()
}

fn h256_to_smth256(hash: &H256) -> SmtH256 {
    let mut buf = [0u8; 32];
    buf.copy_from_slice(hash.as_bytes());
    SmtH256::from(buf)
}
