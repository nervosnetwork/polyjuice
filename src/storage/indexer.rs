use bincode::serialize;
use ckb_hash::blake2b_256;
use ckb_jsonrpc_types::ScriptHashType;
use ckb_simple_account_layer::{run, CkbBlake2bHasher, Config};
use ckb_types::{bytes::Bytes, core, packed, prelude::*, H256};
use rocksdb::{WriteBatch, DB};
use sparse_merkle_tree::{default_store::DefaultStore, SparseMerkleTree, H256 as SmtH256};
use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

use super::{db_get, value, Key, Loader};
use crate::client::HttpRpcClient;
use crate::types::{
    h256_to_smth256, smth256_to_h256, ContractAddress, ContractChange, ContractCode, EoaAddress,
    RunConfig, WitnessData,
};

pub const TYPE_ARGS_LEN: usize = 20;
// 32 bytes storage root + 32 bytes code_hash
pub const OUTPUT_DATA_LEN: usize = 32 + 32;

pub struct Indexer {
    pub db: Arc<DB>,
    pub loader: Loader,
    pub client: HttpRpcClient,
    pub run_config: RunConfig,
}

impl Indexer {
    pub fn new(db: Arc<DB>, ckb_uri: &str, run_config: RunConfig) -> Self {
        let loader = Loader::new(Arc::clone(&db), ckb_uri).unwrap();
        Indexer {
            db,
            loader,
            client: HttpRpcClient::new(ckb_uri.to_string()),
            run_config,
        }
    }

    // Ideally this should never return. The caller is responsible for wrapping
    // it into a separate thread.
    pub fn index(&mut self) -> Result<(), String> {
        let type_code_hash: H256 = self.run_config.type_script.code_hash().unpack();
        let type_hash_type = {
            let ty =
                core::ScriptHashType::try_from(self.run_config.type_script.hash_type()).unwrap();
            ScriptHashType::from(ty)
        };
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
                    let block_delta_key = Bytes::from(&Key::BlockDelta(number));
                    let block_delta: value::BlockDelta = db_get(&self.db, &block_delta_key)?
                        .unwrap_or_else(|| panic!("Can not load BlockDelta({})", number));
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
                    for (address, is_create) in block_delta.contracts {
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
                    for (lock_hash, tx_index, output_index, value) in block_delta.added_cells {
                        batch.delete(&Bytes::from(&Key::LockLiveCell {
                            lock_hash,
                            number: Some(number),
                            tx_index: Some(tx_index),
                            output_index: Some(output_index),
                        }));
                        batch.delete(&Bytes::from(&Key::LiveCellMap(value.out_point())));
                    }
                    for (lock_hash, tx_index, output_index, value) in block_delta.removed_cells {
                        let key = Key::LockLiveCell {
                            lock_hash,
                            number: Some(number),
                            tx_index: Some(tx_index),
                            output_index: Some(output_index),
                        };
                        batch.put(&Bytes::from(&key), &serialize(&value).unwrap());
                        let map_key = Key::LiveCellMap(value.out_point());
                        let map_value = value::LiveCellMap { number, tx_index };
                        batch.put(&Bytes::from(&map_key), &serialize(&map_value).unwrap());
                    }
                    batch.delete(&Bytes::from(&Key::BlockMap(number)));
                    batch.delete(&block_delta_key);
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

            let mut added_cells: HashSet<(H256, u32, u32, value::LockLiveCell)> = HashSet::new();
            let mut removed_cells: HashSet<(H256, u32, u32, value::LockLiveCell)> = HashSet::new();
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

                for input in tx.inputs {
                    // Information from input
                    //   1. is_create
                    //
                    //   - old storage
                    let cell_with_status = self
                        .client
                        .get_live_cell(input.previous_output.clone(), true)?;
                    let cell_info = cell_with_status.cell.unwrap();
                    let output = cell_info.output;
                    let data = cell_info.data.unwrap().content.into_bytes();
                    let capacity = output.capacity.value();
                    let type_script = output.type_.clone().unwrap_or_default();
                    if data.len() == OUTPUT_DATA_LEN
                        && type_script.code_hash == type_code_hash
                        && type_script.hash_type == type_hash_type
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
                    let out_point = packed::OutPoint::from(input.previous_output.clone());
                    let prev_tx_hash = input.previous_output.tx_hash;
                    let prev_output_index = input.previous_output.index.value();
                    let lock_hash: H256 = packed::Script::from(output.lock)
                        .calc_script_hash()
                        .unpack();
                    let info: value::LiveCellMap =
                        db_get(&self.db, &Bytes::from(&Key::LiveCellMap(out_point)))?.unwrap();
                    let value = value::LockLiveCell {
                        tx_hash: prev_tx_hash,
                        output_index: prev_output_index,
                        capacity,
                    };
                    removed_cells.insert((lock_hash, info.tx_index, prev_output_index, value));
                }

                for (output_index, output) in tx.outputs.into_iter().enumerate() {
                    // Information from output
                    //   1. contract address
                    //   2. output_index
                    let data = tx.outputs_data[output_index].clone().into_bytes();
                    let type_script = output.type_.clone().unwrap_or_default();
                    if data.len() == OUTPUT_DATA_LEN
                        && type_script.code_hash == type_code_hash
                        && type_script.hash_type == type_hash_type
                        && type_script.args.len() == TYPE_ARGS_LEN
                    {
                        let address = ContractAddress::try_from(type_script.args.as_bytes())
                            .expect("checked length");
                        if !output_addresses.insert(address.clone()) {
                            panic!("Why type script is not a type_id script?");
                        }
                        contract_outputs.insert(output_index, (address, data));
                    }
                    let lock_hash: H256 = packed::Script::from(output.lock)
                        .calc_script_hash()
                        .unpack();
                    let value = value::LockLiveCell {
                        tx_hash: tx_hash.clone(),
                        output_index: output_index as u32,
                        capacity: output.capacity.value(),
                    };
                    added_cells.insert((lock_hash, tx_index as u32, output_index as u32, value));
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
                            &self.run_config,
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
            batch.put(&last_block_key_bytes, &last_block_info_bytes);

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
            // Lock live cell changes
            let common_cells = added_cells
                .intersection(&removed_cells)
                .cloned()
                .collect::<HashSet<_>>();
            let added_cells = added_cells
                .difference(&common_cells)
                .cloned()
                .collect::<Vec<_>>();
            let removed_cells = removed_cells
                .difference(&common_cells)
                .cloned()
                .collect::<Vec<_>>();
            for (lock_hash, tx_index, output_index, value) in added_cells.clone() {
                let key = Key::LockLiveCell {
                    lock_hash,
                    number: Some(next_number),
                    tx_index: Some(tx_index),
                    output_index: Some(output_index),
                };
                batch.put(&Bytes::from(&key), &serialize(&value).unwrap());
                let map_key = Key::LiveCellMap(value.out_point());
                let map_value = value::LiveCellMap {
                    number: next_number,
                    tx_index,
                };
                batch.put(&Bytes::from(&map_key), &serialize(&map_value).unwrap());
            }
            for (lock_hash, tx_index, output_index, value) in removed_cells.clone() {
                let key = Key::LockLiveCell {
                    lock_hash,
                    number: Some(next_number),
                    tx_index: Some(tx_index),
                    output_index: Some(output_index),
                };
                batch.delete(&Bytes::from(&key));
                batch.delete(&Bytes::from(&Key::LiveCellMap(value.out_point())));
            }
            // Key::BlockDelta
            let block_delta = value::BlockDelta {
                contracts: block_contracts.into_iter().collect::<Vec<_>>(),
                added_cells,
                removed_cells,
            };
            let block_contracts_bytes = serialize(&block_delta).unwrap();
            batch.put(
                &Bytes::from(&Key::BlockDelta(next_number)),
                &block_contracts_bytes,
            );

            self.db.write(batch).map_err(|err| err.to_string())?;
        }
    }
}

fn generate_change(
    run_config: &RunConfig,
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
    let program_data = witness_data.program_data();

    let (mut tree, code) = if let Some((old_storage, input_data)) = contract_inputs.get(address) {
        // Call contract
        let code_hash = blake2b_256(&witness_data.program.code);
        if code_hash[..] != input_data[32..64] {
            return Err(String::from("Code hash in input not match code in witness"));
        }
        if input_data[32..64] != output_data[32..64] {
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
        if old_root_hash[..] != input_data[0..32] {
            panic!("Storage root in input_data not match the state");
        }
        (tree, witness_data.program.code.clone())
    } else {
        let code_hash = blake2b_256(&witness_data.return_data);
        if code_hash[..] != output_data[32..64] {
            return Err(String::from(
                "return data hash not match output data code hash",
            ));
        }
        (
            SparseMerkleTree::default(),
            witness_data.return_data.clone(),
        )
    };

    let config: Config = run_config.into();
    let result = run(&config, &tree, &program_data).map_err(|err| err.to_string())?;
    result.commit(&mut tree).unwrap();
    let new_root_hash: [u8; 32] = (*tree.root()).into();
    if new_root_hash[..] != output_data[0..32] {
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
    // TODO: get logs from RunResult
    let logs = Vec::new();
    Ok((sender, new_storage, logs, code))
}
