use bincode::serialize;
use ckb_jsonrpc_types::{JsonBytes, ScriptHashType};
use ckb_simple_account_layer::{run_with_context, CkbBlake2bHasher, Config, RunContext, RunResult};
use ckb_types::{
    bytes::{BufMut, Bytes, BytesMut},
    core, h256, packed,
    prelude::*,
    H160, H256, U256,
};
use ckb_vm::{
    registers::{A0, A1, A2, A3, A4, A7},
    Error as VMError, Memory, Register, SupportMachine,
};
use rocksdb::{WriteBatch, DB};
use sparse_merkle_tree::{default_store::DefaultStore, SparseMerkleTree, H256 as SmtH256};
use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::error::Error as StdError;
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

use super::{db_get, value, Key, Loader};
use crate::client::HttpRpcClient;
use crate::types::{
    h256_to_smth256, parse_log, smth256_to_h256, vm_load_data, vm_load_h160, vm_load_h256,
    vm_load_i32, vm_load_i64, vm_load_u32, vm_load_u8, CallKind, ContractAddress, ContractChange,
    ContractMeta, EoaAddress, RunConfig, WitnessData,
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
        log::info!("type code hash: {:x}", type_code_hash);
        log::info!("type hash type: {:?}", type_hash_type);
        let last_block_key_bytes = Bytes::from(&Key::Last);
        loop {
            let next_header = if let Some(value::Last { number, hash }) =
                db_get(&self.db, &last_block_key_bytes)?
            {
                match self.client.get_header_by_number(number + 1) {
                    Ok(Some(header)) if header.inner.parent_hash == hash => header,
                    // Rollback
                    Ok(Some(_header)) => {
                        log::info!("Rollback block, nubmer={}, hash={}", number, hash);
                        let block_delta_key = Bytes::from(&Key::BlockDelta(number));
                        let block_delta: value::BlockDelta = db_get(&self.db, &block_delta_key)?
                            .unwrap_or_else(|| panic!("Can not load BlockDelta({})", number));
                        let last_block_info_opt = if number >= 1 {
                            let last_block_map_key = Bytes::from(&Key::BlockMap(number - 1));
                            let block_hash: value::BlockMap =
                                db_get(&self.db, &last_block_map_key)?.unwrap_or_else(|| {
                                    panic!("Can not load BlockMap({})", number - 1)
                                });
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
                                batch.delete(&Bytes::from(&Key::ContractMeta(address)));
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
                        for (lock_hash, old_number, tx_index, output_index, value) in
                            block_delta.removed_cells
                        {
                            let key = Key::LockLiveCell {
                                lock_hash,
                                number: Some(old_number),
                                tx_index: Some(tx_index),
                                output_index: Some(output_index),
                            };
                            batch.put(&Bytes::from(&key), &serialize(&value).unwrap());
                            let map_key = Key::LiveCellMap(value.out_point());
                            let map_value = value::LiveCellMap {
                                number: old_number,
                                tx_index,
                            };
                            batch.put(&Bytes::from(&map_key), &serialize(&map_value).unwrap());
                        }
                        for contract_address in block_delta.destructed_contracts {
                            let key_bytes =
                                Bytes::from(&Key::ContractMeta(contract_address.clone()));
                            let mut meta: value::ContractMeta = db_get(&self.db, &key_bytes)?
                                .ok_or_else(|| {
                                    format!("no such contract: {:x}", contract_address.0)
                                })?;
                            assert_eq!(meta.destructed, true);
                            meta.destructed = false;
                            batch.put(&key_bytes, &serialize(&meta).unwrap());
                        }
                        batch.delete(&Bytes::from(&Key::BlockMap(number)));
                        batch.delete(&block_delta_key);
                        // Update last block info
                        if let Some(block_info) = last_block_info_opt {
                            let value_bytes =
                                serialize(&block_info).map_err(|err| err.to_string())?;
                            batch.put(&last_block_key_bytes, &value_bytes);
                        }
                        self.db.write(batch).map_err(|err| err.to_string())?;
                        continue;
                    }
                    Ok(None) => {
                        // Reach the tip, wait 200ms for next block
                        sleep(Duration::from_millis(50));
                        // TODO: clean up OLD block delta here (before tip-200)
                        continue;
                    }
                    Err(err) => {
                        log::warn!("RPC error: {}", err);
                        sleep(Duration::from_millis(5000));
                        continue;
                    }
                }
            } else {
                self.client.get_header_by_number(0)?.unwrap()
            };

            log::debug!(
                "get block {} => {:x}",
                next_header.inner.number.value(),
                next_header.hash
            );
            let next_block = match self.client.get_block(next_header.hash.clone()) {
                Ok(Some(block)) => block,
                Ok(None) => {
                    log::warn!("Can not get block by hash: {:?}", next_header.hash);
                    sleep(Duration::from_millis(200));
                    continue;
                }
                Err(err) => {
                    log::error!("RPC error: {}", err);
                    sleep(Duration::from_millis(1000));
                    continue;
                }
            };

            let next_number = next_header.inner.number.value();
            let next_hash = next_header.hash;

            log::info!(
                "Process block: hash={:#x}, number={}",
                next_hash,
                next_number
            );

            let mut block_changes: Vec<ContractChange> = Vec::new();
            let mut block_codes: Vec<ContractMeta> = Vec::new();
            let mut destructed_contracts: Vec<ContractAddress> = Vec::new();

            let mut added_cells: HashSet<(H256, u32, u32, value::LockLiveCell)> = HashSet::new();
            let mut removed_cells: HashSet<(H256, u64, u32, u32, value::LockLiveCell)> =
                HashSet::new();
            let mut block_added_cells: HashMap<value::LockLiveCell, value::LiveCellMap> =
                HashMap::default();
            let mut block_removed_cells: HashSet<value::LockLiveCell> = HashSet::default();
            for (tx_index, (tx, tx_hash)) in next_block
                .transactions
                .into_iter()
                .map(|tx| (tx.inner, tx.hash))
                .enumerate()
            {
                log::debug!("process tx: hash={:#x}, tx_index: {}", tx_hash, tx_index);
                // Information from upper level
                //   1. block number
                //   2. tx_hash
                //   3. tx_index
                let mut script_groups: HashMap<ContractAddress, ContractInfo> = HashMap::default();

                for (input_index, input) in tx.inputs.into_iter().enumerate() {
                    // Information from input
                    //   1. is_create
                    //
                    //   - old storage
                    if input.previous_output.tx_hash == H256::default() {
                        continue;
                    }

                    let prev_tx = self
                        .client
                        .get_transaction(input.previous_output.tx_hash.clone())?
                        .unwrap()
                        .transaction
                        .inner;
                    let prev_index = input.previous_output.index.value() as usize;
                    let output = prev_tx.outputs[prev_index].clone();
                    let output_data_size = prev_tx.outputs_data[prev_index].len() as u32;
                    let data = prev_tx.outputs_data[prev_index].clone().into_bytes();
                    let capacity = output.capacity.value();
                    if let Some(ref type_script) = output.type_ {
                        log::debug!(
                            "inputs[{}]: type_script.code_hash={:x}",
                            input_index,
                            type_script.code_hash
                        );
                        log::debug!(
                            "inputs[{}]: type_script.hash_type={:?}",
                            input_index,
                            type_script.hash_type
                        );
                    }
                    let type_script = output.type_.clone().unwrap_or_default();
                    if data.len() == OUTPUT_DATA_LEN
                        && type_script.code_hash == type_code_hash
                        && type_script.hash_type == type_hash_type
                        && type_script.args.len() == TYPE_ARGS_LEN
                    {
                        log::debug!("match type script: input_index={}", input_index);
                        let address = ContractAddress::try_from(type_script.args.as_bytes())
                            .expect("checked length");
                        let change = self.loader.load_latest_contract_change(
                            address.clone(),
                            None,
                            false,
                            true,
                        )?;
                        let mut info = ContractInfo::default();
                        info.tree = change.merkle_tree();
                        info.input = Some((input_index, change));
                        script_groups.insert(address, info);
                    }
                    let out_point = packed::OutPoint::from(input.previous_output.clone());
                    let prev_tx_hash = input.previous_output.tx_hash;
                    let prev_output_index = input.previous_output.index.value();
                    let lock_hash: H256 = packed::Script::from(output.lock)
                        .calc_script_hash()
                        .unpack();
                    let value = value::LockLiveCell {
                        tx_hash: prev_tx_hash,
                        output_index: prev_output_index,
                        capacity,
                        data_size: output_data_size,
                        type_script_hash: output
                            .type_
                            .map(packed::Script::from)
                            .map(|data| data.calc_script_hash().unpack()),
                    };
                    let info: value::LiveCellMap =
                        block_added_cells.get(&value).cloned().unwrap_or_else(|| {
                            db_get(&self.db, &Bytes::from(&Key::LiveCellMap(out_point.clone())))
                                .unwrap()
                                .unwrap()
                        });
                    block_removed_cells.insert(value.clone());
                    removed_cells.insert((
                        lock_hash,
                        info.number,
                        info.tx_index,
                        prev_output_index,
                        value,
                    ));
                }

                for (output_index, output) in tx.outputs.into_iter().enumerate() {
                    // Information from output
                    //   1. contract address
                    //   2. output_index
                    let data = tx.outputs_data[output_index].clone().into_bytes();
                    let data_size = data.len() as u32;
                    if let Some(ref type_script) = output.type_ {
                        log::debug!(
                            "outputs[{}]: type_script.code_hash={:x}",
                            output_index,
                            type_script.code_hash
                        );
                        log::debug!(
                            "outputs[{}]: type_script.hash_type={:?}",
                            output_index,
                            type_script.hash_type
                        );
                    }
                    let type_script = output.type_.clone().unwrap_or_default();
                    if data.len() == OUTPUT_DATA_LEN
                        && type_script.code_hash == type_code_hash
                        && type_script.hash_type == type_hash_type
                        && type_script.args.len() == TYPE_ARGS_LEN
                    {
                        log::debug!("match type script: output_index={}", output_index);
                        let address = ContractAddress::try_from(type_script.args.as_bytes())
                            .expect("checked length");
                        let info = script_groups.entry(address).or_default();
                        if info.output.is_some() {
                            panic!("multiple output contract address");
                        }
                        info.output =
                            Some((output_index, packed::CellOutput::from(output.clone())));
                    }
                    let lock_hash: H256 = packed::Script::from(output.lock)
                        .calc_script_hash()
                        .unpack();
                    let value = value::LockLiveCell {
                        tx_hash: tx_hash.clone(),
                        output_index: output_index as u32,
                        capacity: output.capacity.value(),
                        data_size,
                        type_script_hash: output
                            .type_
                            .map(packed::Script::from)
                            .map(|data| data.calc_script_hash().unpack()),
                    };
                    block_added_cells.insert(
                        value.clone(),
                        value::LiveCellMap {
                            number: next_number,
                            tx_index: tx_index as u32,
                        },
                    );
                    added_cells.insert((lock_hash, tx_index as u32, output_index as u32, value));
                }

                if let Some(tip_block_hash) = tx.header_deps.get(0) {
                    let tip_block = self
                        .client
                        .get_block(tip_block_hash.clone())?
                        .map(core::BlockView::from)
                        .expect("block not exists");
                    let mut header_deps = HashMap::default();
                    for block_hash in tx.header_deps {
                        let header_view = self
                            .client
                            .get_header(block_hash.clone())?
                            .map(core::HeaderView::from)
                            .expect("header deps block not exists");
                        header_deps.insert(header_view.number(), header_view);
                    }
                    if let Some(mut extractor) = ContractExtractor::init(
                        self.run_config.clone(),
                        tip_block,
                        header_deps,
                        tx_hash,
                        tx_index as u32,
                        tx.witnesses,
                        script_groups,
                    )? {
                        extractor.run().map_err(|err| err.to_string())?;
                        block_changes.extend(extractor.get_contract_changes(next_number));
                        block_codes.extend(extractor.get_created_contracts());
                        destructed_contracts.extend(extractor.get_destructed_contracts());
                    }
                }
            }

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
                // Key::ContractMeta
                let db_value_bytes = serialize(&code.db_value()).unwrap();
                batch.put(&Bytes::from(&code.db_key()), &db_value_bytes);
            }
            let common_cells = block_added_cells
                .keys()
                .cloned()
                .collect::<HashSet<_>>()
                .intersection(&block_removed_cells)
                .cloned()
                .collect::<HashSet<_>>();
            for (lock_hash, tx_index, output_index, value) in added_cells.clone() {
                if common_cells.contains(&value) {
                    continue;
                }
                log::debug!(
                    "Add live cell: tx_hash={:#x}, index={}",
                    value.tx_hash,
                    value.output_index
                );
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
            for (lock_hash, number, tx_index, output_index, value) in removed_cells.clone() {
                if common_cells.contains(&value) {
                    continue;
                }
                log::debug!(
                    "Remove live cell: tx_hash={:#x}, index={}",
                    value.tx_hash,
                    value.output_index
                );
                let key = Key::LockLiveCell {
                    lock_hash,
                    number: Some(number),
                    tx_index: Some(tx_index),
                    output_index: Some(output_index),
                };
                batch.delete(&Bytes::from(&key));
                batch.delete(&Bytes::from(&Key::LiveCellMap(value.out_point())));
            }

            // selfdestruct
            for contract_address in &destructed_contracts {
                // For clean up logs when rollback
                block_contracts.insert(contract_address.clone(), false);
                let key_bytes = Bytes::from(&Key::ContractMeta(contract_address.clone()));
                let mut meta: value::ContractMeta = db_get(&self.db, &key_bytes)?
                    .ok_or_else(|| format!("no such contract: {:x}", contract_address.0))?;
                assert_eq!(meta.destructed, false);
                meta.destructed = true;
                batch.put(&key_bytes, &serialize(&meta).unwrap());
            }
            // Key::BlockDelta
            let block_delta = value::BlockDelta {
                contracts: block_contracts.into_iter().collect::<Vec<_>>(),
                added_cells: added_cells.into_iter().collect::<Vec<_>>(),
                removed_cells: removed_cells.into_iter().collect::<Vec<_>>(),
                destructed_contracts,
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

// Extract eth contract changes from CKB transaction
//   0. produce contract metas (CREATE)
//   1. produce contract changes
//   2. produce contract logs
//   3. produce SELFDESTRUCT contracts
pub struct ContractExtractor {
    run_config: RunConfig,
    tip_block: core::BlockView,
    header_deps: HashMap<u64, core::HeaderView>,
    tx_hash: H256,
    tx_index: u32,
    entrance_contract: ContractAddress,
    current_contract: ContractAddress,

    // script_hash => (input, output, programs)
    script_groups: HashMap<ContractAddress, ContractInfo>,
}

#[derive(Default)]
pub struct ContractInfo {
    input: Option<(usize, ContractChange)>,
    output: Option<(usize, packed::CellOutput)>,
    // Increased by 1 after ckb-vm run a program
    program_index: usize,
    programs: Vec<WitnessData>,
    call_indices: Vec<usize>,
    special_call_count: usize,
    // Updated by ckb-vm
    logs: Vec<(Vec<H256>, Bytes)>,
    pub run_result: RunResult,
    selfdestruct: Option<Bytes>,
    // Updated by ckb-vm
    tree: SparseMerkleTree<CkbBlake2bHasher, SmtH256, DefaultStore<SmtH256>>,
}

impl ContractInfo {
    pub fn selfdestruct(&self) -> Option<ContractAddress> {
        assert_eq!(
            self.output.is_none(),
            self.programs[self.programs.len() - 1]
                .selfdestruct
                .is_some(),
        );
        let last_program = &self.programs[self.programs.len() - 1];
        last_program
            .selfdestruct
            .as_ref()
            .map(|_| last_program.program.destination.clone())
    }
    pub fn is_create(&self) -> bool {
        self.input.is_none()
    }
    pub fn code(&self) -> Bytes {
        if self.is_create() {
            self.programs[0].return_data.clone()
        } else {
            self.programs[0].program.code.clone()
        }
    }

    pub fn current_call_index(&self) -> usize {
        self.call_indices[self.program_index]
    }
    pub fn current_call_index_mut(&mut self) -> &mut usize {
        &mut self.call_indices[self.program_index]
    }
    pub fn current_witness(&self) -> &WitnessData {
        &self.programs[self.program_index]
    }
    pub fn current_program_data(&self) -> Bytes {
        let mut witness = self.current_witness().clone();
        if self.program_index > 0 {
            // Put optmized code field back to program data
            witness.program.code = self.code();
        }
        witness.program_data()
    }

    pub fn get_meta(&self, address: &ContractAddress, tx_hash: &H256) -> Option<ContractMeta> {
        if self.is_create() {
            let output_index = self.output.as_ref().map(|(index, _)| *index).unwrap() as u32;
            Some(ContractMeta {
                address: address.clone(),
                code: self.code(),
                tx_hash: tx_hash.clone(),
                output_index,
                destructed: false,
            })
        } else {
            None
        }
    }

    pub fn get_change(
        &self,
        address: &ContractAddress,
        number: u64,
        tx_index: u32,
        tx_hash: &H256,
    ) -> Option<ContractChange> {
        if let Some((output_index, output)) = self.output.as_ref() {
            let new_storage: HashMap<H256, H256> = self
                .tree
                .store()
                .leaves_map()
                .values()
                .map(|leaf| (smth256_to_h256(&leaf.key), smth256_to_h256(&leaf.value)))
                .collect();
            let tx_origin = self.programs[0].program.tx_origin.clone();
            let capacity: u64 = output.capacity().unpack();
            Some(ContractChange {
                tx_origin,
                address: address.clone(),
                number,
                tx_index,
                output_index: *output_index as u32,
                tx_hash: tx_hash.clone(),
                new_storage,
                logs: self.logs.clone(),
                capacity,
                is_create: self.is_create(),
            })
        } else {
            None
        }
    }
}

impl ContractExtractor {
    pub fn init(
        run_config: RunConfig,
        tip_block: core::BlockView,
        header_deps: HashMap<u64, core::HeaderView>,
        tx_hash: H256,
        tx_index: u32,
        witnesses: Vec<JsonBytes>,
        mut script_groups: HashMap<ContractAddress, ContractInfo>,
    ) -> Result<Option<ContractExtractor>, String> {
        let mut tx_origin = EoaAddress::default();
        let mut entrance_contract = None;
        for (addr, info) in script_groups.iter_mut() {
            let witness_index = if let Some((input_index, _)) = info.input {
                input_index
            } else if let Some((output_index, _)) = info.output {
                output_index
            } else {
                panic!("Input/Output both empty");
            };
            let mut start = 0;
            let witness_args = packed::WitnessArgs::from_slice(witnesses[witness_index].as_bytes())
                .map_err(|err| err.to_string())?;
            let raw_witness = witness_args
                .input_type()
                .to_opt()
                .or_else(|| witness_args.output_type().to_opt())
                .map(|witness_data| witness_data.raw_data())
                .ok_or_else(|| {
                    format!(
                        "can not find raw witness data in witnesses[{}]",
                        witness_index
                    )
                })?;
            while let Some((offset, witness_data)) = WitnessData::load_from(&raw_witness[start..])?
            {
                if tx_origin == EoaAddress::default() {
                    tx_origin = witness_data.program.tx_origin.clone();
                }
                if tx_origin != witness_data.program.tx_origin {
                    panic!("multiple tx_origin in one transaction");
                }
                if !witness_data.signature.iter().all(|byte| *byte == 0) {
                    if entrance_contract.is_some() {
                        panic!("Multiple entrance contract");
                    }
                    entrance_contract = Some(addr.clone());
                }
                info.programs.push(witness_data);
                info.call_indices.push(0);
                start += offset;
            }
        }

        if entrance_contract.is_none() && !script_groups.is_empty() {
            panic!("Invalid transaction");
        }

        Ok(entrance_contract.map(|entrance_contract| {
            let current_contract = entrance_contract.clone();
            ContractExtractor {
                run_config,
                tip_block,
                header_deps,
                tx_hash,
                tx_index,
                entrance_contract,
                current_contract,
                script_groups,
            }
        }))
    }

    pub fn run(&mut self) -> Result<(), Box<dyn StdError>> {
        let entrance_contract = self.entrance_contract.clone();
        self.run_with(&entrance_contract, false).map(|_| ())
    }

    pub fn run_with(
        &mut self,
        contract: &ContractAddress,
        is_special_call: bool,
    ) -> Result<Bytes, Box<dyn StdError>> {
        self.current_contract = contract.clone();
        let (tree_clone, saved_program_index, program, program_data) = {
            let info = self
                .script_groups
                .get_mut(contract)
                .ok_or_else(|| format!("No such contract to run: {:x}", contract.0))?;
            let tree_clone = SparseMerkleTree::new(*info.tree.root(), info.tree.store().clone());
            let saved_program_index = info.program_index;
            let program_index = if is_special_call {
                info.special_call_count += 1;
                info.program_index + info.special_call_count
            } else {
                info.program_index
            };
            let program = info.programs[program_index].program.clone();
            let program_data = if program.kind.is_special_call() {
                let dest_info = self
                    .script_groups
                    .get_mut(&program.destination)
                    .ok_or_else(|| {
                        format!("No such contract to run: {:x}", program.destination.0)
                    })?;
                let program_data = dest_info.current_program_data();
                dest_info.program_index += 1;
                program_data
            } else {
                info.current_program_data()
            };
            (tree_clone, saved_program_index, program, program_data)
        };
        let config = Config::from(&self.run_config);
        let _result = match run_with_context(&config, &tree_clone, &program_data, self) {
            Ok(result) => result,
            Err(err) => {
                log::warn!("Error: {:?}", err);
                return Err(err);
            }
        };
        let info = self
            .script_groups
            .get_mut(contract)
            .ok_or_else(|| format!("No such contract to run: {:x}", contract.0))?;

        let program_index = if program.kind.is_special_call() {
            info.program_index + info.special_call_count
        } else {
            saved_program_index
        };
        let return_data = info.programs[program_index].return_data.clone();
        if !program.kind.is_special_call() {
            let run_result = std::mem::take(&mut info.run_result);
            run_result.commit(&mut info.tree).unwrap();
            info.program_index += info.special_call_count + 1;
            info.special_call_count = 0;
        }
        Ok(return_data)
    }

    pub fn get_contract_changes(&self, number: u64) -> Vec<ContractChange> {
        self.script_groups
            .iter()
            .filter_map(|(addr, info)| info.get_change(addr, number, self.tx_index, &self.tx_hash))
            .collect()
    }
    pub fn get_created_contracts(&self) -> Vec<ContractMeta> {
        self.script_groups
            .iter()
            .filter_map(|(addr, info)| info.get_meta(addr, &self.tx_hash))
            .collect()
    }
    pub fn get_destructed_contracts(&self) -> Vec<ContractAddress> {
        self.script_groups
            .values()
            .filter_map(|info| info.selfdestruct())
            .collect()
    }
}

impl<Mac: SupportMachine> RunContext<Mac> for ContractExtractor {
    fn ecall(&mut self, machine: &mut Mac) -> Result<bool, VMError> {
        let code = machine.registers()[A7].to_u64();
        match code {
            // ckb_debug
            2177 => {
                let mut addr = machine.registers()[A0].to_u64();
                let mut buffer = Vec::new();

                loop {
                    let byte = machine
                        .memory_mut()
                        .load8(&Mac::REG::from_u64(addr))?
                        .to_u8();
                    if byte == 0 {
                        break;
                    }
                    buffer.push(byte);
                    addr += 1;
                }

                let s = String::from_utf8(buffer).map_err(|_| VMError::ParseError)?;
                log::debug!("ckb_debug: {}", s);
                Ok(true)
            }
            // insert
            3073 => {
                let key_address = machine.registers()[A0].to_u64();
                let key = vm_load_h256(machine, key_address)?;
                let value_address = machine.registers()[A1].to_u64();
                let value = vm_load_h256(machine, value_address)?;
                log::debug!("[set_storage] key={:x}, value={:x}", key, value);
                let info = self.script_groups.get_mut(&self.current_contract).unwrap();
                info.run_result
                    .write_values
                    .insert(h256_to_smth256(&key), h256_to_smth256(&value));
                machine.set_register(A0, Mac::REG::from_u64(0));
                Ok(true)
            }
            // fetch
            3074 => {
                let key_address = machine.registers()[A0].to_u64();
                let key = vm_load_h256(machine, key_address)?;
                let value_address = machine.registers()[A1].to_u64();
                log::debug!("[get_storage] key {:x}", key);

                let smth256_key = h256_to_smth256(&key);
                let info = self.script_groups.get_mut(&self.current_contract).unwrap();
                let value = match info.run_result.write_values.get(&smth256_key) {
                    Some(value) => *value,
                    None => {
                        let tree_value = info
                            .tree
                            .get(&smth256_key)
                            .map_err(|_| VMError::Unexpected)?;
                        if tree_value != SmtH256::default() {
                            info.run_result.read_values.insert(smth256_key, tree_value);
                        }
                        tree_value
                    }
                };
                machine
                    .memory_mut()
                    .store_bytes(value_address, value.as_slice())?;
                Ok(true)
            }
            // return
            3075 => Ok(true),
            // LOG{0,1,2,3,4}
            3076 => {
                let data_address = machine.registers()[A0].to_u64();
                let data_length = machine.registers()[A1].to_u32();
                let data = vm_load_data(machine, data_address, data_length)?;
                self.script_groups
                    .get_mut(&self.current_contract)
                    .unwrap()
                    .logs
                    .push(parse_log(&data[..]).unwrap());
                Ok(true)
            }
            // SELFDESTRUCT
            3077 => {
                let data_address = machine.registers()[A0].to_u64();
                let data_length = machine.registers()[A1].to_u32();
                let data = vm_load_data(machine, data_address, data_length)?;
                self.script_groups
                    .get_mut(&self.current_contract)
                    .unwrap()
                    .selfdestruct = Some(data.into());
                Ok(true)
            }
            // CALL
            3078 => {
                let mut msg_data_address = machine.registers()[A1].to_u64();
                let kind_value: u8 = vm_load_u8(machine, msg_data_address)?;
                msg_data_address += 1;
                let _flags: u32 = vm_load_u32(machine, msg_data_address)?;
                msg_data_address += 4;
                let _depth: i32 = vm_load_i32(machine, msg_data_address)?;
                msg_data_address += 4;
                let _gas: i64 = vm_load_i64(machine, msg_data_address)?;
                msg_data_address += 8;
                let msg_destination: H160 = vm_load_h160(machine, msg_data_address)?;
                msg_data_address += 20;
                let _sender: H160 = vm_load_h160(machine, msg_data_address)?;
                msg_data_address += 20;
                let input_size: u32 = vm_load_u32(machine, msg_data_address)?;
                msg_data_address += 4;
                let _input_data: Vec<u8> = vm_load_data(machine, msg_data_address, input_size)?;
                msg_data_address += input_size as u64;
                let _value: H256 = vm_load_h256(machine, msg_data_address)?;

                let kind = CallKind::try_from(kind_value).unwrap();

                let info_mut = self
                    .script_groups
                    .get_mut(&self.current_contract)
                    .expect("can not find current contract");
                log::debug!(
                    "address: {:x}, program_index: {}",
                    self.current_contract.0,
                    info_mut.program_index
                );
                let destination = info_mut.current_witness().calls[info_mut.current_call_index()]
                    .0
                    .clone();
                *info_mut.current_call_index_mut() += 1;
                if kind.is_call() {
                    assert_eq!(
                        destination.0, msg_destination,
                        "destination address not match"
                    );
                };
                let info_address = if kind.is_special_call() {
                    self.current_contract.clone()
                } else {
                    destination.clone()
                };
                let saved_current_contract = self.current_contract.clone();
                let return_data = self
                    .run_with(&info_address, kind.is_special_call())
                    .map_err(|_err| VMError::Unexpected)?;
                let create_address = if kind.is_create() {
                    destination
                } else {
                    ContractAddress(H160::default())
                };
                self.current_contract = saved_current_contract;

                // Store return_data to VM memory
                let result_data_address = machine.registers()[A0].to_u64();
                let mut result_data = BytesMut::default();
                result_data.put(&(return_data.len() as u32).to_le_bytes()[..]);
                result_data.put(return_data.as_ref());
                result_data.put(create_address.0.as_bytes());
                machine
                    .memory_mut()
                    .store_bytes(result_data_address, result_data.as_ref())?;
                Ok(true)
            }
            // get code size
            3079 => {
                let address_ptr = machine.registers()[A0].to_u64();
                let address: H160 = vm_load_h160(machine, address_ptr)?;
                let code_size_ptr = machine.registers()[A1].to_u64();
                log::debug!("[get_code_size]: address={:x}", address);
                let code_size = self
                    .script_groups
                    .get(&ContractAddress(address))
                    .expect("Can not get contract info")
                    .code()
                    .len() as u32;
                machine
                    .memory_mut()
                    .store_bytes(code_size_ptr, &code_size.to_le_bytes()[..])?;
                machine.set_register(A0, Mac::REG::from_u8(0));
                Ok(true)
            }
            // copy code
            3080 => {
                let address_ptr = machine.registers()[A0].to_u64();
                let code_offset = machine.registers()[A1].to_u32() as usize;
                let buffer_data_ptr = machine.registers()[A2].to_u64();
                let buffer_size = machine.registers()[A3].to_u32() as usize;
                let done_size_ptr = machine.registers()[A4].to_u64();

                let address: H160 = vm_load_h160(machine, address_ptr)?;
                log::debug!("[copy_code]: address={:x}", address);
                let code = self
                    .script_groups
                    .get(&ContractAddress(address))
                    .expect("Can not get contract info")
                    .code();
                let done_size = std::cmp::min(code.len() - code_offset, buffer_size);
                let code_slice = &code.as_ref()[code_offset..code_offset + done_size];

                log::debug!("code done size: {}", done_size);
                log::debug!("code slice: {}", hex::encode(code_slice));
                machine
                    .memory_mut()
                    .store_bytes(buffer_data_ptr, code_slice)?;
                machine
                    .memory_mut()
                    .store_bytes(done_size_ptr, &(done_size as u32).to_le_bytes()[..])?;
                machine.set_register(A0, Mac::REG::from_u8(0));
                Ok(true)
            }
            3081 => {
                let block_hash_ptr = machine.registers()[A0].to_u64();
                let number = machine.registers()[A1].to_u64();
                let header_view = self.header_deps.get(&number).ok_or_else(|| {
                    log::warn!("get_block_hash({}), load header failed", number);
                    VMError::IO(std::io::ErrorKind::InvalidInput)
                })?;
                let block_hash: H256 = header_view.hash().unpack();
                machine
                    .memory_mut()
                    .store_bytes(block_hash_ptr, block_hash.as_bytes())?;
                machine.set_register(A0, Mac::REG::from_u8(0));
                Ok(true)
            }
            // evmc_tx_context {block_number, block_timestamp, difficulty, chain_id}
            3082 => {
                let buffer_ptr = machine.registers()[A0].to_u64();
                let mut data = [0u8; 8 + 8 + 32 + 20 + 32];
                let number = self.tip_block.number();
                let timestamp = self.tip_block.timestamp() / 1000;
                let difficulty = self.tip_block.difficulty();
                // TODO: config chain ID
                let chain_id = U256::one();
                // FIXME: only recognize secp_blake160 for now
                let cellbase_lock = self
                    .tip_block
                    .transaction(0)
                    .expect("Cellbase must exists")
                    .output(0)
                    .expect("No output in cellbase")
                    .lock();
                let secp_blake160_code_hash: packed::Byte32 =
                    h256!("0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8")
                        .pack();
                let coinbase_opt = if cellbase_lock.hash_type() == core::ScriptHashType::Type.into()
                    && cellbase_lock.code_hash() == secp_blake160_code_hash
                {
                    H160::from_slice(cellbase_lock.args().raw_data().as_ref()).ok()
                } else {
                    None
                };
                let coinbase = coinbase_opt.unwrap_or_default();

                log::debug!("number: {}, timestamp: {}", number, timestamp);
                data[0..8].copy_from_slice(&number.to_le_bytes());
                data[8..16].copy_from_slice(&timestamp.to_le_bytes());
                data[16..48].copy_from_slice(&difficulty.to_be_bytes());
                data[48..68].copy_from_slice(coinbase.as_bytes());
                data[68..100].copy_from_slice(&chain_id.to_be_bytes());
                machine.memory_mut().store_bytes(buffer_ptr, &data[..])?;
                machine.set_register(A0, Mac::REG::from_u8(0));
                Ok(true)
            }
            _ => Ok(false),
        }
    }
}
