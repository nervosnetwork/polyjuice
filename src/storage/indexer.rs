use bincode::{deserialize, serialize};
use ckb_jsonrpc_types::{OutPoint, ScriptHashType, Uint32};
use ckb_types::{bytes::Bytes, h256, packed, prelude::*, H160, H256, U256};
use rocksdb::{WriteBatch, DB};
use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::iter::FromIterator;
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

use super::{db_get, value, Key, KeyType, Loader};
use crate::rpc_client::HttpRpcClient;
use crate::types::{ContractAddress, EoaAddress};

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

                let mut contract_inputs: HashMap<ContractAddress, (usize, HashMap<H256, H256>)> =
                    HashMap::default();
                let mut contract_outputs: HashMap<ContractAddress, (usize, HashMap<H256, H256>)> =
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
                    let data = cell_info.data.unwrap().content;
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
                            .insert(address, (input_index, change.new_storage))
                            .is_some()
                        {
                            panic!("Why type script is not a type_id script?");
                        }
                    }
                }

                for (output_index, output) in tx.outputs.into_iter().enumerate() {
                    // Information from output
                    //   1. contract address
                    //   2. output_index
                    let data = tx.outputs_data[output_index].clone();
                    let type_script = output.type_.clone().unwrap_or_default();
                    if data.len() == OUTPUT_DATA_LEN
                        && type_script.code_hash == TYPE_CODE_HASH
                        && type_script.hash_type == TYPE_HASH_TYPE
                        && type_script.args.len() == TYPE_ARGS_LEN
                    {
                        let address = ContractAddress::try_from(type_script.args.as_bytes())
                            .expect("checked length");
                    }
                }

                for (witness_index, witness) in tx.witnesses.into_iter().enumerate() {
                    // Information from witness
                    //   1. sender address (from signature in witness type field)
                    //   2. new_storage (after run the validator)
                    //   3. logs (after run the validator)
                }
            }
        }
        Ok(())
    }
}
